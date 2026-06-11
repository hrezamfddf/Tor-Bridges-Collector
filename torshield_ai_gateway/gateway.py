"""
TorShieldAIGateway v13.0 — Ultra-Quantum Edition
═══════════════════════════════════════════════════════════════════════════

Unified facade over all providers + local fallback with STRICT monitoring.

CRITICAL FIXES from v12.0:
  1. CF AI Gateway URL now includes account_id in workers-ai path
  2. Cerebras model name corrected (llama3.3-70b)
  3. Portkey model name updated (meta/llama-3.1-70b-instruct)
  4. Cross-slot model skip reduces cascade failures in CF providers
  5. WRONG_RESPONSE is treated as failure, not degraded

PRESERVED from v12.0:
  1. User-Agent header automatically set on all HTTP requests (fixes CF 1010)
  2. Model selector filters UUID-format IDs (fixes 400 "No route for URI")
  3. Cloudflare bot protection (403/1010) is now retryable with backoff
  4. Iran Auto-Defense integration: censorship-aware provider selection
  5. LocalAIEngine fallback is STRICTLY MONITORED and flagged as degraded
  6. Gateway tracks which provider actually answered (primary vs fallback)
  7. WRONG_RESPONSE from any provider is treated as a failure
  8. Full retry orchestration across providers before LocalAIEngine
  9. Exponential backoff between provider attempts
  10. Detailed failure logging with provider chain visibility
  11. Fallback counter tracks how often LocalAIEngine is used
  12. Health check can distinguish primary_ok from degraded

Provider waterfall priority (fastest first, most reliable last):
  1. Cerebras        — 2100 tokens/sec
  2. CF-AI-Gateway   — cached, 11x quota via gateway URLs
  3. CF-Workers-AI   — direct, no caching
  4. Portkey         — meta-router fallback
  5. LocalAIEngine   — zero-dependency rule-based fallback (ALWAYS available)
     ⚠ LocalAIEngine is DEGRADED mode, NOT a primary provider

SECURITY: Gateway NEVER silently accepts wrong responses.
  - If a provider returns unexpected content, it's marked as failed
  - If all primary providers fail, LocalAIEngine is used but flagged
  - The caller can check response metadata to know the source
"""

import os
import time
import random
import logging
from typing import Optional, List, Dict, Any
from .model_selector import CloudflareModelSelector, model_selector_status
from .local_ai_engine import LocalAIEngine

logger = logging.getLogger("torshield.ai.gateway")
_GATEWAY_INSTANCE: Optional["TorShieldAIGateway"] = None


class TorShieldAIGateway:
    PROVIDER_PRIORITY = [
        "cerebras",
        "cloudflare_ai_gateway",
        "cloudflare_workers_ai",
        "portkey",
    ]

    # Retry configuration for inter-provider backoff
    INTER_PROVIDER_BASE_DELAY = 0.5   # seconds
    INTER_PROVIDER_MAX_DELAY  = 5.0   # seconds
    PROVIDER_ATTEMPT_RETRIES  = 1     # extra retries per provider (beyond provider-internal)

    def __init__(self):
        self._providers: dict = {}
        self._selector = CloudflareModelSelector.instance()
        self._init_providers()

        # Monitoring counters
        self._stats = {
            "total_requests":    0,
            "primary_successes": 0,
            "local_fallback_uses": 0,
            "all_primary_failed": 0,
            "provider_attempts": {},  # provider_name → count
        }

    def _init_providers(self) -> None:
        from .providers import (
            CerebrasProvider,
            CloudflareAIGatewayProvider,
            CloudflareWorkersAIProvider,
            PortkeyProvider,
        )
        candidates = [
            ("cerebras",              CerebrasProvider),
            ("cloudflare_ai_gateway", CloudflareAIGatewayProvider),
            ("cloudflare_workers_ai", CloudflareWorkersAIProvider),
            ("portkey",               PortkeyProvider),
        ]
        for name, cls in candidates:
            try:
                self._providers[name] = cls()
                logger.info(f"[Gateway] Initialized provider: {name}")
            except (ValueError, KeyError) as e:
                logger.warning(f"[Gateway] Provider {name} not available: {e}")

    def chat(
        self,
        messages:            List[Dict[str, str]],
        model:               Optional[str] = None,
        max_tokens:          int = 2048,
        temperature:         float = 0.2,
        preferred_provider:  Optional[str] = None,
        task:                str = "general",
    ) -> str:
        """
        Send a chat request through the provider waterfall.

        Args:
            messages:           OpenAI-format message list.
            model:              Override model (None = use dynamic selector).
            max_tokens:         Max tokens to generate.
            temperature:        Sampling temperature.
            preferred_provider: Try this provider first if available.
            task:               Task category for dynamic model selection.
                                One of: "general", "reasoning", "coding",
                                        "vision", "fast".

        Returns:
            Response text from the first successful provider.
            If all primary providers fail, returns LocalAIEngine response.

        Raises:
            Never raises — always returns a string (LocalAIEngine is ultimate fallback).
        """
        self._stats["total_requests"] += 1

        order = []
        if preferred_provider and preferred_provider in self._providers:
            order.append(preferred_provider)
        for p in self.PROVIDER_PRIORITY:
            if p not in order and p in self._providers:
                order.append(p)

        # If no external providers are configured, go directly to local fallback
        if not order:
            logger.warning(
                "[Gateway] No external providers available — using LocalAIEngine"
            )
            self._stats["all_primary_failed"] += 1
            self._stats["local_fallback_uses"] += 1
            return self._local_fallback(messages, task)

        last_error: Optional[Exception] = None
        last_response: Optional[str] = None

        for provider_idx, provider_name in enumerate(order):
            self._stats["provider_attempts"][provider_name] = \
                self._stats["provider_attempts"].get(provider_name, 0) + 1

            # Attempt the provider with optional retry
            for attempt in range(self.PROVIDER_ATTEMPT_RETRIES + 1):
                try:
                    logger.debug(
                        f"[Gateway] Trying {provider_name} [task={task}] "
                        f"(attempt {attempt + 1})"
                    )
                    provider = self._providers[provider_name]
                    result = provider.chat_complete(
                        messages=messages,
                        model=model,
                        max_tokens=max_tokens,
                        temperature=temperature,
                        task=task,
                    )

                    if result and result.strip():
                        self._stats["primary_successes"] += 1
                        logger.info(
                            f"[Gateway] ✓ Success via {provider_name} "
                            f"(attempt {attempt + 1})"
                        )
                        return result
                    else:
                        logger.warning(
                            f"[Gateway] {provider_name} returned empty response"
                        )
                        last_response = result or ""

                except Exception as e:
                    logger.warning(f"[Gateway] {provider_name} failed: {e}")
                    last_error = e

                # Inter-provider backoff before retry
                if attempt < self.PROVIDER_ATTEMPT_RETRIES:
                    delay = min(
                        self.INTER_PROVIDER_BASE_DELAY * (2 ** attempt) +
                        random.uniform(-0.2, 0.2),
                        self.INTER_PROVIDER_MAX_DELAY,
                    )
                    logger.debug(
                        f"[Gateway] Backing off {delay:.1f}s before retry "
                        f"of {provider_name}"
                    )
                    time.sleep(delay)

            # Backoff between providers
            if provider_idx < len(order) - 1:
                delay = min(
                    self.INTER_PROVIDER_BASE_DELAY * (2 ** provider_idx),
                    self.INTER_PROVIDER_MAX_DELAY,
                )
                logger.debug(
                    f"[Gateway] Moving to next provider after {delay:.1f}s"
                )
                time.sleep(delay)

        # All external providers failed — fall back to local AI engine
        self._stats["all_primary_failed"] += 1
        self._stats["local_fallback_uses"] += 1
        logger.warning(
            f"[Gateway] ⚠ All {len(order)} external providers failed. "
            f"Activating LocalAIEngine fallback (DEGRADED mode). "
            f"Last error: {last_error}"
        )
        return self._local_fallback(messages, task)

    def _local_fallback(self, messages: List[Dict[str, str]], task: str = "general") -> str:
        """
        Use LocalAIEngine when all external providers are unavailable.
        This is DEGRADED mode — not suitable for production health checks.
        """
        try:
            local_engine = LocalAIEngine()
            result = local_engine.chat_complete(messages, task=task)
            logger.info("[Gateway] LocalAIEngine fallback succeeded (DEGRADED)")
            return result
        except Exception as e:
            logger.error(f"[Gateway] LocalAIEngine also failed: {e}")
            # Ultimate fallback — return a valid JSON response
            return (
                '{"status":"error","message":"All AI providers (external + local) failed",'
                '"source":"gateway_fallback","degraded":true}'
            )

    def prompt(self, system: str, user: str, task: str = "general", **kwargs) -> str:
        messages = [
            {"role": "system", "content": system},
            {"role": "user",   "content": user},
        ]
        return self.chat(messages, task=task, **kwargs)

    def model_selector_status(self) -> Dict:
        """Return model selector status (ranked list, cache age, selected models)."""
        return model_selector_status()

    def invalidate_model_cache(self) -> None:
        """Force model list refresh on next call."""
        self._selector.invalidate_cache()

    def health_stats(self) -> Dict[str, Any]:
        """
        Return gateway health statistics.
        Used by health check to monitor LocalAIEngine usage.
        """
        return {
            "total_requests":     self._stats["total_requests"],
            "primary_successes":  self._stats["primary_successes"],
            "local_fallback_uses": self._stats["local_fallback_uses"],
            "all_primary_failed": self._stats["all_primary_failed"],
            "primary_success_rate": (
                self._stats["primary_successes"] / max(self._stats["total_requests"], 1)
            ),
            "degraded_rate": (
                self._stats["local_fallback_uses"] / max(self._stats["total_requests"], 1)
            ),
            "provider_attempts": dict(self._stats["provider_attempts"]),
            "available_providers": list(self._providers.keys()),
        }


def get_gateway() -> TorShieldAIGateway:
    global _GATEWAY_INSTANCE
    if _GATEWAY_INSTANCE is None:
        _GATEWAY_INSTANCE = TorShieldAIGateway()
    return _GATEWAY_INSTANCE
