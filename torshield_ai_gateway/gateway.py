"""
TorShieldAIGateway v9.0 — unified facade over all providers.

Provider waterfall priority (fastest first, most reliable last):
  1. Cerebras        — 2100 tokens/sec
  2. CF-AI-Gateway   — cached, 11x quota via gateway URLs
  3. CF-Workers-AI   — direct, no caching
  4. Portkey         — meta-router fallback

NEW in v9.0:
  - task= parameter propagated through the entire call chain.
  - CloudflareModelSelector used automatically by CF providers.
  - Gateway exposes model_selector_status() for monitoring.
"""

import os
import logging
from typing import Optional, List, Dict
from .model_selector import CloudflareModelSelector, model_selector_status

logger = logging.getLogger("torshield.ai.gateway")
_GATEWAY_INSTANCE: Optional["TorShieldAIGateway"] = None


class TorShieldAIGateway:
    PROVIDER_PRIORITY = [
        "cerebras",
        "cloudflare_ai_gateway",
        "cloudflare_workers_ai",
        "portkey",
    ]

    def __init__(self):
        self._providers: dict = {}
        self._selector = CloudflareModelSelector.instance()
        self._init_providers()

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
        """
        order = []
        if preferred_provider and preferred_provider in self._providers:
            order.append(preferred_provider)
        for p in self.PROVIDER_PRIORITY:
            if p not in order and p in self._providers:
                order.append(p)

        last_error: Optional[Exception] = None
        for provider_name in order:
            provider = self._providers[provider_name]
            try:
                logger.debug(f"[Gateway] Trying {provider_name} [task={task}]")
                result = provider.chat_complete(
                    messages=messages,
                    model=model,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    task=task,
                )
                logger.info(f"[Gateway] Success via {provider_name}")
                return result
            except Exception as e:
                logger.warning(f"[Gateway] {provider_name} failed: {e}")
                last_error = e

        raise RuntimeError(
            f"[TorShieldAIGateway] All providers exhausted. Last error: {last_error}"
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


def get_gateway() -> TorShieldAIGateway:
    global _GATEWAY_INSTANCE
    if _GATEWAY_INSTANCE is None:
        _GATEWAY_INSTANCE = TorShieldAIGateway()
    return _GATEWAY_INSTANCE
