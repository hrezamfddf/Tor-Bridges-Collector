#!/usr/bin/env python3
"""
AI Gateway Health Check v12.0 — Ultra-Quantum Edition
═══════════════════════════════════════════════════════════════════════════

CRITICAL FIXES from v11.0:
  1. FIX: Auth errors (403/400/401) are NOT retried — they won't fix themselves
  2. FIX: Reduced default max_retries from 3 to 2 to prevent 20-min timeout
  3. FIX: WRONG_RESPONSE is now treated as FAILURE (not just degraded)
  4. FIX: Per-provider timeout protection — auth failures skip remaining retries

PRESERVED from v10.0/v11.0:
  1. Exponential backoff retry mechanism for network failures
  2. Verbose debugging on authentication failure (NO key exposure)
  3. Strict non-zero exit when NO primary provider is reachable
  4. LocalAIEngine fallback is monitored but NOT counted as "ok"
  5. WRONG_RESPONSE is treated as a failure condition
  6. Env var validation before attempting any API calls
  7. Detailed diagnostic output for header/URL/credential issues

HEALTH CHECK POLICY:
  - A provider is "ok" ONLY if it returns the expected TORSHIELD_OK signal
  - LocalAIEngine fallback is "degraded" status, NOT "ok"
  - Script exits 0 ONLY if at least one PRIMARY provider responds correctly
  - Script exits 1 if ALL primary providers fail (even if LocalAIEngine works)
  - Script exits 2 if required environment variables are missing entirely

RETRY MECHANISM:
  - Configurable max retries (default 2) with exponential backoff
  - Base delay 1s, multiplier 2x, jitter ±0.5s
  - Auth errors (400/401/403) are NOT retried
  - Only network errors (timeout, 5xx, connection) are retried
"""

import os
import sys
import json
import argparse
import time
import logging
import random
import urllib.error
import urllib.request
from typing import Dict, List, Optional, Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger("health_check")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ════════════════════════════════════════════════════════════════════════════
# RETRY WITH EXPONENTIAL BACKOFF
# ════════════════════════════════════════════════════════════════════════════

class ExponentialBackoffRetry:
    """
    Robust exponential backoff retry mechanism with jitter.

    Parameters:
        max_retries:    Maximum number of retry attempts (0 = no retry)
        base_delay_sec: Initial delay between retries in seconds
        max_delay_sec:  Maximum delay cap in seconds
        jitter:         Random jitter range ±seconds to avoid thundering herd

    Backoff formula:
        delay = min(base_delay * 2^attempt + random(-jitter, +jitter), max_delay)
    """

    def __init__(
        self,
        max_retries: int = 3,
        base_delay_sec: float = 1.0,
        max_delay_sec: float = 30.0,
        jitter: float = 0.5,
    ):
        self.max_retries = max_retries
        self.base_delay = base_delay_sec
        self.max_delay = max_delay_sec
        self.jitter = jitter

    def compute_delay(self, attempt: int) -> float:
        """Compute the delay for the given attempt number (0-indexed)."""
        raw_delay = self.base_delay * (2 ** attempt)
        jittered = raw_delay + random.uniform(-self.jitter, self.jitter)
        return min(max(jittered, 0.1), self.max_delay)

    def execute(self, func, *args, **kwargs) -> tuple:
        """
        Execute a function with exponential backoff retry.

        Returns:
            (result, attempts_made, last_error)
            result is None if all attempts failed.
        """
        last_error = None
        for attempt in range(self.max_retries + 1):
            try:
                result = func(*args, **kwargs)
                return result, attempt + 1, None
            except Exception as e:
                last_error = e
                if attempt < self.max_retries:
                    delay = self.compute_delay(attempt)
                    logger.info(
                        f"  [Retry {attempt + 1}/{self.max_retries}] "
                        f"Backing off {delay:.1f}s after: {str(e)[:120]}"
                    )
                    time.sleep(delay)
                else:
                    logger.warning(
                        f"  [Retry EXHAUSTED] All {self.max_retries + 1} attempts failed: "
                        f"{str(e)[:150]}"
                    )
        return None, self.max_retries + 1, last_error


# ════════════════════════════════════════════════════════════════════════════
# VERBOSE AUTH FAILURE DIAGNOSTICS
# ════════════════════════════════════════════════════════════════════════════

class AuthFailureDiagnostics:
    """
    Generates verbose debugging information when authentication fails.
    CRITICAL: NEVER exposes sensitive keys or tokens.
    """

    @staticmethod
    def mask_key(key: str, visible_chars: int = 4) -> str:
        """Mask a key, showing only the first and last few characters."""
        if not key:
            return "<EMPTY>"
        if len(key) <= visible_chars * 2:
            return f"{key[:2]}***{key[-2:]}" if len(key) >= 4 else "***"
        return f"{key[:visible_chars]}...{key[-visible_chars:]}"

    @staticmethod
    def diagnose_http_error(
        error: urllib.error.HTTPError,
        provider: str,
        url: str,
        headers_sent: dict,
        response_body: str = "",
    ) -> Dict[str, Any]:
        """
        Produce a detailed diagnostic report for an HTTP error.
        Masks all sensitive values in headers.
        """
        sensitive_keys = {
            "authorization", "x-portkey-api-key", "api-key",
            "x-api-key", "bearer", "token",
        }

        # Mask headers
        masked_headers = {}
        for k, v in headers_sent.items():
            if k.lower() in sensitive_keys:
                masked_headers[k] = AuthFailureDiagnostics.mask_key(str(v))
            else:
                masked_headers[k] = str(v)

        # Classify the error
        diagnosis = {
            "provider": provider,
            "http_status": error.code,
            "http_reason": str(error.reason) if hasattr(error, 'reason') else "Unknown",
            "url_pattern": AuthFailureDiagnostics._classify_url(url),
            "headers_sent": masked_headers,
            "response_body_preview": response_body[:300] if response_body else "<empty>",
            "diagnosis": AuthFailureDiagnostics._infer_root_cause(
                error.code, url, masked_headers, response_body
            ),
            "recommendations": [],
        }

        # Add recommendations based on error code
        if error.code == 403:
            diagnosis["recommendations"] = [
                "Verify API key is valid and not expired",
                "Check if the API key has the required permissions/scopes",
                "Ensure the key format is correct (no trailing whitespace or newlines)",
                "Check if the provider has IP allowlisting that may block GitHub Actions",
                "Verify the account has remaining quota/credits",
                "Check if the service has region restrictions (Iran sanctions?)",
            ]
            if "cloudflare" in provider.lower():
                diagnosis["recommendations"].extend([
                    "Verify CF_API_TOKEN has 'Workers AI' permission",
                    "Check if CF_ACCOUNT_ID matches the token's account",
                    "Ensure gateway URL format: https://gateway.ai.cloudflare.com/v1/{account_id}/{slug}",
                ])
            elif "cerebras" in provider.lower():
                diagnosis["recommendations"].extend([
                    "Verify Cerebras API key is active at cloud.cerebras.ai",
                    "Check if the key has 'inference' scope enabled",
                    "Ensure the account has available credits",
                ])
            elif "portkey" in provider.lower():
                diagnosis["recommendations"].extend([
                    "Verify Portkey API key at app.portkey.ai",
                    "Check x-portkey-provider header is set correctly",
                    "Ensure virtual key configuration is active",
                ])

        elif error.code == 400:
            diagnosis["recommendations"] = [
                "Check the request payload format matches the API specification",
                "Verify model ID is correct and available on this provider",
                "Check if required fields are missing from the request",
                "Ensure Content-Type header is 'application/json'",
            ]
            if "cloudflare_workers_ai" in provider.lower():
                diagnosis["recommendations"].extend([
                    "CF Workers AI model ID must be full path: @cf/provider/model-name",
                    "Verify the model is available on your account's region",
                    "Check if the model name has been updated/renamed",
                ])

        return diagnosis

    @staticmethod
    def _classify_url(url: str) -> str:
        """Classify URL structure without exposing account IDs."""
        if "cloudflare.com/client/v4/accounts" in url:
            # Mask account ID in URL
            parts = url.split("/accounts/")
            if len(parts) == 2:
                acct_part = parts[1].split("/")[0]
                masked = AuthFailureDiagnostics.mask_key(acct_part, 3)
                return f"https://api.cloudflare.com/client/v4/accounts/{masked}/***"
            return "cloudflare-api (account-masked)"
        elif "cerebras.ai" in url:
            return "cerebras-api"
        elif "portkey.ai" in url:
            return "portkey-api"
        elif "gateway.ai.cloudflare.com" in url:
            return "cf-ai-gateway (account-masked)"
        return url[:60] + "..." if len(url) > 60 else url

    @staticmethod
    def _infer_root_cause(
        status_code: int, url: str, headers: dict, body: str
    ) -> str:
        """Infer the most likely root cause of the failure."""
        body_lower = body.lower() if body else ""

        if status_code == 403:
            # Detect Cloudflare bot protection (error code 1010)
            if "error code: 1010" in (body or ""):
                return (
                    "CLOUDFLARE_BOT_PROTECTION: Request blocked by Cloudflare "
                    "anti-bot (error code 1010). NOT an auth failure — "
                    "User-Agent header missing or blocked. Should be retried "
                    "with a proper browser-like User-Agent."
                )
            if "invalid" in body_lower or "unauthorized" in body_lower:
                return "INVALID_CREDENTIALS: API key is rejected by the provider"
            elif "forbidden" in body_lower or "access denied" in body_lower:
                return "INSUFFICIENT_PERMISSIONS: Key lacks required scopes"
            elif "quota" in body_lower or "limit" in body_lower or "rate" in body_lower:
                return "QUOTA_EXCEEDED: Account has hit rate or usage limits"
            elif "sanction" in body_lower or "region" in body_lower or "embargo" in body_lower:
                return "REGION_BLOCKED: Provider blocks requests from certain regions"
            elif "expired" in body_lower:
                return "KEY_EXPIRED: API key has expired"
            else:
                return "AUTH_FAILURE: 403 Forbidden — likely invalid/expired key or insufficient permissions"

        elif status_code == 400:
            if "model" in body_lower and ("not found" in body_lower or "invalid" in body_lower):
                return "INVALID_MODEL: The requested model ID is not available"
            elif "payload" in body_lower or "body" in body_lower:
                return "MALFORMED_REQUEST: Request payload is invalid"
            elif "header" in body_lower:
                return "HEADER_FORMAT_ERROR: Required header is missing or malformed"
            else:
                return "BAD_REQUEST: Malformed request or invalid parameters"

        return f"HTTP_{status_code}: Unspecified error"


# ════════════════════════════════════════════════════════════════════════════
# ENVIRONMENT VARIABLE VALIDATOR
# ════════════════════════════════════════════════════════════════════════════

class EnvVarValidator:
    """
    Validates that required environment variables are present and properly
    mapped from GitHub Secrets before attempting any API calls.
    """

    PROVIDER_ENV_MAP = {
        "cerebras": {
            "required_patterns": ["CEREBRAS_API_KEY_{i}"],
            "min_keys": 1,
            "description": "At least one CEREBRAS_API_KEY_N needed",
        },
        "cloudflare_ai_gateway": {
            "required_patterns": ["CF_ACCOUNT_ID_{i}", "CF_API_TOKEN_{i}", "CF_AI_GATEWAY_URL_{i}"],
            "min_keys": 1,
            "description": "At least one set of CF_ACCOUNT_ID_N + CF_API_TOKEN_N + CF_AI_GATEWAY_URL_N needed",
        },
        "cloudflare_workers_ai": {
            "required_patterns": ["CF_ACCOUNT_ID_{i}", "CF_API_TOKEN_{i}"],
            "min_keys": 1,
            "description": "At least one set of CF_ACCOUNT_ID_N + CF_API_TOKEN_N needed",
        },
        "portkey": {
            "required_patterns": ["PORTKEY_API_KEY_{i}"],
            "min_keys": 1,
            "description": "At least one PORTKEY_API_KEY_N needed",
        },
    }

    @classmethod
    def validate(cls, providers: List[str]) -> Dict[str, Any]:
        """
        Validate environment variables for the requested providers.
        Returns a report with which providers have valid env vars.
        """
        report = {
            "valid_providers": [],
            "invalid_providers": [],
            "details": {},
            "warnings": [],
        }

        for provider in providers:
            config = cls.PROVIDER_ENV_MAP.get(provider)
            if not config:
                report["invalid_providers"].append(provider)
                report["details"][provider] = {
                    "status": "unknown_provider",
                    "message": f"No env var config defined for provider: {provider}",
                }
                continue

            found_sets = 0
            slot_details = []

            for i in range(1, 12):
                slot_vars = {}
                all_present = True
                for pattern in config["required_patterns"]:
                    var_name = pattern.replace("{i}", str(i))
                    value = os.environ.get(var_name, "")
                    slot_vars[var_name] = bool(value)
                    if not value:
                        all_present = False

                if all_present:
                    found_sets += 1
                    slot_details.append({"slot": i, "status": "configured", "vars": slot_vars})
                elif any(slot_vars.values()):
                    # Partial configuration — some vars present but not all
                    missing = [k for k, v in slot_vars.items() if not v]
                    present = [k for k, v in slot_vars.items() if v]
                    slot_details.append({
                        "slot": i, "status": "partial",
                        "present": present, "missing": missing,
                    })
                    report["warnings"].append(
                        f"[{provider}] Slot {i} partially configured: "
                        f"has {present}, missing {missing}"
                    )

            if found_sets >= config["min_keys"]:
                report["valid_providers"].append(provider)
                report["details"][provider] = {
                    "status": "ok",
                    "configured_slots": found_sets,
                    "slots": slot_details,
                }
            else:
                report["invalid_providers"].append(provider)
                report["details"][provider] = {
                    "status": "missing_env_vars",
                    "configured_slots": found_sets,
                    "required": config["description"],
                    "slots": slot_details,
                }
                report["warnings"].append(
                    f"[{provider}] {config['description']} — found {found_sets} slot(s)"
                )

        return report


# ════════════════════════════════════════════════════════════════════════════
# MODEL SELECTOR CHECK
# ════════════════════════════════════════════════════════════════════════════

def check_model_selector() -> dict:
    """Run model selector status check without making any AI calls."""
    from torshield_ai_gateway.model_selector import CloudflareModelSelector
    sel = CloudflareModelSelector.instance()
    try:
        ranked = sel.ranked_models(task="general", top_n=5)
        top = ranked[0] if ranked else None
        return {
            "status":   "ok",
            "total":    len(ranked),
            "top_model": top.id if top else "none",
            "top_score": top.score if top else 0.0,
            "top_5": [
                {"rank": i+1, "id": m.id, "score": m.score, "tier": m.tier}
                for i, m in enumerate(ranked)
            ],
        }
    except Exception as e:
        return {"status": "error", "error": str(e)[:300]}


# ════════════════════════════════════════════════════════════════════════════
# PROVIDER CHECK WITH RETRY + VERBOSE DIAGNOSTICS
# ════════════════════════════════════════════════════════════════════════════

def check_provider(
    provider_name: str,
    task: str = "general",
    max_retries: int = 3,
) -> dict:
    """
    Check a single provider with exponential backoff retry.

    Returns a detailed result dict including:
      - provider name, status, latency, response
      - retry_attempts, auth_diagnostics (on 403/400)
      - Whether this is a PRIMARY success or DEGRADED (LocalAIEngine)
    """
    from torshield_ai_gateway.gateway import TorShieldAIGateway

    retry_engine = ExponentialBackoffRetry(
        max_retries=max_retries,
        base_delay_sec=1.0,
        max_delay_sec=15.0,  # Reduced from 30s to prevent timeout cascade
        jitter=0.5,
    )

    result = {
        "provider": provider_name,
        "status": "pending",
        "latency_ms": 0,
        "response": "",
        "retry_attempts": 0,
        "auth_diagnostics": None,
        "is_primary": True,
    }

    def _attempt_provider_call():
        """
        Call the provider DIRECTLY (not through the gateway waterfall).
        
        CRITICAL: We must NOT use gw.chat(preferred_provider=...) because
        the gateway waterfall will silently fall through to other providers
        when the preferred one fails. This means checking "portkey" would
        succeed via cerebras, giving a false "portkey OK" result.
        
        Instead, we instantiate the specific provider class and call its
        chat_complete() method directly. If it raises, the provider FAILED.
        """
        from torshield_ai_gateway.providers import (
            CerebrasProvider,
            CloudflareAIGatewayProvider,
            CloudflareWorkersAIProvider,
            PortkeyProvider,
        )
        _PROVIDER_MAP = {
            "cerebras":              CerebrasProvider,
            "cloudflare_ai_gateway": CloudflareAIGatewayProvider,
            "cloudflare_workers_ai": CloudflareWorkersAIProvider,
            "portkey":               PortkeyProvider,
        }
        
        provider_cls = _PROVIDER_MAP.get(provider_name)
        if provider_cls is None:
            raise ValueError(f"Unknown provider: {provider_name}")
        
        start = time.time()
        try:
            provider = provider_cls()
            response = provider.chat_complete(
                messages=[{"role": "user", "content": (
                    "Reply with ONLY the word TORSHIELD_OK and nothing else. "
                    "No punctuation, no explanation, no spaces around it."
                )}],
                max_tokens=20,
                temperature=0.0,
                task=task,
            )
            latency = time.time() - start
            # Since we called the provider directly (no gateway waterfall),
            # any non-empty response came from the PRIMARY provider.
            return {"response": response, "latency": latency, "response_source": "primary"}
        except Exception as e:
            latency = time.time() - start
            # Capture HTTP error details for diagnostics
            error_body = ""
            is_auth_error = False
            if isinstance(e, urllib.error.HTTPError):
                try:
                    error_body = e.read().decode("utf-8", errors="replace")[:500]
                except Exception:
                    pass
                # Auth errors (403/400/401) won't fix with retry
                if e.code in (400, 401, 403):
                    is_auth_error = True
            raise _ProviderCheckError(e, latency, error_body, is_auth_error)

    class _ProviderCheckError(Exception):
        """Wrapper that carries latency, HTTP error body, and auth error flag."""
        def __init__(self, original, latency, error_body="", is_auth_error=False):
            self.original = original
            self.latency = latency
            self.error_body = error_body
            self.is_auth_error = is_auth_error
            super().__init__(str(original))

    # Execute with smart retry — auth errors are NOT retried
    retry_result = None
    last_error = None
    for attempt in range(max_retries + 1):
        try:
            retry_result = _attempt_provider_call()
            result["retry_attempts"] = attempt + 1
            break
        except _ProviderCheckError as e:
            last_error = e
            result["retry_attempts"] = attempt + 1
            # Auth errors (403/400/401) won't fix themselves — stop retrying
            if e.is_auth_error:
                logger.warning(
                    f"  [{provider_name}] Auth error (HTTP 400/401/403) — "
                    f"NOT retrying (won't fix itself)"
                )
                break
            # Network errors — retry with backoff
            if attempt < max_retries:
                delay = retry_engine.compute_delay(attempt)
                logger.info(
                    f"  [{provider_name}] Network error — "
                    f"retry {attempt + 1}/{max_retries} in {delay:.1f}s: "
                    f"{str(e.original)[:100]}"
                )
                time.sleep(delay)
            else:
                logger.warning(
                    f"  [{provider_name}] All {max_retries + 1} attempts exhausted"
                )
        except Exception as e:
            last_error = _ProviderCheckError(e, 0, "", False)
            result["retry_attempts"] = attempt + 1
            if attempt < max_retries:
                delay = retry_engine.compute_delay(attempt)
                time.sleep(delay)

    if retry_result is not None:
        response = retry_result["response"]
        latency = retry_result["latency"]
        response_source = retry_result.get("response_source", "primary")
        # Since we call providers directly (no gateway waterfall),
        # response_source is always "primary" for successful calls.
        result["latency_ms"] = round(latency * 1000)

        # ── Authoritative source check ──────────────────────────────
        # If the gateway metadata says this came from LocalAIEngine,
        # it is ALWAYS degraded — even if the text happens to contain
        # "TORSHIELD_OK".  This prevents false-positive primary counts.
        if response_source == "local_fallback":
            result["status"] = "degraded_local"
            result["response"] = response[:200]
            result["is_primary"] = False
            logger.warning(
                f"  [{provider_name}] DEGRADED: gateway reports response from "
                f"LocalAIEngine fallback (last_response_source={response_source})"
            )
        elif response_source == "primary":
            # Primary provider responded — check content for expected signal
            # Use flexible matching: accept if TORSHIELD_OK appears anywhere
            # in the response (some models add whitespace or newlines)
            cleaned = response.strip().upper()
            is_torshield_ok = "TORSHIELD_OK" in cleaned
            if is_torshield_ok:
                result["status"] = "ok"
                result["response"] = response[:100]
            else:
                # WRONG_RESPONSE from a primary is treated as FAILURE
                result["status"] = "wrong_response"
                result["response"] = response[:200]
                result["is_primary"] = False
                logger.error(
                    f"  [{provider_name}] WRONG_RESPONSE from primary: "
                    f"'{response[:80]}...' (expected TORSHIELD_OK) — "
                    f"TREATED AS FAILURE"
                )
        else:
            # No metadata from gateway — fall back to content-based heuristics
            cleaned = response.strip().upper()
            is_torshield_ok = "TORSHIELD_OK" in cleaned
            if is_torshield_ok:
                result["status"] = "ok"
                result["response"] = response[:100]
            else:
                if _is_local_engine_response(response):
                    result["status"] = "degraded_local"
                    result["response"] = response[:200]
                    result["is_primary"] = False
                    logger.warning(
                        f"  [{provider_name}] FELLBACK to LocalAIEngine (heuristic) — "
                        f"response does not contain TORSHIELD_OK"
                    )
                else:
                    result["status"] = "wrong_response"
                    result["response"] = response[:200]
                    result["is_primary"] = False
                    logger.error(
                        f"  [{provider_name}] WRONG_RESPONSE: "
                        f"'{response[:80]}...' (expected TORSHIELD_OK) — "
                        f"TREATED AS FAILURE"
                    )
    else:
        # All retries failed
        result["status"] = "error"
        result["latency_ms"] = round((last_error.latency if hasattr(last_error, 'latency') else 0) * 1000)

        if isinstance(last_error, _ProviderCheckError) and last_error.original:
            orig = last_error.original
            result["error"] = str(orig)[:300]

            # Generate verbose auth diagnostics for 403/400 errors
            if isinstance(orig, urllib.error.HTTPError):
                if orig.code in (403, 400):
                    # Reconstruct what was sent for diagnostics
                    diag = _generate_provider_diagnostics(
                        provider_name, orig, last_error.error_body
                    )
                    result["auth_diagnostics"] = diag

                    # Log the detailed diagnostics
                    logger.error(
                        f"  [{provider_name}] AUTH FAILURE DIAGNOSTICS:"
                    )
                    logger.error(
                        f"    HTTP {diag.get('http_status')} {diag.get('http_reason')}"
                    )
                    logger.error(
                        f"    Root cause: {diag.get('diagnosis')}"
                    )
                    for rec in diag.get("recommendations", [])[:3]:
                        logger.error(f"    → {rec}")
        else:
            result["error"] = str(last_error)[:300] if last_error else "Unknown error"

    return result


def _is_local_engine_response(response: str) -> bool:
    """Detect if a response came from LocalAIEngine."""
    local_indicators = [
        "bridge_score",
        "dpi_evasion",
        "censorship_level",
        "iran_reachability",
        "transport_recommendation",
        "nin_survival",
        "local_ai_engine",
        '"source": "local"',
    ]
    response_lower = response.lower()
    return any(indicator in response_lower for indicator in local_indicators)


def _generate_provider_diagnostics(
    provider_name: str,
    error: urllib.error.HTTPError,
    error_body: str,
) -> Dict[str, Any]:
    """Generate detailed diagnostics for a provider auth failure."""
    # Reconstruct approximate request details for diagnostics
    from torshield_ai_gateway.gateway import TorShieldAIGateway

    url = ""
    headers = {}

    try:
        if provider_name == "cerebras":
            url = "https://api.cerebras.ai/v1/chat/completions"
            import os
            key = os.environ.get("CEREBRAS_API_KEY_1", "")
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {AuthFailureDiagnostics.mask_key(key)}",
            }
        elif provider_name == "portkey":
            import os
            gw_url = os.environ.get("PORTKEY_GATEWAY_URL", "https://api.portkey.ai/v1")
            url = f"{gw_url}/chat/completions"
            key = os.environ.get("PORTKEY_API_KEY_1", "")
            headers = {
                "Content-Type": "application/json",
                "x-portkey-api-key": AuthFailureDiagnostics.mask_key(key),
                "x-portkey-provider": "openai",
            }
        elif provider_name == "cloudflare_ai_gateway":
            import os
            acct = os.environ.get("CF_ACCOUNT_ID_1", "")
            gw_url = os.environ.get("CF_AI_GATEWAY_URL_1", "")
            url = f"{gw_url}/workers-ai/{acct}/@cf/meta/llama-3.1-8b-instruct"
            token = os.environ.get("CF_API_TOKEN_1", "")
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {AuthFailureDiagnostics.mask_key(token)}",
            }
        elif provider_name == "cloudflare_workers_ai":
            import os
            acct = os.environ.get("CF_ACCOUNT_ID_1", "")
            url = f"https://api.cloudflare.com/client/v4/accounts/{AuthFailureDiagnostics.mask_key(acct, 3)}/ai/run/@cf/meta/llama-3.1-8b-instruct"
            token = os.environ.get("CF_API_TOKEN_1", "")
            headers = {
                "Content-Type": "application/json",
                "Authorization": f"Bearer {AuthFailureDiagnostics.mask_key(token)}",
            }
    except Exception as e:
        logger.debug(f"Diagnostic reconstruction error: {e}")

    return AuthFailureDiagnostics.diagnose_http_error(
        error=error,
        provider=provider_name,
        url=url,
        headers_sent=headers,
        response_body=error_body,
    )


# ════════════════════════════════════════════════════════════════════════════
# MAIN
# ════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="AI Gateway Health Check v11.0 — Ultra-Quantum Edition"
    )
    parser.add_argument("--output", default="gateway_health_report.json")
    parser.add_argument("--task", default="general",
        choices=["general", "reasoning", "coding", "vision", "fast"])
    parser.add_argument("--providers", nargs="+",
        default=["cerebras", "cloudflare_ai_gateway",
                 "cloudflare_workers_ai", "portkey"])
    parser.add_argument("--max-retries", type=int, default=2,
        help="Max retry attempts per provider (default: 2, was 3)")
    parser.add_argument("--skip-env-check", action="store_true",
        help="Skip environment variable validation step")
    args = parser.parse_args()

    report = {
        "version": "12.0-ultra-quantum",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "run_id": os.environ.get("GITHUB_RUN_ID", "local"),
        "model_selector": {},
        "env_validation": {},
        "results": [],
        "summary": {},
    }

    # ── Step 1: Environment Variable Validation ────────────────────────────
    if not args.skip_env_check:
        logger.info("═══ Step 1: Validating Environment Variables ═══")
        env_report = EnvVarValidator.validate(args.providers)
        report["env_validation"] = env_report

        if env_report["valid_providers"]:
            logger.info(
                f"  ✓ Providers with valid env vars: "
                f"{env_report['valid_providers']}"
            )
        if env_report["invalid_providers"]:
            logger.warning(
                f"  ✗ Providers with MISSING env vars: "
                f"{env_report['invalid_providers']}"
            )
        for warning in env_report["warnings"]:
            logger.warning(f"  ⚠ {warning}")

        # If NO providers have valid env vars, exit immediately with code 2
        if not env_report["valid_providers"]:
            logger.error(
                "CRITICAL: No providers have valid environment variables. "
                "Check GitHub Secrets mapping."
            )
            report["summary"] = {
                "total": len(args.providers),
                "ok": 0,
                "degraded": len(args.providers),
                "healthy": False,
                "primary_ok": 0,
                "exit_code": 2,
                "failure_reason": "ALL_PROVIDERS_MISSING_ENV_VARS",
            }
            with open(args.output, "w") as f:
                json.dump(report, f, indent=2)
            sys.exit(2)
    else:
        logger.info("Skipping environment variable validation (--skip-env-check)")

    # ── Step 2: Model Selector Status ──────────────────────────────────────
    logger.info("═══ Step 2: Checking Model Selector ═══")
    ms_result = check_model_selector()
    report["model_selector"] = ms_result
    if ms_result.get("status") == "ok":
        logger.info(
            f"  ✓ Model selector OK — top: {ms_result['top_model']} "
            f"(score={ms_result['top_score']})"
        )
        for entry in ms_result.get("top_5", []):
            logger.info(
                f"    #{entry['rank']} {entry['id']} "
                f"score={entry['score']} tier={entry['tier']}"
            )
    else:
        logger.warning(f"  ⚠ Model selector error: {ms_result.get('error')}")

    # ── Step 3: Provider Checks with Retry ─────────────────────────────────
    logger.info(f"═══ Step 3: Checking Providers (max_retries={args.max_retries}) ═══")
    ok_count = 0
    primary_ok_count = 0
    degraded_count = 0
    error_count = 0

    for pname in args.providers:
        logger.info(f"─── Checking {pname} [task={args.task}] ───")
        result = check_provider(pname, task=args.task, max_retries=args.max_retries)
        report["results"].append(result)

        if result["status"] == "ok":
            ok_count += 1
            primary_ok_count += 1
            logger.info(
                f"  ✓ {pname} OK ({result['latency_ms']}ms, "
                f"attempts={result['retry_attempts']})"
            )
        elif result["status"] == "degraded_local":
            degraded_count += 1
            logger.warning(
                f"  ⚠ {pname} DEGRADED — fell back to LocalAIEngine"
            )
        elif result["status"] == "wrong_response":
            error_count += 1  # WRONG_RESPONSE is now a FAILURE, not degraded
            logger.error(
                f"  ✗ {pname} WRONG_RESPONSE — primary provider returned "
                f"unexpected content (TREATED AS FAILURE)"
            )
        else:
            error_count += 1
            logger.error(
                f"  ✗ {pname} ERROR ({result.get('latency_ms', 0)}ms, "
                f"attempts={result['retry_attempts']}): "
                f"{result.get('error', 'unknown')[:150]}"
            )
            # Log detailed auth diagnostics if available
            if result.get("auth_diagnostics"):
                diag = result["auth_diagnostics"]
                logger.error(f"  📋 Auth Diagnostics for {pname}:")
                logger.error(f"     Root Cause: {diag.get('diagnosis')}")
                for rec in diag.get("recommendations", []):
                    logger.error(f"     → {rec}")

    # ── Step 4: Summary and Exit Decision ──────────────────────────────────
    logger.info("═══ Step 4: Health Summary ═══")

    summary = {
        "total": len(args.providers),
        "ok": ok_count,
        "degraded": degraded_count,
        "error": error_count,
        "primary_ok": primary_ok_count,
        "healthy": primary_ok_count > 0,
        "all_primary_failed": primary_ok_count == 0,
    }

    # Strict exit policy:
    #   - If at least one PRIMARY provider responded with TORSHIELD_OK → exit 0
    #   - If all primary providers failed but LocalAIEngine worked → exit 1
    #   - If everything including LocalAIEngine failed → exit 1
    if primary_ok_count > 0:
        exit_code = 0
        summary["exit_code"] = 0
        summary["failure_reason"] = None
        logger.info(
            f"  ✓ HEALTHY: {primary_ok_count}/{len(args.providers)} "
            f"primary providers OK"
        )
    else:
        exit_code = 1
        summary["exit_code"] = 1
        if degraded_count > 0:
            summary["failure_reason"] = "ALL_PRIMARY_FAILED_LOCAL_ONLY"
            logger.error(
                f"  ✗ CRITICAL: No primary providers available. "
                f"LocalAIEngine is the only fallback ({degraded_count} degraded). "
                f"This is NOT acceptable for production."
            )
        else:
            summary["failure_reason"] = "ALL_PROVIDERS_COMPLETELY_FAILED"
            logger.error(
                f"  ✗ CRITICAL: All {len(args.providers)} providers completely failed. "
                f"Even LocalAIEngine could not help."
            )

    report["summary"] = summary

    with open(args.output, "w") as f:
        json.dump(report, f, indent=2)

    logger.info(f"Health report saved to: {args.output}")
    logger.info(
        f"Result: {primary_ok_count} primary OK, "
        f"{degraded_count} degraded, {error_count} error — "
        f"exit code: {exit_code}"
    )

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
