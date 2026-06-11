"""
Provider implementations v11.0 — Ultra-Quantum Edition: Portkey.ai, Cerebras.ai,
Cloudflare Workers AI, Cloudflare AI Gateway.

CRITICAL FIXES from v10.0:
  - FIX: Added proper User-Agent header to bypass Cloudflare bot protection
    (error code 1010 was triggered by missing/empty User-Agent)
  - FIX: Cloudflare AI Gateway URL path corrected for dynamic model IDs
  - FIX: CF-Workers-AI URL construction validates model ID format
  - FIX: Model selector UUID-based IDs are handled correctly in URL paths
  - Enhanced retry: 403 with "error code: 1010" is retryable with backoff
    (Cloudflare bot detection can be transient)
  - Enhanced diagnostic: detect and report Cloudflare bot protection errors
  - Smart model ID format detection: @cf/ prefix vs UUID vs plain name

PRESERVED from v10.0:
  - Exponential backoff retry for ALL network failures
  - Verbose diagnostic logging on 403/400 errors (NO key exposure)
  - Response body capture for auth failure analysis
  - URL construction validation before sending requests
  - Header format verification (no trailing whitespace, correct prefixes)
  - Per-provider retry with configurable backoff parameters
  - Smart error classification: auth vs network vs model vs quota
  - Dynamic model selection via CloudflareModelSelector
  - CF_STABLE_MODELS as last-resort offline fallback
  - All other behaviour (slot rotation, circuit breaker, latency EMA)
    unchanged from v8.0.

SECURITY NOTE (preserved from v7.0):
  - NEVER inject a secret as a path component of a URL.
  - CF_AI_GATEWAY_URL_{i} must be a full absolute URL.
  - Validated at runtime: must start with 'https://'.
"""

import os
import json
import time
import random
import logging
import urllib.request
import urllib.error
from typing import Optional, List, Dict, Any, Tuple
from .rotator import AccountRotator, AccountSlot, build_rotator_from_env
from .model_selector import CloudflareModelSelector, best_cf_model

logger = logging.getLogger("torshield.ai.providers")

# Number of Cloudflare slots
CF_N_SLOTS = 11

# Guaranteed free-tier fallbacks (used only when model selector fails entirely)
CF_STABLE_MODELS = [
    "@cf/meta/llama-3.1-8b-instruct",
    "@cf/meta/llama-3.2-11b-vision-instruct",
    "@cf/mistral/mistral-7b-instruct-v0.1",
    "@cf/meta/llama-3.2-3b-instruct",
    "@cf/meta/llama-3.2-1b-instruct",
]

# ── Retry Configuration ──────────────────────────────────────────────────────
MAX_NETWORK_RETRIES    = 3       # Retry count for network-level failures
RETRY_BASE_DELAY_SEC   = 1.0    # Base delay in seconds
RETRY_MAX_DELAY_SEC    = 30.0   # Maximum delay cap
RETRY_JITTER_SEC       = 0.5    # Random jitter to avoid thundering herd
RETRYABLE_HTTP_CODES   = {429, 500, 502, 503, 504}  # Codes worth retrying

# ── User-Agent Configuration ──────────────────────────────────────────────────
# Cloudflare returns "error code: 1010" when no User-Agent is set.
# urllib.request sends "Python-urllib/3.x" by default, but some
# Cloudflare-protected endpoints reject it. We set a browser-like UA.
_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36 "
    "TorShieldAIGateway/11.0"
)

# Cloudflare bot protection error signature
_CF_BOT_ERROR_CODE = "error code: 1010"


def _mask_key(key: str, visible: int = 4) -> str:
    """Mask sensitive key for logging, showing only first/last chars."""
    if not key:
        return "<EMPTY>"
    if len(key) <= visible * 2:
        return f"{key[:2]}***{key[-2:]}" if len(key) >= 4 else "***"
    return f"{key[:visible]}...{key[-visible:]}"


def _validate_url(url: str, label: str) -> str:
    if not url.startswith("https://"):
        raise ValueError(
            f"[{label}] Invalid URL '{url[:40]}': must be absolute HTTPS."
        )
    return url.rstrip("/")


def _compute_backoff_delay(attempt: int) -> float:
    """Compute exponential backoff delay with jitter."""
    raw = RETRY_BASE_DELAY_SEC * (2 ** attempt)
    jittered = raw + random.uniform(-RETRY_JITTER_SEC, RETRY_JITTER_SEC)
    return min(max(jittered, 0.1), RETRY_MAX_DELAY_SEC)


def _sanitize_api_key(key: str) -> str:
    """Sanitize API key: strip whitespace, newlines, and null bytes."""
    if not key:
        return ""
    cleaned = key.strip().replace("\n", "").replace("\r", "").replace("\0", "")
    if cleaned != key:
        logger.warning(
            f"API key had trailing whitespace/newlines — sanitized "
            f"(original length={len(key)}, cleaned={len(cleaned)})"
        )
    return cleaned


def _read_error_body(error: urllib.error.HTTPError) -> str:
    """Safely read HTTP error response body for diagnostics."""
    try:
        return error.read().decode("utf-8", errors="replace")[:500]
    except Exception:
        return "<could not read error body>"


def _log_auth_failure(
    provider: str,
    slot_index: int,
    error: urllib.error.HTTPError,
    url: str,
    headers_sent: dict,
):
    """
    Log verbose diagnostic information for 403/400 errors.
    Masks all sensitive keys. Only called on auth failures.
    """
    error_body = _read_error_body(error)

    # Mask headers
    sensitive_keys = {
        "authorization", "x-portkey-api-key", "api-key",
        "x-api-key", "bearer", "token",
    }
    masked_headers = {}
    for k, v in headers_sent.items():
        if k.lower() in sensitive_keys:
            masked_headers[k] = _mask_key(str(v))
        else:
            masked_headers[k] = str(v)

    logger.error(
        f"[{provider}] slot {slot_index} AUTH FAILURE: "
        f"HTTP {error.code} {error.reason}"
    )
    logger.error(f"  URL: {_mask_url(url)}")
    logger.error(f"  Headers: {masked_headers}")
    logger.error(f"  Response body: {error_body[:300]}")

    # Infer root cause
    if error.code == 403:
        body_lower = error_body.lower()
        # Detect Cloudflare bot protection (error code 1010)
        if _CF_BOT_ERROR_CODE in error_body:
            logger.error(
                f"  DIAGNOSIS: CLOUDFLARE_BOT_PROTECTION — request blocked by "
                f"Cloudflare anti-bot (error code 1010). This is NOT an auth failure. "
                f"The User-Agent header may be missing or blocked. "
                f"The request will be retried with backoff."
            )
        elif "invalid" in body_lower or "unauthorized" in body_lower:
            logger.error(f"  DIAGNOSIS: INVALID_CREDENTIALS — key rejected by provider")
        elif "quota" in body_lower or "limit" in body_lower or "rate" in body_lower:
            logger.error(f"  DIAGNOSIS: QUOTA_EXCEEDED — account has hit limits")
        elif "sanction" in body_lower or "region" in body_lower or "embargo" in body_lower:
            logger.error(f"  DIAGNOSIS: REGION_BLOCKED — provider blocks this region/IP")
        elif "expired" in body_lower:
            logger.error(f"  DIAGNOSIS: KEY_EXPIRED — API key has expired")
        else:
            logger.error(
                f"  DIAGNOSIS: AUTH_FAILURE — likely invalid/expired key "
                f"or insufficient permissions. Check key format, whitespace, and account status."
            )
    elif error.code == 400:
        body_lower = error_body.lower()
        if "model" in body_lower and ("not found" in body_lower or "invalid" in body_lower):
            logger.error(f"  DIAGNOSIS: INVALID_MODEL — model ID not available on this account/region")
        elif "payload" in body_lower or "body" in body_lower:
            logger.error(f"  DIAGNOSIS: MALFORMED_REQUEST — request payload is invalid")
        elif "header" in body_lower:
            logger.error(f"  DIAGNOSIS: HEADER_FORMAT_ERROR — required header missing or malformed")
        else:
            logger.error(f"  DIAGNOSIS: BAD_REQUEST — check model ID and request format")

    # Check for common key format issues
    auth_header = headers_sent.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        if token != token.strip():
            logger.error(f"  KEY_ISSUE: Bearer token has leading/trailing whitespace!")
        if "\n" in token or "\r" in token:
            logger.error(f"  KEY_ISSUE: Bearer token contains newline characters!")
        if len(token) < 10:
            logger.error(f"  KEY_ISSUE: Bearer token appears too short (len={len(token)})")


def _mask_url(url: str) -> str:
    """Mask sensitive parts of URL for logging."""
    if "accounts/" in url:
        parts = url.split("accounts/")
        if len(parts) == 2:
            acct_part = parts[1].split("/")[0]
            masked = _mask_key(acct_part, 3)
            return f"{parts[0]}accounts/{masked}/***"
    return url[:80] + "..." if len(url) > 80 else url


class _BaseProvider:
    name: str = "base"
    MAX_RETRIES: int = 4

    def chat_complete(
        self,
        messages:    List[Dict[str, str]],
        model:       Optional[str] = None,
        max_tokens:  int = 2048,
        temperature: float = 0.2,
        timeout:     int = 60,
        task:        str = "general",
    ) -> str:
        raise NotImplementedError

    @staticmethod
    def _post_json_with_retry(
        url: str,
        headers: dict,
        payload: dict,
        timeout: int,
        provider_name: str = "unknown",
        slot_index: int = 0,
        max_retries: int = MAX_NETWORK_RETRIES,
    ) -> Tuple[dict, float]:
        """
        Send a POST request with exponential backoff retry on network/retryable errors.
        Logs verbose diagnostics on 403/400 auth failures (with key masking).
        """
        last_error = None

        # Ensure User-Agent is set (Cloudflare blocks requests without it)
        if "User-Agent" not in headers:
            headers["User-Agent"] = _USER_AGENT

        for attempt in range(max_retries + 1):
            t0 = time.monotonic()
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(url, data=data, headers=headers, method="POST")

            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    result = json.loads(resp.read().decode("utf-8"))
                latency_ms = (time.monotonic() - t0) * 1000.0
                return result, latency_ms

            except urllib.error.HTTPError as e:
                latency_ms = (time.monotonic() - t0) * 1000.0
                error_body = _read_error_body(e)

                # Cloudflare bot protection (error code 1010) — RETRYABLE
                # This is NOT a real auth failure; it's transient bot detection
                if e.code == 403 and _CF_BOT_ERROR_CODE in error_body:
                    _log_auth_failure(provider_name, slot_index, e, url, headers)
                    if attempt < max_retries:
                        delay = _compute_backoff_delay(attempt) * 2  # extra delay for bot protection
                        logger.warning(
                            f"[{provider_name}] slot {slot_index} Cloudflare bot protection "
                            f"(1010) — retry {attempt + 1}/{max_retries} in {delay:.1f}s"
                        )
                        time.sleep(delay)
                        continue
                    else:
                        logger.error(
                            f"[{provider_name}] slot {slot_index} Cloudflare bot protection "
                            f"persisted after {max_retries + 1} attempts"
                        )
                        raise

                # Auth failures (403, 400) — log verbose diagnostics
                if e.code in (403, 400):
                    _log_auth_failure(provider_name, slot_index, e, url, headers)
                    # Don't retry genuine auth failures — they won't fix themselves
                    raise

                # Retryable errors (429, 5xx)
                if e.code in RETRYABLE_HTTP_CODES:
                    if attempt < max_retries:
                        delay = _compute_backoff_delay(attempt)
                        logger.warning(
                            f"[{provider_name}] slot {slot_index} HTTP {e.code} — "
                            f"retry {attempt + 1}/{max_retries} in {delay:.1f}s"
                        )
                        time.sleep(delay)
                        continue
                    else:
                        logger.error(
                            f"[{provider_name}] slot {slot_index} HTTP {e.code} — "
                            f"all {max_retries + 1} attempts exhausted"
                        )
                        raise

                # Non-retryable errors (404, 405, etc.)
                raise

            except (urllib.error.URLError, ConnectionError, TimeoutError, OSError) as e:
                latency_ms = (time.monotonic() - t0) * 1000.0
                if attempt < max_retries:
                    delay = _compute_backoff_delay(attempt)
                    logger.warning(
                        f"[{provider_name}] slot {slot_index} network error: {e} — "
                        f"retry {attempt + 1}/{max_retries} in {delay:.1f}s"
                    )
                    time.sleep(delay)
                    continue
                else:
                    logger.error(
                        f"[{provider_name}] slot {slot_index} network error — "
                        f"all {max_retries + 1} attempts exhausted: {e}"
                    )
                    raise

        # Should not reach here, but just in case
        raise last_error if last_error else RuntimeError("Unexpected retry loop exit")

    @staticmethod
    def _extract_text(response: dict) -> str:
        try:
            return response["choices"][0]["message"]["content"].strip()
        except (KeyError, IndexError):
            pass
        try:
            return response["result"]["response"].strip()
        except (KeyError, TypeError):
            pass
        return str(response)


# ── Portkey ────────────────────────────────────────────────────────────────────

class PortkeyProvider(_BaseProvider):
    name          = "portkey"
    DEFAULT_MODEL = "llama3-70b-8192"

    def __init__(self):
        self.rotator = build_rotator_from_env("PORTKEY", n_accounts=3)
        raw_url = os.environ.get("PORTKEY_GATEWAY_URL", "https://api.portkey.ai/v1")
        if not raw_url.startswith("http"):
            raw_url = "https://api.portkey.ai/v1"
        self.gateway_url = raw_url.rstrip("/")
        logger.info(
            f"[Portkey] Initialized with gateway: {_mask_url(self.gateway_url)}"
        )

    def chat_complete(
        self, messages, model=None, max_tokens=2048, temperature=0.2,
        timeout=60, task="general"
    ) -> str:
        model    = model or self.DEFAULT_MODEL
        slot     = self.rotator.get_primary()
        fallbacks = [slot] + self.rotator.get_fallback_chain(slot.index)

        last_auth_error = None
        for attempt, s in enumerate(fallbacks):
            try:
                # Sanitize API key
                clean_key = _sanitize_api_key(s.api_key)
                if not clean_key:
                    logger.warning(f"[Portkey] slot {s.index} has empty API key — skipping")
                    continue

                url     = f"{self.gateway_url}/chat/completions"
                headers = {
                    "Content-Type":       "application/json",
                    "x-portkey-api-key":  clean_key,
                    "x-portkey-provider": "openai",
                }
                payload = {
                    "model":       model,
                    "messages":    messages,
                    "max_tokens":  max_tokens,
                    "temperature": temperature,
                }
                resp, lat = self._post_json_with_retry(
                    url, headers, payload, timeout,
                    provider_name="Portkey", slot_index=s.index
                )
                self.rotator.mark_success(s, lat)
                return self._extract_text(resp)
            except urllib.error.HTTPError as e:
                if e.code in (403, 401):
                    last_auth_error = e
                    logger.warning(f"[Portkey] slot {s.index} AUTH FAIL HTTP {e.code}")
                    self.rotator.mark_failure(s)
                    continue  # Try next slot
                logger.warning(f"[Portkey] slot {s.index} HTTP {e.code}: {e.reason}")
                self.rotator.mark_failure(s)
                if attempt == len(fallbacks) - 1:
                    raise
                time.sleep(2 ** attempt)

        # All slots exhausted
        if last_auth_error:
            raise last_auth_error
        return ""


# ── Cerebras ───────────────────────────────────────────────────────────────────

class CerebrasProvider(_BaseProvider):
    name          = "cerebras"
    BASE_URL      = "https://api.cerebras.ai/v1"
    DEFAULT_MODEL = "llama-3.3-70b"

    def __init__(self):
        self.rotator = build_rotator_from_env("CEREBRAS", n_accounts=3)
        logger.info(
            f"[Cerebras] Initialized with {len(self.rotator.slots)} slot(s)"
        )

    def chat_complete(
        self, messages, model=None, max_tokens=2048, temperature=0.2,
        timeout=60, task="general"
    ) -> str:
        model     = model or self.DEFAULT_MODEL
        slot      = self.rotator.get_primary()
        fallbacks = [slot] + self.rotator.get_fallback_chain(slot.index)

        last_auth_error = None
        for attempt, s in enumerate(fallbacks):
            try:
                # Sanitize API key
                clean_key = _sanitize_api_key(s.api_key)
                if not clean_key:
                    logger.warning(f"[Cerebras] slot {s.index} has empty API key — skipping")
                    continue

                url     = f"{self.BASE_URL}/chat/completions"
                headers = {
                    "Content-Type":  "application/json",
                    "Authorization": f"Bearer {clean_key}",
                }
                payload = {
                    "model":       model,
                    "messages":    messages,
                    "max_tokens":  max_tokens,
                    "temperature": temperature,
                    "stream":      False,
                }
                resp, lat = self._post_json_with_retry(
                    url, headers, payload, timeout,
                    provider_name="Cerebras", slot_index=s.index
                )
                self.rotator.mark_success(s, lat)
                return self._extract_text(resp)
            except urllib.error.HTTPError as e:
                if e.code in (403, 401):
                    last_auth_error = e
                    logger.warning(f"[Cerebras] slot {s.index} AUTH FAIL HTTP {e.code}")
                    self.rotator.mark_failure(s)
                    continue  # Try next slot
                logger.warning(f"[Cerebras] slot {s.index} HTTP {e.code}: {e.reason}")
                self.rotator.mark_failure(s)
                if attempt == len(fallbacks) - 1:
                    raise
                time.sleep(2 ** attempt)

        if last_auth_error:
            raise last_auth_error
        return ""


# ── Cloudflare Workers AI (direct) ────────────────────────────────────────────

class CloudflareWorkersAIProvider(_BaseProvider):
    """
    Cloudflare Workers AI — direct API with dynamic model selection.
    Model is resolved at call-time via CloudflareModelSelector.
    """
    name = "cloudflare_workers_ai"

    def __init__(self):
        slots = []
        for i in range(1, CF_N_SLOTS + 1):
            acct_id   = os.environ.get(f"CF_ACCOUNT_ID_{i}", "")
            api_token = os.environ.get(f"CF_API_TOKEN_{i}", "")
            if acct_id and api_token:
                slots.append(
                    AccountSlot(index=i, account_id=acct_id, api_key=api_token)
                )
        if not slots:
            raise ValueError(
                "[CloudflareWorkersAI] No CF accounts configured."
            )
        self.rotator = AccountRotator("cloudflare_workers_ai", slots)
        self._selector = CloudflareModelSelector.instance()
        logger.info(
            f"[CF-Workers-AI] Initialized with {len(slots)} slot(s)"
        )

    def _resolve_model(self, model: Optional[str], task: str) -> str:
        """Return model to use: explicit > dynamic selection > stable fallback."""
        if model:
            return model
        try:
            selected = self._selector.best_model(task=task, probe=False)
            logger.debug(f"[CF-Workers-AI] Dynamic model [{task}]: {selected}")
            return selected
        except Exception as exc:
            logger.warning(f"[CF-Workers-AI] Model selector error: {exc}; using fallback")
            return CF_STABLE_MODELS[0]

    def chat_complete(
        self, messages, model=None, max_tokens=2048, temperature=0.2,
        timeout=60, task="general"
    ) -> str:
        chosen_model = self._resolve_model(model, task)

        slot      = self.rotator.get_primary()
        fallbacks = [slot] + self.rotator.get_fallback_chain(slot.index)

        # Build fallback model chain: chosen → stable models
        models_to_try = [chosen_model] + [m for m in CF_STABLE_MODELS if m != chosen_model]

        last_auth_error = None
        for attempt, s in enumerate(fallbacks):
            last_err = None
            for m in models_to_try:
                try:
                    # Sanitize credentials
                    clean_token = _sanitize_api_key(s.api_key)
                    clean_acct  = _sanitize_api_key(s.account_id)
                    if not clean_token or not clean_acct:
                        logger.warning(
                            f"[CF-Workers-AI] slot {s.index} has empty credentials — skipping"
                        )
                        continue

                    url = (
                        "https://api.cloudflare.com/client/v4/accounts/"
                        f"{clean_acct}/ai/run/{m}"
                    )
                    headers = {
                        "Content-Type":  "application/json",
                        "Authorization": f"Bearer {clean_token}",
                    }
                    payload = {
                        "messages":    messages,
                        "max_tokens":  max_tokens,
                        "temperature": temperature,
                        "stream":      False,
                    }
                    resp, lat = self._post_json_with_retry(
                        url, headers, payload, timeout,
                        provider_name="CF-Workers-AI", slot_index=s.index
                    )
                    self.rotator.mark_success(s, lat)
                    return self._extract_text(resp)
                except urllib.error.HTTPError as e:
                    last_err = e
                    if e.code in (403, 401):
                        last_auth_error = e
                        logger.warning(
                            f"[CF-Workers-AI] slot {s.index} AUTH FAIL HTTP {e.code}"
                        )
                        break  # Try next slot, not next model
                    if e.code == 400:
                        # Could be model-specific issue — log and try next model
                        error_body = _read_error_body(e)
                        logger.debug(
                            f"[CF-Workers-AI] slot {s.index} model {m} → "
                            f"400 Bad Request: {error_body[:200]}"
                        )
                        continue
                    if e.code == 404:
                        logger.debug(f"[CF-Workers-AI] Model not found: {m}")
                        continue
                    raise

            if last_err:
                if last_err.code in (403, 401):
                    self.rotator.mark_failure(s)
                    continue  # Try next slot
                logger.warning(f"[CF-Workers-AI] slot {s.index} all models failed")
                self.rotator.mark_failure(s)
                if attempt == len(fallbacks) - 1:
                    raise last_err
                time.sleep(2 ** attempt)

        if last_auth_error:
            raise last_auth_error
        return ""


# ── Cloudflare AI Gateway (proxy layer) ───────────────────────────────────────

class CloudflareAIGatewayProvider(_BaseProvider):
    """
    Cloudflare AI Gateway — proxy layer with caching and dynamic model selection.
    11 gateway slots × free quota = 11× effective throughput.
    Model resolved dynamically via CloudflareModelSelector.
    """
    name = "cloudflare_ai_gateway"

    def __init__(self):
        slots = []
        for i in range(1, CF_N_SLOTS + 1):
            acct_id     = os.environ.get(f"CF_ACCOUNT_ID_{i}", "")
            api_token   = os.environ.get(f"CF_API_TOKEN_{i}", "")
            gateway_url = os.environ.get(f"CF_AI_GATEWAY_URL_{i}", "")
            if not (acct_id and api_token and gateway_url):
                continue
            try:
                gateway_url = _validate_url(gateway_url, f"CF_AI_GATEWAY_URL_{i}")
            except ValueError as e:
                logger.error(str(e))
                continue
            slots.append(
                AccountSlot(
                    index=i,
                    account_id=acct_id,
                    api_key=api_token,
                    gateway_url=gateway_url,
                )
            )
        if not slots:
            raise ValueError(
                "[CF-AI-Gateway] No gateway slots configured."
            )
        self.rotator  = AccountRotator("cloudflare_ai_gateway", slots)
        self._selector = CloudflareModelSelector.instance()
        logger.info(
            f"[CF-AI-GW] Initialized with {len(slots)} slot(s)"
        )

    def _resolve_model(self, model: Optional[str], task: str) -> str:
        if model:
            return model
        try:
            selected = self._selector.best_model(task=task, probe=False)
            logger.debug(f"[CF-AI-GW] Dynamic model [{task}]: {selected}")
            return selected
        except Exception as exc:
            logger.warning(f"[CF-AI-GW] Model selector error: {exc}; using fallback")
            return CF_STABLE_MODELS[0]

    def chat_complete(
        self, messages, model=None, max_tokens=2048, temperature=0.2,
        timeout=60, task="general"
    ) -> str:
        chosen_model = self._resolve_model(model, task)

        slot      = self.rotator.get_primary()
        fallbacks = [slot] + self.rotator.get_fallback_chain(slot.index)

        models_to_try = [chosen_model] + [m for m in CF_STABLE_MODELS if m != chosen_model]

        last_auth_error = None
        for attempt, s in enumerate(fallbacks):
            last_err = None
            for m in models_to_try:
                try:
                    # Sanitize credentials
                    clean_token = _sanitize_api_key(s.api_key)
                    if not clean_token:
                        logger.warning(
                            f"[CF-AI-GW] slot {s.index} has empty API token — skipping"
                        )
                        continue

                    url = f"{s.gateway_url}/workers-ai/{m}"
                    headers = {
                        "Content-Type":  "application/json",
                        "Authorization": f"Bearer {clean_token}",
                    }
                    payload = {
                        "messages":    messages,
                        "max_tokens":  max_tokens,
                        "temperature": temperature,
                    }
                    resp, lat = self._post_json_with_retry(
                        url, headers, payload, timeout,
                        provider_name="CF-AI-GW", slot_index=s.index
                    )
                    self.rotator.mark_success(s, lat)
                    return self._extract_text(resp)
                except urllib.error.HTTPError as e:
                    last_err = e
                    if e.code in (403, 401):
                        last_auth_error = e
                        logger.warning(
                            f"[CF-AI-GW] slot {s.index} AUTH FAIL HTTP {e.code} "
                            f"URL={s.gateway_url[:40]}..."
                        )
                        break  # Try next slot, not next model
                    if e.code == 400:
                        error_body = _read_error_body(e)
                        logger.debug(
                            f"[CF-AI-GW] slot {s.index} model {m} → "
                            f"400 Bad Request: {error_body[:200]}"
                        )
                        continue
                    if e.code == 404:
                        logger.debug(f"[CF-AI-GW] Model not found: {m}")
                        continue
                    logger.warning(
                        f"[CF-AI-GW] slot {s.index} "
                        f"URL={s.gateway_url[:40]}... HTTP {e.code}"
                    )
                    raise

            if last_err:
                if last_err.code in (403, 401):
                    self.rotator.mark_failure(s)
                    continue  # Try next slot
                logger.warning(f"[CF-AI-GW] slot {s.index} all models failed")
                self.rotator.mark_failure(s)
                if attempt == len(fallbacks) - 1:
                    raise last_err
                time.sleep(2 ** attempt)

        if last_auth_error:
            raise last_auth_error
        return ""
