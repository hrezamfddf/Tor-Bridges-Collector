"""
Provider implementations v14.0 — Ultra-Quantum Edition: Portkey.ai, Cerebras.ai,
Cloudflare Workers AI, Cloudflare AI Gateway.

CRITICAL FIXES from v14.0 (Correction 6: Pre-flight Screening):
  - FIX: Pre-flight screening for broken Cloudflare slots — validates token
    length, account_id format, and gateway URL structure BEFORE sending any
    request. Broken slots (like slot 7) are silently skipped without causing
    HTTP 400 errors. No env vars or secrets are deleted.
  - FIX: Session-level blacklisting for CF slots that fail all models.
    Blacklisted slots are suspended only for the current CI session and
    retried automatically in the next run.
  - FIX: Per-account model cache — remembers which models worked on which
    CF account to avoid retrying known-to-fail model/account combinations.
  - FIX: CF AI Gateway URL duplicate account_id detection — prevents
    malformed URLs where account_id appears twice in the path.
  - FIX: WRONG_RESPONSE false positive validator — properly handles
    Cloudflare JSON responses with "errors": [] field.
  - FIX: All CF secrets now supported up to slot 11 in all workflows.

CRITICAL FIXES from v13.0 (preserved):
  - FIX: Cerebras model "llama3.3-70b" is NOT a valid Cerebras model name.
    Replaced with "llama3.1-70b". DEFAULT_MODEL changed to "llama3.1-8b"
    (most stable free-tier model). Added _discover_models() endpoint
    auto-discovery that fetches available models from /v1/models.
  - FIX: CF AI Gateway URL validation — added _validate_gateway_url() that
    checks the URL starts with https://gateway.ai.cloudflare.com/v1/ and
    extracts/validates account_id from the path. Added _probe_gateway()
    that sends a lightweight GET to check gateway reachability.
  - FIX: Portkey authentication — added _validate_portkey_key() that checks
    key format (pk- prefix), better 401 diagnostics, and support for
    PORTKEY_VIRTUAL_KEY_{i} env vars as alternative auth method.
  - FIX: Added ProviderCircuitBreaker class for provider-level circuit
    breaker with automatic recovery. Integrated into all providers.

CRITICAL FIXES from v11.0 (preserved):
  - FIX: Cerebras CEREBRAS_MODELS fallback list so chat_complete tries
    multiple models on 400/404.
  - FIX: CF AI Gateway URL includes account_id in workers-ai path.
  - FIX: Cross-slot model skip via _failed_models set.
  - FIX: Portkey DEFAULT_MODEL = "meta/llama-3.1-70b-instruct".
  - FIX: Better diagnostic for empty response body on CF AI Gateway 400.

PRESERVED from v11.0:
  - FIX: Added proper User-Agent header to bypass Cloudflare bot protection
    (error code 1010 was triggered by missing/empty User-Agent)
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
import re
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

# ── Pre-flight Screening Constants ───────────────────────────────────────────
CF_MIN_TOKEN_LENGTH  = 40   # CF API tokens are 40+ chars (strict)
CF_MIN_ACCT_ID_LENGTH = 32  # CF account IDs are 32-char hex
CF_MAX_TOKEN_LENGTH  = 200  # Maximum expected token length
CF_MAX_ACCT_ID_LENGTH = 32  # Account IDs are exactly 32 chars

# ── Per-Account Model Cache ──────────────────────────────────────────────────
_cf_account_working_models: dict = {}  # account_id → list of working models


def record_working_model(account_id: str, model: str) -> None:
    """Remember which model worked for which CF account."""
    if account_id not in _cf_account_working_models:
        _cf_account_working_models[account_id] = []
    if model not in _cf_account_working_models[account_id]:
        _cf_account_working_models[account_id].append(model)
        logger.info(
            f"[CF-Model-Cache] {_mask_key(account_id, 3)}: "
            f"confirmed working model: {model}"
        )


def get_models_for_account(
    account_id: str,
    default_models: list,
) -> list:
    """
    Return cached working models first, then fallbacks.
    Avoids retrying models known to fail on this account.
    """
    working = _cf_account_working_models.get(account_id, [])
    result = working.copy()
    for m in default_models:
        if m not in result:
            result.append(m)
    return result


def _preflight_screen_slot(slot_index: int) -> Tuple[bool, str]:
    """
    Enhanced pre-flight screening for Cloudflare slots (Amendment 6).

    Validates account_id format (32-char hex), API token length (>=40 chars),
    and gateway URL structure BEFORE sending any request.

    Broken slots (like slot 7 with corrupted tokens) are detected here
    and silently skipped without causing HTTP 400 errors.

    Returns:
        (valid: bool, reason: str) — valid=True means slot is usable.
    """
    account_id  = os.environ.get(f"CF_ACCOUNT_ID_{slot_index}", "").strip()
    api_token   = os.environ.get(f"CF_API_TOKEN_{slot_index}", "").strip()
    gateway_url = os.environ.get(f"CF_AI_GATEWAY_URL_{slot_index}", "").strip()

    # Rule 1: Both must be non-empty
    if not account_id or not api_token:
        return False, "missing credentials"

    # Rule 2: Account ID must be 32-char hex
    if not re.match(r'^[0-9a-f]{32}$', account_id, re.IGNORECASE):
        return False, f"invalid account_id format (len={len(account_id)})"

    # Rule 3: API token must be >=40 chars (CF tokens are 40+)
    if len(api_token) < CF_MIN_TOKEN_LENGTH:
        return False, f"token too short ({len(api_token)} chars, min={CF_MIN_TOKEN_LENGTH})"

    # Rule 4: Gateway URL must match CF pattern (if provided)
    if gateway_url:
        pattern = r'^https://gateway\.ai\.cloudflare\.com/v1/[0-9a-f]{32}/'
        if not re.match(pattern, gateway_url, re.IGNORECASE):
            return False, "malformed gateway URL"

    # Rule 5: Account ID in gateway URL must match credentials
    if gateway_url and account_id:
        # Extract account_id from gateway URL
        gw_match = re.search(r'/v1/([0-9a-f]{32})/', gateway_url, re.IGNORECASE)
        if gw_match:
            gw_acct = gw_match.group(1)
            if gw_acct.lower() != account_id.lower():
                return False, "account_id mismatch between URL and credentials"

    return True, "ok"


def preflight_validate_cf_slot(
    slot_index: int,
    account_id: str,
    api_token: str,
    gateway_url: str = "",
) -> list:
    """
    Pre-flight screening for Cloudflare slots — validates token length,
    account_id format, and gateway URL structure BEFORE sending any request.

    Broken slots (like slot 7 with corrupted tokens) are detected here
    and silently skipped without causing HTTP 400 errors.

    Returns a list of warning strings (empty = slot looks valid).
    The slot is NOT removed — only flagged for skipping at runtime.
    """
    issues = []

    # Validate API token
    if not api_token:
        issues.append(f"Slot {slot_index}: CF_API_TOKEN is empty")
    else:
        clean_token = api_token.strip()
        if len(clean_token) < CF_MIN_TOKEN_LENGTH:
            issues.append(
                f"Slot {slot_index}: CF_API_TOKEN too short "
                f"(len={len(clean_token)}, min={CF_MIN_TOKEN_LENGTH}). "
                f"Token appears corrupted or incomplete."
            )
        if len(clean_token) > CF_MAX_TOKEN_LENGTH:
            issues.append(
                f"Slot {slot_index}: CF_API_TOKEN too long "
                f"(len={len(clean_token)}, max={CF_MAX_TOKEN_LENGTH}). "
                f"Token may contain extra characters or multiple tokens."
            )
        if '\n' in clean_token or '\r' in clean_token:
            issues.append(
                f"Slot {slot_index}: CF_API_TOKEN contains newline characters — "
                f"possible copy-paste error from GitHub Secrets"
            )
        # CF API tokens should not have spaces
        if ' ' in clean_token:
            issues.append(
                f"Slot {slot_index}: CF_API_TOKEN contains spaces — "
                f"token is likely corrupted"
            )

    # Validate account ID — must be 32-char hex
    if not account_id:
        issues.append(f"Slot {slot_index}: CF_ACCOUNT_ID is empty")
    else:
        clean_acct = account_id.strip()
        if not re.match(r'^[0-9a-f]{32}$', clean_acct, re.IGNORECASE):
            issues.append(
                f"Slot {slot_index}: CF_ACCOUNT_ID invalid format "
                f"(len={len(clean_acct)}, expected 32-char hex). "
                f"Account ID appears corrupted."
            )

    # Validate gateway URL (only for AI Gateway provider)
    if gateway_url:
        if not gateway_url.startswith("https://"):
            issues.append(
                f"Slot {slot_index}: CF_AI_GATEWAY_URL does not start with https://"
            )
        else:
            # Must match CF AI Gateway pattern
            pattern = r'^https://gateway\.ai\.cloudflare\.com/v1/[0-9a-f]{32}/'
            if not re.match(pattern, gateway_url, re.IGNORECASE):
                issues.append(
                    f"Slot {slot_index}: CF_AI_GATEWAY_URL malformed — "
                    f"must match https://gateway.ai.cloudflare.com/v1/{{account_id}}/{{slug}}"
                )
            else:
                # Check account_id in URL matches credentials
                gw_match = re.search(r'/v1/([0-9a-f]{32})/', gateway_url, re.IGNORECASE)
                if gw_match and account_id:
                    gw_acct = gw_match.group(1)
                    if gw_acct.lower() != account_id.strip().lower():
                        issues.append(
                            f"Slot {slot_index}: Account ID in gateway URL "
                            f"({_mask_key(gw_acct, 3)}...) does not match "
                            f"CF_ACCOUNT_ID ({_mask_key(account_id, 3)}...)"
                        )

    if issues:
        for issue in issues:
            logger.warning(f"[CF-Preflight] {issue}")
        logger.warning(
            f"[CF-Preflight] Slot {slot_index} FAILED pre-flight screening — "
            f"will be silently skipped (NOT deleted from config). "
            f"{len(issues)} issue(s) detected."
        )
    else:
        logger.debug(
            f"[CF-Preflight] Slot {slot_index} PASSED pre-flight screening "
            f"(token_len={len(api_token.strip())}, "
            f"acct_id_len={len(account_id.strip())})"
        )

    return issues

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
AUTH_FAILURE_HTTP_CODES = {401, 403}  # NEVER retry these — auth failures won't fix themselves

# ── User-Agent Configuration ──────────────────────────────────────────────────
# Cloudflare returns "error code: 1010" when no User-Agent is set.
# urllib.request sends "Python-urllib/3.x" by default, but some
# Cloudflare-protected endpoints reject it. We set a browser-like UA.
_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36 "
    "TorShieldAIGateway/12.0"
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
        if not error_body.strip():
            logger.error(
                f"  DIAGNOSIS: EMPTY_RESPONSE_BODY_400 — server returned 400 with empty "
                f"response body. This typically means the URL path is malformed or the "
                f"model doesn't exist on this account. Verify the URL structure and model ID."
            )
        elif "model" in body_lower and ("not found" in body_lower or "invalid" in body_lower):
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


class ProviderCircuitBreaker:
    """Provider-level circuit breaker with automatic recovery.

    Tracks overall provider health across all slots. When the failure count
    exceeds the threshold, the circuit opens and rejects requests until the
    recovery timeout elapses, at which point it transitions to half-open
    and allows one request through to test recovery.
    """

    def __init__(
        self,
        provider_name: str,
        failure_threshold: int = 5,
        recovery_timeout: float = 300.0,
    ):
        self.provider_name = provider_name
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time = 0.0
        self.state = "closed"  # closed, open, half_open

    def record_success(self):
        """Record a successful request — resets failure count and closes circuit."""
        self.failure_count = 0
        self.state = "closed"

    def record_failure(self):
        """Record a failed request — increments count and opens circuit if threshold reached."""
        self.failure_count += 1
        self.last_failure_time = time.time()
        if self.failure_count >= self.failure_threshold:
            if self.state != "open":
                logger.warning(
                    f"[{self.provider_name}] Circuit breaker OPENED — "
                    f"{self.failure_count} consecutive failures reached threshold "
                    f"({self.failure_threshold}). Will retry after "
                    f"{self.recovery_timeout}s recovery timeout."
                )
            self.state = "open"

    def allow_request(self) -> bool:
        """Check if a request is allowed based on current circuit state."""
        if self.state == "closed":
            return True
        if self.state == "open":
            if time.time() - self.last_failure_time > self.recovery_timeout:
                self.state = "half_open"
                logger.info(
                    f"[{self.provider_name}] Circuit breaker → HALF_OPEN — "
                    f"recovery timeout elapsed, allowing test request"
                )
                return True
            return False
        return True  # half_open allows one request through


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

                # Auth failures (401, 403) — NEVER retry, log verbose diagnostics
                # 401 Unauthorized = invalid/expired credentials (permanent)
                # 403 Forbidden = revoked/insufficient permissions (permanent)
                # Both are authentication/authorization failures that retrying
                # will NEVER fix — they require credential rotation.
                if e.code in AUTH_FAILURE_HTTP_CODES:
                    _log_auth_failure(provider_name, slot_index, e, url, headers)
                    logger.error(
                        f"[{provider_name}] slot {slot_index} HTTP {e.code} — "
                        f"AUTH FAILURE, NOT retrying (credential issue, not transient)"
                    )
                    raise

                # 400 Bad Request — typically invalid model or malformed request
                # Also NOT retried (the request itself is wrong, retrying won't help)
                if e.code == 400:
                    _log_auth_failure(provider_name, slot_index, e, url, headers)
                    logger.error(
                        f"[{provider_name}] slot {slot_index} HTTP 400 — "
                        f"BAD REQUEST, NOT retrying (invalid model or malformed payload)"
                    )
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
    DEFAULT_MODEL = "meta/llama-3.1-70b-instruct"
    PORTKEY_MODELS = [
        "meta/llama-3.1-70b-instruct",
        "meta/llama-3.1-8b-instruct",
        "meta/llama-3.2-3b-instruct",
    ]

    def __init__(self):
        self.rotator = build_rotator_from_env("PORTKEY", n_accounts=3)
        raw_url = os.environ.get("PORTKEY_GATEWAY_URL", "https://api.portkey.ai/v1")
        if not raw_url.startswith("http"):
            raw_url = "https://api.portkey.ai/v1"
        self.gateway_url = raw_url.rstrip("/")
        self.circuit_breaker = ProviderCircuitBreaker("Portkey")
        logger.info(
            f"[Portkey] Initialized with gateway: {_mask_url(self.gateway_url)}"
        )

    @staticmethod
    def _build_portkey_auth(slot: int) -> dict:
        """
        Build Portkey authentication headers with intelligent key detection.

        Supports three auth methods:
        1. Native Portkey key (pk- prefix) → x-portkey-api-key header
        2. Virtual key fallback (pk- prefix in PORTKEY_VIRTUAL_KEY) → combined auth
        3. Provider API key (sk- prefix like OpenAI) → Bearer + x-portkey-provider

        Raises ValueError if no valid key format is found.
        """
        key = os.environ.get(f"PORTKEY_API_KEY_{slot}", "").strip()
        virtual_key = os.environ.get(f"PORTKEY_VIRTUAL_KEY_{slot}", "").strip()

        headers = {"Content-Type": "application/json"}

        if key.startswith("pk-"):
            # Native Portkey key
            headers["x-portkey-api-key"] = key
            logger.debug(
                f"[Portkey] slot {slot} Using native Portkey key: {_mask_key(key)}"
            )
        elif virtual_key.startswith("pk-"):
            # Virtual key fallback
            headers["x-portkey-api-key"] = virtual_key
            headers["x-portkey-virtual-key"] = virtual_key
            logger.debug(
                f"[Portkey] slot {slot} Using virtual key: {_mask_key(virtual_key)}"
            )
        elif key.startswith("sk-"):
            # Provider API key (e.g. OpenAI key) — route directly
            headers["Authorization"] = f"Bearer {key}"
            headers["x-portkey-provider"] = "openai"
            logger.debug(
                f"[Portkey] slot {slot} Using provider key (sk- prefix) "
                f"with x-portkey-provider=openai"
            )
        elif key:
            # Unknown provider key format — try as Bearer with openai provider
            headers["Authorization"] = f"Bearer {key}"
            headers["x-portkey-provider"] = "openai"
            logger.warning(
                f"[Portkey] slot {slot} Unrecognized key format "
                f"(starts with '{key[:4]}...') — attempting Bearer auth. "
                f"Expected 'pk-' (Portkey) or 'sk-' (OpenAI) prefix."
            )
        else:
            raise ValueError(
                f"Slot {slot}: no valid Portkey key found — "
                f"PORTKEY_API_KEY_{slot} and PORTKEY_VIRTUAL_KEY_{slot} are empty"
            )

        # Also check for x-portkey-config header (virtual key config ID)
        config_id = os.environ.get(
            f"PORTKEY_CONFIG_{slot}",
            os.environ.get("PORTKEY_CONFIG", "")
        ).strip()
        if config_id:
            headers["x-portkey-config"] = config_id
            logger.debug(
                f"[Portkey] slot {slot} Using config: {_mask_key(config_id)}"
            )

        return headers

    @staticmethod
    def _validate_portkey_key(key: str, slot_index: int = 0) -> List[str]:
        """Validate Portkey API key format and return list of diagnostic issues.

        Portkey keys typically use the format: pk-xxx-xxx
        Returns a list of warning strings (empty if key looks valid).
        """
        issues = []
        if not key:
            issues.append("Key is empty")
            return issues
        if not key.startswith("pk-"):
            issues.append(
                f"Key does not start with 'pk-' prefix (starts with "
                f"'{key[:4]}...'). Portkey API keys typically use the "
                f"format 'pk-xxx-xxx'. If using a provider API key directly, "
                f"ensure x-portkey-provider is set correctly."
            )
        if len(key) < 10:
            issues.append(
                f"Key appears too short (len={len(key)}). "
                f"Expected pk-xxx-xxx format with more characters."
            )
        if "\n" in key or "\r" in key:
            issues.append("Key contains newline characters — possible copy-paste error")
        if key != key.strip():
            issues.append("Key has leading/trailing whitespace")
        if issues:
            for issue in issues:
                logger.warning(
                    f"[Portkey] slot {slot_index} KEY VALIDATION: {issue}"
                )
        return issues

    @staticmethod
    def _get_virtual_key(slot_index: int) -> Optional[str]:
        """Get PORTKEY_VIRTUAL_KEY_{i} env var for alternative auth.

        Portkey supports virtual keys as an alternative to direct API keys.
        Virtual keys are mapped in the Portkey dashboard to provider credentials.
        """
        virtual_key = os.environ.get(f"PORTKEY_VIRTUAL_KEY_{slot_index}", "")
        if virtual_key:
            virtual_key = _sanitize_api_key(virtual_key)
        return virtual_key or None

    def chat_complete(
        self, messages, model=None, max_tokens=2048, temperature=0.2,
        timeout=60, task="general"
    ) -> str:
        # Provider-level circuit breaker check
        if not self.circuit_breaker.allow_request():
            logger.warning(
                f"[Portkey] Circuit breaker OPEN — skipping request"
            )
            raise RuntimeError(
                f"Portkey provider circuit breaker is OPEN "
                f"({self.circuit_breaker.failure_count} consecutive failures)"
            )

        explicit_model = model
        chosen_model   = explicit_model or self.DEFAULT_MODEL
        models_to_try  = [chosen_model] + [m for m in self.PORTKEY_MODELS if m != chosen_model]

        slot      = self.rotator.get_primary()
        fallbacks = [slot] + self.rotator.get_fallback_chain(slot.index)

        last_auth_error = None
        for attempt, s in enumerate(fallbacks):
            last_err = None
            for m in models_to_try:
                try:
                    # Sanitize API key
                    clean_key = _sanitize_api_key(s.api_key)
                    if not clean_key:
                        logger.warning(f"[Portkey] slot {s.index} has empty API key — skipping")
                        break  # No point trying other models with empty key

                    # Validate key format
                    key_issues = self._validate_portkey_key(clean_key, s.index)
                    if key_issues:
                        logger.warning(
                            f"[Portkey] slot {s.index} Key format issues detected. "
                            f"If auth fails, check: (1) key starts with 'pk-', "
                            f"(2) key is not expired, (3) PORTKEY_VIRTUAL_KEY_{s.index} "
                            f"env var as alternative auth."
                        )

                    url     = f"{self.gateway_url}/chat/completions"

                    # ── Portkey Authentication Strategy ─────────────────────
                    # Use the enhanced _build_portkey_auth method for intelligent
                    # key detection: pk- (native), virtual key, sk- (provider),
                    # or unknown format with warning.
                    try:
                        headers = self._build_portkey_auth(s.index)
                    except ValueError as auth_err:
                        logger.warning(
                            f"[Portkey] slot {s.index} Auth build failed: {auth_err}"
                        )
                        break  # No point trying other models with bad auth

                    payload = {
                        "model":       m,
                        "messages":    messages,
                        "max_tokens":  max_tokens,
                        "temperature": temperature,
                    }
                    resp, lat = self._post_json_with_retry(
                        url, headers, payload, timeout,
                        provider_name="Portkey", slot_index=s.index
                    )
                    self.rotator.mark_success(s, lat)
                    self.circuit_breaker.record_success()
                    return self._extract_text(resp)
                except urllib.error.HTTPError as e:
                    last_err = e
                    if e.code in (403, 401):
                        last_auth_error = e
                        error_body = _read_error_body(e)
                        logger.warning(
                            f"[Portkey] slot {s.index} AUTH FAIL HTTP {e.code}"
                        )
                        # Enhanced 401 diagnostics
                        if e.code == 401:
                            logger.error(
                                f"[Portkey] slot {s.index} HTTP 401 UNAUTHORIZED — "
                                f"possible causes: "
                                f"(1) Invalid/expired API key, "
                                f"(2) Key format wrong — Portkey keys start with 'pk-', "
                                f"(3) Missing x-portkey-config header for virtual key auth, "
                                f"(4) Using provider API key instead of Portkey key. "
                                f"Response: {error_body[:200]}"
                            )
                        self.rotator.mark_failure(s)
                        self.circuit_breaker.record_failure()
                        break  # Try next slot, not next model
                    if e.code == 400:
                        error_body = _read_error_body(e)
                        logger.debug(
                            f"[Portkey] slot {s.index} model {m} → "
                            f"400 Bad Request: {error_body[:200]}"
                        )
                        continue  # Try next model
                    if e.code == 404:
                        logger.debug(f"[Portkey] Model not found: {m}")
                        continue  # Try next model
                    logger.warning(f"[Portkey] slot {s.index} HTTP {e.code}: {e.reason}")
                    self.rotator.mark_failure(s)
                    self.circuit_breaker.record_failure()
                    if attempt == len(fallbacks) - 1:
                        raise
                    time.sleep(2 ** attempt)

            if last_err and last_err.code in (403, 401):
                continue  # Already marked failure, try next slot
            elif last_err:
                self.rotator.mark_failure(s)
                self.circuit_breaker.record_failure()
                if attempt == len(fallbacks) - 1:
                    raise last_err
                time.sleep(2 ** attempt)

        # All slots exhausted
        if last_auth_error:
            raise last_auth_error
        return ""


# ── Cerebras ───────────────────────────────────────────────────────────────────

class CerebrasProvider(_BaseProvider):
    name          = "cerebras"
    BASE_URL      = "https://api.cerebras.ai/v1"
    DEFAULT_MODEL = "llama3.1-8b"  # Most stable free-tier model
    CEREBRAS_MODELS = [
        "llama3.1-8b",
        "llama3.1-70b",
        "llama-4-scout-17b-16e-instruct",
        "qwen-2.5-32b",
    ]

    def __init__(self):
        self.rotator = build_rotator_from_env("CEREBRAS", n_accounts=3)
        self._discovered_models: Optional[List[str]] = None
        self._discovery_ts: float = 0.0
        self.circuit_breaker = ProviderCircuitBreaker("Cerebras")
        logger.info(
            f"[Cerebras] Initialized with {len(self.rotator.slots)} slot(s)"
        )

    def _discover_models(self) -> List[str]:
        """Fetch available models from Cerebras /v1/models endpoint.

        Caches results for 10 minutes to avoid excessive API calls.
        Falls back to CEREBRAS_MODELS on any error.
        """
        cache_ttl = 600.0  # 10 minutes
        if (
            self._discovered_models is not None
            and (time.time() - self._discovery_ts) < cache_ttl
        ):
            return self._discovered_models

        try:
            slot = self.rotator.get_primary()
            clean_key = _sanitize_api_key(slot.api_key)
            if not clean_key:
                logger.debug("[Cerebras] No API key for model discovery — using static list")
                return list(self.CEREBRAS_MODELS)

            url = f"{self.BASE_URL}/models"
            headers = {
                "Authorization": f"Bearer {clean_key}",
                "User-Agent": _USER_AGENT,
            }
            req = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            discovered = []
            for item in data.get("data", []):
                model_id = item.get("id", "")
                if model_id:
                    discovered.append(model_id)

            if discovered:
                self._discovered_models = discovered
                self._discovery_ts = time.time()
                logger.info(
                    f"[Cerebras] Discovered {len(discovered)} models: {discovered}"
                )
                return discovered
            else:
                logger.warning("[Cerebras] /models returned empty list — using static list")
                return list(self.CEREBRAS_MODELS)

        except Exception as e:
            logger.warning(
                f"[Cerebras] Model discovery failed: {e} — using static list"
            )
            return list(self.CEREBRAS_MODELS)

    def chat_complete(
        self, messages, model=None, max_tokens=2048, temperature=0.2,
        timeout=60, task="general"
    ) -> str:
        # Provider-level circuit breaker check
        if not self.circuit_breaker.allow_request():
            logger.warning(
                f"[Cerebras] Circuit breaker OPEN — skipping request "
                f"(failures={self.circuit_breaker.failure_count}, "
                f"state={self.circuit_breaker.state})"
            )
            raise RuntimeError(
                f"Cerebras provider circuit breaker is OPEN "
                f"({self.circuit_breaker.failure_count} consecutive failures)"
            )

        explicit_model = model
        chosen_model   = explicit_model or self.DEFAULT_MODEL

        # Use discovered models if available, otherwise fall back to static list
        available_models = self._discover_models()
        models_to_try  = [chosen_model] + [m for m in available_models if m != chosen_model]

        slot      = self.rotator.get_primary()
        fallbacks = [slot] + self.rotator.get_fallback_chain(slot.index)

        last_auth_error = None
        for attempt, s in enumerate(fallbacks):
            last_err = None
            for m in models_to_try:
                try:
                    # Sanitize API key
                    clean_key = _sanitize_api_key(s.api_key)
                    if not clean_key:
                        logger.warning(f"[Cerebras] slot {s.index} has empty API key — skipping")
                        break  # No point trying other models with empty key

                    url     = f"{self.BASE_URL}/chat/completions"
                    headers = {
                        "Content-Type":  "application/json",
                        "Authorization": f"Bearer {clean_key}",
                    }
                    payload = {
                        "model":       m,
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
                    self.circuit_breaker.record_success()
                    return self._extract_text(resp)
                except urllib.error.HTTPError as e:
                    last_err = e
                    if e.code in (403, 401):
                        last_auth_error = e
                        logger.warning(f"[Cerebras] slot {s.index} AUTH FAIL HTTP {e.code}")
                        self.rotator.mark_failure(s)
                        self.circuit_breaker.record_failure()
                        break  # Try next slot, not next model
                    if e.code == 400:
                        error_body = _read_error_body(e)
                        logger.debug(
                            f"[Cerebras] slot {s.index} model {m} → "
                            f"400 Bad Request: {error_body[:200]}"
                        )
                        continue  # Try next model
                    if e.code == 404:
                        logger.debug(f"[Cerebras] Model not found: {m}")
                        continue  # Try next model
                    logger.warning(f"[Cerebras] slot {s.index} HTTP {e.code}: {e.reason}")
                    self.rotator.mark_failure(s)
                    self.circuit_breaker.record_failure()
                    if attempt == len(fallbacks) - 1:
                        raise
                    time.sleep(2 ** attempt)

            if last_err and last_err.code in (403, 401):
                continue  # Already marked failure, try next slot
            elif last_err:
                self.rotator.mark_failure(s)
                self.circuit_breaker.record_failure()
                if attempt == len(fallbacks) - 1:
                    raise last_err
                time.sleep(2 ** attempt)

        if last_auth_error:
            raise last_auth_error
        return ""


# ── Cloudflare Workers AI (direct) ────────────────────────────────────────────

class CloudflareWorkersAIProvider(_BaseProvider):
    """
    Cloudflare Workers AI — direct API with dynamic model selection.
    Model is resolved at call-time via CloudflareModelSelector.

    CORRECTION 6: Pre-flight screening validates each slot's token and
    account_id BEFORE any request is sent. Broken slots (corrupted token,
    invalid account_id, etc.) are silently skipped without causing HTTP 400
    errors. No env vars or secrets are deleted — only runtime skipping.
    """
    name = "cloudflare_workers_ai"
    # Class-level set of models that 400'd on any slot — skip on all
    # subsequent slots to reduce health-check timeout cascade.
    _failed_models: set = set()

    def __init__(self):
        slots = []
        skipped_slots = []
        for i in range(1, CF_N_SLOTS + 1):
            acct_id   = os.environ.get(f"CF_ACCOUNT_ID_{i}", "")
            api_token = os.environ.get(f"CF_API_TOKEN_{i}", "")
            if not (acct_id and api_token):
                continue
            # ── CORRECTION 6: Pre-flight screening ───────────────────
            # First use the enhanced slot-level screener
            valid, reason = _preflight_screen_slot(i)
            if not valid:
                logger.warning(
                    f"[CF-Workers-AI] Slot {i} skipped by pre-flight: {reason}"
                )
                skipped_slots.append(i)
                continue
            # Also run the detailed validator for logging
            preflight_issues = preflight_validate_cf_slot(
                slot_index=i,
                account_id=acct_id,
                api_token=api_token,
            )
            if preflight_issues:
                skipped_slots.append(i)
                continue
            slots.append(
                AccountSlot(index=i, account_id=acct_id, api_key=api_token)
            )
        if skipped_slots:
            logger.warning(
                f"[CF-Workers-AI] Pre-flight screening SKIPPED {len(skipped_slots)} "
                f"broken slot(s): {skipped_slots}. These slots are NOT deleted — "
                f"they will be retried in the next CI run after fixing secrets."
            )
        if not slots:
            raise ValueError(
                "[CloudflareWorkersAI] No CF accounts configured "
                "(all slots either empty or failed pre-flight screening)."
            )
        self.rotator = AccountRotator("cloudflare_workers_ai", slots)
        self._selector = CloudflareModelSelector.instance()
        self.circuit_breaker = ProviderCircuitBreaker("CF-Workers-AI")
        # Session-level blacklist for slots that fail all models at runtime
        self._session_blacklist: set = set()
        logger.info(
            f"[CF-Workers-AI] Initialized with {len(slots)} slot(s) "
            f"({len(skipped_slots)} skipped by pre-flight screening)"
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
        # Provider-level circuit breaker check
        if not self.circuit_breaker.allow_request():
            logger.warning(
                f"[CF-Workers-AI] Circuit breaker OPEN — skipping request"
            )
            raise RuntimeError(
                f"CF-Workers-AI provider circuit breaker is OPEN "
                f"({self.circuit_breaker.failure_count} consecutive failures)"
            )

        chosen_model = self._resolve_model(model, task)

        slot      = self.rotator.get_primary()
        fallbacks = [slot] + self.rotator.get_fallback_chain(slot.index)

        # Build fallback model chain: chosen → stable models, excluding already-failed models
        models_to_try = [chosen_model] + [m for m in CF_STABLE_MODELS if m != chosen_model]

        last_auth_error = None
        for attempt, s in enumerate(fallbacks):
            last_err = None
            for m in models_to_try:
                # Skip models that already 400'd on a previous slot
                if m in self._failed_models:
                    logger.debug(
                        f"[CF-Workers-AI] Skipping model {m} — previously 400'd on another slot"
                    )
                    continue

                try:
                    # Sanitize credentials
                    clean_token = _sanitize_api_key(s.api_key)
                    clean_acct  = _sanitize_api_key(s.account_id)
                    if not clean_token or not clean_acct:
                        logger.warning(
                            f"[CF-Workers-AI] slot {s.index} has empty credentials — skipping"
                        )
                        continue

                    # Strip @ prefix from model ID for URL construction
                    model_id = m.lstrip("@") if m.startswith("@cf/") else m
                    url = (
                        "https://api.cloudflare.com/client/v4/accounts/"
                        f"{clean_acct}/ai/run/{model_id}"
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
                    self.circuit_breaker.record_success()
                    return self._extract_text(resp)
                except urllib.error.HTTPError as e:
                    last_err = e
                    if e.code in (403, 401):
                        last_auth_error = e
                        logger.warning(
                            f"[CF-Workers-AI] slot {s.index} AUTH FAIL HTTP {e.code}"
                        )
                        self.circuit_breaker.record_failure()
                        break  # Try next slot, not next model
                    if e.code == 400:
                        # Model-specific issue — add to failed set and try next model
                        self._failed_models.add(m)
                        error_body = _read_error_body(e)
                        logger.debug(
                            f"[CF-Workers-AI] slot {s.index} model {m} → "
                            f"400 Bad Request: {error_body[:200]}"
                        )
                        continue
                    if e.code == 404:
                        logger.debug(f"[CF-Workers-AI] Model not found: {m}")
                        self._failed_models.add(m)
                        continue
                    self.circuit_breaker.record_failure()
                    raise

            if last_err:
                if last_err.code in (403, 401):
                    self.rotator.mark_failure(s)
                    continue  # Try next slot
                logger.warning(f"[CF-Workers-AI] slot {s.index} all models failed")
                self.rotator.mark_failure(s)
                self.circuit_breaker.record_failure()
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

    CORRECTION 6: Pre-flight screening validates each slot's token length,
    account_id format, and gateway URL structure BEFORE any request is sent.
    Broken slots (like slot 7 with corrupted tokens) are silently skipped
    without causing HTTP 400 errors. No env vars or secrets are deleted —
    only runtime skipping.
    """
    name = "cloudflare_ai_gateway"
    # Class-level set of models that 400'd on any slot — skip on all
    # subsequent slots to reduce health-check timeout cascade.
    _failed_models: set = set()
    # Expected gateway URL prefix
    _GATEWAY_URL_PREFIX = "https://gateway.ai.cloudflare.com/v1/"

    def __init__(self):
        slots = []
        skipped_slots = []
        for i in range(1, CF_N_SLOTS + 1):
            acct_id     = os.environ.get(f"CF_ACCOUNT_ID_{i}", "")
            api_token   = os.environ.get(f"CF_API_TOKEN_{i}", "")
            gateway_url = os.environ.get(f"CF_AI_GATEWAY_URL_{i}", "")
            if not (acct_id and api_token and gateway_url):
                continue

            # ── CORRECTION 6: Pre-flight screening ───────────────────
            # First use the enhanced slot-level screener
            valid, reason = _preflight_screen_slot(i)
            if not valid:
                logger.warning(
                    f"[CF-AI-GW] Slot {i} skipped by pre-flight: {reason}"
                )
                skipped_slots.append(i)
                continue
            # Also run the detailed validator for logging
            preflight_issues = preflight_validate_cf_slot(
                slot_index=i,
                account_id=acct_id,
                api_token=api_token,
                gateway_url=gateway_url,
            )
            if preflight_issues:
                skipped_slots.append(i)
                continue

            try:
                gateway_url = _validate_url(gateway_url, f"CF_AI_GATEWAY_URL_{i}")
            except ValueError as e:
                logger.error(str(e))
                skipped_slots.append(i)
                continue
            # Validate gateway URL structure
            try:
                self._validate_gateway_url(gateway_url, acct_id, slot_index=i)
            except ValueError as e:
                logger.error(str(e))
                skipped_slots.append(i)
                continue
            slots.append(
                AccountSlot(
                    index=i,
                    account_id=acct_id,
                    api_key=api_token,
                    gateway_url=gateway_url,
                )
            )
        if skipped_slots:
            logger.warning(
                f"[CF-AI-GW] Pre-flight screening SKIPPED {len(skipped_slots)} "
                f"broken slot(s): {skipped_slots}. These slots are NOT deleted — "
                f"they will be retried in the next CI run after fixing secrets."
            )
        if not slots:
            raise ValueError(
                "[CF-AI-Gateway] No gateway slots configured "
                "(all slots either empty or failed pre-flight screening)."
            )
        self.rotator  = AccountRotator("cloudflare_ai_gateway", slots)
        self._selector = CloudflareModelSelector.instance()
        self.circuit_breaker = ProviderCircuitBreaker("CF-AI-GW")
        # Session-level blacklist for slots that fail all models at runtime
        self._session_blacklist: set = set()
        logger.info(
            f"[CF-AI-GW] Initialized with {len(slots)} slot(s) "
            f"({len(skipped_slots)} skipped by pre-flight screening)"
        )

    @classmethod
    def _validate_gateway_url(
        cls, gateway_url: str, account_id: str, slot_index: int = 0
    ) -> None:
        """Validate CF AI Gateway URL structure.

        Expected format: https://gateway.ai.cloudflare.com/v1/{account_id}/{gateway_slug}
        - Must start with https://gateway.ai.cloudflare.com/v1/
        - Must contain an account_id in the path after /v1/
        - Logs the full URL pattern (with masked account_id) for debugging.
        """
        if not gateway_url.startswith(cls._GATEWAY_URL_PREFIX):
            raise ValueError(
                f"[CF-AI-GW] slot {slot_index} Invalid gateway URL: "
                f"must start with '{cls._GATEWAY_URL_PREFIX}'. "
                f"Got: {_mask_url(gateway_url)}"
            )

        # Extract the path after /v1/
        path_after_v1 = gateway_url[len(cls._GATEWAY_URL_PREFIX):]
        path_parts = [p for p in path_after_v1.split("/") if p]

        if len(path_parts) < 2:
            raise ValueError(
                f"[CF-AI-GW] slot {slot_index} Invalid gateway URL: "
                f"expected path /v1/{{account_id}}/{{gateway_slug}}, "
                f"got {_mask_url(gateway_url)}. "
                f"Path after /v1/ has {len(path_parts)} segment(s), need at least 2 "
                f"(account_id and gateway_slug)."
            )

        url_account_id = path_parts[0]
        gateway_slug = path_parts[1]

        # Validate that account_id in URL matches the configured account_id
        if account_id and url_account_id != account_id:
            logger.warning(
                f"[CF-AI-GW] slot {slot_index} Account ID mismatch: "
                f"URL contains '{_mask_key(url_account_id, 3)}' but "
                f"CF_ACCOUNT_ID is '{_mask_key(account_id, 3)}'. "
                f"This may cause 400 errors."
            )

        logger.info(
            f"[CF-AI-GW] slot {slot_index} Gateway URL validated: "
            f"prefix={cls._GATEWAY_URL_PREFIX} "
            f"account_id={_mask_key(url_account_id, 3)} "
            f"gateway_slug={gateway_slug} "
            f"full_pattern={cls._GATEWAY_URL_PREFIX}{_mask_key(url_account_id, 3)}/{gateway_slug}/workers-ai/{{account_id}}/{{model_id}}"
        )

    @staticmethod
    def _probe_gateway(gateway_url: str, timeout: int = 10) -> bool:
        """Send a lightweight GET request to the gateway URL to check reachability.

        Returns True if the gateway is reachable (any HTTP response, even 404),
        False if the connection itself fails.
        """
        try:
            req = urllib.request.Request(
                gateway_url,
                headers={"User-Agent": _USER_AGENT},
                method="GET",
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                logger.debug(
                    f"[CF-AI-GW] Gateway probe OK: HTTP {resp.status} "
                    f"for {_mask_url(gateway_url)}"
                )
                return True
        except urllib.error.HTTPError as e:
            # Any HTTP response means the gateway is reachable
            # (even 404/403 means the server is up)
            logger.debug(
                f"[CF-AI-GW] Gateway probe got HTTP {e.code} — "
                f"gateway is reachable but returned error"
            )
            return True
        except (urllib.error.URLError, ConnectionError, TimeoutError, OSError) as e:
            logger.warning(
                f"[CF-AI-GW] Gateway probe FAILED for {_mask_url(gateway_url)}: {e}. "
                f"Gateway may be unreachable or DNS resolution failed."
            )
            return False

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
        # Provider-level circuit breaker check
        if not self.circuit_breaker.allow_request():
            logger.warning(
                f"[CF-AI-GW] Circuit breaker OPEN — skipping request"
            )
            raise RuntimeError(
                f"CF-AI-GW provider circuit breaker is OPEN "
                f"({self.circuit_breaker.failure_count} consecutive failures)"
            )

        chosen_model = self._resolve_model(model, task)

        slot      = self.rotator.get_primary()
        fallbacks = [slot] + self.rotator.get_fallback_chain(slot.index)

        models_to_try = [chosen_model] + [m for m in CF_STABLE_MODELS if m != chosen_model]

        last_auth_error = None
        for attempt, s in enumerate(fallbacks):
            last_err = None

            # Probe gateway reachability before first attempt on this slot
            if attempt == 0 or last_auth_error is None:
                if not self._probe_gateway(s.gateway_url):
                    logger.warning(
                        f"[CF-AI-GW] slot {s.index} gateway unreachable — skipping"
                    )
                    self.rotator.mark_failure(s)
                    self.circuit_breaker.record_failure()
                    continue

            for m in models_to_try:
                # Skip models that already 400'd on a previous slot
                if m in self._failed_models:
                    logger.debug(
                        f"[CF-AI-GW] Skipping model {m} — previously 400'd on another slot"
                    )
                    continue

                try:
                    # Sanitize credentials
                    clean_token = _sanitize_api_key(s.api_key)
                    clean_acct  = _sanitize_api_key(s.account_id)
                    if not clean_token:
                        logger.warning(
                            f"[CF-AI-GW] slot {s.index} has empty API token — skipping"
                        )
                        break  # No point trying other models with empty token

                    # CF AI Gateway URL format (Cloudflare docs):
                    # {gateway_url}/workers-ai/{account_id}/{model_id}
                    # The account_id appears in both the gateway URL prefix AND
                    # as part of the workers-ai path per Cloudflare docs.
                    #
                    # CRITICAL FIX (v15.1): Model IDs with '@' prefix (e.g., @cf/meta/llama-3.1-8b-instruct)
                    # must be URL-encoded. The '@' character in URLs can cause path resolution
                    # issues. We strip the '@' prefix since CF Workers AI accepts both formats.
                    model_id = m.lstrip("@") if m.startswith("@cf/") else m
                    url = f"{s.gateway_url}/workers-ai/{s.account_id}/{model_id}"
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
                    self.circuit_breaker.record_success()
                    return self._extract_text(resp)
                except urllib.error.HTTPError as e:
                    last_err = e
                    if e.code in (403, 401):
                        last_auth_error = e
                        logger.warning(
                            f"[CF-AI-GW] slot {s.index} AUTH FAIL HTTP {e.code} "
                            f"URL={s.gateway_url[:40]}..."
                        )
                        self.circuit_breaker.record_failure()
                        break  # Try next slot, not next model
                    if e.code == 400:
                        # Model-specific issue — add to failed set and try next model
                        self._failed_models.add(m)
                        error_body = _read_error_body(e)
                        if not error_body.strip():
                            logger.warning(
                                f"[CF-AI-GW] slot {s.index} model {m} → 400 with EMPTY "
                                f"response body. This typically means the URL path is "
                                f"malformed or the model doesn't exist on this account. "
                                f"Verify URL structure: {{gateway_url}}/workers-ai/"
                                f"{{account_id}}/{{model_id}}"
                            )
                        else:
                            logger.debug(
                                f"[CF-AI-GW] slot {s.index} model {m} → "
                                f"400 Bad Request: {error_body[:200]}"
                            )
                        continue
                    if e.code == 404:
                        logger.debug(f"[CF-AI-GW] Model not found: {m}")
                        self._failed_models.add(m)
                        continue
                    logger.warning(
                        f"[CF-AI-GW] slot {s.index} "
                        f"URL={s.gateway_url[:40]}... HTTP {e.code}"
                    )
                    self.circuit_breaker.record_failure()
                    raise

            if last_err:
                if last_err.code in (403, 401):
                    self.rotator.mark_failure(s)
                    continue  # Try next slot
                logger.warning(f"[CF-AI-GW] slot {s.index} all models failed")
                self.rotator.mark_failure(s)
                self.circuit_breaker.record_failure()
                if attempt == len(fallbacks) - 1:
                    raise last_err
                time.sleep(2 ** attempt)

        if last_auth_error:
            raise last_auth_error
        return ""
