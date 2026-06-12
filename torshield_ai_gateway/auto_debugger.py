"""
auto_debugger.py — Auto-Debug System for Tor-Bridges-Collector
================================================================

Automatically diagnoses errors from AI gateway providers and returns
appropriate fix actions. Integrates with the existing AutoDebugEngine
and IranAutoDefense pipeline.

Features:
  - Automatic error classification (auth, model, network, response)
  - Provider-specific diagnostic heuristics
  - Fix action recommendation with reasoning
  - Slot-level error tracking and pattern detection
  - Integration with pre-flight screening for root cause analysis

This module is ADDITIVE — it does not modify any existing auto-debug
or self-healing functionality. It provides enhanced diagnostics that
complement the existing AutoDebugEngine.
"""

from __future__ import annotations

import enum
import logging
import os
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from urllib.error import HTTPError

# Import for config-level error awareness
try:
    from .exceptions import ProviderConfigurationError, BadRequestError
except ImportError:
    class ProviderConfigurationError(Exception):  # type: ignore[no-redef]
        """Fallback when exceptions module not available."""
        pass
    class BadRequestError(Exception):  # type: ignore[no-redef]
        """Fallback BadRequestError when exceptions module not available."""
        pass

logger = logging.getLogger("torshield.auto_debugger")


# ═══════════════════════════════════════════════════════════════════════════
# FIX ACTIONS
# ═══════════════════════════════════════════════════════════════════════════

class FixAction(enum.Enum):
    """Actions the auto-debugger can recommend."""
    SKIP_SLOT = "skip_slot"                    # Skip this slot entirely
    SWITCH_MODEL = "switch_model"              # Try a different model
    ROTATE_KEY = "rotate_key"                  # Try next key slot
    RETRY_WITH_BACKOFF = "retry_with_backoff"  # Network issue, retry later
    RELAX_RESPONSE_VALIDATION = "relax_response_validation"  # Accept partial match
    SKIP_AND_LOG = "skip_and_log"              # Skip but log for analysis
    RECONFIGURE_URL = "reconfigure_url"        # URL path is wrong
    CHECK_PREFLIGHT = "check_preflight"        # Re-run pre-flight screening
    CONFIG_ERROR_SKIP = "config_error_skip"    # ProviderConfigurationError — do NOT retry
    FIX_URL_PATH = "fix_url_path"              # CF URL uses wrong endpoint path
    INCREASE_MAX_TOKENS = "increase_max_tokens"  # max_tokens too small for model
    NO_ACTION = "no_action"                    # Error is not actionable


# ═══════════════════════════════════════════════════════════════════════════
# DIAGNOSTIC RESULT
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class DiagnosticResult:
    """Result of an auto-debug diagnosis."""
    provider: str
    slot: int
    error_type: str
    error_message: str
    fix_action: FixAction
    reasoning: str
    confidence: float = 0.0  # 0.0 to 1.0
    related_slots: List[int] = field(default_factory=list)
    suggested_models: List[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)


# ═══════════════════════════════════════════════════════════════════════════
# ERROR PATTERN DATABASE
# ═══════════════════════════════════════════════════════════════════════════

_ERROR_PATTERNS = {
    # Auth errors — permanent, need credential rotation
    "auth_401": {
        "pattern": re.compile(r"401|unauthorized|invalid.?api.?key", re.IGNORECASE),
        "action": FixAction.ROTATE_KEY,
        "reasoning": "HTTP 401 Unauthorized — credentials are invalid or expired",
        "confidence": 0.95,
    },
    "auth_403": {
        "pattern": re.compile(r"403|forbidden|access.?denied", re.IGNORECASE),
        "action": FixAction.ROTATE_KEY,
        "reasoning": "HTTP 403 Forbidden — credentials lack required permissions",
        "confidence": 0.90,
    },
    # Model errors — need to switch model
    "bad_request_400": {
        "pattern": re.compile(r"BadRequestError|HTTP 400|bad.?request", re.IGNORECASE),
        "action": FixAction.SWITCH_MODEL,
        "reasoning": "HTTP 400 Bad Request — NOT an auth failure. Check model ID, URL path, or payload format. Try next model.",
        "confidence": 0.90,
    },
    "model_400": {
        "pattern": re.compile(r"model.?not.?found|invalid.?model", re.IGNORECASE),
        "action": FixAction.SWITCH_MODEL,
        "reasoning": "Model ID is invalid or not available on this provider",
        "confidence": 0.85,
    },
    "model_404": {
        "pattern": re.compile(r"404|not.?found|no.?route", re.IGNORECASE),
        "action": FixAction.SWITCH_MODEL,
        "reasoning": "HTTP 404 Not Found — model endpoint does not exist",
        "confidence": 0.90,
    },
    # Network errors — transient, retry with backoff
    "network_timeout": {
        "pattern": re.compile(r"timeout|timed.?out|deadline.?exceeded|ETIMEDOUT", re.IGNORECASE),
        "action": FixAction.RETRY_WITH_BACKOFF,
        "reasoning": "Network timeout — transient issue, retry with exponential backoff",
        "confidence": 0.80,
    },
    "network_connection": {
        "pattern": re.compile(r"connection.?refused|connection.?reset|network.?unreachable|dns", re.IGNORECASE),
        "action": FixAction.RETRY_WITH_BACKOFF,
        "reasoning": "Connection failure — likely transient network issue",
        "confidence": 0.75,
    },
    "network_5xx": {
        "pattern": re.compile(r"5[0-9]{2}|internal.?server.?error|bad.?gateway|service.?unavailable", re.IGNORECASE),
        "action": FixAction.RETRY_WITH_BACKOFF,
        "reasoning": "Server-side error (5xx) — transient, retry with backoff",
        "confidence": 0.70,
    },
    # Rate limiting
    "rate_limit_429": {
        "pattern": re.compile(r"429|rate.?limit|too.?many.?requests|quota", re.IGNORECASE),
        "action": FixAction.RETRY_WITH_BACKOFF,
        "reasoning": "Rate limit hit — wait and retry after cooldown",
        "confidence": 0.95,
    },
    # Wrong response
    "wrong_response": {
        "pattern": re.compile(r"wrong.?response|unexpected.?response|TORSHIELD_OK", re.IGNORECASE),
        "action": FixAction.RELAX_RESPONSE_VALIDATION,
        "reasoning": "Response validation too strict — model replied but not exact match",
        "confidence": 0.80,
    },
    # Bot protection
    "bot_protection": {
        "pattern": re.compile(r"error.?code.?1010|bot.?protection|cloudflare.?bot", re.IGNORECASE),
        "action": FixAction.RETRY_WITH_BACKOFF,
        "reasoning": "Cloudflare bot protection triggered — User-Agent issue",
        "confidence": 0.85,
    },
    # URL/configuration errors
    "malformed_url": {
        "pattern": re.compile(r"malformed|url.?error|invalid.?url|path.?error", re.IGNORECASE),
        "action": FixAction.RECONFIGURE_URL,
        "reasoning": "URL is malformed — check path construction and model ID format",
        "confidence": 0.80,
    },
    # Preflight issues
    "preflight_failure": {
        "pattern": re.compile(r"preflight|screening|token.?too.?short|invalid.?account", re.IGNORECASE),
        "action": FixAction.CHECK_PREFLIGHT,
        "reasoning": "Pre-flight screening failure — slot credentials are corrupted",
        "confidence": 0.90,
    },
}

# CF stable models to suggest when switching
_CF_FALLBACK_MODELS = [
    "@cf/meta/llama-3.1-8b-instruct",
    "@cf/meta/llama-3.2-3b-instruct",
    "@cf/meta/llama-3.2-1b-instruct",
    "@cf/mistral/mistral-7b-instruct-v0.1",
]


# ═══════════════════════════════════════════════════════════════════════════
# AUTO DEBUGGER
# ═══════════════════════════════════════════════════════════════════════════

class AutoDebugger:
    """
    Automatic error diagnostic and fix recommendation engine.

    Analyzes errors from AI gateway providers and recommends fix actions
    based on error patterns, provider-specific knowledge, and historical
    slot health data. Works alongside the existing AutoDebugEngine to
    provide faster, more targeted diagnostics for common failure modes.

    Usage:
        debugger = AutoDebugger()
        result = debugger.diagnose_and_fix(
            provider="cloudflare_workers_ai",
            error=some_http_error,
            slot=7,
        )
        print(result.fix_action)  # e.g., FixAction.SKIP_SLOT
    """

    def __init__(self):
        self._diagnostic_history: List[DiagnosticResult] = []
        self._slot_error_counts: Dict[Tuple[str, int], int] = {}
        self._model_error_counts: Dict[str, int] = {}
        logger.info("[AutoDebugger] Initialized")

    def diagnose_and_fix(
        self,
        provider: str,
        error: Exception,
        slot: int,
        model: str = "",
        url: str = "",
    ) -> DiagnosticResult:
        """
        Automatically diagnose errors and return fix action.

        This method examines the error type, HTTP status code, response
        body, and provider context to determine the best course of action.
        It considers:

        1. HTTP status code classification
        2. Error body pattern matching
        3. Provider-specific error signatures
        4. Historical error frequency for this slot
        5. Pre-flight screening correlation

        Args:
            provider: Provider name (e.g., "cloudflare_workers_ai")
            error: The exception that was raised
            slot: Slot index that caused the error
            model: Model ID being used when error occurred
            url: URL that was being accessed

        Returns:
            DiagnosticResult with recommended fix action
        """
        error_str = str(error)
        error_type = type(error).__name__

        # Track slot errors
        slot_key = (provider, slot)
        self._slot_error_counts[slot_key] = (
            self._slot_error_counts.get(slot_key, 0) + 1
        )

        # Track model errors
        if model:
            self._model_error_counts[model] = (
                self._model_error_counts.get(model, 0) + 1
            )

        # ── Primary diagnosis: HTTP error code analysis ────────────────

        if isinstance(error, HTTPError):
            result = self._diagnose_http_error(
                error, provider, slot, model, url
            )
        else:
            # Non-HTTP error — pattern match against error message
            result = self._diagnose_pattern_error(
                error, provider, slot, model
            )

        # ── Secondary analysis: historical pattern check ────────────────

        # If this slot has failed many times, recommend skipping it
        slot_failures = self._slot_error_counts.get(slot_key, 0)
        if slot_failures >= 5 and result.fix_action != FixAction.SKIP_SLOT:
            result.reasoning += (
                f" | Slot has {slot_failures} cumulative failures — "
                f"consider skipping this slot"
            )
            if result.confidence < 0.7:
                result.fix_action = FixAction.SKIP_SLOT
                result.confidence = 0.75

        # If this model has failed many times, suggest alternatives
        model_failures = self._model_error_counts.get(model, 0) if model else 0
        if model_failures >= 3:
            result.suggested_models = [
                m for m in _CF_FALLBACK_MODELS
                if m != model and self._model_error_counts.get(m, 0) < 2
            ]

        # Record diagnostic
        self._diagnostic_history.append(result)

        # Trim history (keep last 1000 entries)
        if len(self._diagnostic_history) > 1000:
            self._diagnostic_history = self._diagnostic_history[-500:]

        logger.info(
            f"[AutoDebugger] Diagnosis: provider={provider}, slot={slot}, "
            f"action={result.fix_action.value}, "
            f"reasoning={result.reasoning[:100]}"
        )

        return result

    def _diagnose_http_error(
        self,
        error: HTTPError,
        provider: str,
        slot: int,
        model: str,
        url: str,
    ) -> DiagnosticResult:
        """Diagnose HTTPError based on status code and response body."""
        status_code = error.code

        # Read error body for additional diagnostics
        try:
            body = error.read().decode("utf-8", errors="replace")[:500]
        except Exception:
            body = ""

        # ── Auth failures (401, 403) ───────────────────────────────────

        if status_code == 401:
            return DiagnosticResult(
                provider=provider,
                slot=slot,
                error_type="auth_failure_401",
                error_message=f"HTTP 401 Unauthorized: {body[:200]}",
                fix_action=FixAction.ROTATE_KEY,
                reasoning=(
                    "HTTP 401 Unauthorized — API key is invalid, expired, "
                    "or has insufficient permissions. Rotating to next key slot."
                ),
                confidence=0.95,
            )

        if status_code == 403:
            # Distinguish between auth failure and bot protection
            if "error code: 1010" in body:
                return DiagnosticResult(
                    provider=provider,
                    slot=slot,
                    error_type="bot_protection_403",
                    error_message=f"Cloudflare bot protection (1010): {body[:200]}",
                    fix_action=FixAction.RETRY_WITH_BACKOFF,
                    reasoning=(
                        "HTTP 403 with error code 1010 — Cloudflare bot "
                        "protection triggered. This is transient and may "
                        "resolve with backoff and User-Agent rotation."
                    ),
                    confidence=0.90,
                )
            return DiagnosticResult(
                provider=provider,
                slot=slot,
                error_type="auth_failure_403",
                error_message=f"HTTP 403 Forbidden: {body[:200]}",
                fix_action=FixAction.ROTATE_KEY,
                reasoning=(
                    "HTTP 403 Forbidden — API key lacks required permissions "
                    "or account is suspended. Rotating to next key slot."
                ),
                confidence=0.90,
            )

        # ── Bad Request (400) ──────────────────────────────────────────

        if status_code == 400:
            if not body.strip():
                # Empty 400 body = malformed URL or corrupted credentials
                return DiagnosticResult(
                    provider=provider,
                    slot=slot,
                    error_type="empty_400",
                    error_message="HTTP 400 with empty response body",
                    fix_action=FixAction.SKIP_SLOT,
                    reasoning=(
                        "HTTP 400 with empty response body — URL path is "
                        "likely malformed or model doesn't exist on this "
                        "account. This slot should be skipped to prevent "
                        "cascade failures."
                    ),
                    confidence=0.85,
                )
            return DiagnosticResult(
                provider=provider,
                slot=slot,
                error_type="bad_request_400",
                error_message=f"HTTP 400 Bad Request: {body[:200]}",
                fix_action=FixAction.SWITCH_MODEL,
                reasoning=(
                    "HTTP 400 Bad Request — model ID is invalid or not "
                    "available on this account. Switching to fallback model."
                ),
                confidence=0.80,
                suggested_models=_CF_FALLBACK_MODELS[:2],
            )

        # ── Not Found (404) ────────────────────────────────────────────

        if status_code == 404:
            return DiagnosticResult(
                provider=provider,
                slot=slot,
                error_type="not_found_404",
                error_message=f"HTTP 404 Not Found: {body[:200]}",
                fix_action=FixAction.SWITCH_MODEL,
                reasoning=(
                    "HTTP 404 Not Found — model endpoint does not exist "
                    "on this account. Switching to fallback model."
                ),
                confidence=0.90,
                suggested_models=_CF_FALLBACK_MODELS[:2],
            )

        # ── Rate Limiting (429) ────────────────────────────────────────

        if status_code == 429:
            return DiagnosticResult(
                provider=provider,
                slot=slot,
                error_type="rate_limit_429",
                error_message=f"HTTP 429 Rate Limited: {body[:200]}",
                fix_action=FixAction.RETRY_WITH_BACKOFF,
                reasoning=(
                    "HTTP 429 Rate Limited — too many requests. "
                    "Waiting with exponential backoff before retry."
                ),
                confidence=0.95,
            )

        # ── Server Errors (5xx) ────────────────────────────────────────

        if 500 <= status_code < 600:
            return DiagnosticResult(
                provider=provider,
                slot=slot,
                error_type=f"server_error_{status_code}",
                error_message=f"HTTP {status_code} Server Error: {body[:200]}",
                fix_action=FixAction.RETRY_WITH_BACKOFF,
                reasoning=(
                    f"HTTP {status_code} Server Error — provider-side issue. "
                    f"Transient, retry with exponential backoff."
                ),
                confidence=0.70,
            )

        # ── Unhandled HTTP error ───────────────────────────────────────

        return DiagnosticResult(
            provider=provider,
            slot=slot,
            error_type=f"http_{status_code}",
            error_message=f"HTTP {status_code}: {body[:200]}",
            fix_action=FixAction.SKIP_AND_LOG,
            reasoning=(
                f"Unhandled HTTP {status_code} error. Skipping slot and "
                f"logging for analysis."
            ),
            confidence=0.50,
        )

    def _diagnose_pattern_error(
        self,
        error: Exception,
        provider: str,
        slot: int,
        model: str,
    ) -> DiagnosticResult:
        """Diagnose non-HTTP errors using pattern matching."""
        error_str = str(error)
        error_type = type(error).__name__

        # Try pattern matching
        for pattern_name, pattern_info in _ERROR_PATTERNS.items():
            if pattern_info["pattern"].search(error_str):
                return DiagnosticResult(
                    provider=provider,
                    slot=slot,
                    error_type=pattern_name,
                    error_message=error_str[:300],
                    fix_action=pattern_info["action"],
                    reasoning=pattern_info["reasoning"],
                    confidence=pattern_info["confidence"],
                )

        # Check error type directly
        if isinstance(error, (TimeoutError,)):
            return DiagnosticResult(
                provider=provider,
                slot=slot,
                error_type="timeout",
                error_message=error_str[:300],
                fix_action=FixAction.RETRY_WITH_BACKOFF,
                reasoning="Timeout error — transient network issue",
                confidence=0.80,
            )

        if isinstance(error, (ConnectionError, OSError)):
            return DiagnosticResult(
                provider=provider,
                slot=slot,
                error_type="connection_error",
                error_message=error_str[:300],
                fix_action=FixAction.RETRY_WITH_BACKOFF,
                reasoning="Connection error — likely transient network issue",
                confidence=0.75,
            )

        if "wrong_response" in error_str.lower():
            return DiagnosticResult(
                provider=provider,
                slot=slot,
                error_type="wrong_response",
                error_message=error_str[:300],
                fix_action=FixAction.RELAX_RESPONSE_VALIDATION,
                reasoning=(
                    "Wrong response — model replied but content doesn't "
                    "match expected signal. Relaxing validation criteria."
                ),
                confidence=0.80,
            )

        # Unknown error
        return DiagnosticResult(
            provider=provider,
            slot=slot,
            error_type=error_type,
            error_message=error_str[:300],
            fix_action=FixAction.SKIP_AND_LOG,
            reasoning=(
                f"Unclassified error ({error_type}). Skipping and logging "
                f"for future analysis."
            ),
            confidence=0.40,
        )

    def get_slot_health(self, provider: str, slot: int) -> dict:
        """
        Get health summary for a specific provider slot.

        Returns a dictionary with error count, last error, and
        recommended action based on historical data.
        """
        slot_key = (provider, slot)
        error_count = self._slot_error_counts.get(slot_key, 0)

        # Find last error for this slot
        last_result = None
        for r in reversed(self._diagnostic_history):
            if r.provider == provider and r.slot == slot:
                last_result = r
                break

        return {
            "provider": provider,
            "slot": slot,
            "error_count": error_count,
            "last_error": (
                {
                    "type": last_result.error_type,
                    "action": last_result.fix_action.value,
                    "reasoning": last_result.reasoning[:200],
                    "timestamp": last_result.timestamp,
                }
                if last_result else None
            ),
            "recommendation": (
                FixAction.SKIP_SLOT.value
                if error_count >= 5
                else FixAction.NO_ACTION.value
            ),
        }

    def get_diagnostics_summary(self) -> dict:
        """
        Get a summary of all diagnostics.

        Returns aggregated statistics about error patterns,
        slot health, and model performance.
        """
        total = len(self._diagnostic_history)
        action_counts: Dict[str, int] = {}
        for r in self._diagnostic_history:
            action_name = r.fix_action.value
            action_counts[action_name] = action_counts.get(action_name, 0) + 1

        # Most problematic slots
        slot_issues = sorted(
            self._slot_error_counts.items(),
            key=lambda x: x[1],
            reverse=True,
        )[:10]

        # Most problematic models
        model_issues = sorted(
            self._model_error_counts.items(),
            key=lambda x: x[1],
            reverse=True,
        )[:5]

        return {
            "total_diagnostics": total,
            "action_distribution": action_counts,
            "problematic_slots": [
                {"provider": k[0], "slot": k[1], "errors": v}
                for k, v in slot_issues
            ],
            "problematic_models": [
                {"model": k, "errors": v}
                for k, v in model_issues
            ],
        }


# ═══════════════════════════════════════════════════════════════════════════
# MODULE-LEVEL CONVENIENCE
# ═══════════════════════════════════════════════════════════════════════════

_debugger: Optional[AutoDebugger] = None


def get_auto_debugger() -> AutoDebugger:
    """Get or create the singleton AutoDebugger instance."""
    global _debugger
    if _debugger is None:
        _debugger = AutoDebugger()
    return _debugger
