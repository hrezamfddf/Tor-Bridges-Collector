"""
auto_debugger.py — Automatic Debug & Fix Engine v1.0
════════════════════════════════════════════════════
Automatically diagnoses and suggests fix actions for common
provider errors. Integrates with the anti-censorship engine
for DPI-related errors.

ARCHITECTURE
────────────
  ┌──────────────────────────────────────────┐
  │          AutoDebugger                     │
  ├──────────────────────────────────────────┤
  │  1. diagnose_and_fix(error) → FixAction  │
  │  2. HTTP 400 → model/slot diagnosis      │
  │  3. HTTP 401 → key format/expired        │
  │  4. Timeout → retry with backoff          │
  │  5. Wrong response → relax validation     │
  │  6. DPI detected → transport switch       │
  └──────────────────────────────────────────┘

FIX ACTIONS (FixAction enum)
─────────────────────────────
  SKIP_SLOT              — permanently skip this slot
  SWITCH_MODEL           — try a different model
  ROTATE_KEY             — rotate to next API key slot
  RETRY_WITH_BACKOFF     — retry with exponential backoff
  RELAX_RESPONSE_VALIDATION — accept broader response formats
  SKIP_AND_LOG           — skip and log for later analysis
"""

from __future__ import annotations

import logging
import time
from enum import Enum, auto
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("torshield.auto_debugger")


# ═══════════════════════════════════════════════════════════════════════════
# FIX ACTION ENUM
# ═══════════════════════════════════════════════════════════════════════════

class FixAction(Enum):
    """Actions that the auto-debugger can recommend.

    Each action corresponds to a specific error category and
    provides a clear remediation path for the caller.
    """
    SKIP_SLOT = auto()                    # Permanently skip this slot
    SWITCH_MODEL = auto()                 # Try a different model
    ROTATE_KEY = auto()                   # Rotate to next API key slot
    RETRY_WITH_BACKOFF = auto()           # Retry with exponential backoff
    RELAX_RESPONSE_VALIDATION = auto()    # Accept broader response formats
    SKIP_AND_LOG = auto()                 # Skip and log for later analysis


# ═══════════════════════════════════════════════════════════════════════════
# DIAGNOSTIC RESULT
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class DiagnosticResult:
    """Result of an auto-diagnostic analysis.

    Contains the recommended fix action, human-readable diagnosis,
    and optional metadata for further processing.
    """
    action: FixAction
    diagnosis: str
    provider: str = ""
    slot_index: int = 0
    model: str = ""
    http_status: int = 0
    error_body: str = ""
    confidence: float = 0.0  # 0.0 to 1.0
    metadata: Dict = field(default_factory=dict)


# ═══════════════════════════════════════════════════════════════════════════
# ERROR PATTERN DATABASE
# ═══════════════════════════════════════════════════════════════════════════

# Maps (http_status, body_pattern) → (FixAction, diagnosis_template)
_ERROR_PATTERNS: List[Dict] = [
    # HTTP 400 patterns
    {
        "status": 400,
        "body_pattern": "",
        "action": FixAction.SKIP_SLOT,
        "diagnosis": "HTTP 400 with empty body — URL path malformed or slot credentials invalid",
        "confidence": 0.95,
    },
    {
        "status": 400,
        "body_pattern": "model",
        "action": FixAction.SWITCH_MODEL,
        "diagnosis": "HTTP 400 with 'model' in body — model ID not available on this account",
        "confidence": 0.85,
    },
    {
        "status": 400,
        "body_pattern": "payload",
        "action": FixAction.RETRY_WITH_BACKOFF,
        "diagnosis": "HTTP 400 with 'payload' in body — malformed request, retry may help",
        "confidence": 0.6,
    },
    # HTTP 401 patterns
    {
        "status": 401,
        "body_pattern": "",
        "action": FixAction.SKIP_SLOT,
        "diagnosis": "HTTP 401 — invalid/expired API key, skip this slot",
        "confidence": 0.95,
    },
    {
        "status": 401,
        "body_pattern": "invalid",
        "action": FixAction.SKIP_SLOT,
        "diagnosis": "HTTP 401 'invalid' — key rejected by provider, skip slot",
        "confidence": 0.95,
    },
    {
        "status": 401,
        "body_pattern": "expired",
        "action": FixAction.ROTATE_KEY,
        "diagnosis": "HTTP 401 'expired' — key has expired, rotate to next slot",
        "confidence": 0.9,
    },
    # HTTP 403 patterns
    {
        "status": 403,
        "body_pattern": "error code: 1010",
        "action": FixAction.RETRY_WITH_BACKOFF,
        "diagnosis": "HTTP 403 Cloudflare bot protection — retry with backoff",
        "confidence": 0.8,
    },
    {
        "status": 403,
        "body_pattern": "",
        "action": FixAction.SKIP_SLOT,
        "diagnosis": "HTTP 403 — insufficient permissions, skip this slot",
        "confidence": 0.9,
    },
    # HTTP 429 patterns
    {
        "status": 429,
        "body_pattern": "",
        "action": FixAction.RETRY_WITH_BACKOFF,
        "diagnosis": "HTTP 429 — rate limited, retry with backoff",
        "confidence": 0.95,
    },
    # HTTP 5xx patterns
    {
        "status": 500,
        "body_pattern": "",
        "action": FixAction.RETRY_WITH_BACKOFF,
        "diagnosis": "HTTP 500 — server error, retry with backoff",
        "confidence": 0.85,
    },
    {
        "status": 502,
        "body_pattern": "",
        "action": FixAction.RETRY_WITH_BACKOFF,
        "diagnosis": "HTTP 502 — bad gateway, retry with backoff",
        "confidence": 0.85,
    },
    {
        "status": 503,
        "body_pattern": "",
        "action": FixAction.RETRY_WITH_BACKOFF,
        "diagnosis": "HTTP 503 — service unavailable, retry with backoff",
        "confidence": 0.85,
    },
]


# ═══════════════════════════════════════════════════════════════════════════
# AUTO-DEBUGGER CLASS
# ═══════════════════════════════════════════════════════════════════════════

class AutoDebugger:
    """Automatic diagnostic and fix recommendation engine.

    Analyzes provider errors and recommends specific FixActions
    to resolve them. Designed for integration into provider retry
    loops to enable self-healing behavior.

    Usage:
        debugger = AutoDebugger()
        result = debugger.diagnose_and_fix(
            error=exception,
            provider_name="CF-AI-GW",
            slot_index=5,
            model="@cf/meta/llama-3.1-8b-instruct",
        )
        if result.action == FixAction.SKIP_SLOT:
            # Permanently skip this slot
            ...
        elif result.action == FixAction.RETRY_WITH_BACKOFF:
            # Retry with computed delay
            delay = debugger.compute_backoff(attempt)
            ...

    INTEGRATION WITH ANTI-CENSORSHIP:
        When the auto-debugger detects DPI-related errors (403, 407, 451,
        Persian filtering keywords), it can recommend transport switching
        via the AntiCensorshipEngine.
    """

    def __init__(self) -> None:
        self._diagnostic_history: List[DiagnosticResult] = []
        self._slot_skip_count: Dict[int, int] = {}  # slot_index → skip count
        self._model_skip_count: Dict[str, int] = {}  # model → skip count
        self._max_history: int = 1000

    def diagnose_and_fix(
        self,
        error: Optional[Exception] = None,
        provider_name: str = "",
        slot_index: int = 0,
        model: str = "",
        http_status: int = 0,
        error_body: str = "",
        response_text: str = "",
    ) -> DiagnosticResult:
        """Analyze an error and recommend a fix action.

        This is the main entry point for the auto-debugger. It examines
        the error details, matches against known error patterns, and
        returns a DiagnosticResult with the recommended FixAction.

        Args:
            error: The original exception (if available).
            provider_name: Name of the provider (e.g., "CF-AI-GW").
            slot_index: Slot index that caused the error.
            model: Model ID that was being used.
            http_status: HTTP status code (0 for non-HTTP errors).
            error_body: Error response body text.
            response_text: Full response text (for wrong_response diagnosis).

        Returns:
            DiagnosticResult with recommended FixAction and diagnosis.
        """
        import urllib.error

        # Extract HTTP status from error if not provided
        if http_status == 0 and isinstance(error, urllib.error.HTTPError):
            http_status = error.code
            if not error_body:
                try:
                    error_body = error.read().decode("utf-8", errors="replace")[:500]
                except Exception:
                    error_body = ""

        # Check for timeout errors
        if isinstance(error, (TimeoutError, OSError)) and http_status == 0:
            result = DiagnosticResult(
                action=FixAction.RETRY_WITH_BACKOFF,
                diagnosis=f"Timeout/network error from {provider_name} slot {slot_index}: "
                          f"retry with exponential backoff",
                provider=provider_name,
                slot_index=slot_index,
                model=model,
                http_status=0,
                error_body=error_body,
                confidence=0.8,
            )
            self._record_diagnostic(result)
            return result

        # Check for wrong response (content validation failure)
        if response_text and http_status == 200:
            result = DiagnosticResult(
                action=FixAction.RELAX_RESPONSE_VALIDATION,
                diagnosis=f"Wrong response from {provider_name} slot {slot_index}: "
                          f"model returned unexpected content, suggest relaxing validation",
                provider=provider_name,
                slot_index=slot_index,
                model=model,
                http_status=200,
                error_body=error_body,
                confidence=0.7,
                metadata={"response_text": response_text[:200]},
            )
            self._record_diagnostic(result)
            return result

        # Match against error pattern database
        best_match: Optional[Dict] = None
        best_confidence = 0.0

        for pattern in _ERROR_PATTERNS:
            if pattern["status"] != http_status:
                continue

            # Check body pattern match
            body_pattern = pattern.get("body_pattern", "")
            if body_pattern and body_pattern.lower() in error_body.lower():
                pattern_confidence = pattern["confidence"]
            elif not body_pattern and not error_body.strip():
                # Empty body matches empty pattern
                pattern_confidence = pattern["confidence"]
            elif not body_pattern:
                # No body pattern requirement — any body matches
                pattern_confidence = pattern["confidence"] * 0.8
            else:
                continue  # Body pattern doesn't match

            if pattern_confidence > best_confidence:
                best_confidence = pattern_confidence
                best_match = pattern

        if best_match:
            result = DiagnosticResult(
                action=best_match["action"],
                diagnosis=best_match["diagnosis"],
                provider=provider_name,
                slot_index=slot_index,
                model=model,
                http_status=http_status,
                error_body=error_body[:300],
                confidence=best_confidence,
            )
        else:
            # Unknown error pattern — skip and log
            result = DiagnosticResult(
                action=FixAction.SKIP_AND_LOG,
                diagnosis=f"Unknown error from {provider_name} slot {slot_index}: "
                          f"HTTP {http_status}, body='{error_body[:100]}'",
                provider=provider_name,
                slot_index=slot_index,
                model=model,
                http_status=http_status,
                error_body=error_body[:300],
                confidence=0.3,
            )

        self._record_diagnostic(result)
        logger.info(
            f"[AutoDebugger] {provider_name} slot {slot_index}: "
            f"action={result.action.name}, diagnosis={result.diagnosis}"
        )
        return result

    def compute_backoff(
        self,
        attempt: int,
        base_delay: float = 1.0,
        max_delay: float = 120.0,
        jitter: float = 2.0,
    ) -> float:
        """Compute exponential backoff delay with jitter.

        Args:
            attempt: Current attempt number (0-indexed).
            base_delay: Base delay in seconds.
            max_delay: Maximum delay cap.
            jitter: Random jitter range.

        Returns:
            Delay in seconds before next retry.
        """
        import random
        raw = base_delay * (2 ** attempt)
        jittered = raw + random.uniform(-jitter, jitter)
        return min(max(jittered, 0.1), max_delay)

    def _record_diagnostic(self, result: DiagnosticResult) -> None:
        """Record a diagnostic result for pattern analysis."""
        self._diagnostic_history.append(result)

        # Track skip counts
        if result.action == FixAction.SKIP_SLOT:
            self._slot_skip_count[result.slot_index] = (
                self._slot_skip_count.get(result.slot_index, 0) + 1
            )
        if result.action == FixAction.SWITCH_MODEL:
            self._model_skip_count[result.model] = (
                self._model_skip_count.get(result.model, 0) + 1
            )

        # Trim history if too long
        if len(self._diagnostic_history) > self._max_history:
            self._diagnostic_history = self._diagnostic_history[-self._max_history:]

    @property
    def status(self) -> Dict:
        """Return current debugger status for logging/debugging."""
        action_counts: Dict[str, int] = {}
        for r in self._diagnostic_history:
            action_name = r.action.name
            action_counts[action_name] = action_counts.get(action_name, 0) + 1

        return {
            "total_diagnostics": len(self._diagnostic_history),
            "action_counts": action_counts,
            "slot_skip_counts": dict(self._slot_skip_count),
            "model_skip_counts": dict(self._model_skip_count),
            "recent_diagnoses": [
                {
                    "provider": r.provider,
                    "slot": r.slot_index,
                    "action": r.action.name,
                    "diagnosis": r.diagnosis[:100],
                    "confidence": r.confidence,
                }
                for r in self._diagnostic_history[-10:]
            ],
        }
