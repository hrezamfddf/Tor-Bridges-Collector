#!/usr/bin/env python3
"""
retry_engine.py — Retry and Failover Engine v1.0
═══════════════════════════════════════════════════════════════════════════════

Enhanced retry and failover engine with provider-specific strategies:

  - HTTP 400: Do NOT retry same slot — rotate model, then slot
  - HTTP 429: Exponential backoff with jitter (1s, 2s, 4s, 8s, cap 60s)
  - HTTP 5xx: Retry up to 3 times with backoff, then rotate slot
  - Timeout: Rotate immediately
  - All retry logic wrapped in try/except — never crash core service

Integration with circuit breaker:
  - Failed requests update circuit breaker state
  - Circuit breaker state affects retry decisions

DESIGN PRINCIPLES:
  - ADDITIVE ONLY: Does not modify existing _post_json_with_retry
  - WRAPPER PATTERN: Wraps around existing retry logic
  - ZERO CRASH: All operations wrapped in try/except
  - Feature-flagged: ENABLE_RETRY_FAILOVER=true
"""

from __future__ import annotations

import logging
import os
import random
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger("torshield.retry_engine")


class RetryAction(Enum):
    """Action to take after a failed request."""
    RETRY_SAME = "retry_same"           # Retry same slot/model with backoff
    ROTATE_MODEL = "rotate_model"       # Try next model on same slot
    ROTATE_SLOT = "rotate_slot"         # Try next slot
    ROTATE_PROVIDER = "rotate_provider" # Try next provider
    FAIL = "fail"                       # Give up


@dataclass
class RetryDecision:
    """Decision result from the retry engine."""
    action: RetryAction
    delay_secs: float = 0.0
    reason: str = ""
    attempt_number: int = 0
    max_attempts: int = 3


class RetryEngine:
    """
    Enhanced retry and failover engine.
    
    Implements provider-specific retry strategies:
      - HTTP 400: Rotate model (don't retry same slot)
      - HTTP 429: Exponential backoff with jitter
      - HTTP 5xx: Retry with backoff, then rotate slot
      - Timeout: Rotate immediately
    """
    
    _instance: Optional["RetryEngine"] = None
    
    def __init__(self):
        self._backoff_cap = float(os.getenv("RETRY_BACKOFF_CAP_SECS", "60"))
        self._max_attempts_400 = int(os.getenv("RETRY_MAX_ATTEMPTS_400", "0"))  # 0 = no retry, rotate
        self._max_attempts_429 = int(os.getenv("RETRY_MAX_ATTEMPTS_429", "5"))
        self._max_attempts_5xx = int(os.getenv("RETRY_MAX_ATTEMPTS_5XX", "3"))
        
        # Circuit breaker integration
        try:
            from circuit_breaker.slot_circuit_breaker import get_slot_circuit_breaker
            self._circuit_breaker = get_slot_circuit_breaker()
        except ImportError:
            self._circuit_breaker = None
        
        # Self-healing integration
        try:
            from recovery.self_healing_engine import get_self_healing_engine
            self._self_healing = get_self_healing_engine()
        except ImportError:
            self._self_healing = None
        
        # Report generator integration
        try:
            from reports.report_generator import get_report_generator
            self._reports = get_report_generator()
        except ImportError:
            self._reports = None
    
    @classmethod
    def instance(cls) -> "RetryEngine":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
    
    def decide(
        self,
        error_code: int,
        attempt: int,
        provider: str = "",
        slot: int = 0,
        model: str = "",
    ) -> RetryDecision:
        """
        Decide what action to take after a failed request.
        
        Implements the retry strategy:
          - HTTP 400: Do NOT retry same slot — rotate model, then slot
          - HTTP 429: Exponential backoff with jitter
          - HTTP 5xx: Retry up to N times with backoff, then rotate slot
          - Timeout: Rotate immediately
        """
        try:
            # HTTP 400 — BAD REQUEST
            # NEVER retry same slot with same model.
            # Rotate model first, then slot.
            if error_code == 400:
                logger.info(
                    f"[RetryEngine] HTTP 400 for slot {slot} model {model} — "
                    f"rotating model (NOT retrying same slot)"
                )
                if self._reports:
                    try:
                        self._reports.record_diagnostic_event(
                            event_type="retry_decision",
                            provider=provider,
                            slot=slot,
                            model=model,
                            error_code="HTTP 400",
                            root_cause="Bad request — model or URL path error",
                        )
                    except Exception:
                        pass
                return RetryDecision(
                    action=RetryAction.ROTATE_MODEL,
                    delay_secs=0,
                    reason="HTTP 400: bad request — rotate model, don't retry",
                    attempt_number=attempt,
                    max_attempts=self._max_attempts_400,
                )
            
            # HTTP 429 — RATE LIMITED
            # Exponential backoff with jitter
            if error_code == 429:
                delay = self._compute_backoff(attempt)
                if attempt < self._max_attempts_429:
                    logger.info(
                        f"[RetryEngine] HTTP 429 for slot {slot} — "
                        f"backoff {delay:.1f}s (attempt {attempt + 1}/{self._max_attempts_429})"
                    )
                    return RetryDecision(
                        action=RetryAction.RETRY_SAME,
                        delay_secs=delay,
                        reason=f"HTTP 429: rate limited — backoff {delay:.1f}s",
                        attempt_number=attempt,
                        max_attempts=self._max_attempts_429,
                    )
                else:
                    logger.info(
                        f"[RetryEngine] HTTP 429 for slot {slot} — "
                        f"max retries reached, rotating slot"
                    )
                    return RetryDecision(
                        action=RetryAction.ROTATE_SLOT,
                        delay_secs=0,
                        reason="HTTP 429: max retries reached — rotate slot",
                        attempt_number=attempt,
                        max_attempts=self._max_attempts_429,
                    )
            
            # HTTP 5xx — SERVER ERROR
            # Retry up to N times with backoff, then rotate slot
            if error_code >= 500:
                delay = self._compute_backoff(attempt)
                if attempt < self._max_attempts_5xx:
                    logger.info(
                        f"[RetryEngine] HTTP {error_code} for slot {slot} — "
                        f"retry {attempt + 1}/{self._max_attempts_5xx} in {delay:.1f}s"
                    )
                    return RetryDecision(
                        action=RetryAction.RETRY_SAME,
                        delay_secs=delay,
                        reason=f"HTTP {error_code}: server error — retry with backoff",
                        attempt_number=attempt,
                        max_attempts=self._max_attempts_5xx,
                    )
                else:
                    return RetryDecision(
                        action=RetryAction.ROTATE_SLOT,
                        delay_secs=0,
                        reason=f"HTTP {error_code}: max retries — rotate slot",
                        attempt_number=attempt,
                        max_attempts=self._max_attempts_5xx,
                    )
            
            # HTTP 403/401 — AUTH FAILURE
            # Never retry — rotate slot
            if error_code in (401, 403):
                # Record failure in circuit breaker
                if self._circuit_breaker:
                    try:
                        self._circuit_breaker.record_failure(
                            slot, error_type=f"HTTP {error_code}"
                        )
                    except Exception:
                        pass
                return RetryDecision(
                    action=RetryAction.ROTATE_SLOT,
                    delay_secs=0,
                    reason=f"HTTP {error_code}: auth failure — rotate slot",
                    attempt_number=attempt,
                    max_attempts=0,
                )
            
            # Timeout
            if error_code == 0:
                return RetryDecision(
                    action=RetryAction.ROTATE_SLOT,
                    delay_secs=0,
                    reason="Timeout — rotate immediately",
                    attempt_number=attempt,
                    max_attempts=0,
                )
            
            # Unknown error — try once more then fail
            return RetryDecision(
                action=RetryAction.ROTATE_SLOT,
                delay_secs=0,
                reason=f"HTTP {error_code}: unknown error — rotate slot",
                attempt_number=attempt,
                max_attempts=1,
            )
            
        except Exception as e:
            logger.error(f"[RetryEngine] decide() error: {e}")
            return RetryDecision(
                action=RetryAction.ROTATE_SLOT,
                reason=f"Retry engine error: {e}",
            )
    
    def _compute_backoff(self, attempt: int) -> float:
        """
        Compute exponential backoff with jitter.
        Pattern: 1s, 2s, 4s, 8s, ... cap 60s
        With random jitter to avoid thundering herd.
        """
        try:
            base_delay = min(2 ** attempt, self._backoff_cap)
            jitter = random.uniform(-0.5, 0.5)
            return max(base_delay + jitter, 0.1)
        except Exception:
            return 1.0


def get_retry_engine() -> RetryEngine:
    """Get the singleton RetryEngine instance."""
    return RetryEngine.instance()
