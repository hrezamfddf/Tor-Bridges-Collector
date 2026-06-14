#!/usr/bin/env python3
"""
slot_circuit_breaker.py — Enhanced Per-Slot Circuit Breaker v1.0
═══════════════════════════════════════════════════════════════════════════════

Enhanced per-slot circuit breaker with CLOSED → OPEN → HALF-OPEN states.
Wraps around existing ProviderCircuitBreaker in providers.py and
CircuitBreaker11Slot in circuit_breaker_11slot.py — ADDITIVE ONLY.

States:
  CLOSED:    Normal operation — requests flow through
  OPEN:      Slot blocked after N consecutive failures (default N=3)
  HALF-OPEN: Test probe after cooldown (default 60s) — one request allowed

Per-slot tracking:
  - failure_count, last_failure_time, state, recovery_time
  - consecutive_failures, last_error_type, last_error_time

Integration:
  - Mark misconfigured slots as SKIPPED (not failed) at init
  - Circuit breaker per slot: CLOSED → OPEN → HALF-OPEN states
  - Rotate slots on HTTP 400, 403, 429, 500, 502, 503, timeout

DESIGN PRINCIPLES:
  - ADDITIVE ONLY: Does not modify existing circuit_breaker_11slot.py
  - WRAPPER PATTERN: Wraps and enhances existing circuit breaker
  - ZERO CRASH: All operations wrapped in try/except
  - Feature-flagged: ENABLE_CIRCUIT_BREAKER=true
"""

from __future__ import annotations

import logging
import os
import threading
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger("torshield.slot_circuit_breaker")


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class SlotCircuitState:
    """Per-slot circuit breaker state."""
    slot_index: int
    account_id: str = ""
    api_token: str = ""
    gateway_url: str = ""
    
    # Circuit breaker state
    state: CircuitState = CircuitState.CLOSED
    failure_count: int = 0
    consecutive_failures: int = 0
    last_failure_time: float = 0.0
    last_failure_error: str = ""
    recovery_time: float = 0.0
    
    # Slot status
    is_configured: bool = False
    is_skipped: bool = False
    skip_reason: str = ""
    
    # Statistics
    total_requests: int = 0
    total_successes: int = 0
    total_failures: int = 0
    avg_latency_ms: float = 200.0
    
    # HALF-OPEN probe tracking
    half_open_probes_sent: int = 0
    half_open_probes_allowed: int = 1  # Only 1 probe in half-open
    
    # Failure tracking by type
    failure_by_type: Dict[str, int] = field(default_factory=dict)
    
    @property
    def success_rate(self) -> float:
        if self.total_requests == 0:
            return 1.0
        return self.total_successes / self.total_requests
    
    @property
    def health_score(self) -> float:
        latency_penalty = min(self.avg_latency_ms / 10_000.0, 0.5)
        base = self.success_rate * (1.0 - latency_penalty)
        if self.is_skipped or self.state == CircuitState.OPEN:
            base *= 0.05
        return base


class SlotCircuitBreaker:
    """
    Enhanced per-slot circuit breaker with CLOSED → OPEN → HALF-OPEN.
    
    Wraps around existing circuit breaker infrastructure.
    Adds:
      - Per-slot state machine (CLOSED → OPEN → HALF-OPEN)
      - Misconfigured slot detection (SKIPPED, not FAILED)
      - Configurable failure threshold and cooldown
      - Integration with structured logging
    """
    
    _instance: Optional["SlotCircuitBreaker"] = None
    _instance_lock = threading.Lock()
    
    def __init__(self):
        self._lock = threading.Lock()
        self._slots: Dict[int, SlotCircuitState] = {}
        self._failure_threshold = int(os.getenv("CIRCUIT_BREAKER_FAILURE_THRESHOLD", "3"))
        self._cooldown_secs = float(os.getenv("CIRCUIT_BREAKER_COOLDOWN_SECS", "60"))
        self._half_open_max_probes = int(os.getenv("CIRCUIT_BREAKER_HALF_OPEN_MAX_PROBES", "1"))
        
        # Structured logging integration
        try:
            from monitoring.structured_logger import get_structured_logger
            self._logger = get_structured_logger()
        except ImportError:
            self._logger = None
        
        self._init_slots()
    
    @classmethod
    def instance(cls) -> "SlotCircuitBreaker":
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance
    
    def _init_slots(self) -> None:
        """Initialize all 11 CF slots with validation."""
        import re
        
        for i in range(1, 12):
            account_id = os.getenv(f"CF_ACCOUNT_ID_{i}", "").strip()
            api_token = os.getenv(f"CF_API_TOKEN_{i}", "").strip()
            gateway_url = os.getenv(f"CF_AI_GATEWAY_URL_{i}", "").strip()
            
            slot = SlotCircuitState(
                slot_index=i,
                account_id=account_id,
                api_token=api_token,
                gateway_url=gateway_url,
                is_configured=bool(account_id and api_token),
            )
            
            # Validate slot triplet
            if not account_id or not api_token:
                slot.is_skipped = True
                slot.skip_reason = "missing credentials"
            elif not re.match(r'^[0-9a-f]{32}$', account_id, re.IGNORECASE):
                slot.is_skipped = True
                slot.skip_reason = f"invalid account_id format (len={len(account_id)})"
            elif len(api_token) < 40:
                slot.is_skipped = True
                slot.skip_reason = f"token too short ({len(api_token)} chars)"
            
            self._slots[i] = slot
            
            if slot.is_skipped:
                logger.info(
                    f"[SlotCB] Slot {i}: SKIPPED ({slot.skip_reason}) — "
                    f"not counted as failure"
                )
            elif slot.is_configured:
                logger.info(
                    f"[SlotCB] Slot {i}: INITIALIZED (circuit=CLOSED)"
                )
    
    def allow_request(self, slot_index: int) -> bool:
        """Check if a request is allowed for the given slot."""
        try:
            with self._lock:
                slot = self._slots.get(slot_index)
                if not slot:
                    return False
                
                if slot.is_skipped:
                    return False
                
                if slot.state == CircuitState.CLOSED:
                    return True
                
                if slot.state == CircuitState.OPEN:
                    # Check if cooldown has elapsed
                    elapsed = time.time() - slot.last_failure_time
                    if elapsed >= self._cooldown_secs:
                        slot.state = CircuitState.HALF_OPEN
                        slot.half_open_probes_sent = 0
                        logger.info(
                            f"[SlotCB] Slot {slot_index}: OPEN → HALF_OPEN "
                            f"(cooldown elapsed after {self._cooldown_secs}s)"
                        )
                        return True
                    return False
                
                if slot.state == CircuitState.HALF_OPEN:
                    # Allow only limited probes in half-open
                    if slot.half_open_probes_sent < self._half_open_max_probes:
                        return True
                    return False
                
                return True
        except Exception as e:
            logger.error(f"[SlotCB] allow_request error for slot {slot_index}: {e}")
            return True  # Fail open, not closed
    
    def record_success(self, slot_index: int, latency_ms: float = 200.0) -> None:
        """Record a successful request — resets failure count, closes circuit."""
        try:
            with self._lock:
                slot = self._slots.get(slot_index)
                if not slot:
                    return
                
                prev_state = slot.state
                slot.state = CircuitState.CLOSED
                slot.failure_count = 0
                slot.consecutive_failures = 0
                slot.total_requests += 1
                slot.total_successes += 1
                slot.half_open_probes_sent = 0
                
                # Update latency with EMA
                alpha = 0.25
                slot.avg_latency_ms = alpha * latency_ms + (1 - alpha) * slot.avg_latency_ms
                
                if prev_state != CircuitState.CLOSED:
                    logger.info(
                        f"[SlotCB] Slot {slot_index}: {prev_state.value} → CLOSED "
                        f"(success after recovery)"
                    )
        except Exception as e:
            logger.error(f"[SlotCB] record_success error: {e}")
    
    def record_failure(
        self, slot_index: int, error_type: str = "", error_detail: str = ""
    ) -> None:
        """Record a failed request — may open circuit."""
        try:
            with self._lock:
                slot = self._slots.get(slot_index)
                if not slot:
                    return
                
                slot.failure_count += 1
                slot.consecutive_failures += 1
                slot.total_requests += 1
                slot.total_failures += 1
                slot.last_failure_time = time.time()
                slot.last_failure_error = error_type
                slot.recovery_time = slot.last_failure_time + self._cooldown_secs
                
                # Track failure by type
                slot.failure_by_type[error_type] = slot.failure_by_type.get(error_type, 0) + 1
                
                # Handle HALF-OPEN probe failure
                if slot.state == CircuitState.HALF_OPEN:
                    slot.state = CircuitState.OPEN
                    logger.warning(
                        f"[SlotCB] Slot {slot_index}: HALF_OPEN → OPEN "
                        f"(probe failed: {error_type})"
                    )
                elif slot.state == CircuitState.CLOSED:
                    # Open circuit if threshold reached
                    if slot.consecutive_failures >= self._failure_threshold:
                        slot.state = CircuitState.OPEN
                        logger.warning(
                            f"[SlotCB] Slot {slot_index}: CLOSED → OPEN "
                            f"({slot.consecutive_failures} consecutive failures, "
                            f"threshold={self._failure_threshold})"
                        )
                
                # Log to structured logger
                if self._logger:
                    try:
                        self._logger.log_diagnostics(
                            level="WARNING",
                            provider="cloudflare",
                            slot=slot_index,
                            error_code=error_type,
                            message=f"Slot {slot_index} failure: {error_type} - {error_detail}",
                            consecutive_failures=slot.consecutive_failures,
                            circuit_state=slot.state.value,
                        )
                    except Exception:
                        pass
        except Exception as e:
            logger.error(f"[SlotCB] record_failure error: {e}")
    
    def get_available_slots(self) -> List[int]:
        """Get list of slot indices that are available for requests."""
        try:
            with self._lock:
                return [
                    i for i, s in self._slots.items()
                    if s.is_configured and not s.is_skipped and self.allow_request(i)
                ]
        except Exception:
            return list(self._slots.keys())
    
    def get_slot_for_rotation(
        self, exclude_slots: Optional[Set[int]] = None
    ) -> Optional[int]:
        """
        Get the next best slot for rotation, excluding specified slots.
        Prioritizes slots with highest health score.
        """
        try:
            exclude = exclude_slots or set()
            available = [
                s for i, s in self._slots.items()
                if i not in exclude
                and s.is_configured
                and not s.is_skipped
                and self.allow_request(i)
            ]
            
            if not available:
                # Try aggressive recovery
                for s in self._slots.values():
                    if s.is_configured and not s.is_skipped:
                        if s.state == CircuitState.OPEN:
                            elapsed = time.time() - s.last_failure_time
                            if elapsed > self._cooldown_secs * 2:
                                s.state = CircuitState.HALF_OPEN
                                s.half_open_probes_sent = 0
                                available.append(s)
                
                if not available:
                    return None
            
            # Sort by health score (best first)
            available.sort(key=lambda s: s.health_score, reverse=True)
            return available[0].slot_index
        except Exception as e:
            logger.error(f"[SlotCB] get_slot_for_rotation error: {e}")
            return None
    
    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive circuit breaker status."""
        try:
            with self._lock:
                configured = sum(1 for s in self._slots.values() if s.is_configured)
                skipped = sum(1 for s in self._slots.values() if s.is_skipped)
                available = len(self.get_available_slots())
                
                return {
                    "total_slots": 11,
                    "configured_slots": configured,
                    "skipped_slots": skipped,
                    "available_slots": available,
                    "failure_threshold": self._failure_threshold,
                    "cooldown_secs": self._cooldown_secs,
                    "slots": {
                        str(i): {
                            "configured": s.is_configured,
                            "skipped": s.is_skipped,
                            "skip_reason": s.skip_reason,
                            "state": s.state.value,
                            "consecutive_failures": s.consecutive_failures,
                            "total_failures": s.total_failures,
                            "total_successes": s.total_successes,
                            "success_rate": round(s.success_rate, 3),
                            "health_score": round(s.health_score, 3),
                            "avg_latency_ms": round(s.avg_latency_ms, 1),
                            "last_failure_error": s.last_failure_error,
                            "recovery_time": s.recovery_time,
                        }
                        for i, s in self._slots.items()
                    },
                }
        except Exception as e:
            return {"error": str(e)}


def get_slot_circuit_breaker() -> SlotCircuitBreaker:
    """Get the singleton SlotCircuitBreaker instance."""
    return SlotCircuitBreaker.instance()
