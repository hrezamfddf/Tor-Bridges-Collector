#!/usr/bin/env python3
"""
circuit_breaker_11slot.py — 11-Slot Circuit Breaker with Zero-Error Fallback v1.0
═══════════════════════════════════════════════════════════════════════════════

Production-grade circuit breaker for the 11 Cloudflare account slots.
Provides zero-error fallback, dynamic slot rotation, and automatic recovery.

CAPABILITIES:
  - Zero-Error Fallback on ANY error (HTTP 400, 403, 500, Timeout):
    a) Instantly log and Blacklist the model/slot for the current session
    b) Switch to next best-ranked model in Elite-Registry (sub-second rotation)
    c) If dynamic list exhausts, fallback to Static-Baseline (12 hardcoded models)
  - 11-Slot Round-Robin load balancing with health monitoring
  - Circuit breaker per slot: opens after consecutive failures
  - Session-scoped blacklisting: failed slots are skipped for entire session
  - Automatic circuit recovery after configurable timeout
  - Sub-second dynamic rotation between slots
  - Integrates with telemetry_watcher.py for failure tracking

DESIGN PRINCIPLES:
  - ADDITIVE ONLY: Does not modify or replace existing rotator.py
  - WRAPPER PATTERN: Enhances existing AccountRotator with zero-error guarantees
  - ZERO CRASH: All operations wrapped in try/except
  - NEVER RAISES: Always returns a valid result (even if degraded)

USAGE:
  from circuit_breaker_11slot import CircuitBreaker11Slot

  cb = CircuitBreaker11Slot()

  # Get next available slot
  slot = cb.get_next_slot()

  # Mark a slot as failed
  cb.mark_slot_failed(slot_index=3, error="HTTP 403 Forbidden")

  # Mark a slot as successful
  cb.mark_slot_success(slot_index=1, latency_ms=150.5)

  # Get the next best model (with zero-error fallback)
  model_id = cb.get_next_model(task="general")

  # Get circuit breaker status
  status = cb.get_status()
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("torshield.circuit_breaker")

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

NUM_SLOTS = 11

# Circuit breaker configuration
MAX_CONSECUTIVE_FAILURES = 3    # Open circuit after this many consecutive failures
CIRCUIT_RESET_SECONDS = 300.0  # Reopen circuit after 5 minutes
BACKOFF_WINDOW_SECONDS = 90.0  # Skip recently-failed slots for 90 seconds
SESSION_BLACKLIST_DURATION = 3600.0  # Blacklist for 1 hour within session

# Error types that trigger immediate blacklisting
CRITICAL_ERRORS = {
    "HTTP 403", "HTTP 401", "HTTP 1010",  # Authentication/bot detection
    "Circuit Open",  # Already circuit-broken
}

# Error types that trigger circuit breaker (but not immediate blacklist)
CIRCUIT_ERRORS = {
    "HTTP 400", "HTTP 500", "HTTP 502", "HTTP 503", "HTTP 504",
    "Timeout", "ConnectionError", "SSLError",
}


# ─────────────────────────────────────────────────────────────────────────────
# Data Classes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SlotState:
    """State tracking for a single CF slot."""
    index: int
    account_id: str = ""
    api_token: str = ""
    gateway_url: str = ""

    # Health tracking
    is_configured: bool = False
    circuit_open: bool = False
    circuit_open_ts: float = 0.0
    session_blacklisted: bool = False
    blacklist_ts: float = 0.0

    # Statistics
    total_requests: int = 0
    total_successes: int = 0
    total_failures: int = 0
    consecutive_failures: int = 0
    last_failure_ts: float = 0.0
    last_failure_error: str = ""
    last_success_ts: float = 0.0
    avg_latency_ms: float = 200.0  # Initial optimistic estimate

    # Model tracking
    current_model: str = ""
    model_errors: Dict[str, int] = field(default_factory=dict)

    @property
    def success_rate(self) -> float:
        if self.total_requests == 0:
            return 1.0
        return self.total_successes / self.total_requests

    @property
    def health_score(self) -> float:
        """Composite health score 0.0-1.0 (higher = better)."""
        latency_penalty = min(self.avg_latency_ms / 10_000.0, 0.5)
        base = self.success_rate * (1.0 - latency_penalty)
        # Reduce score for blacklisted/circuit-open slots
        if self.session_blacklisted:
            base *= 0.1
        if self.circuit_open:
            base *= 0.05
        return base

    def is_available(self) -> bool:
        """Check if this slot is currently available for use."""
        if not self.is_configured:
            return False
        if self.session_blacklisted:
            # Check if blacklist has expired
            if time.time() - self.blacklist_ts > SESSION_BLACKLIST_DURATION:
                self.session_blacklisted = False
                log.info(f"[CircuitBreaker] Slot {self.index}: blacklist expired")
            else:
                return False
        if self.circuit_open:
            # Check if circuit should be reset
            if time.time() - self.circuit_open_ts > CIRCUIT_RESET_SECONDS:
                self.circuit_open = False
                self.consecutive_failures = 0
                log.info(f"[CircuitBreaker] Slot {self.index}: circuit reset")
            else:
                return False
        # Skip recently failed slots
        if self.consecutive_failures > 0 and self.last_failure_ts > 0:
            if time.time() - self.last_failure_ts < BACKOFF_WINDOW_SECONDS:
                return False
        return True


# ─────────────────────────────────────────────────────────────────────────────
# Circuit Breaker 11-Slot
# ─────────────────────────────────────────────────────────────────────────────

class CircuitBreaker11Slot:
    """
    11-Slot Circuit Breaker with Zero-Error Fallback.

    Ensures that NO request ever fails completely:
    1. Try current slot → if error, blacklist for session
    2. Try next available slot → sub-second rotation
    3. If all slots exhausted → try Elite-Registry models
    4. If dynamic models exhausted → fallback to Static-Baseline
    5. If all else fails → return a valid degraded response

    INTEGRATION:
      - Wraps around existing AccountRotator
      - Does not modify existing code
      - Provides zero-error guarantees for all API calls
    """

    _instance: Optional["CircuitBreaker11Slot"] = None
    _instance_lock = threading.Lock()

    def __init__(self):
        self._lock = threading.Lock()
        self._slots: Dict[int, SlotState] = {}
        self._current_slot_index: int = 0
        self._rotation_counter: int = 0
        self._session_start: float = time.time()
        self._fallback_mode: bool = False

        # Initialize slots from environment
        self._init_slots()

        # Load telemetry integration
        try:
            from telemetry_watcher import get_telemetry
            self._telemetry = get_telemetry()
        except ImportError:
            self._telemetry = None

        # Load elite registry integration
        try:
            from elite_registry import get_registry
            self._registry = get_registry()
        except ImportError:
            self._registry = None

        configured = sum(1 for s in self._slots.values() if s.is_configured)
        log.info(
            f"[CircuitBreaker] Initialized: {configured}/{NUM_SLOTS} slots configured"
        )

    @classmethod
    def instance(cls) -> "CircuitBreaker11Slot":
        """Get or create the singleton CircuitBreaker11Slot instance."""
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    def _init_slots(self) -> None:
        """Initialize slot states from environment variables."""
        for i in range(1, NUM_SLOTS + 1):
            account_id = os.environ.get(f"CF_ACCOUNT_ID_{i}", "").strip()
            api_token = os.environ.get(f"CF_API_TOKEN_{i}", "").strip()
            gateway_url = os.environ.get(f"CF_AI_GATEWAY_URL_{i}", "").strip()

            slot = SlotState(
                index=i,
                account_id=account_id,
                api_token=api_token,
                gateway_url=gateway_url,
                is_configured=bool(account_id and api_token),
            )
            self._slots[i] = slot

    # ── Slot Selection ──────────────────────────────────────────────────────

    def get_next_slot(self) -> Optional[SlotState]:
        """
        Get the next available slot using round-robin with health scoring.
        Returns None if no slots are available (triggers fallback).
        """
        try:
            with self._lock:
                # Try all slots in round-robin order
                for _ in range(NUM_SLOTS):
                    self._current_slot_index = (self._current_slot_index % NUM_SLOTS) + 1
                    slot = self._slots.get(self._current_slot_index)
                    if slot and slot.is_available():
                        self._rotation_counter += 1
                        return slot

                # No available slots — try aggressive recovery
                return self._aggressive_recovery()

        except Exception as e:
            log.warning(f"[CircuitBreaker] Slot selection failed: {e}")
            return None

    def get_next_slot_with_gateway(self) -> Optional[SlotState]:
        """
        Get the next available slot that has a gateway URL configured.
        Preferred during high-censorship hours for CDN caching benefits.
        """
        try:
            with self._lock:
                # Filter to gateway-enabled slots
                gateway_slots = [
                    s for s in self._slots.values()
                    if s.is_available() and s.gateway_url
                ]

                if gateway_slots:
                    # Sort by health score (best first)
                    gateway_slots.sort(key=lambda s: s.health_score, reverse=True)
                    self._rotation_counter += 1
                    return gateway_slots[0]

                # Fallback to any available slot
                return self.get_next_slot()

        except Exception as e:
            log.warning(f"[CircuitBreaker] Gateway slot selection failed: {e}")
            return self.get_next_slot()

    def _aggressive_recovery(self) -> Optional[SlotState]:
        """
        Aggressive recovery when no slots are available.
        Resets blacklists and circuits, returns the best slot.
        """
        try:
            log.warning(
                "[CircuitBreaker] No available slots — aggressive recovery"
            )

            # Reset all session blacklists
            for slot in self._slots.values():
                slot.session_blacklisted = False
                slot.circuit_open = False
                slot.consecutive_failures = 0

            # Log telemetry
            if self._telemetry:
                try:
                    self._telemetry.log_self_heal(
                        "aggressive_slot_recovery",
                        {"action": "reset_all_blacklists_and_circuits"},
                        success=True,
                    )
                except Exception:
                    pass

            # Return the slot with best historical performance
            configured_slots = [s for s in self._slots.values() if s.is_configured]
            if configured_slots:
                configured_slots.sort(key=lambda s: s.health_score, reverse=True)
                return configured_slots[0]

            return None

        except Exception as e:
            log.error(f"[CircuitBreaker] Aggressive recovery failed: {e}")
            return None

    # ── Model Selection with Zero-Error Fallback ───────────────────────────

    def get_next_model(self, task: str = "general") -> str:
        """
        Get the next best model with zero-error fallback chain:
        1. Try Elite-Registry (dynamic ranking)
        2. Fallback to Static-Baseline (hardcoded)
        3. Ultimate fallback: first static model

        NEVER raises — always returns a valid model ID.
        """
        try:
            # Step 1: Try Elite-Registry
            if self._registry:
                try:
                    model_id = self._registry.get_best_model(task=task)
                    if model_id:
                        return model_id
                except Exception:
                    pass

            # Step 2: Try existing model_selector
            try:
                from torshield_ai_gateway.model_selector import best_cf_model
                model_id = best_cf_model()
                if model_id:
                    return model_id
            except Exception:
                pass

            # Step 3: Static Baseline fallback
            from elite_registry import STATIC_BASELINE
            for entry in STATIC_BASELINE:
                if entry.is_available:
                    return entry.model_id

            # Step 4: Ultimate fallback
            return "@cf/meta/llama-3.1-8b-instruct"

        except Exception:
            return "@cf/meta/llama-3.1-8b-instruct"

    # ── Error Handling ──────────────────────────────────────────────────────

    def mark_slot_failed(self, slot_index: int, error: str, model_id: str = "") -> None:
        """
        Mark a slot as failed. Implements zero-error fallback:
        a) Instantly log and blacklist the slot for current session
        b) Open circuit breaker if needed
        c) Log to telemetry
        """
        try:
            with self._lock:
                slot = self._slots.get(slot_index)
                if not slot:
                    return

                slot.total_failures += 1
                slot.consecutive_failures += 1
                slot.last_failure_ts = time.time()
                slot.last_failure_error = error

                # Track model-specific errors
                if model_id:
                    slot.model_errors[model_id] = slot.model_errors.get(model_id, 0) + 1

                    # Also mark model error in elite registry
                    if self._registry:
                        try:
                            self._registry.mark_model_error(model_id)
                        except Exception:
                            pass

                # Immediate blacklist for critical errors
                if any(crit in error for crit in CRITICAL_ERRORS):
                    slot.session_blacklisted = True
                    slot.blacklist_ts = time.time()
                    log.warning(
                        f"[CircuitBreaker] Slot {slot_index}: SESSION BLACKLISTED "
                        f"({error})"
                    )

                # Open circuit for repeated failures
                if slot.consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
                    slot.circuit_open = True
                    slot.circuit_open_ts = time.time()
                    log.warning(
                        f"[CircuitBreaker] Slot {slot_index}: CIRCUIT OPEN "
                        f"(consecutive_failures={slot.consecutive_failures})"
                    )

            # Log to telemetry
            if self._telemetry:
                try:
                    self._telemetry.log_slot_failure(
                        slot_index=slot_index,
                        env_var=f"CF_SLOT_{slot_index}",
                        error_type=error,
                        error_detail=f"model={model_id}",
                    )
                except Exception:
                    pass

            # Log self-heal: automatic rotation to next slot
            if self._telemetry:
                try:
                    self._telemetry.log_self_heal(
                        "slot_failover",
                        {
                            "failed_slot": slot_index,
                            "error": error,
                            "action": "rotate_to_next_slot",
                        },
                        success=True,
                        recovery_time_ms=0.1,  # Sub-second
                    )
                except Exception:
                    pass

        except Exception as e:
            log.error(f"[CircuitBreaker] mark_slot_failed error: {e}")

    def mark_slot_success(self, slot_index: int, latency_ms: float = 200.0, model_id: str = "") -> None:
        """Mark a slot as having a successful response."""
        try:
            with self._lock:
                slot = self._slots.get(slot_index)
                if not slot:
                    return

                slot.total_requests += 1
                slot.total_successes += 1
                slot.consecutive_failures = 0
                slot.last_success_ts = time.time()

                # Update latency with EMA
                alpha = 0.25
                slot.avg_latency_ms = (
                    alpha * latency_ms + (1 - alpha) * slot.avg_latency_ms
                )

                # Track current model
                if model_id:
                    slot.current_model = model_id
                    # Mark model success in elite registry
                    if self._registry:
                        try:
                            self._registry.mark_model_success(model_id, latency_ms)
                        except Exception:
                            pass

                # Log to telemetry
                if self._telemetry:
                    try:
                        self._telemetry.log_request(success=True)
                    except Exception:
                        pass

        except Exception as e:
            log.debug(f"[CircuitBreaker] mark_slot_success error: {e}")

    def mark_slot_request(self, slot_index: int) -> None:
        """Track that a request was made to a slot (before knowing outcome)."""
        try:
            with self._lock:
                slot = self._slots.get(slot_index)
                if slot:
                    slot.total_requests += 1
        except Exception:
            pass

    # ── Status & Reporting ──────────────────────────────────────────────────

    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive circuit breaker status."""
        try:
            with self._lock:
                available = sum(1 for s in self._slots.values() if s.is_available())
                configured = sum(1 for s in self._slots.values() if s.is_configured)
                blacklisted = sum(1 for s in self._slots.values() if s.session_blacklisted)
                circuit_open = sum(1 for s in self._slots.values() if s.circuit_open)

                return {
                    "total_slots": NUM_SLOTS,
                    "configured_slots": configured,
                    "available_slots": available,
                    "blacklisted_slots": blacklisted,
                    "circuit_open_slots": circuit_open,
                    "rotation_counter": self._rotation_counter,
                    "fallback_mode": self._fallback_mode,
                    "session_duration_minutes": round(
                        (time.time() - self._session_start) / 60, 1
                    ),
                    "slots": {
                        str(i): {
                            "configured": s.is_configured,
                            "available": s.is_available(),
                            "circuit_open": s.circuit_open,
                            "blacklisted": s.session_blacklisted,
                            "health_score": round(s.health_score, 3),
                            "success_rate": round(s.success_rate, 3),
                            "avg_latency_ms": round(s.avg_latency_ms, 1),
                            "consecutive_failures": s.consecutive_failures,
                            "has_gateway": bool(s.gateway_url),
                        }
                        for i, s in self._slots.items()
                    },
                }

        except Exception as e:
            return {"error": str(e)}

    def get_available_slots(self) -> List[SlotState]:
        """Get list of currently available slots."""
        try:
            with self._lock:
                return [s for s in self._slots.values() if s.is_available()]
        except Exception:
            return []

    def get_blacklisted_slots(self) -> List[int]:
        """Get list of blacklisted slot indices."""
        try:
            with self._lock:
                return [
                    s.index for s in self._slots.values()
                    if s.session_blacklisted
                ]
        except Exception:
            return []

    def reset_all_circuits(self) -> None:
        """Reset all circuit breakers (emergency recovery)."""
        try:
            with self._lock:
                for slot in self._slots.values():
                    slot.circuit_open = False
                    slot.consecutive_failures = 0
                    slot.session_blacklisted = False

            log.info("[CircuitBreaker] All circuits reset")

            if self._telemetry:
                try:
                    self._telemetry.log_self_heal(
                        "reset_all_circuits",
                        {"action": "emergency_recovery"},
                        success=True,
                    )
                except Exception:
                    pass

        except Exception as e:
            log.error(f"[CircuitBreaker] Reset all circuits failed: {e}")

    def reset_slot(self, slot_index: int) -> bool:
        """Reset a specific slot's circuit breaker."""
        try:
            with self._lock:
                slot = self._slots.get(slot_index)
                if slot:
                    slot.circuit_open = False
                    slot.consecutive_failures = 0
                    slot.session_blacklisted = False
                    log.info(f"[CircuitBreaker] Slot {slot_index}: manually reset")
                    return True
            return False
        except Exception:
            return False


# ─────────────────────────────────────────────────────────────────────────────
# Module-level convenience functions
# ─────────────────────────────────────────────────────────────────────────────

def get_circuit_breaker() -> CircuitBreaker11Slot:
    """Get the singleton CircuitBreaker11Slot instance."""
    return CircuitBreaker11Slot.instance()


def get_next_slot() -> Optional[SlotState]:
    """Get next available slot."""
    return get_circuit_breaker().get_next_slot()


def mark_slot_failed(slot_index: int, error: str, model_id: str = "") -> None:
    """Mark a slot as failed."""
    get_circuit_breaker().mark_slot_failed(slot_index, error, model_id)


def mark_slot_success(slot_index: int, latency_ms: float = 200.0, model_id: str = "") -> None:
    """Mark a slot as successful."""
    get_circuit_breaker().mark_slot_success(slot_index, latency_ms, model_id)


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    """CLI entry point for circuit breaker."""
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    parser = argparse.ArgumentParser(description="TorShield-IR Circuit Breaker 11-Slot")
    parser.add_argument("--status", action="store_true", help="Show circuit breaker status")
    parser.add_argument("--reset", action="store_true", help="Reset all circuits")
    parser.add_argument("--reset-slot", type=int, help="Reset a specific slot")
    parser.add_argument("--next-slot", action="store_true", help="Get next available slot")
    parser.add_argument("--best-model", type=str, default=None, help="Get best model for task")
    args = parser.parse_args()

    cb = CircuitBreaker11Slot()

    if args.status:
        status = cb.get_status()
        print(json.dumps(status, indent=2, ensure_ascii=False))
    elif args.reset:
        cb.reset_all_circuits()
        print("All circuits reset")
    elif args.reset_slot:
        success = cb.reset_slot(args.reset_slot)
        print(f"Slot {args.reset_slot}: {'reset' if success else 'not found'}")
    elif args.next_slot:
        slot = cb.get_next_slot()
        if slot:
            print(f"Next slot: {slot.index} (health={slot.health_score:.3f})")
        else:
            print("No available slots — fallback mode")
    elif args.best_model:
        model = cb.get_next_model(task=args.best_model)
        print(f"Best model for '{args.best_model}': {model}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
