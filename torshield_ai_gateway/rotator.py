"""
AccountRotator v8.0 — production-grade multi-slot rotation with advanced features:

  • Deterministic primary selection via GITHUB_RUN_ID hash
  • Circuit-breaker: auto-skip slots that recently failed (configurable window)
  • Latency tracking: exponential moving average per slot
  • Health scoring: success-rate + latency composite score
  • Weighted selection: prefer lower-latency, higher-reliability slots
  • Graceful degradation: resets all failures when no slots are available
  • Zero dependency on CF_GATEWAY_SLUG — uses full CF_AI_GATEWAY_URL_{i} instead

REMOVED in v8.0:
  - CF_GATEWAY_SLUG_{i} pattern (replaced by CF_AI_GATEWAY_URL_{i})
  - build_rotator_from_env gateway_slug field
"""

import os
import hashlib
import time
import math
import logging
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger("torshield.ai.rotator")

# ── Constants ──────────────────────────────────────────────────────────────────
BACKOFF_WINDOW      = 90.0    # seconds to skip a failed slot
LATENCY_EMA_ALPHA   = 0.25    # EMA smoothing factor (0=ignore new, 1=only new)
MAX_CONSECUTIVE_ERR = 3       # open circuit after this many consecutive errors
CIRCUIT_RESET_SEC   = 180.0   # reopen circuit after this many seconds


@dataclass
class AccountSlot:
    index:           int
    account_id:      str
    api_key:         str
    gateway_url:     str  = ""   # full URL, e.g. https://gateway.ai.cloudflare.com/v1/ACC/SLUG
    extra:           dict = field(default_factory=dict)

    # ── runtime health state ───────────────────────────────────────────────────
    failures:            int   = 0
    consecutive_errors:  int   = 0
    last_failure_ts:     float = 0.0
    total_requests:      int   = 0
    total_successes:     int   = 0
    avg_latency_ms:      float = 200.0   # initial optimistic estimate

    # ── circuit-breaker state ──────────────────────────────────────────────────
    circuit_open:        bool  = False
    circuit_open_ts:     float = 0.0

    @property
    def success_rate(self) -> float:
        if self.total_requests == 0:
            return 1.0
        return self.total_successes / self.total_requests

    @property
    def health_score(self) -> float:
        """
        Composite score 0.0–1.0 (higher = better slot to use).
        Formula: success_rate * (1 - latency_penalty)
        latency_penalty = clamp(avg_latency_ms / 10000, 0, 0.5)
        """
        latency_penalty = min(self.avg_latency_ms / 10_000.0, 0.5)
        return self.success_rate * (1.0 - latency_penalty)

    def record_latency(self, latency_ms: float) -> None:
        """Exponential moving average update."""
        self.avg_latency_ms = (
            LATENCY_EMA_ALPHA * latency_ms
            + (1.0 - LATENCY_EMA_ALPHA) * self.avg_latency_ms
        )

    def is_circuit_open(self) -> bool:
        if not self.circuit_open:
            return False
        if (time.time() - self.circuit_open_ts) > CIRCUIT_RESET_SEC:
            logger.info(f"[Rotator] Slot {self.index}: circuit reset after timeout")
            self.circuit_open = False
            self.consecutive_errors = 0
            return False
        return True

    def open_circuit(self) -> None:
        self.circuit_open = True
        self.circuit_open_ts = time.time()
        logger.warning(
            f"[Rotator] Slot {self.index}: circuit OPEN "
            f"(consecutive_errors={self.consecutive_errors})"
        )


class AccountRotator:
    """
    Rotates across multiple free-tier account slots for a single provider.

    Selection strategy (in order):
      1. Exclude circuit-open slots
      2. Exclude recently-failed slots (within BACKOFF_WINDOW)
      3. Among remaining: weighted-random by health_score
      4. If all slots unavailable: reset failures and retry (graceful degradation)
    """

    def __init__(self, provider_name: str, slots: List[AccountSlot]):
        self.provider_name = provider_name
        self.slots = [s for s in slots if s.api_key]
        if not self.slots:
            raise ValueError(
                f"[AccountRotator:{provider_name}] No configured slots — "
                f"check env vars for this provider"
            )

    @staticmethod
    def _run_seed() -> int:
        run_id  = os.environ.get("GITHUB_RUN_ID", str(int(time.time())))
        attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "1")
        seed    = int(
            hashlib.sha256(f"{run_id}:{attempt}".encode()).hexdigest(), 16
        )
        return seed

    def _available_slots(self) -> List[AccountSlot]:
        now = time.time()
        return [
            s for s in self.slots
            if (
                not s.is_circuit_open()
                and (
                    s.failures == 0
                    or (now - s.last_failure_ts) > BACKOFF_WINDOW
                )
            )
        ]

    def _reset_failures(self) -> None:
        for s in self.slots:
            s.failures = 0
            s.last_failure_ts = 0.0
        logger.info(
            f"[Rotator:{self.provider_name}] All failures reset (graceful degradation)"
        )

    def get_primary(self) -> AccountSlot:
        available = self._available_slots()
        if not available:
            self._reset_failures()
            available = self.slots

        # Weighted selection: probability proportional to health_score
        total_score = sum(s.health_score for s in available)
        if total_score == 0:
            total_score = len(available)
            weights = [1.0 / len(available)] * len(available)
        else:
            weights = [s.health_score / total_score for s in available]

        # Deterministic pseudo-random using run seed + cumulative weight
        seed = self._run_seed()
        threshold = (seed % 10_000) / 10_000.0
        cumulative = 0.0
        for slot, weight in zip(available, weights):
            cumulative += weight
            if threshold <= cumulative:
                return slot
        return available[-1]  # fallback to last

    def get_fallback_chain(self, exclude_index: int) -> List[AccountSlot]:
        available = self._available_slots()
        # Sort by health_score descending so best slots come first
        chain = [s for s in available if s.index != exclude_index]
        chain.sort(key=lambda s: s.health_score, reverse=True)
        return chain

    def mark_success(self, slot: AccountSlot, latency_ms: float = 200.0) -> None:
        slot.failures          = 0
        slot.consecutive_errors = 0
        slot.last_failure_ts   = 0.0
        slot.total_requests   += 1
        slot.total_successes  += 1
        slot.record_latency(latency_ms)

    def mark_failure(self, slot: AccountSlot) -> None:
        slot.failures            += 1
        slot.consecutive_errors  += 1
        slot.last_failure_ts      = time.time()
        slot.total_requests      += 1
        if slot.consecutive_errors >= MAX_CONSECUTIVE_ERR:
            slot.open_circuit()

    def status_report(self) -> List[dict]:
        return [
            {
                "index":             s.index,
                "success_rate":      round(s.success_rate, 3),
                "avg_latency_ms":    round(s.avg_latency_ms, 1),
                "health_score":      round(s.health_score, 3),
                "circuit_open":      s.circuit_open,
                "consecutive_errors": s.consecutive_errors,
                "total_requests":    s.total_requests,
            }
            for s in self.slots
        ]


def build_rotator_from_env(
    provider_name: str,
    n_accounts: int = 11,
) -> AccountRotator:
    """
    Build an AccountRotator by reading environment variables.

    Pattern (v8.0 — CF_GATEWAY_SLUG removed):
      {PROVIDER}_API_KEY_{i}       — API key for slot i
      {PROVIDER}_ACCOUNT_ID_{i}    — Account ID for slot i (optional for some providers)

    For Cloudflare specifically, gateway_url is handled in the provider class
    directly from CF_AI_GATEWAY_URL_{i} — NOT from this generic builder.

    Missing vars are silently skipped (unconfigured accounts are ignored).
    """
    prefix = provider_name.upper().replace(".", "_").replace("-", "_")
    slots  = []
    for i in range(1, n_accounts + 1):
        api_key    = os.environ.get(f"{prefix}_API_KEY_{i}", "")
        account_id = os.environ.get(f"{prefix}_ACCOUNT_ID_{i}", "")
        if api_key:
            slots.append(
                AccountSlot(
                    index=i,
                    account_id=account_id,
                    api_key=api_key,
                )
            )
    return AccountRotator(provider_name, slots)
