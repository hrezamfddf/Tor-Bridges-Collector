"""
quarantine_manager.py — FEATURE 5: Temporal Blocking Pattern Anomaly Detection.

Detects bridges that exhibit sudden spikes in blocking rate using a rolling
z-score (window = 7 days, threshold = 2σ).  Flagged bridges enter a quarantine
tier and are excluded from recommended outputs until 3 consecutive clean
measurement days are observed.

All quarantine decisions are appended as structured JSON lines to
data/quarantine_log.jsonl for full auditability.

Algorithm:
  1. For each bridge with ≥ 14 OONI data points (≥ 2 windows), compute
     daily anomaly counts over the 90-day history.
  2. Compute rolling z-score: z = (mean_recent7 − mean_historical) / std_historical
  3. If z > 2.0 → quarantine the bridge.
  4. For already-quarantined bridges: check if the last 3 daily measurements
     are all clean (anomaly = False).  If so, release from quarantine.

Public interface:
  from quarantine_manager import QuarantineManager
  qm = QuarantineManager()
  qm.update(ooni_daily_records)   # re-evaluate all bridges
  qm.is_quarantined(host)         # True / False
  qm.quarantined_set()            # set[str] of quarantined host strings
"""

from __future__ import annotations

import json
import logging
import math
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

QUARANTINE_STATE_PATH = Path("data/quarantine_state.json")
QUARANTINE_LOG_PATH   = Path("data/quarantine_log.jsonl")
ZSCORE_WINDOW         = 7    # days for the "recent" window
ZSCORE_THRESHOLD      = 2.0  # sigma
CLEAN_DAYS_TO_RELEASE = 3    # consecutive clean days required to exit quarantine

Path("data").mkdir(parents=True, exist_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
# Statistics helpers (pure Python, no scipy dependency)
# ─────────────────────────────────────────────────────────────────────────────

def _mean(values: List[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def _std(values: List[float]) -> float:
    if len(values) < 2:
        return 0.0
    m   = _mean(values)
    var = sum((x - m) ** 2 for x in values) / (len(values) - 1)
    return math.sqrt(var)


def rolling_zscore(daily_rates: List[float], window: int = ZSCORE_WINDOW) -> float:
    """
    Compute the z-score of the most recent `window` days vs. all prior days.
    Returns 0.0 when insufficient historical data is available.
    """
    if len(daily_rates) < window + 1:
        return 0.0
    recent     = daily_rates[-window:]
    historical = daily_rates[:-window]
    hist_mean  = _mean(historical)
    hist_std   = _std(historical)
    if hist_std == 0.0:
        return 0.0
    recent_mean = _mean(recent)
    return (recent_mean - hist_mean) / hist_std


# ─────────────────────────────────────────────────────────────────────────────
# Quarantine state
# ─────────────────────────────────────────────────────────────────────────────

class QuarantineManager:
    """
    Manages the bridge quarantine tier.

    State file schema (data/quarantine_state.json):
    {
      "1.2.3.4": {
        "quarantined_at": "ISO-8601",
        "z_score": 3.14,
        "consecutive_clean": 0
      },
      ...
    }
    """

    def __init__(self) -> None:
        self._state: Dict[str, Dict[str, Any]] = self._load_state()

    # ── Persistence ──────────────────────────────────────────────────────────

    def _load_state(self) -> Dict[str, Dict[str, Any]]:
        if QUARANTINE_STATE_PATH.exists():
            try:
                return json.loads(QUARANTINE_STATE_PATH.read_text(encoding="utf-8"))
            except Exception as exc:
                log.warning(f"Cannot load quarantine state: {exc}")
        return {}

    def _save_state(self) -> None:
        QUARANTINE_STATE_PATH.write_text(
            json.dumps(self._state, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

    def _log_event(self, event: Dict[str, Any]) -> None:
        """Append a structured event line to quarantine_log.jsonl."""
        event["logged_at"] = datetime.now(timezone.utc).isoformat()
        with open(QUARANTINE_LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, ensure_ascii=False) + "\n")

    # ── Core operations ──────────────────────────────────────────────────────

    def quarantine(self, host: str, z_score: float, reason: str) -> None:
        if host in self._state:
            return  # already quarantined
        ts = datetime.now(timezone.utc).isoformat()
        self._state[host] = {
            "quarantined_at":    ts,
            "z_score":           round(z_score, 3),
            "consecutive_clean": 0,
            "reason":            reason,
        }
        self._save_state()
        self._log_event({
            "action":            "quarantined",
            "bridge_host":       host,
            "z_score":           round(z_score, 3),
            "reason":            reason,
            "quarantine_min_until": (
                datetime.now(timezone.utc) + timedelta(days=CLEAN_DAYS_TO_RELEASE)
            ).isoformat(),
        })
        log.warning(
            f"QUARANTINE: {host} (z={z_score:.2f}, reason={reason}). "
            f"Needs {CLEAN_DAYS_TO_RELEASE} consecutive clean days to release."
        )

    def record_clean_measurement(self, host: str) -> bool:
        """
        Increment the consecutive clean counter.  Returns True if the bridge
        has been released from quarantine.
        """
        if host not in self._state:
            return False
        self._state[host]["consecutive_clean"] = (
            self._state[host].get("consecutive_clean", 0) + 1
        )
        if self._state[host]["consecutive_clean"] >= CLEAN_DAYS_TO_RELEASE:
            return self.release(host, reason="3_consecutive_clean_days")
        self._save_state()
        return False

    def record_anomaly_measurement(self, host: str) -> None:
        """Reset the clean counter when an anomaly is observed in quarantine."""
        if host in self._state:
            self._state[host]["consecutive_clean"] = 0
            self._save_state()

    def release(self, host: str, reason: str = "manual") -> bool:
        if host not in self._state:
            return False
        entry = self._state.pop(host)
        self._save_state()
        self._log_event({
            "action":       "released",
            "bridge_host":  host,
            "reason":       reason,
            "was_quarantined_at": entry.get("quarantined_at"),
        })
        log.info(f"RELEASED from quarantine: {host} (reason={reason})")
        return True

    # ── Queries ──────────────────────────────────────────────────────────────

    def is_quarantined(self, host: str) -> bool:
        return host in self._state

    def quarantined_set(self) -> Set[str]:
        return set(self._state.keys())

    def state_snapshot(self) -> Dict[str, Dict[str, Any]]:
        return dict(self._state)

    # ── Batch update from OONI measurement history ───────────────────────────

    def update_from_ooni_history(
        self,
        bridge_daily_history: Dict[str, List[Tuple[str, bool]]],
    ) -> Dict[str, Any]:
        """
        Evaluate all bridges against the rolling z-score anomaly detector.

        bridge_daily_history: {host: [(date_str, is_anomaly), ...]}
          date_str in 'YYYY-MM-DD' format, sorted ascending.

        Returns a summary dict.
        """
        newly_quarantined = []
        released          = []
        clean_incremented = []

        for host, daily in bridge_daily_history.items():
            if not daily:
                continue

            # Build daily anomaly rate series (0.0 or 1.0 per day)
            rates: List[float] = [1.0 if anomaly else 0.0 for _, anomaly in daily]

            z = rolling_zscore(rates, window=ZSCORE_WINDOW)

            latest_is_anomaly = daily[-1][1] if daily else False

            if z > ZSCORE_THRESHOLD and not self.is_quarantined(host):
                self.quarantine(host, z_score=z, reason="anomaly_spike")
                newly_quarantined.append(host)

            elif self.is_quarantined(host):
                if latest_is_anomaly:
                    self.record_anomaly_measurement(host)
                else:
                    released_now = self.record_clean_measurement(host)
                    if released_now:
                        released.append(host)
                    else:
                        clean_incremented.append(host)

        summary = {
            "evaluated":          len(bridge_daily_history),
            "currently_quarantined": len(self._state),
            "newly_quarantined":  len(newly_quarantined),
            "released":           len(released),
            "hosts_quarantined":  list(self._state.keys()),
        }
        log.info(
            f"Quarantine update: {summary['newly_quarantined']} new, "
            f"{summary['released']} released, "
            f"{summary['currently_quarantined']} total quarantined."
        )
        return summary
