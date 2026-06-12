"""
core/dt_utils.py — Timezone-safe datetime utilities for TorShield-IR.

Root cause of the TypeError:
  datetime.utcnow()         → naive  datetime (no tzinfo)
  datetime.fromisoformat()  → aware  datetime when the ISO string has "+00:00"
  Python raises TypeError when comparing naive vs aware datetimes.

Fix applied everywhere: always work in UTC-aware datetimes.
  utc_now()    replaces  datetime.utcnow()
  parse_dt()   replaces  datetime.fromisoformat() in comparisons
"""

from __future__ import annotations
from datetime import datetime, timezone


def utc_now() -> datetime:
    """Return the current time as a UTC-aware datetime."""
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string with +00:00 suffix."""
    return utc_now().isoformat()


def parse_dt(s: str) -> datetime:
    """
    Parse an ISO-8601 datetime string and always return a UTC-aware datetime.

    Handles both formats stored in bridge_history.json:
      • Naive   — "2026-06-05T07:45:38"        (old records, assume UTC)
      • Aware   — "2026-06-05T07:45:38+00:00"  (new records, keep as-is)
    """
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        # Malformed string — return Unix epoch so comparisons still work
        return datetime(1970, 1, 1, tzinfo=timezone.utc)

    if dt.tzinfo is None:
        # Naive datetime — the codebase always stored UTC, so attach UTC.
        dt = dt.replace(tzinfo=timezone.utc)
    return dt
