"""
core/history.py — Bridge history and persistence manager.

Stores first-seen date, last-seen date, test results, and Iran scores
for every bridge seen across all collection runs.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import timedelta
from pathlib import Path
from typing import Any, Dict, Optional

import config
from core.dt_utils import parse_dt, utc_now, utc_now_iso

log = logging.getLogger(__name__)


class HistoryManager:
    """Manages the on-disk bridge history database (bridge_history.json)."""

    def __init__(self):
        self._db: Dict[str, Dict[str, Any]] = {}
        os.makedirs(config.BRIDGE_DIR, exist_ok=True)
        os.makedirs(config.EXPORT_DIR, exist_ok=True)
        self._load()

    # ─────────────────────────────────────────────
    # Load / Save
    # ─────────────────────────────────────────────

    def _load(self) -> None:
        path = config.HISTORY_FILE
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    self._db = json.load(f)
                log.info(f"Loaded {len(self._db)} bridges from history.")
            except Exception as e:
                log.warning(f"Could not load history: {e}. Starting fresh.")
                self._db = {}

    def save(self) -> None:
        path = config.HISTORY_FILE
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self._db, f, indent=2, ensure_ascii=False)
            log.debug(f"History saved ({len(self._db)} entries).")
        except Exception as e:
            log.error(f"Failed to save history: {e}")

    # ─────────────────────────────────────────────
    # Normalisation helpers
    # ─────────────────────────────────────────────

    @staticmethod
    def _normalize_key(line: str) -> str:
        """Return a canonical key for deduplication."""
        line = line.strip()
        if line.startswith("Bridge "):
            line = line[7:]
        return line.lower()

    # ─────────────────────────────────────────────
    # Mutation
    # ─────────────────────────────────────────────

    def add_bridge(self, line: str, transport: str = "unknown") -> None:
        """Register a bridge as newly seen (or update last_seen)."""
        key = self._normalize_key(line)
        if not key:
            return
        now = utc_now_iso()          # ← always UTC-aware ISO string
        if key not in self._db:
            self._db[key] = {
                "raw":        line.strip(),
                "transport":  transport,
                "first_seen": now,
                "last_seen":  now,
                "test_pass":  None,
                "test_time":  None,
                "latency_ms": None,
                "score":      0,
            }
        else:
            self._db[key]["last_seen"] = now
            self._db[key]["raw"] = line.strip()

    def update_test(self, line: str, passed: bool, latency_ms: Optional[int] = None) -> None:
        """Record the result of a connectivity test."""
        key = self._normalize_key(line)
        if key in self._db:
            self._db[key]["test_pass"] = passed
            self._db[key]["test_time"] = utc_now_iso()   # ← UTC-aware
            if latency_ms is not None:
                self._db[key]["latency_ms"] = latency_ms

    def update_score(self, line: str, score: int) -> None:
        key = self._normalize_key(line)
        if key in self._db:
            self._db[key]["score"] = score

    # ─────────────────────────────────────────────
    # Queries
    # ─────────────────────────────────────────────

    def get_all(self) -> Dict[str, Dict[str, Any]]:
        return self._db

    def get_by_transport(self, transport: str) -> list[Dict[str, Any]]:
        t = transport.lower()
        return [v for v in self._db.values() if v.get("transport", "").lower() == t]

    def get_recent(self, hours: int = 72) -> list[Dict[str, Any]]:
        cutoff = utc_now() - timedelta(hours=hours)   # ← UTC-aware
        result = []
        for v in self._db.values():
            try:
                if parse_dt(v["first_seen"]) > cutoff:   # ← both UTC-aware
                    result.append(v)
            except (KeyError, ValueError):
                pass
        return result

    def get_tested(self, passed: bool = True) -> list[Dict[str, Any]]:
        return [v for v in self._db.values() if v.get("test_pass") == passed]

    def get_stats(self) -> Dict[str, Any]:
        total    = len(self._db)
        tested   = sum(1 for v in self._db.values() if v.get("test_pass") is not None)
        passing  = sum(1 for v in self._db.values() if v.get("test_pass") is True)
        by_transport: Dict[str, int] = {}
        for v in self._db.values():
            t = v.get("transport", "unknown")
            by_transport[t] = by_transport.get(t, 0) + 1
        return {
            "total":        total,
            "tested":       tested,
            "passing":      passing,
            "by_transport": by_transport,
            "updated":      utc_now_iso(),   # ← UTC-aware
        }

    # ─────────────────────────────────────────────
    # Cleanup
    # ─────────────────────────────────────────────

    def purge_old(self, days: int = None) -> int:
        days   = days or config.HISTORY_RETENTION_DAYS
        cutoff = utc_now() - timedelta(days=days)   # ← UTC-aware
        before = len(self._db)
        self._db = {
            k: v for k, v in self._db.items()
            if parse_dt(v.get("last_seen", "2000-01-01")) > cutoff  # ← safe parse
        }
        removed = before - len(self._db)
        if removed:
            log.info(f"Purged {removed} stale bridges (older than {days} days).")
        return removed
