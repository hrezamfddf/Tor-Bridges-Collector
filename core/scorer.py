"""
core/scorer.py — Iran-aware bridge scoring engine.

Scores each bridge 0-100 based on its likelihood of working inside Iran,
especially under Deep Packet Inspection (DPI) and during internet cuts
(شبکه ملی / NIN active).

Scoring dimensions:
  Transport      0-30 pts  (snowflake best, vanilla worst)
                            → FEATURE 4: weights loaded dynamically from
                              data/transport_weights.json when available
  Port           0-20 pts  (443 best, high random ports worst)
  IP version     0-10 pts  (IPv4 preferred in Iran)
  Freshness      0-20 pts  (newer bridges less likely to be blocked)
  Test result    0-20 pts  (proven reachable earns full marks)
  CDN bonus      +10 pts   (CDN-fronted bridges survive internet cuts)
  JA3 penalty    0-15 pts  (FEATURE 2: deducted for high-risk TLS fingerprint)
"""

from __future__ import annotations

import json
import ipaddress
import logging
import re
from datetime import timedelta, timezone
from core.dt_utils import parse_dt, utc_now
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import config
from core.tester import detect_transport, extract_endpoint

log = logging.getLogger(__name__)

# Path to adaptive transport weights (written by adaptive_transport.py)
_TRANSPORT_WEIGHTS_PATH = Path("data/transport_weights.json")


class IranScorer:

    # ── Default transport scores (overridden by dynamic weights if available) ──
    _DEFAULT_TRANSPORT_SCORES: Dict[str, int] = {
        "snowflake":  30,
        "webtunnel":  28,
        "obfs4":      25,
        "meek_lite":  20,
        "vanilla":    5,
        "unknown":    8,
    }

    # ── Port scores ──────────────────────────────────────────────────────────
    _IRAN_PORT_SCORES: Dict[int, int] = {
        443:  20, 80: 15, 8080: 12, 8443: 12,
        2083: 10, 2087: 10, 2096: 10,
    }
    _PORT_SCORE_DEFAULT_LOW  = 8
    _PORT_SCORE_DEFAULT_HIGH = 4

    # ── CDN survival patterns ────────────────────────────────────────────────
    _CDN_SURVIVAL_PATTERNS = [re.compile(p, re.I) for p in [
        r'fastly\.net', r'arvancloud\.(com|ir)', r'cdn\.irimc\.ir',
        r'cloudfront\.net', r'azureedge\.net', r'aspnetcdn\.com',
        r'googlevideo\.com', r'gstatic\.com',
    ]]

    # ── JA3 max penalty (points to deduct for critical fingerprint) ──────────
    _JA3_MAX_PENALTY = 15

    def __init__(self) -> None:
        # FEATURE 4: load adaptive transport scores if available
        self.TRANSPORT_SCORES = self._load_transport_scores()
        # FEATURE 2: lazy-load JA3 intelligence
        self._ja3: Optional[Any] = None

    def _load_transport_scores(self) -> Dict[str, int]:
        """
        FEATURE 4: Load transport scores from data/transport_weights.json
        (written by adaptive_transport.py). Falls back to hardcoded defaults.
        """
        try:
            if _TRANSPORT_WEIGHTS_PATH.exists():
                data  = json.loads(_TRANSPORT_WEIGHTS_PATH.read_text())
                raw   = data.get("scores", {})
                if raw:
                    merged = dict(self._DEFAULT_TRANSPORT_SCORES)
                    for t, s in raw.items():
                        if t in merged:
                            merged[t] = int(round(s))
                    log.debug(f"Adaptive transport scores loaded: {merged}")
                    return merged
        except Exception as exc:
            log.debug(f"Could not load adaptive transport scores: {exc}")
        return dict(self._DEFAULT_TRANSPORT_SCORES)

    def _ja3_penalty(self, record: Dict[str, Any]) -> int:
        """
        FEATURE 2: Compute JA3 fingerprint DPI penalty (0–15 pts deducted).
        Uses the JA3Intel database; falls back to transport-type heuristic.
        """
        try:
            if self._ja3 is None:
                from ja3_intelligence import JA3Intel
                self._ja3 = JA3Intel()
            ja3_hash = record.get("ja3_hash", "")
            transport = record.get("transport", detect_transport(record.get("raw", "")))
            port = record.get("port") or 0
            if not isinstance(port, int):
                try:
                    port = int(port)
                except (ValueError, TypeError):
                    port = 0

            if ja3_hash:
                risk_score = self._ja3.score(ja3_hash)
            else:
                # No hash available — use transport + port as proxies
                risk_score = self._ja3.transport_default_risk(transport)
                risk_score = max(risk_score, self._ja3.port_risk(port))

            return int(round(risk_score * self._JA3_MAX_PENALTY))
        except Exception:
            return 0

    def _port_score(self, port: int) -> int:
        if port in self._IRAN_PORT_SCORES:
            return self._IRAN_PORT_SCORES[port]
        if port < 1024:
            return self._PORT_SCORE_DEFAULT_LOW
        return self._PORT_SCORE_DEFAULT_HIGH

    def _ipv_score(self, host: str) -> int:
        if not host:
            return 5
        try:
            addr = ipaddress.ip_address(host)
            return 10 if addr.version == 4 else 5
        except ValueError:
            return 10  # Domain — assume IPv4 CDN

    def _freshness_score(self, first_seen: str) -> int:
        # FIX 3: always produce timezone-aware datetime objects so that
        # the subtraction never raises "can't subtract offset-naive and
        # offset-aware datetimes" on Python 3.10+.
        try:
            ts  = parse_dt(first_seen)          # always UTC-aware via dt_utils
            age = utc_now() - ts
            if age <= timedelta(hours=24):
                return 20
            if age <= timedelta(hours=72):
                return 15
            if age <= timedelta(days=7):
                return 10
            if age <= timedelta(days=30):
                return 5
            return 2
        except Exception:
            return 5

    def _test_score(self, test_pass) -> int:
        if test_pass is True:
            return 20
        if test_pass is False:
            return 0
        return 10  # untested — neutral

    def _cdn_bonus(self, line: str) -> int:
        for pat in self._CDN_SURVIVAL_PATTERNS:
            if pat.search(line):
                return 10
        return 0

    # ─────────────────────────────────────────────────────────────────────

    def score(self, record: Dict[str, Any]) -> int:
        """
        Compute a 0-100 Iran effectiveness score for a bridge record.

        Positive dimensions: transport (adaptive) + port + IP version +
                             freshness + test result + CDN bonus
        Negative dimension:  JA3 fingerprint DPI penalty (FEATURE 2)
        """
        raw       = record.get("raw", "")
        transport = record.get("transport", detect_transport(raw))
        host, port, _ = extract_endpoint(raw)

        t_score    = self.TRANSPORT_SCORES.get(transport.lower(), 8)   # FEATURE 4
        p_score    = self._port_score(port or 0)
        ip_score   = self._ipv_score(host or "")
        f_score    = self._freshness_score(record.get("first_seen", ""))
        test_score = self._test_score(record.get("test_pass"))
        cdn_bonus  = self._cdn_bonus(raw)
        ja3_pen    = self._ja3_penalty(record)                          # FEATURE 2

        total = t_score + p_score + ip_score + f_score + test_score + cdn_bonus - ja3_pen
        return min(max(total, 0), 100)

    def score_all(self, history: Dict[str, Dict[str, Any]]) -> None:
        """Update the 'score' field on every record in-place."""
        for record in history.values():
            record["score"] = self.score(record)
        log.info("Scoring complete.")

    def top_for_iran(
        self,
        history: Dict[str, Dict[str, Any]],
        n: int = 50,
        min_score: int = 0,
    ) -> List[Dict[str, Any]]:
        """Return the top-N records sorted by Iran score."""
        candidates = [v for v in history.values() if v.get("score", 0) >= min_score]
        return sorted(candidates, key=lambda r: r.get("score", 0), reverse=True)[:n]

    def iran_cut_pack(
        self,
        history: Dict[str, Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Return bridges most likely to work during Iranian internet cut (NIN active).
        Priority: snowflake > webtunnel (CDN) > obfs4 on port 443.
        """
        results = []
        for v in history.values():
            t = v.get("transport", "")
            if t == "snowflake":
                results.append((v, 100))
            elif t == "webtunnel" and self._cdn_bonus(v.get("raw", "")):
                results.append((v, 90))
            elif t == "webtunnel":
                results.append((v, 75))
            elif t == "meek_lite":
                results.append((v, 70))
            elif t == "obfs4":
                _, port, _ = extract_endpoint(v.get("raw", ""))
                if port in (443, 80):
                    results.append((v, 60))
        results.sort(key=lambda x: x[1], reverse=True)
        return [r for r, _ in results]
