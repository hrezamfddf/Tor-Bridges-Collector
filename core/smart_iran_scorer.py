"""
core/smart_iran_scorer.py — Unified AI + Heuristic Bridge Scorer
═════════════════════════════════════════════════════════════════
Integrates every existing scoring signal into a single authoritative
0–100 score for each bridge, tuned specifically for Iran reachability.

SIGNAL PIPELINE
───────────────
  ┌──────────────────────────────────────────────────────┐
  │  Bridge Record (raw line + metadata)                  │
  └───────────────┬──────────────────────────────────────┘
                  │
     ┌────────────┼────────────────────────────────┐
     │            │                                │
  ┌──▼───┐  ┌────▼────┐  ┌────────────┐  ┌───────▼──────┐
  │IranS-│  │NIN Score│  │Anti-AI DPI │  │Censorship    │
  │corer │  │(nin_     │  │Score       │  │Level Adjust  │
  │(core)│  │bypass)  │  │(anti_ai)   │  │(monitor)     │
  └──┬───┘  └────┬────┘  └─────┬──────┘  └───────┬──────┘
     │            │             │                  │
     └────────────▼─────────────▼──────────────────┘
                          │
                  ┌───────▼────────┐
                  │  Weighted Blend │  weights tune per censorship level
                  └───────┬────────┘
                          │
               ┌──────────▼──────────┐
               │  AI Refinement       │  optional: use iran_intelligence
               │  (top-20 only)       │  AI call for high-stakes bridges
               └──────────┬──────────┘
                          │
                  ┌───────▼────────┐
                  │  Final Score    │  0–100, tier, recommendation
                  └────────────────┘

WEIGHTS (default, tuned per level)
───────────────────────────────────
  base_iran_score  : 0.35   (IranScorer — transport/port/freshness/CDN/JA3)
  nin_score        : 0.25   (NIN survivability — CDN ASN + transport)
  dpi_score        : 0.25   (Anti-AI DPI resistance)
  port_bonus       : 0.05   (extra weight for Iran-safe ports)
  level_modifier   : 0.10   (censorship level adjustment)

AI refinement is only called for bridges with intermediate scores (35–70)
where heuristics are uncertain.  Bridges clearly excellent (>70) or clearly
poor (<35) are not re-scored to avoid unnecessary API calls.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger(__name__)

DATA_DIR = Path("data")
DATA_DIR.mkdir(parents=True, exist_ok=True)

# ── Iran-safe ports (score bonus) ─────────────────────────────────────────────
_SAFE_PORTS: Dict[int, float] = {
    443:  1.00,
    80:   0.80,
    2053: 0.90,
    2083: 0.85,
    2087: 0.85,
    2096: 0.80,
    8443: 0.75,
    8080: 0.60,
}

# ── Transport DPI resistance scores ──────────────────────────────────────────
_TRANSPORT_DPI: Dict[str, float] = {
    "snowflake":  0.95,
    "webtunnel":  0.88,
    "meek_lite":  0.80,
    "obfs4":      0.72,
    "vanilla":    0.05,
    "unknown":    0.30,
}

# ── NIN survivability scores ───────────────────────────────────────────────
_TRANSPORT_NIN: Dict[str, float] = {
    "snowflake":  1.00,
    "webtunnel":  0.90,   # CDN-fronted variant
    "meek_lite":  0.85,
    "obfs4":      0.35,
    "vanilla":    0.05,
    "unknown":    0.20,
}

# ── CDN ASN survival bonus ─────────────────────────────────────────────────
_CDN_ASN_BONUS: Dict[str, float] = {
    "AS200000":  0.95,   # ArvanCloud IR
    "AS13335":   0.90,   # Cloudflare
    "AS20940":   0.80,   # Akamai
    "AS16509":   0.75,   # Amazon CloudFront
    "AS8075":    0.70,   # Microsoft Azure
    "AS15169":   0.65,   # Google
    "AS54113":   0.70,   # Fastly
}

# ── Weights per censorship level ──────────────────────────────────────────
_LEVEL_WEIGHTS: Dict[int, Dict[str, float]] = {
    1: {"base": 0.50, "nin": 0.10, "dpi": 0.20, "port": 0.10, "level": 0.10},
    2: {"base": 0.40, "nin": 0.15, "dpi": 0.25, "port": 0.10, "level": 0.10},
    3: {"base": 0.35, "nin": 0.20, "dpi": 0.25, "port": 0.10, "level": 0.10},
    4: {"base": 0.25, "nin": 0.25, "dpi": 0.30, "port": 0.10, "level": 0.10},
    5: {"base": 0.15, "nin": 0.45, "dpi": 0.25, "port": 0.05, "level": 0.10},
}

# ── Level multipliers for certain transports ─────────────────────────────
_LEVEL_TRANSPORT_BOOST: Dict[int, Dict[str, float]] = {
    4: {"snowflake": 1.15, "webtunnel": 1.10, "obfs4": 0.85, "vanilla": 0.30},
    5: {"snowflake": 1.30, "webtunnel": 1.25, "obfs4": 0.50, "vanilla": 0.10,
        "meek_lite": 1.10},
}

# ── IP/port extraction ────────────────────────────────────────────────────
_IP_PORT_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})")
_TRANS_RE   = re.compile(
    r"\b(snowflake|webtunnel|obfs4|meek_lite|vanilla)\b", re.I
)


def _extract_endpoint(raw: str) -> Tuple[str, int, str]:
    """Extract (host, port, transport) from a raw bridge line."""
    # Transport
    m_t = _TRANS_RE.search(raw.lower())
    transport = m_t.group(1) if m_t else "unknown"
    if "obfs4" in raw.lower():
        transport = "obfs4"

    # IP:port
    m = _IP_PORT_RE.search(raw)
    if m:
        return m.group(1), int(m.group(2)), transport

    return "", 0, transport


# ─────────────────────────────────────────────────────────────────────────────
# Data structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class BridgeScore:
    bridge_id:       str
    transport:       str
    port:            int
    base_score:      float   # from IranScorer (0–100)
    nin_score:       float   # NIN survivability (0–1)
    dpi_score:       float   # DPI resistance (0–1)
    port_score:      float   # Port safety (0–1)
    level_mod:       float   # Censorship level modifier (0–1)
    final_score:     float   # Weighted composite (0–100)
    ai_refined:      bool    = False
    ai_score:        float   = -1.0   # AI judgment (0–1), -1 = not used
    tier:            str     = "capable"   # excellent/good/capable/poor
    recommendation:  str     = "use"       # use/avoid/test
    raw:             str     = ""


# ─────────────────────────────────────────────────────────────────────────────
# Core scorer
# ─────────────────────────────────────────────────────────────────────────────

class SmartIranScorer:
    """
    Unified bridge scorer integrating all Iran-specific heuristics + optional AI.

    Usage
    ─────
    scorer = SmartIranScorer(censorship_level=4, use_ai=True)
    results = scorer.score_all(bridge_records)      # List[BridgeScore]
    top     = scorer.top_bridges(results, n=50)
    scorer.write_report(results)
    """

    def __init__(
        self,
        censorship_level:  int  = 3,
        use_ai:            bool = False,   # AI refinement for uncertain bridges
        ai_threshold_low:  float = 35.0,
        ai_threshold_high: float = 70.0,
    ):
        self.level            = max(1, min(5, censorship_level))
        self.use_ai           = use_ai
        self.ai_thresh_low    = ai_threshold_low
        self.ai_thresh_high   = ai_threshold_high
        self._weights         = _LEVEL_WEIGHTS[self.level]
        self._iran_scorer:    Optional[Any] = None
        self._ai_layer:       Optional[Any] = None
        self._load_subsystems()

    def _load_subsystems(self) -> None:
        """Load IranScorer and AI layer (failures are non-fatal)."""
        try:
            from core.scorer import IranScorer
            self._iran_scorer = IranScorer()
        except Exception as exc:
            log.warning(f"[SmartScorer] IranScorer unavailable: {exc}")

        if self.use_ai:
            try:
                from torshield_ai_gateway.iran_intelligence import IranIntelligenceLayer
                self._ai_layer = IranIntelligenceLayer()
            except Exception as exc:
                log.warning(f"[SmartScorer] AI layer unavailable: {exc}")
                self.use_ai = False

    # ── Signal computation ────────────────────────────────────────────────

    def _base_score(self, record: Dict[str, Any]) -> float:
        """IranScorer 0–100 → normalised 0–1."""
        if self._iran_scorer:
            try:
                return self._iran_scorer.score(record) / 100.0
            except Exception:
                pass
        # Fallback: basic transport score
        raw = record.get("raw", record.get("line", ""))
        _, _, transport = _extract_endpoint(raw)
        return _TRANSPORT_DPI.get(transport, 0.30)

    def _nin_signal(self, record: Dict[str, Any]) -> float:
        raw       = record.get("raw", record.get("line", ""))
        _, port, transport = _extract_endpoint(raw)
        asn       = record.get("asn", "")

        t_nin     = _TRANSPORT_NIN.get(transport, 0.20)
        asn_bonus = _CDN_ASN_BONUS.get(asn, 0.0)
        port_ok   = 1.0 if port in (443, 80, 2053, 2083, 2087) else 0.4

        return min(1.0, t_nin * 0.6 + asn_bonus * 0.25 + port_ok * 0.15)

    def _dpi_signal(self, record: Dict[str, Any]) -> float:
        raw       = record.get("raw", record.get("line", ""))
        _, _, transport = _extract_endpoint(raw)
        return _TRANSPORT_DPI.get(transport, 0.30)

    def _port_signal(self, port: int) -> float:
        return _SAFE_PORTS.get(port, 0.20)

    def _level_modifier(self, transport: str) -> float:
        """Extra boost/penalty depending on current censorship level."""
        boosts = _LEVEL_TRANSPORT_BOOST.get(self.level, {})
        return boosts.get(transport, 1.0)

    # ── Composite score ───────────────────────────────────────────────────

    def _compute(self, record: Dict[str, Any]) -> BridgeScore:
        raw       = record.get("raw", record.get("line", ""))
        _, port, transport = _extract_endpoint(raw)
        bridge_id = record.get("fingerprint", record.get("id", raw[:40]))

        w         = self._weights
        base_s    = self._base_score(record)
        nin_s     = self._nin_signal(record)
        dpi_s     = self._dpi_signal(record)
        port_s    = self._port_signal(port)
        level_mod = self._level_modifier(transport)

        # Weighted blend (0–1)
        raw_score = (
            w["base"]  * base_s +
            w["nin"]   * nin_s  +
            w["dpi"]   * dpi_s  +
            w["port"]  * port_s +
            w["level"] * (level_mod - 1.0 + 0.5)   # centre modifier at 0.5
        )

        # Apply level transport multiplier
        raw_score = raw_score * (0.85 + 0.15 * level_mod)

        final = min(100.0, max(0.0, raw_score * 100.0))

        return BridgeScore(
            bridge_id    = bridge_id,
            transport    = transport,
            port         = port,
            base_score   = round(base_s * 100, 1),
            nin_score    = round(nin_s, 3),
            dpi_score    = round(dpi_s, 3),
            port_score   = round(port_s, 3),
            level_mod    = round(level_mod, 3),
            final_score  = round(final, 1),
            raw          = raw,
        )

    def _assign_tier(self, bs: BridgeScore) -> BridgeScore:
        s = bs.final_score
        if s >= 75:
            bs.tier           = "excellent"
            bs.recommendation = "use"
        elif s >= 55:
            bs.tier           = "good"
            bs.recommendation = "use"
        elif s >= 35:
            bs.tier           = "capable"
            bs.recommendation = "test"
        else:
            bs.tier           = "poor"
            bs.recommendation = "avoid"
        return bs

    # ── AI refinement ─────────────────────────────────────────────────────

    def _maybe_ai_refine(self, bs: BridgeScore) -> BridgeScore:
        """Call AI only for 'uncertain' mid-range bridges."""
        if not self.use_ai or not self._ai_layer:
            return bs
        if bs.final_score < self.ai_thresh_low or bs.final_score > self.ai_thresh_high:
            return bs   # Certain — skip API call
        try:
            result = self._ai_layer.score_bridge_iran_reachability(bs.raw)
            ai_s   = float(result.get("score", 0.5))
            # Blend: 60% heuristic + 40% AI
            blended = (bs.final_score / 100.0) * 0.6 + ai_s * 0.4
            bs.final_score = round(min(100.0, blended * 100.0), 1)
            bs.ai_refined  = True
            bs.ai_score    = round(ai_s, 3)
        except Exception as exc:
            log.debug(f"[SmartScorer] AI refinement skipped: {exc}")
        return bs

    # ── Public API ────────────────────────────────────────────────────────

    def score_record(self, record: Dict[str, Any]) -> BridgeScore:
        bs = self._compute(record)
        bs = self._assign_tier(bs)
        bs = self._maybe_ai_refine(bs)
        return bs

    def score_all(
        self, records: List[Dict[str, Any]]
    ) -> List[BridgeScore]:
        results = [self.score_record(r) for r in records]
        results.sort(key=lambda x: x.final_score, reverse=True)
        log.info(
            f"[SmartScorer] Scored {len(results)} bridges at level {self.level} | "
            f"excellent={sum(1 for r in results if r.tier=='excellent')} "
            f"good={sum(1 for r in results if r.tier=='good')} "
            f"capable={sum(1 for r in results if r.tier=='capable')} "
            f"poor={sum(1 for r in results if r.tier=='poor')}"
        )
        return results

    def top_bridges(
        self,
        results:     List[BridgeScore],
        n:           int = 50,
        min_score:   float = 30.0,
        transports:  Optional[List[str]] = None,
    ) -> List[BridgeScore]:
        """
        Return top-N bridges, optionally filtered by transport type.

        Args:
            results:    Output of score_all().
            n:          Maximum bridges to return.
            min_score:  Minimum final score to include.
            transports: If set, only include these transport types.
        """
        filtered = [r for r in results if r.final_score >= min_score]
        if transports:
            filtered = [r for r in filtered if r.transport in transports]
        return filtered[:n]

    def write_report(
        self,
        results: List[BridgeScore],
        path:    Path = DATA_DIR / "smart_iran_score_report.json",
    ) -> None:
        """Write full scoring report to JSON."""
        report = {
            "censorship_level": self.level,
            "ai_used":          self.use_ai,
            "total_bridges":    len(results),
            "tier_counts": {
                "excellent": sum(1 for r in results if r.tier == "excellent"),
                "good":      sum(1 for r in results if r.tier == "good"),
                "capable":   sum(1 for r in results if r.tier == "capable"),
                "poor":      sum(1 for r in results if r.tier == "poor"),
            },
            "top_50": [
                {
                    "rank":        i + 1,
                    "score":       r.final_score,
                    "tier":        r.tier,
                    "transport":   r.transport,
                    "port":        r.port,
                    "nin_score":   r.nin_score,
                    "dpi_score":   r.dpi_score,
                    "ai_refined":  r.ai_refined,
                    "recommend":   r.recommendation,
                    "bridge":      r.raw[:80],
                }
                for i, r in enumerate(results[:50])
            ],
        }
        path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        log.info(f"[SmartScorer] Report → {path}")

    def export_bridge_lines(
        self,
        results:   List[BridgeScore],
        path:      Path,
        n:         int = 50,
        min_score: float = 30.0,
    ) -> int:
        """Export raw bridge lines for top-N bridges to a text file."""
        top = self.top_bridges(results, n=n, min_score=min_score)
        lines = [r.raw for r in top if r.raw.strip()]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        log.info(f"[SmartScorer] Exported {len(lines)} bridges → {path}")
        return len(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Convenience pipeline
# ─────────────────────────────────────────────────────────────────────────────

def run_smart_scoring(
    records:           List[Dict[str, Any]],
    censorship_level:  int  = 3,
    use_ai:            bool = False,
    output_prefix:     str  = "smart",
) -> Tuple[List[BridgeScore], Path]:
    """
    One-call pipeline: score all bridges, write report, export best lines.

    Returns:
        (results, report_path)
    """
    scorer  = SmartIranScorer(censorship_level=censorship_level, use_ai=use_ai)
    results = scorer.score_all(records)

    report_path = DATA_DIR / f"{output_prefix}_iran_score_report.json"
    scorer.write_report(results, report_path)

    export_path = Path("export") / f"{output_prefix}_iran_best.txt"
    scorer.export_bridge_lines(results, export_path)

    return results, report_path


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    import argparse
    logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s %(message)s")

    parser = argparse.ArgumentParser()
    parser.add_argument("--level",  type=int, default=3,   help="Censorship level 1-5")
    parser.add_argument("--ai",     action="store_true",   help="Enable AI refinement")
    parser.add_argument("--input",  default="bridge/iran_results.json")
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"[SmartScorer] Input not found: {input_path}")
        sys.exit(1)

    data    = json.loads(input_path.read_text(encoding="utf-8"))
    records = data.get("bridges", data) if isinstance(data, dict) else data

    results, rp = run_smart_scoring(
        records, censorship_level=args.level, use_ai=args.ai
    )
    print(f"Scored {len(results)} bridges → report: {rp}")
    print(f"Top-5:")
    for r in results[:5]:
        print(f"  [{r.tier:9}] {r.final_score:5.1f}  {r.transport:10}  {r.raw[:60]}")
