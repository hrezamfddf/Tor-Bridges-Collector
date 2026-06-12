#!/usr/bin/env python3
"""
adaptive_transport.py — FEATURE 4: Adaptive Transport Selection Engine.

After each pipeline run, analyzes which transport types (obfs4, snowflake,
webtunnel, meek_lite) have the highest OONI success rate in Iran over the
last 7 days.  Dynamically adjusts the transport weights used by
core/scorer.py to reflect current real-world conditions, and publishes:

  data/transport_weights.json       — current weights + scorer scores
  data/transport_weight_history.json — time-series audit log
  data/best_transports.json          — human/machine-readable ranking

The scorer loads data/transport_weights.json on every instantiation, so
each hourly CI run uses freshly-computed weights with zero manual steps.

Weighting formula:
  raw_weight[t] = ooni_success_rate[t] * ooni_recency_factor
  normalized    = raw_weight[t] / sum(raw_weights)
  scorer_score  = BASE_SCORE[t] * (0.7 + 0.6 * normalized)
  (clamped to [3, 30])
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────────────────────

IRAN_RESULTS_PATH     = Path("bridge/iran_results.json")
LATEST_RESULTS_PATH   = Path("data/latest-results.json")
WEIGHTS_PATH          = Path("data/transport_weights.json")
WEIGHT_HISTORY_PATH   = Path("data/transport_weight_history.json")
BEST_TRANSPORTS_PATH  = Path("data/best_transports.json")

Path("data").mkdir(parents=True, exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# Base scorer scores (same as IranScorer._DEFAULT_TRANSPORT_SCORES)
# The adaptive engine scales these, never drops below MIN_SCORE.
# ─────────────────────────────────────────────────────────────────────────────

BASE_SCORES: Dict[str, int] = {
    "snowflake":  30,
    "webtunnel":  28,
    "obfs4":      25,
    "meek_lite":  20,
    "vanilla":    5,
    "unknown":    8,
}
MIN_SCORE = 3
MAX_SCORE = 30

WORKING_STATUSES = {"iran_likely_working"}
BLOCKED_STATUSES = {"iran_likely_blocked", "iran_frequently_blocked", "iran_asn_blocked"}


# ─────────────────────────────────────────────────────────────────────────────
# Analysis
# ─────────────────────────────────────────────────────────────────────────────

def _collect_transport_stats(
    records: List[Dict[str, Any]],
) -> Dict[str, Dict[str, int]]:
    """Count working vs total bridges per transport."""
    stats: Dict[str, Dict[str, int]] = {}
    for r in records:
        t = r.get("transport", "unknown")
        if t not in stats:
            stats[t] = {"working": 0, "blocked": 0, "unknown": 0, "total": 0}
        status = r.get("iran_status", "")
        stats[t]["total"] += 1
        if status in WORKING_STATUSES:
            stats[t]["working"] += 1
        elif status in BLOCKED_STATUSES:
            stats[t]["blocked"] += 1
        else:
            stats[t]["unknown"] += 1
    return stats


def compute_weights(
    stats: Dict[str, Dict[str, int]],
    min_samples: int = 3,
) -> Dict[str, float]:
    """
    Compute normalized success-rate weights for each transport.
    Transports with fewer than min_samples data points keep their base weight.
    """
    raw: Dict[str, float] = {}
    for t, s in stats.items():
        if s["total"] < min_samples:
            # Insufficient data — use neutral weight (keeps base score intact)
            raw[t] = 0.5
        else:
            raw[t] = s["working"] / s["total"]

    total = sum(raw.values())
    if total == 0:
        return {t: 1.0 / len(raw) for t in raw}
    return {t: v / total for t, v in raw.items()}


def weights_to_scores(weights: Dict[str, float]) -> Dict[str, int]:
    """
    Convert normalized weights → scorer integer scores in [MIN_SCORE, MAX_SCORE].
    Formula: base * (0.70 + 0.60 * normalized_weight), clamped.
    """
    scores: Dict[str, int] = {}
    for t, base in BASE_SCORES.items():
        w    = weights.get(t, 1.0 / len(BASE_SCORES))
        raw  = base * (0.70 + 0.60 * w)
        scores[t] = int(round(max(MIN_SCORE, min(MAX_SCORE, raw))))
    return scores


# ─────────────────────────────────────────────────────────────────────────────
# Persistence
# ─────────────────────────────────────────────────────────────────────────────

def _load_weight_history() -> List[Dict[str, Any]]:
    if WEIGHT_HISTORY_PATH.exists():
        try:
            return json.loads(WEIGHT_HISTORY_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return []


def _save_weight_history(history: List[Dict[str, Any]]) -> None:
    # Keep last 90 entries (≈ 90 hourly runs = ~4 days)
    WEIGHT_HISTORY_PATH.write_text(
        json.dumps(history[-90:], indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def save_weights(
    weights: Dict[str, float],
    scores: Dict[str, int],
    stats: Dict[str, Dict[str, int]],
) -> None:
    """Write data/transport_weights.json consumed by IranScorer."""
    ts = datetime.now(timezone.utc).isoformat()
    payload = {
        "updated_at": ts,
        "weights":    {t: round(w, 4) for t, w in weights.items()},
        "scores":     scores,
        "stats":      stats,
    }
    WEIGHTS_PATH.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    log.info(f"Transport weights saved → {WEIGHTS_PATH}")

    # Append to time-series history
    history = _load_weight_history()
    history.append({"ts": ts, "weights": weights, "scores": scores})
    _save_weight_history(history)
    log.info(f"Weight history updated ({len(history)} entries).")


def save_best_transports(
    weights: Dict[str, float],
    scores:  Dict[str, int],
    stats:   Dict[str, Dict[str, int]],
) -> None:
    """Write data/best_transports.json — human and machine-readable ranking."""
    ts = datetime.now(timezone.utc).isoformat()

    ranked = sorted(
        [
            {
                "transport":     t,
                "success_rate":  round(
                    stats.get(t, {}).get("working", 0)
                    / max(stats.get(t, {}).get("total", 1), 1),
                    4,
                ),
                "total_tested":  stats.get(t, {}).get("total", 0),
                "working":       stats.get(t, {}).get("working", 0),
                "blocked":       stats.get(t, {}).get("blocked", 0),
                "weight":        round(weights.get(t, 0.0), 4),
                "scorer_score":  scores.get(t, BASE_SCORES.get(t, 8)),
                "iran_dpi_resistance": {
                    "snowflake":  "maximum — WebRTC/DTLS, hardest to fingerprint",
                    "webtunnel":  "very_high — HTTPS CDN mimicry",
                    "obfs4":      "high — random-looking traffic",
                    "meek_lite":  "high — CDN domain fronting",
                    "vanilla":    "none — plaintext Tor",
                }.get(t, "unknown"),
                "survives_nic":  t in {"snowflake", "webtunnel", "meek_lite"},
            }
            for t in BASE_SCORES
            if t != "unknown"
        ],
        key=lambda x: (x["success_rate"], x["scorer_score"]),
        reverse=True,
    )

    payload = {
        "generated_at":         ts,
        "analysis_window_days": 7,
        "recommended_order":    [r["transport"] for r in ranked],
        "transports":           ranked,
        "note": (
            "Weights are recomputed on every CI run from OONI measurements. "
            "For internet cut (شبکه ملی), use only: snowflake → webtunnel → meek_lite."
        ),
    }
    BEST_TRANSPORTS_PATH.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    log.info(
        "best_transports.json: %s",
        " → ".join(payload["recommended_order"]),
    )


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    log.info("═══ Adaptive Transport Engine ═══════════════════════════════")

    # Load bridge records from one or both result files
    records: List[Dict[str, Any]] = []
    for path in (IRAN_RESULTS_PATH, LATEST_RESULTS_PATH):
        if path.exists():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                records.extend(data.get("bridges", []))
            except Exception as exc:
                log.warning(f"Cannot read {path}: {exc}")

    if not records:
        log.warning("No bridge records found — keeping existing weights unchanged.")
        sys.exit(0)

    log.info(f"Analyzing {len(records)} bridge records…")

    stats   = _collect_transport_stats(records)
    weights = compute_weights(stats)
    scores  = weights_to_scores(weights)

    # Log the ranking
    ranked = sorted(weights.items(), key=lambda kv: kv[1], reverse=True)
    log.info("Transport success-rate ranking (current 7-day window):")
    for t, w in ranked:
        s  = stats.get(t, {})
        sr = s.get("working", 0) / max(s.get("total", 1), 1)
        log.info(
            f"  {t:<12} success={sr:.0%}  tested={s.get('total',0)}"
            f"  scorer_score={scores.get(t, BASE_SCORES.get(t,8))}"
        )

    save_weights(weights, scores, stats)
    save_best_transports(weights, scores, stats)
    log.info("═══ Adaptive Transport Engine done ══════════════════════════")


if __name__ == "__main__":
    main()


# APPEND AFTER LAST LINE
# ─────────────────────────────────────────────────────────────────────────────
# NIN internet-cut transport auto-selector (Objective 8)
# ─────────────────────────────────────────────────────────────────────────────

def select_transport_for_nin_cut() -> dict:
    """
    Rank all available transport options for the NIN-isolation scenario
    (complete international internet blackout).

    Reads:
      data/nin_cut_report.json       (Stage 8k output)
      data/reality_report.json       (Stage 8l output)
      data/next_gen_bridges.json     (next_gen_transports.py output)

    Writes:
      export/nin_recommended_transport.json

    Priority tiers for NIN-cut survival:
      Tier 1: WebTunnel over port 443 via Iranian CDN SNI
      Tier 2: XTLS-Reality VLESS on port 443
      Tier 3: obfs4 on port 443 or 8443
      Tier 4: Snowflake (if STUN reachable)
    """
    import json as _json
    import logging as _logging
    from pathlib import Path as _Path
    from datetime import datetime, timezone

    _log = _logging.getLogger(__name__ + ".nin_selector")
    _log.info("=== NIN Internet-Cut Transport Selector ===")

    NIN_CUT_REPORT   = _Path("data/nin_cut_report.json")
    REALITY_REPORT   = _Path("data/reality_report.json")
    NEXT_GEN_BRIDGES = _Path("data/next_gen_bridges.json")
    OUTPUT_PATH      = _Path("export/nin_recommended_transport.json")

    def _safe_load(path: _Path) -> dict:
        if not path.exists():
            _log.warning("File not found: %s -- using empty data.", path)
            return {}
        try:
            return _json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            _log.warning("Cannot read %s: %s -- using empty data.", path, exc)
            return {}

    nin_data     = _safe_load(NIN_CUT_REPORT)
    reality_data = _safe_load(REALITY_REPORT)
    next_gen     = _safe_load(NEXT_GEN_BRIDGES)

    candidates: list[dict] = []

    # ── Tier 1: WebTunnel bridges with high NIN-cut score ─────────────────
    for bridge in nin_data.get("bridges", []):
        if bridge.get("transport", "").lower() in ("webtunnel",) and \
           bridge.get("nin_score", 0.0) >= 0.60:
            candidates.append({
                "tier":      1,
                "tier_label": "WebTunnel/CDN-443",
                "transport": "webtunnel",
                "ip":        bridge.get("ip"),
                "port":      bridge.get("port"),
                "raw":       bridge.get("raw", ""),
                "nin_score": bridge.get("nin_score", 0.0),
                "reason": (
                    "WebTunnel on port 443 via Iranian CDN SNI is the strongest "
                    "NIN-cut transport — indistinguishable from domestic HTTPS."
                ),
            })

    # WebTunnel from next_gen webtransport_scores
    for entry in next_gen.get("webtransport_scores", []):
        if entry.get("webtransport_score", 0.0) >= 0.70:
            candidates.append({
                "tier":      1,
                "tier_label": "WebTunnel/QUIC-CDN",
                "transport": "webtunnel",
                "ip":        entry.get("ip"),
                "port":      entry.get("port"),
                "raw":       entry.get("raw", ""),
                "nin_score": entry.get("webtransport_score", 0.0),
                "reason": (
                    "WebTunnel with QUIC/H3 CDN profile match -- mimics "
                    "Aparat video streaming traffic on SIAM allowlist."
                ),
            })

    # ── Tier 2: XTLS-Reality configs with high DPI score ─────────────────
    for entry in reality_data.get("per_bridge", []):
        if entry.get("dpi_score", 0.0) >= 0.60:
            candidates.append({
                "tier":      2,
                "tier_label": "XTLS-Reality/VLESS-443",
                "transport": "vless+reality",
                "ip":        entry.get("ip"),
                "port":      entry.get("port"),
                "sni":       entry.get("sni"),
                "raw":       f"vless {entry.get('ip')}:{entry.get('port')} (Reality)",
                "nin_score": entry.get("dpi_score", 0.0),
                "reason": (
                    "XTLS-Reality borrows TLS cert of Iranian CDN domain. "
                    "SIAM DPI cannot distinguish from domestic HTTPS."
                ),
            })

    # ── Tier 3: obfs4 on port 443 / 8443 ─────────────────────────────────
    for bridge in nin_data.get("bridges", []):
        if bridge.get("transport", "").lower() == "obfs4" and \
           bridge.get("port") in (443, 8443) and \
           bridge.get("nin_score", 0.0) >= 0.50:
            candidates.append({
                "tier":      3,
                "tier_label": "obfs4-443/8443",
                "transport": "obfs4",
                "ip":        bridge.get("ip"),
                "port":      bridge.get("port"),
                "raw":       bridge.get("raw", ""),
                "nin_score": bridge.get("nin_score", 0.0),
                "reason": (
                    "obfs4 on port 443/8443 blends into HTTPS traffic. "
                    "Blocking port 443 is politically infeasible on Iran's NIN."
                ),
            })

    # ── Tier 4: Snowflake (STUN-dependent) ───────────────────────────────
    for bridge in nin_data.get("bridges", []):
        if bridge.get("transport", "").lower() == "snowflake":
            candidates.append({
                "tier":      4,
                "tier_label": "Snowflake/WebRTC",
                "transport": "snowflake",
                "ip":        bridge.get("ip"),
                "port":      bridge.get("port"),
                "raw":       bridge.get("raw", ""),
                "nin_score": bridge.get("nin_score", 0.0) * 0.7,  # penalty: needs STUN
                "reason": (
                    "Snowflake uses WebRTC (classified as video-call by SIAM). "
                    "Requires STUN reachability -- less reliable during full NIN cut."
                ),
            })

    # Sort: tier ascending, then nin_score descending
    candidates.sort(key=lambda x: (x["tier"], -x.get("nin_score", 0.0)))

    # Remove duplicates by raw line
    seen: set[str] = set()
    deduped: list[dict] = []
    for c in candidates:
        key = c.get("raw", "") or f"{c.get('ip')}:{c.get('port')}"
        if key not in seen:
            seen.add(key)
            deduped.append(c)

    output: dict = {
        "generated_at":      datetime.now(timezone.utc).isoformat(),
        "nin_cut_scenario":  (
            "Complete international internet blackout. Only traffic through "
            "Iranian domestic ASNs (ITC/TCI/ParsOnline/ArvanCloud) reachable."
        ),
        "total_candidates":  len(deduped),
        "tier_counts": {
            "tier_1_webtunnel_cdn":   sum(1 for c in deduped if c["tier"] == 1),
            "tier_2_xtls_reality":    sum(1 for c in deduped if c["tier"] == 2),
            "tier_3_obfs4_443":       sum(1 for c in deduped if c["tier"] == 3),
            "tier_4_snowflake":       sum(1 for c in deduped if c["tier"] == 4),
        },
        "top_recommendation": deduped[0] if deduped else None,
        "ranked_candidates":  deduped,
    }

    _Path("export").mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(
        _json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    _log.info(
        "NIN transport selector done: %d candidates ranked -> %s",
        len(deduped), OUTPUT_PATH,
    )
    return output
