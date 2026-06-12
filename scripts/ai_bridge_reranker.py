#!/usr/bin/env python3
"""
AI Bridge Re-Ranker v9.0 — Smart Iran Scoring Pipeline
═══════════════════════════════════════════════════════
Integrates CensorshipMonitor + SmartIranScorer + IranIntelligenceLayer
into a single pipeline that scores and exports the best bridges for
Iran based on the CURRENT censorship state.

PIPELINE
────────
  1. CensorshipMonitor.run_sync()   → detect censorship level 1–5
  2. SmartIranScorer(level)         → score all bridges (AI+heuristic)
  3. IranIntelligenceLayer          → AI batch refinement (top-100 only)
  4. Export by tier:
       export/iran_pack.txt         ← levels 1–3 best bridges
       export/iran_nin_pack.txt     ← levels 4–5 NIN-safe bridges
       export/iran_smart_report.json← full scored report

ADDITIVE: all original fields preserved; smart_iran_scores field added.
"""

import os, sys, json, argparse, logging, time
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
logger = logging.getLogger("ai_reranker_v9")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ── Fallback if CensorshipMonitor can't run ────────────────────────────────

def _get_censorship_level(use_probes: bool = True) -> tuple[int, float]:
    """Return (level, confidence). Falls back to cached state or default 3."""
    if use_probes:
        try:
            from core.censorship_monitor import run_sync
            state = run_sync(write_state=True)
            logger.info(
                f"[Censorship] Level {state.level} "
                f"(confidence={state.confidence:.0%})"
            )
            return state.level, state.confidence
        except Exception as exc:
            logger.warning(f"[Censorship] Live probe failed: {exc}")

    # Try last saved state
    try:
        from core.censorship_monitor import get_last_state
        state = get_last_state()
        if state:
            logger.info(f"[Censorship] Using cached level {state.level}")
            return state.level, state.confidence
    except Exception:
        pass

    logger.info("[Censorship] Using default level 3")
    return 3, 0.5


# ── Score bridges with SmartIranScorer ────────────────────────────────────

def _smart_score(
    records: list, level: int, use_ai_refine: bool
) -> list:
    """Run SmartIranScorer over all records. Returns BridgeScore list."""
    try:
        from core.smart_iran_scorer import SmartIranScorer
        scorer  = SmartIranScorer(censorship_level=level, use_ai=False)  # heuristic pass
        results = scorer.score_all(records)
        logger.info(
            f"[SmartScorer] {len(results)} scored | level={level} | "
            f"excellent={sum(1 for r in results if r.tier=='excellent')} "
            f"good={sum(1 for r in results if r.tier=='good')}"
        )
        return results
    except Exception as exc:
        logger.warning(f"[SmartScorer] Unavailable: {exc}")
        return []


# ── AI batch refinement ───────────────────────────────────────────────────

def _ai_batch_refine(
    bridge_records: list,
    smart_results:  list,
    level:          int,
    batch_size:     int,
    top_n:          int = 100,
) -> dict:
    """
    Call IranIntelligenceLayer.batch_ai_score on top-100 bridges.
    Returns dict: bridge_line → ai_score_entry.
    """
    try:
        from torshield_ai_gateway.iran_intelligence import IranIntelligenceLayer
        intel = IranIntelligenceLayer()

        # Pick bridge lines for top-N by heuristic score
        if smart_results:
            top_lines = [r.raw for r in smart_results[:top_n] if r.raw.strip()]
        else:
            top_lines = []
            for b in bridge_records[:top_n]:
                if isinstance(b, str):
                    top_lines.append(b)
                else:
                    top_lines.append(b.get("raw", b.get("bridge_line", b.get("line", ""))))
            top_lines = [l for l in top_lines if l.strip()]

        logger.info(f"[AIRefine] batch_ai_score: {len(top_lines)} bridges …")
        ai_results = intel.batch_ai_score(top_lines, censorship_level=level, batch_size=batch_size)
        return {r["bridge_line"]: r for r in ai_results if "bridge_line" in r}

    except Exception as exc:
        logger.warning(f"[AIRefine] Unavailable: {exc}")
        return {}


# ── Attach scores to original records ────────────────────────────────────

def _attach_scores(
    records:        list,
    smart_map:      dict,   # bridge_id → BridgeScore
    ai_map:         dict,   # bridge_line → AI result
    level:          int,
    level_conf:     float,
) -> list:
    """Merge heuristic + AI scores into original record dicts."""
    output = []
    for b in records:
        rec = dict(b) if isinstance(b, dict) else {"bridge_line": b, "raw": b}
        raw = rec.get("raw", rec.get("bridge_line", rec.get("line", "")))

        # Heuristic score
        hs = smart_map.get(raw) or smart_map.get(raw[:80])
        heuristic_entry = {}
        if hs:
            heuristic_entry = {
                "heuristic_score": hs.final_score,
                "tier":            hs.tier,
                "transport":       hs.transport,
                "port":            hs.port,
                "nin_score":       hs.nin_score,
                "dpi_score":       hs.dpi_score,
                "recommendation":  hs.recommendation,
            }

        # AI score
        ai_entry = {}
        ai_match = ai_map.get(raw) or ai_map.get(raw[:80])
        if ai_match:
            ai_entry = {
                "ai_score":       ai_match.get("score", 0.5),
                "ai_tier":        ai_match.get("tier", "capable"),
                "ai_recommend":   ai_match.get("recommendation", "test"),
            }

        # Composite final score (blend if both available)
        if heuristic_entry and ai_entry:
            final = (
                heuristic_entry["heuristic_score"] * 0.6 +
                ai_entry["ai_score"] * 100.0 * 0.4
            )
        elif heuristic_entry:
            final = heuristic_entry["heuristic_score"]
        elif ai_entry:
            final = ai_entry["ai_score"] * 100.0
        else:
            final = 50.0

        rec["smart_iran_scores"] = {
            **heuristic_entry,
            **ai_entry,
            "final_score":      round(final, 1),
            "censorship_level": level,
            "level_confidence": round(level_conf, 3),
            "model_version":    "torshield-ir-v9.0",
        }
        output.append(rec)

    output.sort(
        key=lambda x: x.get("smart_iran_scores", {}).get("final_score", 0),
        reverse=True,
    )
    return output


# ── Export packs ──────────────────────────────────────────────────────────

def _export_packs(scored: list, level: int) -> None:
    """Write export/iran_pack.txt and export/iran_nin_pack.txt."""
    export_dir = Path("export")
    export_dir.mkdir(parents=True, exist_ok=True)

    def _line(r: dict) -> str:
        return (
            r.get("raw") or
            r.get("bridge_line") or
            r.get("line") or ""
        ).strip()

    all_lines = [_line(r) for r in scored if _line(r)]

    # Standard pack: all bridges with score ≥ 35
    std_lines = [
        _line(r) for r in scored
        if _line(r) and r.get("smart_iran_scores", {}).get("final_score", 0) >= 35
    ][:100]

    # NIN pack: snowflake + webtunnel only, or score ≥ 60
    nin_lines = [
        _line(r) for r in scored
        if _line(r) and (
            r.get("smart_iran_scores", {}).get("transport", "") in ("snowflake", "webtunnel")
            or r.get("smart_iran_scores", {}).get("nin_score", 0) >= 0.7
            or r.get("smart_iran_scores", {}).get("final_score", 0) >= 60
        )
    ][:50]

    (export_dir / "iran_pack.txt").write_text(
        "\n".join(std_lines or all_lines[:100]) + "\n", encoding="utf-8"
    )
    (export_dir / "iran_nin_pack.txt").write_text(
        "\n".join(nin_lines or std_lines[:50]) + "\n", encoding="utf-8"
    )
    logger.info(
        f"[Export] iran_pack.txt: {len(std_lines)} | "
        f"iran_nin_pack.txt: {len(nin_lines)}"
    )


# ── Main ──────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input",        required=True)
    parser.add_argument("--output",       required=True)
    parser.add_argument("--iran-mode",    default="strict", choices=["strict", "standard"])
    parser.add_argument("--batch-size",   type=int, default=20)
    parser.add_argument("--use-probes",   action="store_true",
                        help="Run live censorship probes (slower, more accurate)")
    parser.add_argument("--level",        type=int, default=0,
                        help="Override censorship level 1-5 (0=auto-detect)")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        logger.error(f"Input not found: {args.input}")
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        Path(args.output).write_text(
            json.dumps({"bridges": [], "ai_iran_scored": True, "total": 0}),
            encoding="utf-8",
        )
        sys.exit(0)

    # ── 1. Load input ─────────────────────────────────────────────────────
    with open(args.input, encoding="utf-8") as f:
        data = json.load(f)
    records = data if isinstance(data, list) else data.get("bridges", [])
    logger.info(f"Loaded {len(records)} bridges from {args.input}")

    # ── 2. Detect censorship level ────────────────────────────────────────
    if args.level > 0:
        level, level_conf = args.level, 1.0
        logger.info(f"[Censorship] Manual override: level {level}")
    else:
        level, level_conf = _get_censorship_level(use_probes=args.use_probes)

    # ── 3. Heuristic scoring ──────────────────────────────────────────────
    smart_results = _smart_score(records, level, use_ai_refine=False)
    smart_map     = {r.raw: r for r in smart_results if r.raw.strip()} if smart_results else {}

    # ── 4. AI batch refinement ────────────────────────────────────────────
    ai_map = _ai_batch_refine(
        records, smart_results, level,
        batch_size=args.batch_size, top_n=100
    )

    # ── 5. Attach scores ──────────────────────────────────────────────────
    scored = _attach_scores(records, smart_map, ai_map, level, level_conf)

    # ── 6. Export packs ───────────────────────────────────────────────────
    _export_packs(scored, level)

    # ── 7. Write output ───────────────────────────────────────────────────
    output_data = (
        {**data, "bridges": scored, "ai_iran_scored": True,
         "censorship_level": level, "scorer_version": "v9.0"}
        if isinstance(data, dict)
        else {"bridges": scored, "ai_iran_scored": True,
              "censorship_level": level, "total": len(scored)}
    )
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)

    logger.info(
        f"Smart-scored {len(scored)} bridges → {args.output} | level={level}"
    )

    # Top-5 summary
    for i, r in enumerate(scored[:5]):
        s = r.get("smart_iran_scores", {})
        logger.info(
            f"  #{i+1} score={s.get('final_score',0):5.1f} "
            f"tier={s.get('tier','?'):9} "
            f"transport={s.get('transport','?')}"
        )


if __name__ == "__main__":
    main()
