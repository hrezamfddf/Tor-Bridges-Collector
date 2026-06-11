#!/usr/bin/env python3
"""
main.py — Tor Bridges Ultra Collector v2.0
Fully-automated, Iran-optimised bridge collector pipeline.

Pipeline stages:
  1. collect  — Fetch from bridges.torproject.org + MOAT API + static
  2. test     — Async TCP/TLS connectivity testing
  3. score    — Compute Iran effectiveness scores
  4. export   — Write all bridge files + Iran packs + JSON API
  5. notify   — Upload ZIP to Telegram (if enabled)

Usage:
  python main.py                  # Run full pipeline (default)
  python main.py --mode collect   # Only collect new bridges
  python main.py --mode test      # Only test existing bridges
  python main.py --mode export    # Only re-export files
  python main.py --detect-iran    # Check local network / NIN status
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
from datetime import datetime
from core.dt_utils import utc_now

# ─────────────────────────────────────────────────────────────────────────────
# Logging setup — rich if available, plain fallback
# ─────────────────────────────────────────────────────────────────────────────

def _setup_logging() -> None:
    fmt = "[%(asctime)s] %(levelname)-8s %(message)s"
    datefmt = "%Y-%m-%d %H:%M:%S"
    try:
        from rich.logging import RichHandler
        logging.basicConfig(
            level=logging.INFO,
            format="%(message)s",
            datefmt=datefmt,
            handlers=[RichHandler(rich_tracebacks=True, show_path=False)],
        )
    except ImportError:
        logging.basicConfig(level=logging.INFO, format=fmt, datefmt=datefmt)

_setup_logging()
log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Import project modules (after logging is ready)
# ─────────────────────────────────────────────────────────────────────────────

import config
from core.history   import HistoryManager
from core.collector import BridgeCollector
from core.tester    import BridgeTester
from core.scorer    import IranScorer
from core.formatter import BridgeFormatter
from core.notifier  import TelegramNotifier


# ─────────────────────────────────────────────────────────────────────────────
# CLI argument parser
# ─────────────────────────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Tor Bridges Ultra Collector — Iran-optimised",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # FIX 2: action="append" lets --mode be specified multiple times.
    # e.g. --mode score --mode export accumulates → ["score","export"].
    # When omitted, args.modes is None → defaults to ["all"].
    _VALID_MODES = {"all", "collect", "test", "score", "export", "notify"}
    p.add_argument(
        "--mode",
        action="append",
        dest="modes",
        metavar="MODE",
        help=(
            "Pipeline stage to run; may be repeated. "
            "Choices: all|collect|test|score|export|notify "
            "(default: all)"
        ),
    )
    p.add_argument(
        "--workers", type=int, default=config.MAX_WORKERS,
        help=f"Parallel workers for testing (default: {config.MAX_WORKERS})",
    )
    p.add_argument(
        "--deep", action="store_true", default=config.DEEP_TEST,
        help="Deep-test mode: test ALL bridges, not just recent ones",
    )
    p.add_argument(
        "--detect-iran", action="store_true",
        help="Check if international internet is reachable from current host",
    )
    p.add_argument(
        "--notify", action="store_true",
        help="Force Telegram notification regardless of schedule",
    )
    p.add_argument(
        "--anti-dpi", action="store_true",
        help="Run AI-powered anti-DPI analysis for Iran",
    )
    p.add_argument(
        "--anti-filter", action="store_true",
        help="Run smart anti-filtering analysis for Iran",
    )
    p.add_argument(
        "--auto-debug", action="store_true",
        help="Run comprehensive auto-debug diagnosis",
    )
    return p.parse_args()


# ─────────────────────────────────────────────────────────────────────────────
# Pipeline stages
# ─────────────────────────────────────────────────────────────────────────────

async def stage_collect(history: HistoryManager) -> None:
    log.info("━━ STAGE 1: COLLECT ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    collector = BridgeCollector(history)
    new_count = await collector.collect_all()
    history.purge_old()
    history.save()
    log.info(f"Collection done — {new_count} new bridges, {len(history.get_all())} total.")


async def stage_test(history: HistoryManager, workers: int, deep: bool) -> None:
    log.info("━━ STAGE 2: TEST ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    db = history.get_all()

    if deep:
        # Deep mode: test everything
        bridge_lines = [v["raw"] for v in db.values()]
    else:
        # Normal mode: prioritise untested and recently-seen bridges
        bridge_lines = [
            v["raw"] for v in db.values()
            if v.get("test_pass") is None or v.get("test_pass") is True
        ]

    if not bridge_lines:
        log.info("No bridges to test.")
        return

    tester = BridgeTester(workers=workers)
    results = await tester.test_all(bridge_lines)

    for line, (ok, lat) in results.items():
        history.update_test(line, ok, lat if lat > 0 else None)

    history.save()
    passed = sum(1 for ok, _ in results.values() if ok)
    log.info(f"Test done — {passed}/{len(results)} reachable.")


def stage_score(history: HistoryManager) -> None:
    log.info("━━ STAGE 3: SCORE ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    scorer = IranScorer()
    scorer.score_all(history.get_all())
    history.save()
    log.info("Scoring done.")


def stage_export(history: HistoryManager) -> dict:
    log.info("━━ STAGE 4: EXPORT ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    formatter = BridgeFormatter()
    stats = formatter.export_all(history)
    stats.update(history.get_stats())
    formatter.update_readme(stats)
    log.info("Export done.")
    return stats


def stage_notify(stats: dict, force: bool = False) -> None:
    log.info("━━ STAGE 5: NOTIFY ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    should_notify = force or config.TELEGRAM_UPLOAD

    # In GitHub Actions, auto-notify at midnight UTC
    if config.IS_GITHUB and not force and not config.TELEGRAM_UPLOAD:
        current_hour = utc_now().hour
        should_notify = (current_hour == 0)

    if not should_notify:
        log.info("Telegram notification skipped (not scheduled or TELEGRAM_UPLOAD=false).")
        return

    zip_path = stats.get("__zip_path__")
    notifier = TelegramNotifier()
    notifier.notify(stats, zip_path=zip_path)


# ─────────────────────────────────────────────────────────────────────────────
# Iran detection helper
# ─────────────────────────────────────────────────────────────────────────────

async def run_iran_detection() -> None:
    from core.iran_detector import check_connectivity, recommend_strategy
    log.info("Checking network connectivity from this host…")
    int_ok, nin_active = await check_connectivity()
    strategy = recommend_strategy(nin_active)
    log.info(f"Recommendation: {strategy}")


def run_anti_dpi_analysis() -> None:
    """Run AI-powered anti-DPI analysis for Iran."""
    from ai_anti_dpi_iran import IranAntiDPI
    log.info("━━ ANTI-DPI ANALYSIS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    dpi = IranAntiDPI()
    threats = dpi.analyze_threats()
    log.info(f"Active threats: {threats['total_active']}, Risk: {threats['risk_level']}")
    log.info(f"Recommended evasions: {', '.join(threats['recommended_evasions'][:3])}")
    tls = dpi.get_tls_randomization()
    log.info(f"TLS profile: {tls['recommended_profile']}")


def run_anti_filter_analysis() -> None:
    """Run smart anti-filtering analysis for Iran."""
    from iran_smart_anti_filter import IranSmartAntiFilter
    log.info("━━ ANTI-FILTER ANALYSIS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    saf = IranSmartAntiFilter()
    status = saf.get_status()
    log.info(f"Censorship Level: {status['censorship']['level']} ({status['censorship']['label']})")
    log.info(f"Recommended transports: {', '.join(status['censorship']['recommended_transports'][:3])}")
    window = status['connection_window']
    log.info(f"Current DPI intensity: {window['current_intensity']} (Iran time: {window['current_iran_time']})")
    log.info(f"Best connection window: {window['next_low_window']}")


def run_auto_debug() -> None:
    """Run comprehensive auto-debug diagnosis."""
    from auto_debug_system import AutoDebugSystem
    log.info("━━ AUTO-DEBUG DIAGNOSIS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    ads = AutoDebugSystem()
    report = ads.run_full_diagnosis()
    summary = report['summary']
    log.info(f"Diagnosis: {summary['ok']} OK, {summary['warnings']} warnings, {summary['errors']} errors")
    log.info(f"Overall status: {summary['overall_status']}")
    for rec in report.get('recommendations', []):
        log.info(f"  Recommendation: {rec}")


# ─────────────────────────────────────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────────────────────────────────────

async def main() -> None:
    args = _parse_args()

    # ── Iran detection shortcut ───────────────────────────────────────────
    if args.detect_iran:
        await run_iran_detection()
        return

    # ── Anti-DPI analysis shortcut ─────────────────────────────────────────
    if args.anti_dpi:
        run_anti_dpi_analysis()
        return

    # ── Anti-filter analysis shortcut ──────────────────────────────────────
    if args.anti_filter:
        run_anti_filter_analysis()
        return

    # ── Auto-debug shortcut ────────────────────────────────────────────────
    if args.auto_debug:
        run_auto_debug()
        return

    # ── Initialise history ────────────────────────────────────────────────
    history = HistoryManager()
    # FIX 2: resolve accumulated modes list; validate each entry.
    _VALID_MODES = {"all", "collect", "test", "score", "export", "notify"}
    raw_modes: list = args.modes or ["all"]
    for m in raw_modes:
        if m not in _VALID_MODES:
            log.error(f"Unknown mode {m!r}. Valid choices: {sorted(_VALID_MODES)}")
            sys.exit(1)
    # Expand "all" to the full ordered sequence; preserve order for others.
    _ALL_STAGES = ["collect", "test", "score", "export", "notify"]
    if "all" in raw_modes:
        modes = _ALL_STAGES
    else:
        # Deduplicate while preserving order
        seen: set = set()
        modes = [m for m in raw_modes if not (m in seen or seen.add(m))]  # type: ignore[func-returns-value]

    start = utc_now()
    log.info(f"🚀 Tor Bridges Ultra Collector — modes={modes} | {start.strftime('%Y-%m-%d %H:%M UTC')}")

    if "collect" in modes:
        await stage_collect(history)

    if "test" in modes:
        await stage_test(history, workers=args.workers, deep=args.deep)

    if "score" in modes:
        stage_score(history)

    stats: dict = {}
    if "export" in modes:
        stats = stage_export(history)

    if "notify" in modes or args.notify:
        if not stats:
            stats = history.get_stats()
            # Try to find an existing zip
            zip_candidate = os.path.join(config.BRIDGE_DIR, "tor_bridges.zip")
            if os.path.exists(zip_candidate):
                stats["__zip_path__"] = zip_candidate
        stage_notify(stats, force=args.notify)

    elapsed = (utc_now() - start).total_seconds()
    log.info(f"✅ Pipeline finished in {elapsed:.1f}s.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Interrupted by user.")
        sys.exit(0)
