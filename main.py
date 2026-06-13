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
    p.add_argument(
        "--utls-status", action="store_true",
        help="Show uTLS evasion layer status",
    )
    p.add_argument(
        "--circuit-status", action="store_true",
        help="Show 11-slot circuit breaker status",
    )
    p.add_argument(
        "--registry-status", action="store_true",
        help="Show elite registry model discovery status",
    )
    p.add_argument(
        "--telemetry-report", action="store_true",
        help="Generate 24-hour telemetry report",
    )
    p.add_argument(
        "--full-shield", action="store_true",
        help="Run full shield: anti-DPI + anti-filter + uTLS + circuit breaker check",
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

    # Also run Quantum Shield assessment if available
    try:
        from torshield_ai_gateway.iran_quantum_shield import get_quantum_shield
        shield = get_quantum_shield()
        assessment = shield.assess_dpi_threat()
        log.info(f"Quantum Shield: Level={assessment.threat_level.name}, "
                 f"Score={assessment.threat_score:.2f}, "
                 f"NIN Probability={assessment.nin_probability:.2f}")
        log.info(f"Best transports: {', '.join(t.transport_name for t in assessment.best_transports[:3])}")
    except Exception as e:
        log.debug(f"Quantum Shield assessment skipped: {e}")


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

    # Also run Quantum Shield diagnosis if available
    try:
        from torshield_ai_gateway.iran_quantum_shield import get_quantum_shield
        shield = get_quantum_shield()
        q_report = shield.run_auto_diagnosis()
        log.info(f"Quantum Shield Diagnosis: {q_report['overall_status']}")
        for err in q_report.get('errors', []):
            log.error(f"  QS Error: {err}")
        for warn in q_report.get('warnings', []):
            log.warning(f"  QS Warning: {warn}")
    except Exception as e:
        log.debug(f"Quantum Shield diagnosis skipped: {e}")


def run_utls_status() -> None:
    """Show uTLS evasion layer status."""
    from uTLS_evasion_layer import UTLSManager
    log.info("━━ uTLS EVASION LAYER STATUS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    manager = UTLSManager()
    status = manager.get_status()
    for key, value in status.items():
        log.info(f"  {key}: {value}")

    # Show SNI masking config
    sni_config = manager.get_sni_masking_config()
    log.info(f"  SNI Front: {sni_config['sni_front']} ({sni_config['front_type']})")

    # Show current profile
    profile = manager.get_randomized_profile()
    log.info(f"  Active Profile: {profile.name} (JA3: {profile.ja3_hash[:16]}...)")


def run_circuit_status() -> None:
    """Show 11-slot circuit breaker status."""
    from circuit_breaker_11slot import CircuitBreaker11Slot
    log.info("━━ 11-SLOT CIRCUIT BREAKER STATUS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    cb = CircuitBreaker11Slot()
    status = cb.get_status()
    log.info(f"  Configured: {status['configured_slots']}/{status['total_slots']}")
    log.info(f"  Available: {status['available_slots']}")
    log.info(f"  Blacklisted: {status['blacklisted_slots']}")
    log.info(f"  Circuit Open: {status['circuit_open_slots']}")
    log.info(f"  Rotation Counter: {status['rotation_counter']}")

    for slot_idx, slot_info in status.get('slots', {}).items():
        if slot_info['configured']:
            state = "AVAILABLE" if slot_info['available'] else ("BLACKLISTED" if slot_info['blacklisted'] else "CIRCUIT OPEN")
            log.info(
                f"  Slot {slot_idx}: {state} | "
                f"health={slot_info['health_score']:.3f} | "
                f"success_rate={slot_info['success_rate']:.3f} | "
                f"latency={slot_info['avg_latency_ms']:.0f}ms | "
                f"gateway={'YES' if slot_info['has_gateway'] else 'NO'}"
            )


def run_registry_status() -> None:
    """Show elite registry model discovery status."""
    from elite_registry import EliteRegistry
    log.info("━━ ELITE REGISTRY STATUS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    registry = EliteRegistry()
    status = registry.get_status()
    log.info(f"  Total Models: {status['total_models']}")
    log.info(f"  Available Models: {status['available_models']}")
    log.info(f"  Last Refresh: {status['last_refresh']}")
    log.info(f"  Cache Age: {status['cache_age_hours']}h")

    # Show top 5 models
    log.info("  Top 5 Models (by fitness score):")
    for i, model in enumerate(status.get('top_5_models', []), 1):
        log.info(
            f"    {i}. {model['model_id']} "
            f"(fitness={model['fitness_score']:.3f}, "
            f"dpi={model['dpi_resistance_index']:.3f}, "
            f"latency={model['response_latency']:.3f}, "
            f"context={model['context_window_utility']:.3f})"
        )


def run_telemetry_report() -> None:
    """Generate 24-hour telemetry report."""
    from telemetry_watcher import TelemetryWatcher
    log.info("━━ 24-HOUR TELEMETRY REPORT ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    watcher = TelemetryWatcher()
    report = watcher.get_24h_summary()
    log.info(f"  Date: {report.date}")
    log.info(f"  Total DPI Events: {report.total_dpi_events}")
    log.info(f"  DPI Blocked: {report.dpi_events_blocked}")
    log.info(f"  DPI Evaded: {report.dpi_events_evaded}")
    log.info(f"  Evasion Success Rate: {report.evasion_success_rate:.1%}")
    log.info(f"  Slot Failures: {report.total_slot_failures}")
    log.info(f"  Slots Poisoned: {report.slots_poisoned}")
    log.info(f"  Slots Recovered: {report.slots_recovered}")
    log.info(f"  Self-Heal Events: {report.total_self_heal_events}")
    log.info(f"  Failures Recovered: {report.failures_recovered}")
    log.info(f"  Model Resolution Failures: {report.model_resolution_failures}")
    log.info(f"  Auto-Debug Triggered: {report.auto_debug_triggered}")
    log.info(f"  Uptime: {report.uptime_percentage:.1f}%")

    # Also show current status
    current_status = watcher.get_status()
    log.info(f"  Current Iran Time: {current_status.get('iran_time', 'N/A')}")
    log.info(f"  Censorship Intensity: {current_status.get('censorship_intensity', 'N/A')}")
    log.info(f"  High Censorship Hours: {current_status.get('is_high_censorship_hours', False)}")


def run_full_shield() -> None:
    """Run full shield: all evasion and monitoring systems."""
    log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    log.info("━━ FULL SHIELD: ALL SYSTEMS CHECK ━━━━━━━━━━━━━━━━━━━━━━━━━")
    log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

    # 1. Anti-DPI analysis
    run_anti_dpi_analysis()

    # 2. Anti-filter analysis
    run_anti_filter_analysis()

    # 3. uTLS status
    run_utls_status()

    # 4. Circuit breaker status
    run_circuit_status()

    # 5. Registry status
    run_registry_status()

    # 6. Telemetry report
    run_telemetry_report()

    # 7. Auto-debug check
    from telemetry_watcher import get_telemetry
    telemetry = get_telemetry()
    should_debug = telemetry.check_auto_debug()
    if should_debug:
        log.info("━━ AUTO-DEBUG TRIGGERED BY TELEMETRY ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
        run_auto_debug()

    log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    log.info("━━ FULL SHIELD CHECK COMPLETE ━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    log.info("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")


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

    # ── uTLS status shortcut ──────────────────────────────────────────────
    if args.utls_status:
        run_utls_status()
        return

    # ── Circuit breaker status shortcut ───────────────────────────────────
    if args.circuit_status:
        run_circuit_status()
        return

    # ── Elite registry status shortcut ────────────────────────────────────
    if args.registry_status:
        run_registry_status()
        return

    # ── Telemetry report shortcut ─────────────────────────────────────────
    if args.telemetry_report:
        run_telemetry_report()
        return

    # ── Full shield shortcut ──────────────────────────────────────────────
    if args.full_shield:
        run_full_shield()
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
