#!/usr/bin/env python3
"""
ooni_correlator.py — OONI measurement cross-referencer for TorShield-IR.

Queries the OONI API for Tor bridge measurements from Iranian probes over
the last 7 days, cross-references the results with the Go probe_scheduler's
merged output, computes a composite reachability score per bridge, writes a
human-readable Markdown report and a machine-readable JSON summary, and
exits with code 1 if fewer than 30 % of tested bridges achieve a composite
score above 0.5 (triggering a GitHub Actions failure notification).

Composite scoring formula:
  composite = 0.35 * tcp_reachable
            + 0.40 * ooni_factor     (1.0 clean | 0.5 unknown | 0.0 anomaly)
            + 0.25 * ripe_factor     (1.0 reachable | 0.5 untested | 0.0 unreachable)
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from requests.adapters import HTTPAdapter, Retry

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

OONI_BASE        = "https://api.ooni.io/api/v1/measurements"
OONI_TIMEOUT     = 30
OONI_RATE_SLEEP  = 0.2   # 5 req/s → 200 ms between requests
PASS_THRESHOLD   = 0.30  # exit 1 if fewer than 30 % score above 0.5

IRAN_RESULTS_PATH     = Path("bridge/iran_results.json")
SCHEDULER_RESULTS_PATH = Path("data/scheduler_results.json")
LATEST_RESULTS_PATH   = Path("data/latest-results.json")
REPORT_PATH           = Path("docs/iran-bridge-status.md")

REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
LATEST_RESULTS_PATH.parent.mkdir(parents=True, exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# HTTP session
# ─────────────────────────────────────────────────────────────────────────────

def _make_session() -> requests.Session:
    s = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=2.0,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
    )
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.headers["Accept"]     = "application/json"
    s.headers["User-Agent"] = "TorShield-IR/1.0"
    return s


_session = _make_session()

# ─────────────────────────────────────────────────────────────────────────────
# OONI API queries
# ─────────────────────────────────────────────────────────────────────────────

def _ooni_query(
    test_name: str,
    since: str,
    until: str,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """Query OONI for IR measurements of a given test_name. Returns result list."""
    params: Dict[str, Any] = {
        "probe_cc":       "IR",
        "test_name":      test_name,
        "since":          since,
        "until":          until,
        "limit":          str(limit),
        "order_by":       "test_start_time",
    }
    time.sleep(OONI_RATE_SLEEP)
    try:
        r = _session.get(OONI_BASE, params=params, timeout=OONI_TIMEOUT)
        if r.status_code == 200:
            return r.json().get("results", [])
        log.warning(f"OONI [{test_name}] HTTP {r.status_code}")
        return []
    except Exception as exc:
        log.warning(f"OONI [{test_name}] error: {exc}")
        return []


def fetch_iran_measurements(days: int = 7) -> Dict[str, List[Dict[str, Any]]]:
    """
    Fetch Tor-related measurements from Iran over the last `days` days.
    Returns a dict keyed by bridge IP (or 'global') with measurement lists.
    """
    now    = datetime.now(tz=timezone.utc)
    since  = (now - timedelta(days=days)).strftime("%Y-%m-%d")
    until  = now.strftime("%Y-%m-%d")

    log.info(f"Querying OONI measurements from Iran ({since} → {until})…")

    # torsf = Tor Snowflake; tor = general Tor/obfs4 measurements
    sf_results   = _ooni_query("torsf", since, until, limit=100)
    tor_results  = _ooni_query("tor",   since, until, limit=100)

    all_results: List[Dict[str, Any]] = sf_results + tor_results
    log.info(f"OONI: {len(all_results)} measurements retrieved (torsf={len(sf_results)}, tor={len(tor_results)})")

    # Index by input field (usually bridge IP or bridge line)
    indexed: Dict[str, List[Dict[str, Any]]] = {}
    for m in all_results:
        key = m.get("input") or "global"
        indexed.setdefault(key, []).append(m)
    return indexed


# ─────────────────────────────────────────────────────────────────────────────
# Composite scoring
# ─────────────────────────────────────────────────────────────────────────────

def _ooni_factor(measurements: List[Dict[str, Any]]) -> float:
    """Compute the OONI dimension of the composite score (0.0–1.0)."""
    if not measurements:
        return 0.5  # no data → neutral
    any_anomaly = any(m.get("anomaly") or m.get("confirmed") for m in measurements)
    all_clean   = all(not m.get("anomaly") and not m.get("confirmed") for m in measurements)
    if any_anomaly:
        return 0.0
    if all_clean:
        return 1.0
    return 0.5


def _ripe_factor(ripe_reachable: Optional[bool], ripe_tested: bool) -> float:
    """Compute the RIPE Atlas dimension of the composite score (0.0–1.0)."""
    if not ripe_tested:
        return 0.5
    return 1.0 if ripe_reachable else 0.0


def compute_composite(
    tcp_reachable: bool,
    ooni_measurements: List[Dict[str, Any]],
    ripe_reachable: Optional[bool],
    ripe_tested: bool,
) -> float:
    """
    composite = 0.35 * tcp + 0.40 * ooni_factor + 0.25 * ripe_factor
    """
    tcp_f  = 1.0 if tcp_reachable else 0.0
    ooni_f = _ooni_factor(ooni_measurements)
    ripe_f = _ripe_factor(ripe_reachable, ripe_tested)
    return round(0.35 * tcp_f + 0.40 * ooni_f + 0.25 * ripe_f, 4)


# ─────────────────────────────────────────────────────────────────────────────
# Data loading helpers
# ─────────────────────────────────────────────────────────────────────────────

def _load_iran_results() -> Dict[str, Any]:
    """Load bridge/iran_results.json written by the Go iran_tester."""
    if not IRAN_RESULTS_PATH.exists():
        log.warning(f"{IRAN_RESULTS_PATH} not found — OONI-only mode.")
        return {"bridges": [], "summary": {}}
    return json.loads(IRAN_RESULTS_PATH.read_text(encoding="utf-8"))


def _load_scheduler_results() -> Dict[str, Dict[str, Any]]:
    """Load data/scheduler_results.json, indexed by bridge_line."""
    if not SCHEDULER_RESULTS_PATH.exists():
        return {}
    data = json.loads(SCHEDULER_RESULTS_PATH.read_text(encoding="utf-8"))
    return {r["bridge_line"]: r for r in data.get("results", [])}


# ─────────────────────────────────────────────────────────────────────────────
# Main correlation logic
# ─────────────────────────────────────────────────────────────────────────────

def _build_daily_history(
    ooni_by_ip: Dict[str, List[Dict[str, Any]]],
) -> Dict[str, List[tuple]]:
    """
    FEATURE 5: Build per-bridge daily anomaly histories for the quarantine
    rolling z-score engine.

    Returns {host: [(date_str, is_anomaly), ...]} sorted ascending by date.
    """
    from collections import defaultdict
    daily: Dict[str, Dict[str, bool]] = defaultdict(dict)
    for host, measurements in ooni_by_ip.items():
        for m in measurements:
            ts_raw = m.get("test_start_time", "")
            if not ts_raw:
                continue
            try:
                date_str = ts_raw[:10]  # "YYYY-MM-DD"
                is_anom  = bool(m.get("anomaly") or m.get("confirmed"))
                # If multiple measurements on same day, OR them (conservative)
                daily[host][date_str] = daily[host].get(date_str, False) or is_anom
            except Exception:
                continue
    return {
        host: sorted([(d, v) for d, v in day_map.items()], key=lambda x: x[0])
        for host, day_map in daily.items()
    }


def correlate() -> List[Dict[str, Any]]:
    """
    Cross-reference OONI, iran_tester, and RIPE Atlas results for each bridge.
    Applies quarantine exclusions (FEATURE 5) and composite scoring.
    Returns a list of enriched bridge records with composite_score attached.
    """
    iran_data     = _load_iran_results()
    sched_by_line = _load_scheduler_results()
    ooni_by_ip    = fetch_iran_measurements(days=7)

    # FEATURE 5: build daily histories and update quarantine state
    daily_hist = _build_daily_history(ooni_by_ip)
    try:
        from quarantine_manager import QuarantineManager
        qm = QuarantineManager()
        qm_summary = qm.update_from_ooni_history(daily_hist)
        quarantined = qm.quarantined_set()
        log.info(
            f"Quarantine: {qm_summary['currently_quarantined']} bridges quarantined, "
            f"{qm_summary['newly_quarantined']} new this run."
        )
    except Exception as exc:
        log.warning(f"QuarantineManager error (non-fatal): {exc}")
        quarantined = set()

    enriched: List[Dict[str, Any]] = []

    for bridge_rec in iran_data.get("bridges", []):
        host      = bridge_rec.get("host", "")
        line      = bridge_rec.get("line", "")
        tcp_ok    = bridge_rec.get("tcp_reachable", False)

        # FEATURE 5: hard-exclude quarantined bridges from enriched list
        if host and host in quarantined:
            bridge_rec["quarantined"] = True
            bridge_rec["composite_score"] = 0.0
            enriched.append(bridge_rec)
            continue

        # OONI: look up by host IP or full bridge line
        ooni_meas = ooni_by_ip.get(host, []) or ooni_by_ip.get(line, [])

        # RIPE Atlas: look up from scheduler merged results
        sched_rec      = sched_by_line.get(line, {})
        ripe_tested    = sched_rec.get("ripe_tested", False)
        ripe_reachable = sched_rec.get("ripe_reachable") if ripe_tested else None

        score = compute_composite(tcp_ok, ooni_meas, ripe_reachable, ripe_tested)

        # FEATURE 5: apply quarantine flag
        bridge_rec["quarantined"] = False

        enriched.append({
            **bridge_rec,
            "ooni_measurements_ir": len(ooni_meas),
            "ooni_factor":          _ooni_factor(ooni_meas),
            "ripe_tested":          ripe_tested,
            "ripe_reachable":       ripe_reachable,
            "composite_score":      score,
        })

    # Sort by composite score descending
    enriched.sort(key=lambda r: r.get("composite_score", 0.0), reverse=True)
    return enriched


# ─────────────────────────────────────────────────────────────────────────────
# Output writers
# ─────────────────────────────────────────────────────────────────────────────

def write_latest_results(records: List[Dict[str, Any]]) -> None:
    above_threshold = sum(1 for r in records if r.get("composite_score", 0) > 0.5)
    payload = {
        "schema":           "1.0",
        "generated_at":     datetime.now(tz=timezone.utc).isoformat(),
        "total_bridges":    len(records),
        "above_0_5":        above_threshold,
        "pass_rate":        round(above_threshold / len(records), 4) if records else 0.0,
        "bridges":          records,
    }
    LATEST_RESULTS_PATH.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    log.info(f"data/latest-results.json: {len(records)} records written.")


def write_markdown_report(records: List[Dict[str, Any]]) -> None:
    ts        = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total     = len(records)
    above     = sum(1 for r in records if r.get("composite_score", 0) > 0.5)
    pass_rate = above / total if total else 0.0

    # Summary statistics
    ooni_clean   = sum(1 for r in records if r.get("ooni_factor", 0.5) == 1.0)
    ooni_anomaly = sum(1 for r in records if r.get("ooni_factor", 0.5) == 0.0)
    ooni_unknown = total - ooni_clean - ooni_anomaly

    # Top-20 working bridges table
    top20 = [r for r in records if r.get("composite_score", 0) > 0.5][:20]

    def transport_badge(t: str) -> str:
        badges = {
            "snowflake":  "🌨️",
            "webtunnel":  "🌐",
            "obfs4":      "🔐",
            "meek_lite":  "☁️",
            "vanilla":    "🟡",
        }
        return badges.get(t, "❓")

    rows = []
    for r in top20:
        host   = r.get("host", "")[:20]
        port   = r.get("port", 0)
        t_icon = transport_badge(r.get("transport", ""))
        score  = f"{r.get('composite_score', 0):.2f}"
        ooni   = "✅" if r.get("ooni_factor", 0.5) == 1.0 else ("❌" if r.get("ooni_factor", 0.5) == 0.0 else "❓")
        tcp    = "✅" if r.get("tcp_reachable") else "❌"
        rows.append(f"| `{host}:{port}` | {t_icon} | {tcp} | {ooni} | `{score}` |")

    table_body = "\n".join(rows) if rows else "| — | — | — | — | — |"

    status_emoji = "✅" if pass_rate >= PASS_THRESHOLD else "🚨"

    report = f"""# {status_emoji} TorShield-IR — Iran Bridge Status Report

**Generated:** `{ts}`  
**Pipeline:** Python scraper → Go iran_tester → Rust bridge-probe → OONI correlator

---

## Summary

| Metric | Value |
| :--- | :--- |
| Total bridges analysed | `{total}` |
| Composite score > 0.5 | `{above}` ({pass_rate:.0%}) |
| OONI clean (Iran) | `{ooni_clean}` |
| OONI anomaly/blocked | `{ooni_anomaly}` |
| OONI no data | `{ooni_unknown}` |
| Quality gate (≥ 30 %) | `{"PASS ✅" if pass_rate >= PASS_THRESHOLD else "FAIL 🚨"}` |

---

## Iran DPI Intelligence

Iran's censorship infrastructure (SIAM) uses:
- **TLS fingerprinting** — JA3 hash matching for known Tor patterns (`e7d705a3286e19ea42f587b344ee6865`)
- **Port-based blocking** — Ports 9001, 9030, 9050 are consistently blocked
- **IP-based blocking** — Known Tor relay/bridge IPs are blocklisted within 24–48 h of first use
- **Traffic volume anomaly detection** — Unusual traffic shapes are flagged

### Recommended Transport Priority for Iran

```
Snowflake → WebTunnel (CDN-fronted) → obfs4 (port 443) → meek-lite → vanilla
```

---

## Top {len(top20)} Working Bridges (composite score > 0.5)

| Host:Port | Transport | TCP | OONI-IR | Score |
| :--- | :---: | :---: | :---: | :---: |
{table_body}

---

## Classification Definitions

| Status | Meaning |
| :--- | :--- |
| `iran_likely_working` | OONI shows clean results from Iranian probes in last 7 days |
| `iran_likely_blocked` | OONI shows anomaly/confirmed block from Iranian probes |
| `iran_frequently_blocked` | Recurrence rate > 2 blocks per 30-day period |
| `iran_unknown` | No OONI data from Iranian probes; TCP reachable from GitHub Actions |
| `tcp_unreachable` | TCP connection failed from GitHub Actions runner (likely globally down) |
| `iran_asn_blocked` | Bridge IP resolves to an Iranian ISP ASN — excluded from all packs |

---

## DPI Risk Flags

| Flag | Description |
| :--- | :--- |
| `iran_dpi_high_risk` | Bridge uses a JA3 fingerprint or port known to Iran's DPI blocklist |
| `iran_port_high_risk` | Bridge is on port 9001, 9030, or 9050 |
| `domain_front_degraded` | WebTunnel front domain resolves to a non-CDN IP |
| `domain_front_cdn_ok` | WebTunnel front domain resolves to a known CDN (Cloudflare, Azure, Fastly) |

---

*This report is generated automatically by [TorShield-IR](https://github.com/user/torshield-ir).*
"""

    REPORT_PATH.write_text(report, encoding="utf-8")
    log.info(f"docs/iran-bridge-status.md written ({len(records)} bridge records).")


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    log.info("═══ OONI Correlator ═════════════════════════════════════════")

    records = correlate()

    if not records:
        log.warning("No bridge records to process — writing empty report.")
        write_latest_results([])
        write_markdown_report([])
        sys.exit(0)

    write_latest_results(records)
    write_markdown_report(records)

    # Quality gate: exit code 1 if < 30 % of tested bridges score above 0.5
    total      = len(records)
    above      = sum(1 for r in records if r.get("composite_score", 0) > 0.5)
    pass_rate  = above / total if total else 0.0

    log.info(f"Quality gate: {above}/{total} bridges score > 0.5 ({pass_rate:.0%})")

    if pass_rate < PASS_THRESHOLD:
        log.error(
            f"QUALITY GATE FAILED: Only {pass_rate:.0%} of bridges exceed composite "
            f"score 0.5 (threshold: {PASS_THRESHOLD:.0%}). "
            "This may indicate widespread blocking or a pipeline failure."
        )
        sys.exit(1)

    log.info("Quality gate PASSED. ✅")
    log.info("═══ Correlator done ═════════════════════════════════════════")


if __name__ == "__main__":
    main()
