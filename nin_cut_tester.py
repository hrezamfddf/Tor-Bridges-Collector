#!/usr/bin/env python3
"""
nin_cut_tester.py — Stage 8k: NIN Internet-Cut Survivability Tester

Tests Tor bridges for reachability inside Iran's National Information Network
during complete international internet blackout events.  Operates exclusively
on IP addresses and ports — zero DNS lookups — because DNS is fully blocked
during NIN-isolation events.

Scoring criteria (0.0–1.0):
  a. IP falls within Iranian CDN or domestic ASN range → +0.40
  b. Port is NIN-allowed (80, 443, 8080, 8443) → +0.30
  c. Transport is WebTunnel or obfs4 → +0.30

Outputs:
  data/nin_cut_report.json     — per-bridge scores + aggregate summary
  export/nin_cut_survivable.txt — bridges with score >= 0.60
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# ── File paths ────────────────────────────────────────────────────────────────
INPUT_FILE   = Path("export/nin_cut_bridges.txt")
REPORT_PATH  = Path("data/nin_cut_report.json")
EXPORT_PATH  = Path("export/nin_cut_survivable.txt")

# ── NIN-allowed ports ─────────────────────────────────────────────────────────
NIN_ALLOWED_PORTS: set[int] = {80, 443, 8080, 8443}

# ── High-survivability transport types ────────────────────────────────────────
HIGH_SURVIVAL_TRANSPORTS: set[str] = {"webtunnel", "obfs4"}

# ── Iranian domestic ASN CIDR ranges ─────────────────────────────────────────
# AS44244 ITC, AS16322 ParsOnline, AS48159 TCI, AS58224 Iran Telecom,
# AS24631 Afranet, ArvanCloud, RightTel — approximate prefix coverage.
IRAN_DOMESTIC_CIDRS: list[ipaddress.IPv4Network] = []

_RAW_IRAN_CIDRS = [
    # ITC (AS44244)
    "5.22.192.0/18", "5.23.112.0/21", "5.53.32.0/19",
    "5.160.0.0/14", "5.200.64.0/18", "5.201.128.0/17",
    "5.250.0.0/17",
    # TCI (AS58224)
    "2.144.0.0/13", "2.176.0.0/12",
    "37.137.0.0/15", "78.38.0.0/15", "85.185.0.0/16",
    "91.92.0.0/22", "91.186.188.0/22",
    "94.182.0.0/16", "94.183.0.0/16",
    "109.122.192.0/18", "185.1.74.0/24",
    # ParsOnline (AS16322)
    "91.108.4.0/22", "91.108.56.0/22",
    # ArvanCloud CDN (domestic)
    "185.143.232.0/22", "185.215.232.0/22", "179.43.145.0/24",
    # Afranet (AS24631)
    "87.247.168.0/21", "94.74.128.0/17",
    # MCI / Irancell
    "85.204.100.0/22", "79.175.128.0/17",
    # Rightel
    "185.213.176.0/22",
    # Shatel
    "31.14.80.0/20", "31.184.128.0/18",
    # Iranian CDN / hosting
    "5.34.192.0/19", "5.56.128.0/17",
    "46.143.196.0/22", "46.209.0.0/16",
    "78.109.192.0/18", "78.157.32.0/19",
    "80.75.0.0/17", "80.191.0.0/16",
    "82.99.192.0/18", "82.138.128.0/17",
    "185.8.172.0/22", "185.55.224.0/22",
    "188.136.128.0/17", "193.151.128.0/17",
    "194.5.174.0/23", "194.60.240.0/21",
]

for _cidr in _RAW_IRAN_CIDRS:
    try:
        IRAN_DOMESTIC_CIDRS.append(ipaddress.IPv4Network(_cidr, strict=False))
    except ValueError:
        pass


# ── Helpers ───────────────────────────────────────────────────────────────────

def _parse_bridge_line(line: str) -> dict[str, Any] | None:
    """
    Parse a Tor bridge line of various formats.
    Returns dict with keys: raw, ip, port, transport.
    Returns None if the line cannot be parsed.
    No DNS lookups are performed — IP addresses only.
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    transport = "vanilla"
    rest = line

    # Detect pluggable transport prefix
    pt_match = re.match(r"^(obfs4|webtunnel|snowflake|meek_lite|obfs3)\s+", line, re.I)
    if pt_match:
        transport = pt_match.group(1).lower()
        rest = line[pt_match.end():]

    # Extract ip:port — accept both IPv4 and [IPv6]:port
    # Try IPv4 first
    ipv4_match = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})\b", rest)
    if ipv4_match:
        ip_str   = ipv4_match.group(1)
        port_str = ipv4_match.group(2)
    else:
        # Try IPv6 [addr]:port
        ipv6_match = re.search(r"\[([0-9a-fA-F:]+)\]:(\d{2,5})", rest)
        if ipv6_match:
            ip_str   = ipv6_match.group(1)
            port_str = ipv6_match.group(2)
        else:
            return None

    try:
        port = int(port_str)
        if not (1 <= port <= 65535):
            return None
        # Validate IP — skip if it's a hostname (no digits-only octets check)
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return None

    return {
        "raw":       line,
        "ip":        str(ip_obj),
        "port":      port,
        "transport": transport,
        "ip_obj":    ip_obj,
    }


def _is_iran_domestic(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True if the IP falls within known Iranian domestic ASN prefixes."""
    if not isinstance(ip_obj, ipaddress.IPv4Address):
        return False
    for cidr in IRAN_DOMESTIC_CIDRS:
        if ip_obj in cidr:
            return True
    return False


def _score_bridge(parsed: dict[str, Any]) -> float:
    """Compute NIN-cut survivability score 0.0–1.0."""
    score = 0.0

    # Criterion a: domestic IP
    if _is_iran_domestic(parsed["ip_obj"]):
        score += 0.40

    # Criterion b: NIN-allowed port
    if parsed["port"] in NIN_ALLOWED_PORTS:
        score += 0.30

    # Criterion c: high-survivability transport
    if parsed["transport"].lower() in HIGH_SURVIVAL_TRANSPORTS:
        score += 0.30

    return round(min(score, 1.0), 4)


async def _probe_bridge(parsed: dict[str, Any]) -> dict[str, Any]:
    """
    Attempt a TCP connection to the bridge using asyncio (no DNS lookup).
    Adds 'tcp_reachable' and 'tcp_latency_ms' keys.
    Non-critical: if the connection fails for any reason the record is
    still returned; only the tcp_reachable flag changes.
    """
    ip   = parsed["ip"]
    port = parsed["port"]
    result: dict[str, Any] = {
        "raw":          parsed["raw"],
        "ip":           ip,
        "port":         port,
        "transport":    parsed["transport"],
        "domestic_ip":  _is_iran_domestic(parsed["ip_obj"]),
        "nin_port":     port in NIN_ALLOWED_PORTS,
        "nin_transport": parsed["transport"].lower() in HIGH_SURVIVAL_TRANSPORTS,
        "nin_score":    _score_bridge(parsed),
        "tcp_reachable": False,
        "tcp_latency_ms": None,
    }

    try:
        import time
        t0 = time.monotonic()
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=8.0,
        )
        latency = round((time.monotonic() - t0) * 1000, 1)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        result["tcp_reachable"]   = True
        result["tcp_latency_ms"]  = latency
        # Boost score if actually reachable
        result["nin_score"] = round(min(result["nin_score"] + 0.15, 1.0), 4)
    except Exception as exc:
        log.debug("TCP probe %s:%d failed: %s", ip, port, exc)

    return result


async def _run_all_probes(bridges: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Run TCP probes for all bridges concurrently (max 50 at once)."""
    semaphore = asyncio.Semaphore(50)

    async def _limited(b: dict[str, Any]) -> dict[str, Any]:
        async with semaphore:
            return await _probe_bridge(b)

    tasks = [_limited(b) for b in bridges]
    results = await asyncio.gather(*tasks, return_exceptions=False)
    return list(results)


def _load_bridges() -> list[dict[str, Any]]:
    """Load and parse bridge lines from the input file."""
    if not INPUT_FILE.exists():
        log.warning("Input file not found: %s — returning empty list.", INPUT_FILE)
        return []
    raw_lines = INPUT_FILE.read_text(encoding="utf-8").splitlines()
    parsed: list[dict[str, Any]] = []
    skipped = 0
    for line in raw_lines:
        result = _parse_bridge_line(line)
        if result:
            parsed.append(result)
        elif line.strip() and not line.startswith("#"):
            skipped += 1
    log.info("Loaded %d bridges from %s (%d skipped / unparseable).",
             len(parsed), INPUT_FILE, skipped)
    return parsed


def _write_outputs(results: list[dict[str, Any]]) -> None:
    """Write JSON report and survivable bridge list."""
    Path("data").mkdir(parents=True, exist_ok=True)
    Path("export").mkdir(parents=True, exist_ok=True)

    survivable = [r for r in results if r.get("nin_score", 0.0) >= 0.60]
    reachable  = [r for r in results if r.get("tcp_reachable")]

    report: dict[str, Any] = {
        "generated_at":        datetime.now(timezone.utc).isoformat(),
        "total_bridges":       len(results),
        "survivable_count":    len(survivable),
        "tcp_reachable_count": len(reachable),
        "score_threshold":     0.60,
        "scoring_note": (
            "Score components: domestic_ip (+0.40), nin_port (+0.30), "
            "nin_transport (+0.30), tcp_reachable_bonus (+0.15, capped at 1.0). "
            "NIN-cut scenario: international internet fully blocked; "
            "only traffic through Iranian ASNs remains reachable."
        ),
        "iran_asns_checked": [
            "AS44244 ITC", "AS16322 ParsOnline", "AS48159 TCI",
            "AS58224 Iran Telecom", "AS24631 Afranet", "ArvanCloud",
        ],
        "bridges": results,
    }

    REPORT_PATH.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    log.info("NIN-cut report written: %d bridges, %d survivable → %s",
             len(results), len(survivable), REPORT_PATH)

    # Export survivable bridge lines
    lines = [r["raw"] for r in survivable]
    EXPORT_PATH.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    log.info("Survivable bridges written: %d → %s", len(lines), EXPORT_PATH)


def _write_empty_outputs() -> None:
    """Write empty but valid outputs when input is missing."""
    Path("data").mkdir(parents=True, exist_ok=True)
    Path("export").mkdir(parents=True, exist_ok=True)
    empty_report: dict[str, Any] = {
        "generated_at":     datetime.now(timezone.utc).isoformat(),
        "total_bridges":    0,
        "survivable_count": 0,
        "bridges":          [],
        "note":             f"Input file not found: {INPUT_FILE}",
    }
    REPORT_PATH.write_text(json.dumps(empty_report, indent=2), encoding="utf-8")
    EXPORT_PATH.write_text("", encoding="utf-8")
    log.info("Empty outputs written (input file missing).")


def main() -> int:
    log.info("═══ Stage 8k: NIN Internet-Cut Survivability Tester ════════")

    bridges = _load_bridges()
    if not bridges:
        _write_empty_outputs()
        log.info("No bridges to test — exiting cleanly.")
        return 0

    log.info("Running TCP probes on %d bridges (no DNS)…", len(bridges))
    try:
        results = asyncio.run(_run_all_probes(bridges))
    except Exception as exc:
        log.error("Async probe loop failed: %s — falling back to score-only mode.", exc)
        # Score-only fallback: no TCP probing
        results = []
        for b in bridges:
            results.append({
                "raw":           b["raw"],
                "ip":            b["ip"],
                "port":          b["port"],
                "transport":     b["transport"],
                "domestic_ip":   _is_iran_domestic(b["ip_obj"]),
                "nin_port":      b["port"] in NIN_ALLOWED_PORTS,
                "nin_transport": b["transport"].lower() in HIGH_SURVIVAL_TRANSPORTS,
                "nin_score":     _score_bridge(b),
                "tcp_reachable": False,
                "tcp_latency_ms": None,
            })

    _write_outputs(results)

    survivable = sum(1 for r in results if r.get("nin_score", 0.0) >= 0.60)
    log.info("═══ Stage 8k done: %d/%d bridges NIN-cut survivable ════════",
             survivable, len(results))
    return 0


if __name__ == "__main__":
    sys.exit(main())
