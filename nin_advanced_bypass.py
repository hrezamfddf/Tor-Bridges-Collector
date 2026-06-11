#!/usr/bin/env python3
"""
nin_advanced_bypass.py — Iran NIN (National Internet / Intranet) Advanced Bypass

During Iran's National Internet (NIN / شبکه ملی اطلاعات) activation — when
international internet access is cut — only specific CDN/domestic endpoints
remain reachable.  This module identifies bridges that can survive NIN by:

  1. Detecting which bridges use CDN domains accessible within NIN
     (Arvan Cloud, domestic CDNs, certain Cloudflare IPs allowed by IRGC)
  2. Scoring domain-fronting quality (WebTunnel > meek_lite >> obfs4)
  3. Writing a prioritised bridge pack for NIN scenarios

Key references:
  - Iran NIN CDNs accessible during cuts: ArvanCloud, DerakCloud, major IR ISP CDNs
  - IRGC-permitted international endpoints (2022-2026 confirmed data)
  - Censored Planet / OONI Iran reports 2022-2024
"""

from __future__ import annotations
import json
import logging
import re
import socket
from pathlib import Path
from typing import Any
import urllib.request

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s %(message)s")

# CDN domains/patterns that typically remain reachable during NIN cuts
NIN_REACHABLE_CDNS: list[str] = [
    "arvancloud.com", "arvancloud.ir", "cdn.arvancloud.com",
    "derak.cloud", "parspack.com", "iranserver.com",
    "cloudflare.com",        # Cloudflare often partially reachable
    "fastly.net",            # Some Fastly nodes survive
    "gcore.com",             # GCore CDN nodes in ME region
    "cdn77.com",
]

# These ASN ranges have been observed as still reachable during NIN
NIN_REACHABLE_ASNS: set[str] = {
    "AS13335",   # Cloudflare
    "AS20940",   # Akamai
    "AS16509",   # Amazon CloudFront
    "AS15169",   # Google (partial)
    "AS54113",   # Fastly
}

# Ports that Iran's SIAM/NGFW typically leaves open during NIN
NIN_OPEN_PORTS: set[int] = {80, 443, 8080, 8443, 2053, 2083, 2087, 2096}

_IP4_RE = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})')
_HTTPS_RE = re.compile(r'https?://([^/:\s]+)(?::(\d+))?', re.I)


def _detect_transport(line: str) -> str:
    l = line.lower()
    if "snowflake" in l: return "snowflake"
    if "webtunnel" in l or "url=https" in l: return "webtunnel"
    if "obfs4" in l: return "obfs4"
    if "meek" in l: return "meek_lite"
    return "vanilla"


def _extract_endpoint(line: str) -> tuple[str | None, int | None]:
    m = _HTTPS_RE.search(line)
    if m:
        return m.group(1), int(m.group(2)) if m.group(2) else 443
    m = _IP4_RE.search(line)
    if m:
        return m.group(1), int(m.group(2))
    return None, None


def _domain_in_nin_cdn(host: str) -> bool:
    """Check if host matches a known NIN-surviving CDN."""
    if not host:
        return False
    hl = host.lower()
    return any(cdn in hl for cdn in NIN_REACHABLE_CDNS)


def _port_nin_open(port: int | None) -> bool:
    return port in NIN_OPEN_PORTS if port else False


def _tcp_reachable(host: str, port: int, timeout: float = 6.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def score_for_nin(bridge_line: str) -> dict[str, Any]:
    """Score a bridge for Iran NIN survivability."""
    line = bridge_line.strip()
    transport = _detect_transport(line)
    host, port = _extract_endpoint(line)

    score = 0.0
    flags: list[str] = []

    # Transport scoring (NIN perspective)
    if transport == "webtunnel":
        score += 0.50; flags.append("webtunnel_cdn_fronted")
    elif transport == "snowflake":
        score += 0.45; flags.append("snowflake_webrtc")
    elif transport == "meek_lite":
        score += 0.35; flags.append("meek_domain_fronted")
    elif transport == "obfs4":
        score += 0.10; flags.append("obfs4_tcp_only")
    else:
        score += 0.05

    # CDN domain check
    if host and _domain_in_nin_cdn(host):
        score += 0.30; flags.append("nin_cdn_reachable")

    # Port check
    if _port_nin_open(port):
        score += 0.15; flags.append("nin_port_open")

    # Live TCP reachability (best effort, don't fail on error)
    reachable = False
    if host and port and transport not in ("snowflake",):
        try:
            reachable = _tcp_reachable(host, port)
            if reachable:
                score += 0.10; flags.append("tcp_alive")
        except Exception:
            pass

    return {
        "bridge_line": line,
        "transport": transport,
        "host": host or "",
        "port": port or 0,
        "nin_score": round(min(score, 1.0), 3),
        "nin_flags": flags,
        "tcp_reachable": reachable,
    }


def main() -> None:
    bridge_dir = Path("bridge")
    test_json = bridge_dir / "bridge_list_for_testing.json"
    if not test_json.exists():
        log.warning("bridge_list_for_testing.json not found — skipping NIN bypass analysis")
        return

    bridges: list[str] = json.loads(test_json.read_text(encoding="utf-8"))
    log.info("NIN bypass scoring: %d bridges", len(bridges))

    results = [score_for_nin(b) for b in bridges[:300]]
    results.sort(key=lambda x: x["nin_score"], reverse=True)

    out_dir = Path("data")
    out_dir.mkdir(exist_ok=True)
    (out_dir / "nin_advanced_report.json").write_text(
        json.dumps({"nin_bridge_scores": results}, indent=2, ensure_ascii=False)
    )

    # Write NIN-optimised bridge pack (score >= 0.50)
    export_dir = Path("export")
    export_dir.mkdir(exist_ok=True)
    nin_bridges = [r["bridge_line"] for r in results if r["nin_score"] >= 0.50]
    if nin_bridges:
        (export_dir / "nin_cut_bridges.txt").write_text(
            "\n".join(nin_bridges) + "\n", encoding="utf-8"
        )
        log.info("NIN pack: %d bridges → export/nin_cut_bridges.txt", len(nin_bridges))
    else:
        log.warning("No bridges scored >= 0.50 for NIN scenario")

    log.info("NIN advanced bypass analysis complete.")


if __name__ == "__main__":
    main()
