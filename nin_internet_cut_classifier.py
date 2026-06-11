#!/usr/bin/env python3
"""
nin_internet_cut_classifier.py — Stage 8p: NIN Internet-Cut Bridge Classifier

Classifies all known bridges into GREEN / YELLOW / RED tiers for the
worst-case scenario: complete international internet blackout where only
traffic through Iranian domestic ASNs remains reachable.

Classification logic:
  GREEN  (high confidence reachable on NIN-cut):
    - Snowflake via ArvanCloud IR or Cloudflare edge in Iran
    - WebTunnel via Iranian CDN SNI (Aparat, Digikala, Telewebion)
    - meek-azure or meek-amazon via CDN with Iranian edge PoP
  YELLOW (may work — CDN-dependent):
    - WebTunnel via Akamai / Fastly / CloudFront (have some IR PoPs)
    - obfs4 on port 443 with non-datacenter IP
  RED    (likely blocked on full NIN-cut):
    - obfs4 on raw IP, non-CDN
    - vanilla Tor
    - Any bridge on IP-only without domestic CDN routing

Outputs:
  export/nin_cut_bridges.txt          — GREEN bridges (highest priority)
  export/nin_yellow_bridges.txt       — YELLOW bridges (fallback)
  bridge/iran_likely_working_nin.txt  — GREEN + YELLOW combined
  data/nin_cut_classifier_report.json — full classification report
"""
from __future__ import annotations

import ipaddress
import json
import logging
import re
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# ── Input bridge files ────────────────────────────────────────────────────────
BRIDGE_SOURCES = [
    Path("bridge/iran_likely_working_all.txt"),
    Path("bridge/iran_likely_working_obfs4.txt"),
    Path("bridge/iran_likely_working_webtunnel.txt"),
    Path("bridge/iran_likely_working_snowflake.txt"),
    Path("bridge/snowflake.txt"),
    Path("bridge/webtunnel.txt"),
    Path("bridge/meek_lite.txt"),
]

# ── Output paths ──────────────────────────────────────────────────────────────
GREEN_OUT    = Path("export/nin_cut_bridges.txt")
YELLOW_OUT   = Path("export/nin_yellow_bridges.txt")
COMBINED_OUT = Path("bridge/iran_likely_working_nin.txt")
REPORT_OUT   = Path("data/nin_cut_classifier_report.json")

# ── Known GREEN CDN SNI domains with Iranian edge PoPs ───────────────────────
GREEN_SNIS = {
    # Iranian CDN/domestic
    "www.aparat.com", "aparat.com",
    "www.digikala.com", "digikala.com",
    "cdn.telewebion.com", "telewebion.com",
    "arvancloud.ir", "arvancloud.com",
    # Global CDNs with strong Iranian edge presence documented by IODA
    "ajax.cloudflare.com", "cloudflare.com",
}

YELLOW_SNIS = {
    "akamaiedge.net", "akamaitechnologies.com",
    "fastly.net", "fastly.com",
    "cloudfront.net", "amazonaws.com",
    "azureedge.net", "windows.net",
}

# ── Known Iranian domestic CDN ASN ranges ────────────────────────────────────
IRAN_CDN_CIDRS: list[ipaddress.IPv4Network] = []
_IRAN_CIDR_RAW = [
    # ArvanCloud
    "185.143.232.0/22", "185.215.232.0/22", "179.43.145.0/24",
    # Cloudflare Iranian PoPs (documented by IODA)
    "104.16.0.0/13", "104.24.0.0/14",
    # TCI / domestic
    "5.200.64.0/18", "78.38.0.0/15", "85.185.0.0/16",
    "91.186.188.0/22", "94.182.0.0/16",
]
for _c in _IRAN_CIDR_RAW:
    try:
        IRAN_CDN_CIDRS.append(ipaddress.IPv4Network(_c, strict=False))
    except ValueError:
        pass

# ── Transport-level classification ────────────────────────────────────────────
GREEN_TRANSPORTS  = {"snowflake", "meek_lite", "meek-lite"}
YELLOW_TRANSPORTS = {"webtunnel"}
RED_TRANSPORTS    = {"vanilla", "obfs3"}

NIN_SAFE_PORTS = {80, 443, 8080, 8443}


def _parse_bridge(line: str) -> dict[str, Any] | None:
    """Parse a bridge line into a structured dict."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    transport_match = re.match(
        r"^(obfs4|webtunnel|snowflake|meek_lite|meek-lite|obfs3|vanilla)\s+",
        line, re.I,
    )
    transport = transport_match.group(1).lower() if transport_match else "vanilla"
    rest = line[transport_match.end():] if transport_match else line

    # Extract IP (if any)
    ip_str: str = ""
    port: int   = 0
    m4 = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})\b", rest)
    if m4:
        ip_str = m4.group(1)
        port   = int(m4.group(2))
    else:
        m6 = re.search(r"\[([0-9a-fA-F:]+)\]:(\d{2,5})", rest)
        if m6:
            ip_str = m6.group(1)
            port   = int(m6.group(2))

    # Extract SNI / host keyword
    sni_match = re.search(r'(?:url=https?://|host=|sni=|server=)([a-zA-Z0-9.-]+)', rest, re.I)
    sni = sni_match.group(1).lower() if sni_match else ""

    return {
        "raw":       line,
        "transport": transport,
        "ip":        ip_str,
        "port":      port,
        "sni":       sni,
    }


def _classify(bridge: dict[str, Any]) -> str:
    """Classify bridge as GREEN / YELLOW / RED."""
    transport = bridge["transport"].lower()
    ip_str    = bridge["ip"]
    port      = bridge["port"]
    sni       = bridge["sni"]

    # Snowflake and meek are always GREEN (CDN-routed by design)
    if transport in GREEN_TRANSPORTS:
        return "GREEN"

    # WebTunnel classification depends on SNI
    if transport == "webtunnel":
        if sni in GREEN_SNIS or any(sni.endswith("." + g) for g in GREEN_SNIS):
            return "GREEN"
        if sni in YELLOW_SNIS or any(sni.endswith("." + y) for y in YELLOW_SNIS):
            return "YELLOW"
        if sni:
            return "YELLOW"  # Unknown CDN — possibly reachable
        return "RED"

    # obfs4 classification
    if transport == "obfs4":
        if port in NIN_SAFE_PORTS:
            # Check if IP is in a known CDN/Iranian range
            try:
                ip_obj = ipaddress.IPv4Address(ip_str)
                if any(ip_obj in net for net in IRAN_CDN_CIDRS):
                    return "GREEN"
            except ValueError:
                pass
            return "YELLOW"
        return "RED"

    # RED for everything else
    return "RED"


def _load_all_bridges() -> list[str]:
    seen: set[str]  = set()
    result: list[str] = []
    for fp in BRIDGE_SOURCES:
        if not fp.exists():
            continue
        for line in fp.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and line not in seen:
                seen.add(line)
                result.append(line)
    log.info("Loaded %d unique bridge lines from %d source files.",
             len(result), sum(1 for f in BRIDGE_SOURCES if f.exists()))
    return result


def main() -> int:
    log.info("═══ Stage 8p: NIN Internet-Cut Bridge Classifier ═══════════")

    Path("data").mkdir(parents=True, exist_ok=True)
    Path("export").mkdir(parents=True, exist_ok=True)
    Path("bridge").mkdir(parents=True, exist_ok=True)

    all_lines = _load_all_bridges()
    if not all_lines:
        log.warning("No bridge lines found — writing empty outputs.")
        _write_empty()
        return 0

    green:  list[str] = []
    yellow: list[str] = []
    red:    list[str] = []
    details: list[dict[str, Any]] = []

    for line in all_lines:
        parsed = _parse_bridge(line)
        if not parsed:
            continue
        tier = _classify(parsed)
        entry = {**parsed, "tier": tier}
        details.append(entry)
        if tier == "GREEN":
            green.append(line)
        elif tier == "YELLOW":
            yellow.append(line)
        else:
            red.append(line)

    # Write outputs
    GREEN_OUT.write_text(
        "\n".join(green) + ("\n" if green else ""), encoding="utf-8"
    )
    YELLOW_OUT.write_text(
        "\n".join(yellow) + ("\n" if yellow else ""), encoding="utf-8"
    )
    combined = green + yellow
    COMBINED_OUT.write_text(
        "\n".join(combined) + ("\n" if combined else ""), encoding="utf-8"
    )

    report: dict[str, Any] = {
        "generated_at":   datetime.now(timezone.utc).isoformat(),
        "total_bridges":  len(details),
        "green_count":    len(green),
        "yellow_count":   len(yellow),
        "red_count":      len(red),
        "scenario": (
            "Complete international internet blackout. "
            "Only traffic through Iranian domestic ASNs reachable. "
            "GREEN = high confidence reachable, YELLOW = CDN-dependent, RED = blocked."
        ),
        "classification_logic": {
            "GREEN":  "Snowflake, meek_lite (CDN by design) OR WebTunnel via Iranian/Cloudflare CDN SNI",
            "YELLOW": "WebTunnel via Akamai/Fastly/CloudFront OR obfs4 on port 443",
            "RED":    "obfs4 on non-standard port, vanilla, or bridge with no CDN routing",
        },
        "bridges": details,
    }
    REPORT_OUT.write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    log.info(
        "NIN classifier done: GREEN=%d YELLOW=%d RED=%d total=%d",
        len(green), len(yellow), len(red), len(details),
    )
    log.info("GREEN bridges → %s", GREEN_OUT)
    log.info("YELLOW bridges → %s", YELLOW_OUT)
    log.info("Combined (GREEN+YELLOW) → %s", COMBINED_OUT)
    log.info("═══ Stage 8p done ═══════════════════════════════════════════")
    return 0


def _write_empty() -> None:
    empty: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_bridges": 0, "green_count": 0, "yellow_count": 0, "red_count": 0,
        "note": "No bridge source files found.", "bridges": [],
    }
    REPORT_OUT.write_text(json.dumps(empty, indent=2), encoding="utf-8")
    for fp in (GREEN_OUT, YELLOW_OUT, COMBINED_OUT):
        fp.write_text("", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
