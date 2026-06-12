#!/usr/bin/env python3
"""
core/nin_selector.py — FEATURE 6: National Internet Network (NIN / شبکه ملی) Bridge Selector.

When Iran activates the NIN and cuts international connectivity, most Tor bridges
become unreachable because their IPs are outside Iran's domestic routing table.
Only a narrow class of bridges can survive a full internet cut:

  Priority 1 — Snowflake (WebRTC via signalling servers that may be CDN-fronted)
  Priority 2 — WebTunnel behind CDN edges that have Iranian PoPs (Fastly, Arvan, etc.)
  Priority 3 — meek-lite over Azure/AWS domains that Iran cannot block without massive
                collateral damage to its own banking/cloud infrastructure

This module reads the current bridge intelligence files, filters for NIN-survivable
bridges, and writes a dedicated export pack: export/iran_cut_pack.txt

It also exposes a reachability score adjustment function used by IranScorer when
nin_mode=True:
    scored_bridges = nin_selector.rescore_for_nin(all_bridges)

NIN-survival criteria (all must be True to pass):
  1. Transport is snowflake, webtunnel, or meek_lite
  2. Bridge IP or domain resolves to a known CDN ASN  -OR- transport is snowflake
  3. Bridge is NOT flagged iran_asn_blocked
  4. Bridge composite_score >= 0.40

Output files:
  export/iran_cut_pack.txt           — plain text, one bridge per line
  data/nin_eligible.json             — full metadata for eligible bridges
  data/nin_summary.json              — counts and recommended order
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

# Transport types that can survive an internet cut via CDN routing
NIN_SURVIVABLE_TRANSPORTS = {"snowflake", "webtunnel", "meek_lite"}

# CDN ASN ranges known to have Iranian PoPs or be impossible to block entirely
# without breaking Iran's own HTTPS banking infrastructure
NIN_SAFE_CDN_ASNS = {
    "AS20940",   # Akamai Technologies
    "AS16509",   # Amazon (AWS CloudFront)
    "AS54113",   # Fastly
    "AS13335",   # Cloudflare
    "AS8075",    # Microsoft (Azure, includes azureedge.net / meek)
    "AS15169",   # Google (Alphabet; gstatic.com, googlevideo.com)
    "AS206804",  # EstNOC / ArvanCloud international PoP
    "AS209675",  # ArvanCloud IR
}

# Domain patterns associated with CDN fronting that Iran cannot block
# without catastrophic collateral to domestic services
NIN_SAFE_DOMAIN_PATTERNS = [
    re.compile(r"fastly\.net$",        re.I),
    re.compile(r"arvancloud\.(com|ir)$", re.I),
    re.compile(r"azureedge\.net$",     re.I),
    re.compile(r"cloudfront\.net$",    re.I),
    re.compile(r"ajax\.aspnetcdn\.com$", re.I),  # meek-lite Azure
    re.compile(r"gstatic\.com$",       re.I),
    re.compile(r"cdn\.irimc\.ir$",     re.I),    # IRIB CDN (domestic)
    re.compile(r"googlevideo\.com$",   re.I),
]

# Minimum composite score to include in NIN pack
NIN_MIN_SCORE = 0.40

# Paths
IRAN_RESULTS_PATH  = Path("bridge/iran_results.json")
LATEST_RESULTS_PATH = Path("data/latest-results.json")
EXPORT_DIR          = Path("export")
DATA_DIR            = Path("data")

EXPORT_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# Eligibility check
# ─────────────────────────────────────────────────────────────────────────────

def _domain_is_cdn_safe(host: str) -> bool:
    """Return True if the bridge host matches a known NIN-safe CDN domain."""
    for pattern in NIN_SAFE_DOMAIN_PATTERNS:
        if pattern.search(host):
            return True
    return False


def _asn_is_cdn_safe(asn: str) -> bool:
    return asn.upper() in NIN_SAFE_CDN_ASNS


def is_nin_eligible(record: Dict[str, Any]) -> bool:
    """
    Return True if this bridge record meets all NIN-survival criteria.
    """
    transport = record.get("transport", "").lower()
    if transport not in NIN_SURVIVABLE_TRANSPORTS:
        return False

    # Never include bridges blocked via Iranian ISP ASNs
    if record.get("iran_status") == "iran_asn_blocked":
        return False

    # Score gate
    score = float(record.get("composite_score", record.get("score", 0.0)))
    if score < NIN_MIN_SCORE:
        return False

    # Snowflake passes automatically — signalling is inherently CDN-fronted
    if transport == "snowflake":
        return True

    # WebTunnel and meek_lite require CDN verification
    host = record.get("host", "")
    asn  = record.get("asn", "")
    raw  = record.get("line", record.get("bridge_line", ""))

    if _domain_is_cdn_safe(host) or _asn_is_cdn_safe(asn):
        return True

    # Also check raw bridge line for CDN URL markers
    if _domain_is_cdn_safe(raw):
        return True

    # WebTunnel bridges with domain_front_cdn_ok flag are eligible
    flags = record.get("flags", []) or []
    if "domain_front_cdn_ok" in flags:
        return True

    return False


# ─────────────────────────────────────────────────────────────────────────────
# Rescoring for NIN mode
# ─────────────────────────────────────────────────────────────────────────────

# Score multipliers applied when NIN is active
NIN_TRANSPORT_MULTIPLIER = {
    "snowflake":  1.5,   # maximum priority
    "webtunnel":  1.35,  # CDN fronting survives cuts
    "meek_lite":  1.25,  # Azure/meek fronting
    "obfs4":      0.4,   # bare IP — likely unreachable during cut
    "vanilla":    0.1,   # plaintext Tor — almost certainly blocked
    "unknown":    0.3,
}


def rescore_for_nin(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Adjust composite scores for NIN-active scenario.
    Returns a new list sorted by the adjusted score (descending).
    This does NOT modify the underlying records permanently.
    """
    rescored: List[Dict[str, Any]] = []
    for rec in records:
        transport  = rec.get("transport", "unknown").lower()
        multiplier = NIN_TRANSPORT_MULTIPLIER.get(transport, 0.3)
        original   = float(rec.get("composite_score", rec.get("score", 0.5)))
        adjusted   = round(min(1.0, original * multiplier), 4)
        entry = dict(rec)
        entry["nin_score"]          = adjusted
        entry["nin_multiplier"]     = multiplier
        entry["nin_eligible"]       = is_nin_eligible(rec)
        rescored.append(entry)

    rescored.sort(key=lambda x: x["nin_score"], reverse=True)
    return rescored


# ─────────────────────────────────────────────────────────────────────────────
# Export builder
# ─────────────────────────────────────────────────────────────────────────────

def _load_all_records() -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    seen: set = set()
    for path in (LATEST_RESULTS_PATH, IRAN_RESULTS_PATH):
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            for r in data.get("bridges", []):
                key = r.get("line") or r.get("bridge_line") or r.get("raw", "")
                if key and key not in seen:
                    seen.add(key)
                    records.append(r)
        except Exception as exc:
            log.warning("Cannot read %s: %s", path, exc)
    return records


def build_nin_pack() -> Dict[str, Any]:
    """
    Build and export the NIN bridge pack.
    Returns a summary dict.
    """
    log.info("═══ NIN Bridge Selector: Building internet-cut pack ════════")
    records  = _load_all_records()

    if not records:
        log.warning("No bridge records found — NIN pack will be empty.")
        return {"eligible": 0, "total": 0}

    eligible = [r for r in records if is_nin_eligible(r)]

    # Sort: snowflake first, then webtunnel, then meek; within each by score
    _TRANSPORT_ORDER = {"snowflake": 0, "webtunnel": 1, "meek_lite": 2}
    eligible.sort(
        key=lambda r: (
            _TRANSPORT_ORDER.get(r.get("transport", ""), 9),
            -float(r.get("composite_score", r.get("score", 0))),
        )
    )

    # Write plain-text bridge pack
    pack_lines: List[str] = [
        "# TorShield-IR — Internet Cut Pack (شبکه ملی / NIN Mode)",
        f"# Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"# Bridges: {len(eligible)}  (survivable during full international internet cut)",
        "# Order: Snowflake → WebTunnel (CDN) → meek-lite (Azure)",
        "#",
        "# These bridges work by routing through CDN edges with Iranian PoPs",
        "# or WebRTC/DTLS signalling that Iran cannot block without collateral damage.",
        "#",
    ]
    for r in eligible:
        raw = r.get("line") or r.get("bridge_line") or r.get("raw", "")
        if raw:
            pack_lines.append(raw)

    pack_text = "\n".join(pack_lines) + "\n"
    nin_pack_path = EXPORT_DIR / "iran_cut_pack.txt"
    nin_pack_path.write_text(pack_text, encoding="utf-8")
    log.info("NIN pack written: %s (%d bridges)", nin_pack_path, len(eligible))

    # Write machine-readable eligible JSON
    eligible_json_path = DATA_DIR / "nin_eligible.json"
    eligible_json_path.write_text(
        json.dumps(eligible, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    # Transport breakdown for summary
    transport_counts: Dict[str, int] = {}
    for r in eligible:
        t = r.get("transport", "unknown")
        transport_counts[t] = transport_counts.get(t, 0) + 1

    summary = {
        "generated_at":      datetime.now(timezone.utc).isoformat(),
        "total_tested":      len(records),
        "nin_eligible":      len(eligible),
        "transport_counts":  transport_counts,
        "recommended_order": ["snowflake", "webtunnel", "meek_lite"],
        "pack_path":         str(nin_pack_path),
        "note": (
            "هنگام قطع اینترنت بین‌المللی (شبکه ملی)، فقط بریج‌های این فایل کار می‌کنند. "
            "During international internet cut, only bridges in this pack are reachable. "
            "Use: Snowflake first, then WebTunnel (CDN-fronted), then meek-lite."
        ),
    }

    summary_path = DATA_DIR / "nin_summary.json"
    summary_path.write_text(
        json.dumps(summary, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    log.info(
        "NIN summary: eligible=%d / total=%d | %s",
        len(eligible),
        len(records),
        " | ".join(f"{t}={n}" for t, n in transport_counts.items()),
    )
    log.info("═══ NIN Bridge Selector done ════════════════════════════════")
    return summary


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    build_nin_pack()
