#!/usr/bin/env python3
"""
ztunnel_ct_monitor.py — Stage 8o: Certificate Transparency MITM Monitor

Queries crt.sh Certificate Transparency logs for domains used by
WebTunnel, meek, and Snowflake bridges.  Flags certificates issued by
known Iranian CAs (IRCA Root, TIC, etc.) as potential MITM indicators.

Outputs:
  data/ct_monitor_report.json    — full per-domain CT scan results
  export/ct_flagged_domains.txt  — domains with suspicious certificates
  export/ct_clean_bridges.txt    — bridges with clean CT records
"""
from __future__ import annotations

import json
import logging
import re
import sys
import time
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

# ── Paths ─────────────────────────────────────────────────────────────────────
BRIDGE_FILES = [
    Path("bridge/iran_likely_working_webtunnel.txt"),
    Path("bridge/iran_likely_working_all.txt"),
    Path("export/nin_cut_bridges.txt"),
]
CT_REPORT    = Path("data/ct_monitor_report.json")
FLAGGED_OUT  = Path("export/ct_flagged_domains.txt")
CLEAN_OUT    = Path("export/ct_clean_bridges.txt")

CRT_SH_URL = "https://crt.sh/?q={domain}&output=json"

# ── Iranian CA indicators ─────────────────────────────────────────────────────
IRAN_CA_INDICATORS = [
    "irca",
    "tic.",
    "iran-ssl",
    "c=ir",
    "o=tic",
    "iranian",
    "irnicregistry",
    "postirca",
    "parsca",
    "parsssl",
    "irssl",
]


def _extract_domains(line: str) -> list[str]:
    """Extract hostnames (not IPs) from a bridge line."""
    line = line.strip()
    if not line or line.startswith("#"):
        return []
    domains: list[str] = []
    # Find URL-like patterns: url=https://hostname/...
    url_matches = re.findall(r'https?://([a-zA-Z0-9.-]+)', line)
    domains.extend(url_matches)
    # Find host= or server= keyword args
    kw_matches = re.findall(r'(?:host|server|sni)=([a-zA-Z0-9.-]+)', line, re.I)
    domains.extend(kw_matches)
    # Filter: must not be an IP, must have at least one dot
    result = []
    for d in domains:
        if re.match(r'^\d+\.\d+\.\d+\.\d+$', d):
            continue
        if '.' in d and len(d) > 4:
            result.append(d.lower())
    return list(set(result))


def _query_crt_sh(domain: str) -> list[dict[str, Any]]:
    """Query crt.sh for certificates for a domain.  Returns list or []."""
    url = CRT_SH_URL.format(domain=urllib.request.quote(domain))
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "TorShield-IR/6.0 CT-monitor (research)"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except Exception as exc:
        log.debug("crt.sh query failed for %s: %s", domain, exc)
        return []


def _risk_level(certs: list[dict[str, Any]]) -> tuple[str, list[str]]:
    """
    Assess certificate risk level.
    Returns ('clean'|'medium'|'high'|'critical', [reasons]).
    """
    if not certs:
        return "medium", ["no_ct_records_found"]

    suspicious: list[str] = []
    for cert in certs[:20]:  # Check only most recent 20
        issuer = (cert.get("issuer_name", "") or "").lower()
        common = (cert.get("common_name", "") or "").lower()
        for indicator in IRAN_CA_INDICATORS:
            if indicator in issuer:
                suspicious.append(f"iran_ca_issuer:{issuer[:80]}")
            if indicator in common:
                suspicious.append(f"iran_ca_cn:{common[:60]}")

    if not suspicious:
        return "clean", []
    if len(set(suspicious)) >= 3:
        return "critical", list(set(suspicious))
    if len(set(suspicious)) >= 2:
        return "high", list(set(suspicious))
    return "medium", list(set(suspicious))


def _load_all_bridges() -> list[str]:
    """Load bridge lines from all known bridge files."""
    lines: list[str] = []
    for fp in BRIDGE_FILES:
        if fp.exists():
            for line in fp.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    lines.append(line)
    log.info("Loaded %d bridge lines from %d files.", len(lines), len(BRIDGE_FILES))
    return list(set(lines))


def main() -> int:
    log.info("═══ Stage 8o: Certificate Transparency MITM Monitor ════════")

    Path("data").mkdir(parents=True, exist_ok=True)
    Path("export").mkdir(parents=True, exist_ok=True)

    bridges = _load_all_bridges()
    if not bridges:
        _write_empty("No bridge files found.")
        return 0

    # Collect unique domains
    domain_to_bridges: dict[str, list[str]] = {}
    for line in bridges:
        for domain in _extract_domains(line):
            domain_to_bridges.setdefault(domain, []).append(line)

    if not domain_to_bridges:
        log.info("No hostnames found in bridge lines (all IP-only) — CT scan skipped.")
        _write_empty("No hostname-based bridges found.")
        return 0

    log.info("Found %d unique domains to check.", len(domain_to_bridges))

    results: list[dict[str, Any]] = []
    flagged_domains: list[str]    = []
    clean_bridges:   list[str]    = []

    for i, (domain, bridge_lines) in enumerate(domain_to_bridges.items()):
        log.info("[%d/%d] Checking CT for: %s", i + 1, len(domain_to_bridges), domain)
        certs = _query_crt_sh(domain)
        risk, reasons = _risk_level(certs)
        log.info("  → risk=%s  certs_found=%d  reasons=%s", risk, len(certs), reasons)

        entry: dict[str, Any] = {
            "domain":           domain,
            "risk_level":       risk,
            "reasons":          reasons,
            "certs_found":      len(certs),
            "associated_bridges": bridge_lines[:5],
            "checked_at":       datetime.now(timezone.utc).isoformat(),
        }
        results.append(entry)

        if risk in ("high", "critical"):
            flagged_domains.append(domain)
        else:
            # Only mark bridges as clean if ALL their domains pass
            for bl in bridge_lines:
                all_domains_for_bridge = _extract_domains(bl)
                if not all_domains_for_bridge or domain in all_domains_for_bridge:
                    if risk == "clean":
                        clean_bridges.append(bl)

        # Rate-limit: max ~4 req/s to be polite to crt.sh
        time.sleep(0.25)

    # Write outputs
    report: dict[str, Any] = {
        "generated_at":     datetime.now(timezone.utc).isoformat(),
        "domains_checked":  len(results),
        "flagged_count":    len(flagged_domains),
        "clean_count":      len([r for r in results if r["risk_level"] == "clean"]),
        "iran_ca_indicators_checked": IRAN_CA_INDICATORS,
        "iran_mitm_note": (
            "Iran's TIC (Telecommunication Infrastructure Company) has been "
            "documented issuing fraudulent certificates for MITM attacks on "
            "HTTPS traffic. CT logs are the primary detection mechanism. "
            "Bridges flagged 'high'/'critical' should be treated as potentially "
            "compromised within Iran's NIN."
        ),
        "domains": results,
    }
    CT_REPORT.write_text(json.dumps(report, indent=2, ensure_ascii=False),
                         encoding="utf-8")
    log.info("CT report written: %d domains, %d flagged → %s",
             len(results), len(flagged_domains), CT_REPORT)

    FLAGGED_OUT.write_text(
        "\n".join(sorted(set(flagged_domains))) + ("\n" if flagged_domains else ""),
        encoding="utf-8",
    )
    CLEAN_OUT.write_text(
        "\n".join(sorted(set(clean_bridges))) + ("\n" if clean_bridges else ""),
        encoding="utf-8",
    )

    log.info("Flagged domains: %d → %s", len(flagged_domains), FLAGGED_OUT)
    log.info("Clean bridges: %d → %s", len(set(clean_bridges)), CLEAN_OUT)
    log.info("═══ Stage 8o done ═══════════════════════════════════════════")
    return 0


def _write_empty(reason: str) -> None:
    empty: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "domains_checked": 0,
        "flagged_count": 0,
        "note": reason,
        "domains": [],
    }
    CT_REPORT.write_text(json.dumps(empty, indent=2), encoding="utf-8")
    FLAGGED_OUT.write_text("", encoding="utf-8")
    CLEAN_OUT.write_text("", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
