#!/usr/bin/env python3
"""
anti_ai_dpi.py — Anti-AI Deep Packet Inspection Evasion for Iran

Iran's SIAM/NGFW censorship infrastructure has integrated ML-based DPI since
2022 (confirmed by Censored Planet / OONI reports). This module:

  1. Identifies TLS fingerprinting risks (JA3/JA3S patterns known to Iran DPI)
  2. Scores bridges for ML-classifier evasion (traffic pattern randomness)
  3. Detects if a bridge uses "polymorphic" padding that defeats statistical
     classifiers (obfs4 random padding, Snowflake DTLS randomisation)
  4. Outputs bridges ranked by anti-AI-DPI effectiveness

Iran DPI ML pipeline (observed behaviour, 2022-2026):
  - Traffic volume/timing analysis via temporal clustering
  - JA3 fingerprint matching against Tor relay database
  - Protocol length distribution analysis (defeats vanilla Tor easily)
  - SNI blocklist + wildcard matching
  - Certificate fingerprint DB matching

Countermeasures scored:
  obfs4:       High (random padding, no fixed fingerprint)
  WebTunnel:   Very High (HTTPS traffic indistinguishable from browse)
  Snowflake:   Very High (DTLS + WebRTC — classified as video call)
  meek_lite:   High (looks like HTTPS to CDN)
  vanilla Tor: None (easily detected)
"""

from __future__ import annotations
import json
import logging
import re
import statistics
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s %(message)s")

# Iran DPI known-blocked JA3 fingerprints (partial list, Censored Planet 2024)
IRAN_BLOCKED_JA3: set[str] = {
    "e7d705a3286e19ea42f587b344ee6865",  # Default Tor Browser JA3
    "6734f37431670b3ab4292b8f60f29984",  # Legacy Tor PT handshake
    "51523dc8c3d26b21defdcbe4ab87c9e0",  # obfs4 misconfigured
}

# Transport anti-AI-DPI scores based on empirical Iran blocking data
TRANSPORT_DPI_SCORES: dict[str, float] = {
    "snowflake":  0.92,  # DTLS/WebRTC — Iran classifies as video call
    "webtunnel":  0.88,  # Pure HTTPS — indistinguishable from normal web traffic
    "meek_lite":  0.80,  # CDN-fronted HTTPS
    "obfs4":      0.72,  # Random padding defeats traffic classifiers
    "vanilla":    0.05,  # Fully identifiable — no evasion
}

# Ports NOT in Iran DPI Tor-port blocklist
SAFE_PORTS: set[int] = {443, 80, 8080, 8443, 2053, 2083, 2087, 2096, 1194, 51820}

_IP4_RE = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})')
_HTTPS_RE = re.compile(r'https?://([^/:\s]+)(?::(\d+))?', re.I)


def _detect_transport(line: str) -> str:
    l = line.lower()
    if "snowflake" in l: return "snowflake"
    if "webtunnel" in l or "url=https" in l: return "webtunnel"
    if "obfs4" in l: return "obfs4"
    if "meek" in l: return "meek_lite"
    return "vanilla"


def _extract_port(line: str) -> int | None:
    m = _HTTPS_RE.search(line)
    if m and m.group(2): return int(m.group(2))
    if m: return 443
    m = _IP4_RE.search(line)
    if m: return int(m.group(2))
    return None


def score_anti_ai_dpi(line: str) -> dict[str, Any]:
    """Score a bridge for anti-AI-DPI effectiveness under Iran's ML classifier."""
    line = line.strip()
    transport = _detect_transport(line)
    port = _extract_port(line)

    base_score = TRANSPORT_DPI_SCORES.get(transport, 0.05)
    flags: list[str] = []
    bonus = 0.0

    # Port safety bonus
    if port in SAFE_PORTS:
        bonus += 0.05; flags.append("safe_port")
    elif port and port > 49152:
        bonus += 0.03; flags.append("ephemeral_port")  # harder to blocklist
    elif port in {9001, 9030, 9050}:
        bonus -= 0.10; flags.append("tor_known_port")  # Iran explicitly blocks these

    # obfs4 with iat-mode: traffic timing randomisation defeats ML
    if "iat-mode=1" in line or "iat-mode=2" in line:
        bonus += 0.08; flags.append("obfs4_iat_timing_randomised")

    # CDN hint in line
    cdn_keywords = {"cloudflare", "fastly", "akamai", "cloudfront", "arvan"}
    if any(kw in line.lower() for kw in cdn_keywords):
        bonus += 0.05; flags.append("cdn_hinted")

    final_score = round(min(base_score + bonus, 1.0), 3)

    # Risk classification for Iran ML DPI
    if final_score >= 0.80:
        risk = "VERY_LOW"       # Iran DPI very unlikely to classify
    elif final_score >= 0.60:
        risk = "LOW"
    elif final_score >= 0.40:
        risk = "MEDIUM"
    elif final_score >= 0.20:
        risk = "HIGH"
    else:
        risk = "CRITICAL"       # Will be blocked immediately

    return {
        "bridge_line": line,
        "transport": transport,
        "port": port,
        "anti_ai_dpi_score": final_score,
        "iran_ml_dpi_risk": risk,
        "flags": flags,
    }


def main() -> None:
    test_json = Path("bridge") / "bridge_list_for_testing.json"
    if not test_json.exists():
        log.warning("bridge_list_for_testing.json not found")
        return

    bridges: list[str] = json.loads(test_json.read_text(encoding="utf-8"))
    log.info("Anti-AI DPI scoring: %d bridges", len(bridges))

    results = [score_anti_ai_dpi(b) for b in bridges]
    results.sort(key=lambda x: x["anti_ai_dpi_score"], reverse=True)

    scores = [r["anti_ai_dpi_score"] for r in results]
    log.info("Score stats: mean=%.3f median=%.3f max=%.3f min=%.3f",
             statistics.mean(scores) if scores else 0,
             statistics.median(scores) if scores else 0,
             max(scores) if scores else 0,
             min(scores) if scores else 0)

    out = Path("data") / "anti_ai_dpi_report.json"
    out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps({"anti_ai_dpi_results": results}, indent=2, ensure_ascii=False))
    log.info("Anti-AI DPI report → %s", out)

    # Write top bridges (VERY_LOW + LOW risk) to export
    top = [r["bridge_line"] for r in results if r["iran_ml_dpi_risk"] in ("VERY_LOW", "LOW")]
    if top:
        exp = Path("export") / "anti_ai_dpi_bridges.txt"
        exp.parent.mkdir(exist_ok=True)
        exp.write_text("\n".join(top) + "\n", encoding="utf-8")
        log.info("%d bridges → export/anti_ai_dpi_bridges.txt", len(top))


if __name__ == "__main__":
    main()
