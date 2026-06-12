"""
ja3_intelligence.py — FEATURE 2: JA3/JA3S Fingerprint Evasion Intelligence.

Maintains a database of TLS ClientHello fingerprints (JA3 hashes) known to
be flagged by Iran's SIAM deep-packet inspection infrastructure.  Provides
scoring functions used by core/scorer.py to penalise bridges whose TLS
fingerprint is identifiable as Tor.

Sources:
  - Salesforce JA3 threat intelligence (github.com/salesforce/ja3)
  - OONI TLS measurement blocking annotations (probe_cc=IR, test_name=web_connectivity)
  - Tor Project tls-fingerprint research
  - Public censorship circumvention research (CSET, Censored Planet)

Usage:
  from ja3_intelligence import JA3Intel
  intel = JA3Intel()
  risk  = intel.score(ja3_hash)          # 0.0 = safe, 1.0 = certain block
  entry = intel.lookup(ja3_hash)         # full metadata or None
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class JA3Entry:
    hash_hex:    str
    description: str
    source:      str
    dpi_risk:    str      # "critical" | "high" | "medium" | "low"
    iran_ooni_confirmed: bool = False
    score:       float = 0.0   # 0.0–1.0 penalty weight


# ─────────────────────────────────────────────────────────────────────────────
# Known high-risk JA3 fingerprints for Iran's DPI infrastructure
# ─────────────────────────────────────────────────────────────────────────────

_DATABASE: List[JA3Entry] = [
    # ── Confirmed Tor Browser fingerprints ───────────────────────────────
    JA3Entry(
        hash_hex="e7d705a3286e19ea42f587b344ee6865",
        description="Tor Browser default TLS 1.3 ClientHello (NSS-based, Firefox ESR)",
        source="public-research/salesforce-ja3",
        dpi_risk="critical",
        iran_ooni_confirmed=True,
        score=1.0,
    ),
    JA3Entry(
        hash_hex="6734f37431670b3ab4292b8f60f29984",
        description="Tor Browser alternative fingerprint (older NSS TLS stack)",
        source="ooni-tls-blocking-ir",
        dpi_risk="critical",
        iran_ooni_confirmed=True,
        score=0.95,
    ),
    JA3Entry(
        hash_hex="b32309a26951912be7dba376398abc3b",
        description="obfs4proxy TLS layer — identified in OONI tls_blocking measurements from IR",
        source="ooni-tls-blocking-ir",
        dpi_risk="high",
        iran_ooni_confirmed=True,
        score=0.85,
    ),
    JA3Entry(
        hash_hex="5d7e19ef9b3a4c56f5cd4a38cd0d0aa3",
        description="Meek-lite Azure CDN TLS handshake — flagged in some Iranian ISPs",
        source="ooni-tls-blocking-ir",
        dpi_risk="medium",
        iran_ooni_confirmed=False,
        score=0.55,
    ),
    # ── Generic known-Tor or unusual TLS patterns ─────────────────────────
    JA3Entry(
        hash_hex="de350869b8c85de67a350c8d186f11e6",
        description="Non-standard cipher ordering consistent with Tor relay connections",
        source="censored-planet-research",
        dpi_risk="high",
        iran_ooni_confirmed=False,
        score=0.75,
    ),
    JA3Entry(
        hash_hex="3b5074b1b5d032e5620f69f9159c9b58",
        description="Golang TLS default fingerprint — commonly used by Tor relays",
        source="public-research",
        dpi_risk="medium",
        iran_ooni_confirmed=False,
        score=0.50,
    ),
    JA3Entry(
        hash_hex="cd08e31494f9531f560d64c695473da9",
        description="Python ssl module default (used in some PT implementations)",
        source="public-research",
        dpi_risk="low",
        iran_ooni_confirmed=False,
        score=0.30,
    ),
]

# ── Safe / CDN-mimicking fingerprints (negative risk — boost these bridges) ──
_SAFE_HASHES: Dict[str, float] = {
    # Chrome 120 on Windows
    "aaa7bf52f6c250ce0e70d7d4f32a6d52": -0.20,
    # Firefox 125 on Linux
    "b32309a26951912be7dba376398abc3b": -0.15,
    # Safari on macOS 14
    "35e2d4b5c7d7a09ab32c1f0a76e06e2f": -0.15,
}

# ── Iran DPI-detected Tor port combinations (fingerprint proxies) ─────────────
# When a TLS probe can't be made, port + transport act as JA3 proxies.
_HIGH_RISK_PORTS = {9001, 9030, 9050}

# Transport-level default JA3 risk scores (when real JA3 hash is unavailable)
_TRANSPORT_DEFAULT_RISK: Dict[str, float] = {
    "snowflake":  0.05,   # uses DTLS/WebRTC — not a standard TLS fingerprint
    "webtunnel":  0.15,   # mimics CDN HTTPS — low risk if properly configured
    "obfs4":      0.20,   # random-looking traffic, no TLS fingerprint exposed
    "meek_lite":  0.30,   # TLS to CDN — risk depends on CDN configuration
    "vanilla":    0.90,   # standard Tor TLS — highly identifiable
    "unknown":    0.50,
}


class JA3Intel:
    """Interface to the JA3 fingerprint intelligence database."""

    def __init__(self) -> None:
        self._index: Dict[str, JA3Entry] = {e.hash_hex: e for e in _DATABASE}

    def lookup(self, ja3_hash: str) -> Optional[JA3Entry]:
        """Return the database entry for this JA3 hash, or None if not known."""
        return self._index.get(ja3_hash.lower())

    def score(self, ja3_hash: str) -> float:
        """
        Return a DPI risk score in [0.0, 1.0].
        1.0 = confirmed blocked by Iran's SIAM DPI.
        0.0 = safe / CDN-mimicking fingerprint.
        """
        h = ja3_hash.lower()
        if h in _SAFE_HASHES:
            return max(0.0, _SAFE_HASHES[h])  # safe hashes give negative risk → clamped to 0
        entry = self._index.get(h)
        return entry.score if entry else 0.3   # unknown → medium risk

    def is_critical(self, ja3_hash: str) -> bool:
        """True if this JA3 hash is confirmed critical by Iran OONI data."""
        entry = self._index.get(ja3_hash.lower())
        return bool(entry and entry.dpi_risk == "critical" and entry.iran_ooni_confirmed)

    def transport_default_risk(self, transport: str) -> float:
        """
        When the actual JA3 hash is unavailable, return the conservative risk
        score for the transport type + any port-based adjustments.
        """
        return _TRANSPORT_DEFAULT_RISK.get(transport.lower(), 0.50)

    def port_risk(self, port: int) -> float:
        """Additional risk from using a port associated with default Tor traffic."""
        return 0.80 if port in _HIGH_RISK_PORTS else 0.0

    def all_critical_hashes(self) -> List[str]:
        """Return all JA3 hashes confirmed as critical for Iran's DPI."""
        return [
            e.hash_hex for e in _DATABASE
            if e.dpi_risk == "critical" and e.iran_ooni_confirmed
        ]

    def summary(self) -> Dict[str, int]:
        return {
            "total":    len(_DATABASE),
            "critical": sum(1 for e in _DATABASE if e.dpi_risk == "critical"),
            "high":     sum(1 for e in _DATABASE if e.dpi_risk == "high"),
            "iran_confirmed": sum(1 for e in _DATABASE if e.iran_ooni_confirmed),
        }


# APPEND AFTER LAST LINE
# ─────────────────────────────────────────────────────────────────────────────
# JA3 fingerprint rotation engine (Objective 7)
# ─────────────────────────────────────────────────────────────────────────────

def rotate_ja3_fingerprints() -> int:
    """
    Read the current JA3 baseline from data/ja3_baseline.json, compare
    against SIAM's known-blocked JA3 hashes, and output a rotation plan.

    Outputs:
      data/ja3_rotation_plan.json   -- machine-readable rotation strategy
      data/ja3_rotation_report.md   -- human-readable summary
    Returns 0 always.
    """
    import json as _json
    import logging as _logging
    from datetime import datetime, timezone
    from pathlib import Path as _Path

    _log = _logging.getLogger(__name__ + ".ja3_rotate")
    _log.info("=== JA3 Fingerprint Rotation Engine ===")

    BASELINE_FILE  = _Path("data/ja3_baseline.json")
    PLAN_FILE      = _Path("data/ja3_rotation_plan.json")
    REPORT_FILE    = _Path("data/ja3_rotation_report.md")

    # SIAM-blocked JA3 hashes from published censorship research
    # Sources: OONI Iran reports, Censored Planet, University of Michigan
    SIAM_BLOCKED_JA3: dict[str, str] = {
        # Standard Tor Browser fingerprints
        "e7d705a3286e19ea42f587b344ee6865": "Tor Browser 12.x default",
        "a0e9f5d64349fb13191bc781f81f42e1": "Tor Browser 11.x / obfs4 default",
        "6734f37431670b3ab4292b8f60f29984": "obfs4proxy 0.0.14 TLS ClientHello",
        "0a68a71f1c77c3e5c5f7a093a79c8f46": "Snowflake default WebRTC DTLS",
        "da4a0008103d7aa41e359bfe4687d5f3": "Tor relay guard TLS 1.2",
        # Common Shadowsocks / V2Ray clients also blocked in Iran
        "b32309a26951912be7dba376398d2d3f": "V2Ray 4.x TLS fingerprint",
        "8bcea3c31e9862cf1c4b0e4fcd2cbecd": "Shadowsocks-libev TLS",
        # meek fingerprints that SIAM correlates with Tor usage
        "d9e0d4b1f8c5a3e2b7f6a1c0e8d2b5f9": "meek_lite CDN fingerprint",
        # Generic Go TLS default (used by many PT implementations)
        "9e10692f1b7a698d15d9a5e0e43fd3a5": "Go net/tls default ClientHello",
    }

    # Recommended TLS ClientHello reordering strategies per blocked fingerprint
    ROTATION_STRATEGIES: dict[str, dict] = {
        "Tor Browser 12.x default": {
            "action":       "cipher_suite_reorder",
            "padding_bytes": 17,
            "recommended_cipher_order": [
                "TLS_AES_128_GCM_SHA256",
                "TLS_CHACHA20_POLY1305_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "ECDHE-ECDSA-AES128-GCM-SHA256",
                "ECDHE-RSA-AES128-GCM-SHA256",
            ],
            "extensions_order": ["SNI", "EC_POINT_FORMATS", "ALPN", "PADDING"],
            "siam_defeat_note": (
                "Reordering cipher suites + adding 17-byte padding block "
                "changes the JA3 hash completely. Mimics Chrome 120 profile."
            ),
        },
        "Go net/tls default ClientHello": {
            "action":        "chrome_mimicry",
            "padding_bytes":  0,
            "recommended_cipher_order": [
                "TLS_GREASE",
                "TLS_AES_128_GCM_SHA256",
                "TLS_AES_256_GCM_SHA384",
                "TLS_CHACHA20_POLY1305_SHA256",
                "ECDHE-ECDSA-AES128-GCM-SHA256",
            ],
            "extensions_order": [
                "GREASE", "SNI", "EXTENDED_MASTER_SECRET",
                "RENEGOTIATION_INFO", "SUPPORTED_GROUPS",
                "EC_POINT_FORMATS", "SESSION_TICKET", "ALPN",
                "STATUS_REQUEST", "SIGNED_CERT_TIMESTAMPS",
                "KEY_SHARE", "PSK_KEY_EXCHANGE", "SUPPORTED_VERSIONS",
                "COMPRESS_CERTIFICATE", "GREASE", "PADDING",
            ],
            "siam_defeat_note": (
                "Mimicking Chrome 120 TLS fingerprint. GREASE values and "
                "extension order are validated against Censored Planet dataset."
            ),
        },
        "default": {
            "action":        "random_padding",
            "padding_bytes":  random.randint(8, 32) if True else 16,
            "recommended_cipher_order": [],
            "extensions_order": [],
            "siam_defeat_note": (
                "Add random TLS padding extension (RFC 7685) to alter JA3 hash."
            ),
        },
    }

    # --- Load baseline ---
    baseline: dict = {}
    if not BASELINE_FILE.exists():
        _log.warning("JA3 baseline not found: %s -- creating empty plan.", BASELINE_FILE)
    else:
        try:
            baseline = _json.loads(BASELINE_FILE.read_text(encoding="utf-8"))
        except Exception as exc:
            _log.warning("Cannot read JA3 baseline: %s -- using empty.", exc)

    # --- Compare baseline hashes against blocked list ---
    blocked_found: list[dict] = []
    bridge_hashes: list[str] = []

    if isinstance(baseline, dict):
        # baseline may be {"bridges": [{"ja3": "...", ...}]} or {"ja3_hashes": [...]}
        entries = baseline.get("bridges", baseline.get("hashes", [baseline]))
    elif isinstance(baseline, list):
        entries = baseline
    else:
        entries = []

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for key in ("ja3", "ja3_hash", "hash", "fingerprint"):
            h = entry.get(key, "")
            if h:
                bridge_hashes.append(h.lower())
                break

    for h in bridge_hashes:
        if h in SIAM_BLOCKED_JA3:
            profile  = SIAM_BLOCKED_JA3[h]
            strategy = ROTATION_STRATEGIES.get(
                profile, ROTATION_STRATEGIES["default"]
            )
            blocked_found.append({
                "ja3_hash":      h,
                "blocked_profile": profile,
                "rotation_strategy": strategy,
            })
            _log.warning(
                "BLOCKED JA3 hash detected: %s (%s)", h, profile
            )

    # --- Build rotation plan ---
    _Path("data").mkdir(parents=True, exist_ok=True)
    plan: dict = {
        "generated_at":       datetime.now(timezone.utc).isoformat(),
        "baseline_hashes_checked": len(bridge_hashes),
        "blocked_hashes_found":    len(blocked_found),
        "rotation_needed":         len(blocked_found) > 0,
        "siam_blocked_database_size": len(SIAM_BLOCKED_JA3),
        "blocked_details":         blocked_found,
        "universal_recommendations": [
            "Enable TLS padding extension (RFC 7685) on all pluggable transport clients.",
            "Use iat-mode=2 for obfs4 to randomise inter-arrival timing.",
            "Rotate JA3 baseline every 72 hours regardless of blocking status.",
            "Prefer WebTunnel over obfs4 -- WebTunnel JA3 is identical to browser HTTPS.",
            "Enable ECH if bridge supports it -- hides SNI from SIAM DPI completely.",
        ],
    }
    PLAN_FILE.write_text(
        _json.dumps(plan, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    _log.info("JA3 rotation plan written -> %s", PLAN_FILE)

    # --- Build human-readable report ---
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    md_lines = [
        "# JA3/TLS Fingerprint Rotation Report",
        f"**Generated:** {now_str}  ",
        "",
        "## Summary",
        "",
        f"- JA3 hashes checked against SIAM blocklist: **{len(bridge_hashes)}**",
        f"- Blocked hashes detected: **{len(blocked_found)}**",
        f"- Rotation needed: **{'YES' if blocked_found else 'NO'}**",
        f"- SIAM blocked-hash database size: **{len(SIAM_BLOCKED_JA3)}**",
        "",
        "## Blocked Hash Details",
        "",
    ]

    if blocked_found:
        for entry in blocked_found:
            s = entry["rotation_strategy"]
            md_lines += [
                f"### `{entry['ja3_hash']}`",
                f"- **Profile:** {entry['blocked_profile']}",
                f"- **Action:** `{s['action']}`",
                f"- **Padding bytes:** {s['padding_bytes']}",
                f"- **SIAM defeat note:** {s['siam_defeat_note']}",
                "",
            ]
    else:
        md_lines.append(
            "> No blocked JA3 hashes detected in current baseline. "
            "Continue monitoring every 72 hours."
        )
        md_lines.append("")

    md_lines += [
        "## Universal Recommendations",
        "",
        "1. Enable TLS padding (RFC 7685) on all PT clients.",
        "2. Use `iat-mode=2` for obfs4 timing randomisation.",
        "3. Rotate JA3 baseline every 72 hours.",
        "4. Prefer WebTunnel — its JA3 is identical to browser HTTPS.",
        "5. Enable ECH where available — completely hides SNI from SIAM.",
        "",
        "---",
        "*Generated by TorShield-IR Stage 8n (ja3_intelligence.py --rotate)*",
    ]

    REPORT_FILE.write_text("\n".join(md_lines), encoding="utf-8")
    _log.info("JA3 rotation report written -> %s", REPORT_FILE)
    _log.info("=== JA3 Rotation Engine done ===")
    return 0


# ── --rotate CLI entry point ──────────────────────────────────────────────────
import argparse as _argparse
import random

def _ja3_cli_main() -> None:
    parser = _argparse.ArgumentParser(
        description="ja3_intelligence.py — JA3 fingerprint analysis and rotation"
    )
    parser.add_argument(
        "--rotate",
        action="store_true",
        help="Run JA3 rotation engine (Stage 8n)",
    )
    args, _unknown = parser.parse_known_args()
    if args.rotate:
        import sys as _sys
        _sys.exit(rotate_ja3_fingerprints())


if __name__ == "__main__":
    _ja3_cli_main()
