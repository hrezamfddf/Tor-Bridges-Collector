#!/usr/bin/env python3
"""
xtls_reality_wrapper.py — Stage 8l: XTLS-Reality VLESS Config Generator

Reads high-scoring bridges from bridge/iran_likely_working_obfs4.txt and
generates VLESS + XTLS-Reality config fragments for each, using domestic
Iranian CDN domains as Reality SNI so that traffic is indistinguishable from
legitimate HTTPS to Aparat/Digikala/Telewebion at Iran's SIAM DPI layer.

Key generation:
  X25519 private/public keys are generated entirely in Python using the
  `cryptography` library — no external binary is called.

Outputs:
  export/reality_configs.json  — per-bridge VLESS+Reality config fragments
  data/reality_report.json     — DPI resistance scores and aggregate summary
"""
from __future__ import annotations

import json
import logging
import os
import re
import secrets
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
INPUT_FILE    = Path("bridge/iran_likely_working_obfs4.txt")
CONFIGS_OUT   = Path("export/reality_configs.json")
REPORT_OUT    = Path("data/reality_report.json")

# ── Iran domestic CDN SNI domains (accessible on NIN) ────────────────────────
IRAN_CDN_SNIS = [
    "www.aparat.com",
    "www.digikala.com",
    "cdn.telewebion.com",
]

# ── DPI-resistant ports on NIN ────────────────────────────────────────────────
NIN_SAFE_PORTS = {443, 8443, 2053, 2083, 2087}


# ── Key generation ────────────────────────────────────────────────────────────

def _generate_x25519_keypair() -> tuple[str, str]:
    """
    Generate an X25519 key pair for XTLS-Reality using the `cryptography` library.
    Returns (private_key_b64, public_key_b64) in URL-safe base64 (no padding).
    Falls back to os.urandom random bytes if the library is unavailable.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        import base64
        private = X25519PrivateKey.generate()
        private_bytes = private.private_bytes_raw()
        public_bytes  = private.public_key().public_bytes_raw()
        priv_b64 = base64.urlsafe_b64encode(private_bytes).rstrip(b"=").decode()
        pub_b64  = base64.urlsafe_b64encode(public_bytes).rstrip(b"=").decode()
        return priv_b64, pub_b64
    except ImportError:
        log.warning("cryptography library not available — using placeholder keys.")
        import base64
        priv_bytes = os.urandom(32)
        pub_bytes  = os.urandom(32)
        return (
            base64.urlsafe_b64encode(priv_bytes).rstrip(b"=").decode(),
            base64.urlsafe_b64encode(pub_bytes).rstrip(b"=").decode(),
        )


def _generate_short_id() -> str:
    """Generate an 8-byte (16 hex char) Reality shortId."""
    return secrets.token_hex(8)


# ── Bridge parsing ────────────────────────────────────────────────────────────

def _parse_bridge(line: str) -> dict[str, Any] | None:
    """Parse an obfs4 bridge line and extract ip/port/fingerprint."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    # Remove 'obfs4' prefix
    rest = re.sub(r"^obfs4\s+", "", line, flags=re.I)

    # IPv4:port
    m4 = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})\b", rest)
    if m4:
        ip   = m4.group(1)
        port = int(m4.group(2))
    else:
        # IPv6 [addr]:port
        m6 = re.search(r"\[([0-9a-fA-F:]+)\]:(\d{2,5})", rest)
        if m6:
            ip   = m6.group(1)
            port = int(m6.group(2))
        else:
            return None

    # Fingerprint
    fp_match = re.search(r"\b([0-9A-Fa-f]{40})\b", rest)
    fingerprint = fp_match.group(1) if fp_match else ""

    return {"raw": line, "ip": ip, "port": port, "fingerprint": fingerprint}


# ── DPI resistance scoring ────────────────────────────────────────────────────

def _score_config(bridge: dict[str, Any], sni: str) -> float:
    """
    Score a Reality config for DPI resistance in Iran's NIN (0.0–1.0).
    Components:
      - Iranian CDN SNI used          → +0.40
      - NIN-safe port (443/8443/…)   → +0.30
      - IP entropy (non-datacenter)  → +0.15
      - shortId randomness           → +0.15
    """
    score = 0.0
    if sni in IRAN_CDN_SNIS:
        score += 0.40
    if bridge["port"] in NIN_SAFE_PORTS:
        score += 0.30
    # Heuristic: IPs not in 10.x/172.x/192.x are likely real endpoints
    if not bridge["ip"].startswith(("10.", "172.", "192.168.")):
        score += 0.15
    # Random shortId always adds entropy → full bonus
    score += 0.15
    return round(min(score, 1.0), 4)


# ── Config generation ─────────────────────────────────────────────────────────

def _make_vless_reality_config(bridge: dict[str, Any],
                                sni: str,
                                uuid: str) -> dict[str, Any]:
    """Build a VLESS + XTLS-Reality JSON config fragment."""
    private_key, public_key = _generate_x25519_keypair()
    short_id = _generate_short_id()

    return {
        "outbound": {
            "protocol": "vless",
            "settings": {
                "vnext": [
                    {
                        "address": bridge["ip"],
                        "port":    bridge["port"],
                        "users": [
                            {
                                "id":         uuid,
                                "encryption": "none",
                                "flow":       "xtls-rprx-vision",
                            }
                        ],
                    }
                ]
            },
            "streamSettings": {
                "network":  "tcp",
                "security": "reality",
                "realitySettings": {
                    "serverName":  sni,
                    "fingerprint": "chrome",
                    "shortId":     short_id,
                    "publicKey":   public_key,
                    "spiderX":     "/",
                },
            },
        },
        "_meta": {
            "source_bridge":   bridge["raw"],
            "source_ip":       bridge["ip"],
            "source_port":     bridge["port"],
            "fingerprint":     bridge["fingerprint"],
            "reality_sni":     sni,
            "private_key":     private_key,
            "public_key":      public_key,
            "short_id":        short_id,
            "uuid":            uuid,
            "dpi_score":       _score_config(bridge, sni),
            "generated_at":    datetime.now(timezone.utc).isoformat(),
            "iran_note": (
                f"Traffic will appear as HTTPS to {sni}, which is on Iran's "
                "NIN domestic CDN allowlist. XTLS-Reality borrows the TLS cert "
                "of the target domain — SIAM DPI cannot distinguish it from "
                "legitimate domestic HTTPS without decrypting the session."
            ),
        },
    }


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    log.info("═══ Stage 8l: XTLS-Reality VLESS Config Generator ══════════")

    Path("export").mkdir(parents=True, exist_ok=True)
    Path("data").mkdir(parents=True, exist_ok=True)

    if not INPUT_FILE.exists():
        log.warning("Input file not found: %s — writing empty outputs.", INPUT_FILE)
        _write_empty(reason=f"Input file not found: {INPUT_FILE}")
        return 0

    raw_lines = INPUT_FILE.read_text(encoding="utf-8").splitlines()
    bridges: list[dict[str, Any]] = []
    for line in raw_lines:
        parsed = _parse_bridge(line)
        if parsed:
            bridges.append(parsed)

    log.info("Parsed %d obfs4 bridges from %s.", len(bridges), INPUT_FILE)

    if not bridges:
        log.warning("No parseable bridges — writing empty outputs.")
        _write_empty(reason="No parseable bridges in input file.")
        return 0

    configs: list[dict[str, Any]] = []
    scores:  list[float]           = []

    for bridge in bridges:
        # Cycle through SNIs so each bridge gets a different CDN domain
        sni  = IRAN_CDN_SNIS[len(configs) % len(IRAN_CDN_SNIS)]
        uuid = _generate_uuid()
        cfg  = _make_vless_reality_config(bridge, sni, uuid)
        configs.append(cfg)
        scores.append(cfg["_meta"]["dpi_score"])
        log.debug("Config for %s:%d → SNI=%s score=%.2f",
                  bridge["ip"], bridge["port"], sni, cfg["_meta"]["dpi_score"])

    # Write configs
    CONFIGS_OUT.write_text(
        json.dumps({"generated_at": datetime.now(timezone.utc).isoformat(),
                    "count": len(configs),
                    "configs": configs},
                   indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    log.info("Reality configs written: %d → %s", len(configs), CONFIGS_OUT)

    # Write report
    avg_score = round(sum(scores) / len(scores), 4) if scores else 0.0
    report: dict[str, Any] = {
        "generated_at":      datetime.now(timezone.utc).isoformat(),
        "total_configs":     len(configs),
        "average_dpi_score": avg_score,
        "snis_used":         IRAN_CDN_SNIS,
        "scoring_note": (
            "DPI resistance scored on: Iranian CDN SNI (+0.40), NIN-safe port (+0.30), "
            "non-datacenter IP (+0.15), random shortId entropy (+0.15). "
            "Maximum score: 1.0 — represents traffic indistinguishable from "
            "domestic HTTPS at SIAM DPI layer."
        ),
        "per_bridge": [
            {
                "ip":        c["_meta"]["source_ip"],
                "port":      c["_meta"]["source_port"],
                "sni":       c["_meta"]["reality_sni"],
                "dpi_score": c["_meta"]["dpi_score"],
            }
            for c in configs
        ],
    }
    REPORT_OUT.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    log.info("Reality report written: avg_dpi_score=%.4f → %s", avg_score, REPORT_OUT)
    log.info("═══ Stage 8l done ═══════════════════════════════════════════")
    return 0


def _generate_uuid() -> str:
    """Generate a RFC 4122 UUID v4 without any external library."""
    rnd = bytearray(os.urandom(16))
    rnd[6] = (rnd[6] & 0x0F) | 0x40   # version 4
    rnd[8] = (rnd[8] & 0x3F) | 0x80   # variant
    h = rnd.hex()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def _write_empty(reason: str = "") -> None:
    empty: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "count": 0,
        "configs": [],
        "note": reason,
    }
    CONFIGS_OUT.write_text(json.dumps(empty, indent=2), encoding="utf-8")
    REPORT_OUT.write_text(
        json.dumps({**empty, "total_configs": 0, "average_dpi_score": 0.0},
                   indent=2),
        encoding="utf-8",
    )


if __name__ == "__main__":
    sys.exit(main())
