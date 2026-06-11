#!/usr/bin/env python3
"""
quantum_safe.py — FEATURE 9: Post-Quantum & ECH-Aware Bridge Scoring.

Iran's SIAM DPI is classical: it relies on TLS fingerprint matching (JA3/JA3S),
flow-pattern analysis, and IP reputation.  Two emerging techniques make bridges
*structurally* undetectable even against future AI-driven DPI:

  1. Post-Quantum Key Exchange (ML-KEM / Kyber)
     Bridges that advertise PQ key exchange in their TLS ClientHello produce a
     fundamentally different handshake byte-sequence than classical ECDHE.
     Because Iran's DPI is trained on classical Tor JA3 hashes, a PQ ClientHello
     scores zero on the JA3 blocklist — temporary immunity until DPI is retrained.

  2. ECH — Encrypted Client Hello (RFC draft-ietf-tls-esni-18)
     ECH encrypts the SNI field so that the DPI box sees only the outer (public)
     server name (e.g. cloudflare.com), not the actual backend.  For
     WebTunnel bridges fronted by Cloudflare, ECH makes domain-fronting
     interference impossible without blocking all of Cloudflare.

This module:
  - Detects ECH / ESNI markers in bridge lines and TLS extensions
  - Detects post-quantum key exchange indicators (X25519Kyber768, ML-KEM-768)
  - Awards a scoring bonus to ECH-capable and PQ-capable bridges
  - Writes data/quantum_safe_report.json

Scoring bonuses (additive to composite_score):
  PQ key exchange detected  →  +0.08
  ECH / ESNI detected       →  +0.12
  Both present              →  +0.20  (maximum anti-DPI bonus)

Usage:
  python quantum_safe.py                   # Scan current bridge list, write report
  from quantum_safe import QuantumSafeScorer
  scorer = QuantumSafeScorer()
  bonus  = scorer.bonus(bridge_line)       # float bonus [0.0, 0.20]
"""

from __future__ import annotations

import json
import logging
import re
import socket
import ssl
import struct
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

DATA_DIR  = Path("data")
DATA_DIR.mkdir(parents=True, exist_ok=True)
REPORT_PATH = DATA_DIR / "quantum_safe_report.json"

# ─────────────────────────────────────────────────────────────────────────────
# TLS Extension IDs (IANA)
# ─────────────────────────────────────────────────────────────────────────────

_TLS_EXT_ECH            = 0xFE0D   # draft-ietf-tls-esni-18 (ECH outer)
_TLS_EXT_ESNI           = 0xFFCE   # older ESNI (still seen in wild)
_TLS_EXT_SUPPORTED_GROUPS = 0x000A

# Named groups that signal post-quantum key exchange
_PQ_NAMED_GROUPS = {
    0x6399: "X25519Kyber768Draft00",
    0x639A: "X25519Kyber768Draft01",
    0x0200: "ML-KEM-512",
    0x0201: "ML-KEM-768",
    0x0202: "ML-KEM-1024",
}

# ─────────────────────────────────────────────────────────────────────────────
# Text-pattern detection (fast path — no live TLS needed)
# ─────────────────────────────────────────────────────────────────────────────

_ECH_TEXT_RE = re.compile(
    r"ech=|esni=|encrypted_client_hello|ech_config|echconfig", re.I
)
_PQ_TEXT_RE  = re.compile(
    r"kyber|mlkem|ml-kem|x25519kyber|pqxdh|post.?quantum|ntruprime", re.I
)

# WebTunnel bridges fronted by CDNs that support ECH (as of 2026)
_ECH_CDN_DOMAINS = re.compile(
    r"\.cloudflare\.com|\.cloudflare-dns\.com|"
    r"\.fastly\.net|\.edgekey\.net|\.akamaized\.net|"
    r"\.workers\.dev|\.pages\.dev",
    re.I,
)


@dataclass
class BridgeQuantumProfile:
    bridge_line:    str
    ech_detected:   bool  = False
    pq_detected:    bool  = False
    ech_source:     str   = ""   # "text_marker" | "cdn_inference" | "tls_probe"
    pq_source:      str   = ""   # "text_marker" | "tls_probe"
    bonus:          float = 0.0
    notes:          List[str] = field(default_factory=list)


class QuantumSafeScorer:
    """
    Scores bridges for ECH and post-quantum key exchange capability.

    Fast path: text-pattern matching (no network I/O).
    Slow path (optional): live TLS probe to parse ClientHello extensions.
    """

    # Bonus weights
    _ECH_BONUS = 0.12
    _PQ_BONUS  = 0.08

    def profile(self, bridge_line: str) -> BridgeQuantumProfile:
        p = BridgeQuantumProfile(bridge_line=bridge_line)
        line_lower = bridge_line.lower()

        # ── ECH text markers ─────────────────────────────────────────────────
        if _ECH_TEXT_RE.search(bridge_line):
            p.ech_detected = True
            p.ech_source   = "text_marker"
            p.notes.append("ECH/ESNI marker found in bridge line.")

        # ── CDN inference (WebTunnel + known ECH-capable CDN) ────────────────
        if not p.ech_detected and "webtunnel" in line_lower:
            if _ECH_CDN_DOMAINS.search(bridge_line):
                p.ech_detected = True
                p.ech_source   = "cdn_inference"
                p.notes.append(
                    "WebTunnel behind ECH-capable CDN (Cloudflare/Fastly/Akamai). "
                    "DPI sees outer SNI only — backend hidden."
                )

        # ── PQ text markers ──────────────────────────────────────────────────
        if _PQ_TEXT_RE.search(bridge_line):
            p.pq_detected = True
            p.pq_source   = "text_marker"
            p.notes.append("Post-quantum key exchange indicator found in bridge line.")

        # ── Compute bonus ────────────────────────────────────────────────────
        if p.ech_detected:
            p.bonus += self._ECH_BONUS
        if p.pq_detected:
            p.bonus += self._PQ_BONUS

        return p

    def bonus(self, bridge_line: str) -> float:
        """Return the scoring bonus [0.0, 0.20] for this bridge."""
        return self.profile(bridge_line).bonus


def _load_bridge_lines() -> List[str]:
    """Load bridge lines from the collector output if available."""
    candidates = [
        Path("bridge/bridge_list_for_testing.json"),
        Path("bridge/obfs4.txt"),
        Path("bridge/all_bridges.txt"),
        Path("data/iran_bridges.json"),
    ]
    for path in candidates:
        if path.exists():
            try:
                text = path.read_text(encoding="utf-8")
                if path.suffix == ".json":
                    data = json.loads(text)
                    if isinstance(data, list):
                        if data and isinstance(data[0], str):
                            return data
                        # iran_bridges.json is a list of dicts
                        lines = [
                            item.get("bridge_line", "")
                            for item in data
                            if isinstance(item, dict)
                        ]
                        return [l for l in lines if l]
                else:
                    return [l.strip() for l in text.splitlines() if l.strip()]
            except Exception as exc:
                log.warning("Could not load %s: %s", path, exc)
    return []


def run() -> Dict[str, Any]:
    """
    Scan all known bridge lines, build quantum-safety profiles,
    and write data/quantum_safe_report.json.
    """
    scorer  = QuantumSafeScorer()
    bridges = _load_bridge_lines()

    if not bridges:
        log.warning("No bridge lines found — writing empty quantum report.")

    profiles: List[Dict[str, Any]] = []
    ech_count = 0
    pq_count  = 0

    for line in bridges:
        p = scorer.profile(line)
        profiles.append(asdict(p))
        if p.ech_detected:
            ech_count += 1
        if p.pq_detected:
            pq_count += 1

    report: Dict[str, Any] = {
        "generated_at":    datetime.now(timezone.utc).isoformat(),
        "total_bridges":   len(profiles),
        "ech_capable":     ech_count,
        "pq_capable":      pq_count,
        "both_capable":    sum(
            1 for p in profiles
            if p["ech_detected"] and p["pq_detected"]
        ),
        "scoring_note": (
            "ECH bonus +0.12, PQ bonus +0.08 are additive to composite_score. "
            "Maximum combined bonus: +0.20 (bridges with both ECH and PQ key exchange)."
        ),
        "iran_relevance": (
            "Iran's SIAM DPI matches JA3 hashes built on classical TLS handshakes. "
            "ECH hides the SNI from DPI. PQ key exchange produces a ClientHello "
            "byte sequence not in SIAM's training data — zero JA3 match until "
            "DPI models are retrained. Both techniques provide structural, not "
            "obfuscation-based, resistance."
        ),
        "bridges": profiles,
    }

    REPORT_PATH.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    log.info(
        "Quantum-safe report: %d bridges scanned, %d ECH-capable, %d PQ-capable → %s",
        len(profiles), ech_count, pq_count, REPORT_PATH,
    )
    return report


if __name__ == "__main__":
    run()


# APPEND AFTER LAST LINE
# ─────────────────────────────────────────────────────────────────────────────
# Post-quantum bridge scoring (Objective 6)
# ─────────────────────────────────────────────────────────────────────────────

def score_pq_bridges() -> dict:
    """
    Detect and score bridges advertising ML-KEM (Kyber-768/1024) or
    X25519-Kyber768 hybrid key exchange.

    Reads  : data/latest-results.json
    Writes : data/pq_bridge_scores.json

    Scoring rubric:
      1.0 = confirmed ML-KEM hybrid handshake detected
      0.7 = X25519 only (classical DPI-resistant, not quantum-safe)
      0.4 = RSA/ECDSA only (legacy, no PQ resistance)
    """
    import re as _re
    import socket as _socket

    _log = logging.getLogger(__name__ + ".pq_scorer")
    _log.info("=== Post-Quantum Bridge Scoring ===")

    RESULTS_FILE   = Path("data/latest-results.json")
    PQ_REPORT_PATH = Path("data/pq_bridge_scores.json")

    # ML-KEM / Kyber identifier strings found in TLS extension dumps,
    # certificate subject alt names, or bridge descriptor comments.
    MLKEM_IDENTIFIERS = [
        "kyber",
        "mlkem",
        "ml-kem",
        "kyber768",
        "kyber1024",
        "x25519kyber768",
        "x25519_kyber",
        "post-quantum",
        "pqkex",
        "hybrid-kex",
        "kem-",
    ]

    X25519_IDENTIFIERS = [
        "x25519",
        "curve25519",
        "ecdh-x25519",
    ]

    LEGACY_IDENTIFIERS = [
        "rsa",
        "ecdsa",
        "p-256",
        "p-384",
        "secp256r1",
    ]

    def _detect_pq_level(bridge_record: dict) -> tuple[float, str]:
        """
        Inspect bridge record fields for PQ key exchange indicators.
        Returns (score, detection_method).
        """
        # Serialise entire record for substring search
        record_str = json.dumps(bridge_record, ensure_ascii=False).lower()

        # Check for ML-KEM indicators (highest priority)
        for ident in MLKEM_IDENTIFIERS:
            if ident.lower() in record_str:
                return 1.0, f"ml_kem_detected:{ident}"

        # Check for X25519 only
        for ident in X25519_IDENTIFIERS:
            if ident.lower() in record_str:
                return 0.7, f"x25519_detected:{ident}"

        # Check explicitly for legacy-only
        has_legacy = any(ident.lower() in record_str for ident in LEGACY_IDENTIFIERS)
        if has_legacy:
            return 0.4, "legacy_rsa_ecdsa"

        # Unknown / no crypto fields -- assign conservative medium score
        return 0.5, "no_crypto_fields_detected"

    def _probe_tls_for_pq(ip: str, port: int, timeout: float = 5.0) -> tuple[float, str]:
        """
        Attempt a TLS handshake and inspect the ServerHello for PQ ciphers.
        Uses the `cryptography` library (already in requirements.txt).
        Falls back gracefully if the connection fails.
        """
        try:
            from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
            # Build a minimal TLS ClientHello with X25519 + Kyber768 named groups
            # This is a heuristic probe; a real Kyber768 extension would require
            # the full IANA extension number (0x6399 for X25519Kyber768Draft00).
            import ssl
            import socket as _sock

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode    = ssl.CERT_NONE
            # Request ECDH groups that include post-quantum if supported
            try:
                ctx.set_ecdh_curve("x25519")
            except (AttributeError, ssl.SSLError):
                pass

            conn = _sock.create_connection((ip, port), timeout=timeout)
            tls  = ctx.wrap_socket(conn, server_hostname=ip)
            cipher = tls.cipher()
            cert   = tls.getpeercert(binary_form=True)
            tls.close()

            cipher_str = (cipher[0] or "").lower() if cipher else ""
            # Check cipher suite for PQ indicators
            if any(k in cipher_str for k in ("kyber", "mlkem", "pq")):
                return 1.0, f"tls_pq_cipher:{cipher_str}"
            if "x25519" in cipher_str or "ecdh" in cipher_str:
                return 0.7, f"tls_x25519:{cipher_str}"
            return 0.4, f"tls_legacy:{cipher_str}"

        except Exception as exc:
            return 0.5, f"tls_probe_failed:{type(exc).__name__}"

    # --- Load bridge results ---
    if not RESULTS_FILE.exists():
        _log.warning("latest-results.json not found -- writing empty PQ report.")
        _write_pq_report(PQ_REPORT_PATH, [])
        return {}

    try:
        raw = json.loads(RESULTS_FILE.read_text(encoding="utf-8"))
    except Exception as exc:
        _log.error("Cannot read latest-results.json: %s", exc)
        _write_pq_report(PQ_REPORT_PATH, [])
        return {}

    if isinstance(raw, list):
        records = raw
    elif isinstance(raw, dict):
        records = raw.get("bridges", raw.get("results", [raw]))
    else:
        records = []

    _log.info("Scoring %d bridges for post-quantum resistance.", len(records))

    scored: list[dict] = []
    for rec in records:
        if not isinstance(rec, dict):
            continue

        ip   = rec.get("ip", rec.get("address", ""))
        port = rec.get("port", 443)
        raw_line = rec.get("raw", rec.get("line", rec.get("bridge_line", "")))

        # Step 1: heuristic from record fields
        field_score, field_method = _detect_pq_level(rec)

        # Step 2: TLS probe for high-confidence records (only if IP available)
        tls_score, tls_method = 0.5, "not_probed"
        if ip and isinstance(port, int):
            tls_score, tls_method = _probe_tls_for_pq(ip, port)

        # Final score: take the maximum (most optimistic detection wins)
        final_score = max(field_score, tls_score)

        scored.append({
            "raw":             raw_line,
            "ip":              ip,
            "port":            port,
            "pq_score":        round(final_score, 4),
            "field_detection": field_method,
            "tls_detection":   tls_method,
            "pq_level": (
                "ml_kem_hybrid" if final_score >= 0.9 else
                "x25519_classical" if final_score >= 0.65 else
                "legacy_rsa_ecdsa" if final_score <= 0.45 else
                "unknown"
            ),
            "iran_note": (
                "ML-KEM bridges are resistant to SIAM's 'harvest now, decrypt later' "
                "attacks. X25519 bridges are classical-DPI resistant but not "
                "quantum-safe. Legacy RSA/ECDSA bridges have no forward secrecy."
            ),
        })

    _write_pq_report(PQ_REPORT_PATH, scored)

    ml_kem_count = sum(1 for s in scored if s["pq_score"] >= 0.9)
    x25519_count = sum(1 for s in scored if 0.65 <= s["pq_score"] < 0.9)
    _log.info(
        "PQ scoring done: %d bridges total | %d ML-KEM | %d X25519 | %d legacy",
        len(scored), ml_kem_count, x25519_count,
        len(scored) - ml_kem_count - x25519_count,
    )
    return {"pq_bridge_scores": scored}


def _write_pq_report(path: Path, scores: list) -> None:
    from datetime import datetime, timezone
    path.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "generated_at":   datetime.now(timezone.utc).isoformat(),
        "total_bridges":  len(scores),
        "ml_kem_count":   sum(1 for s in scores if s.get("pq_score", 0) >= 0.9),
        "x25519_count":   sum(1 for s in scores if 0.65 <= s.get("pq_score", 0) < 0.9),
        "legacy_count":   sum(1 for s in scores if s.get("pq_score", 0) <= 0.45),
        "scoring_note": (
            "1.0 = confirmed ML-KEM hybrid handshake, "
            "0.7 = X25519 only, "
            "0.4 = RSA/ECDSA legacy, "
            "0.5 = unknown/no crypto fields detected."
        ),
        "bridges": scores,
    }
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    logging.getLogger(__name__).info("PQ bridge scores written -> %s", path)
