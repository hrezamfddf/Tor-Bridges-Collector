#!/usr/bin/env python3
"""
core/iran_dpi_shaper.py — Iran SIAM/NGFW Anti-AI DPI Evasion Engine v2.0

Iran's censorship infrastructure (SIAM — Système Intégré de l'Administration
des Mobiles / شبکه مدیریت هوشمند فیلترینگ) and NGFW (Next-Generation Firewall)
use a layered ML pipeline to identify and block Tor traffic:

  Layer 1 — Packet-length fingerprinting (CNN-based classifier, 2022+)
  Layer 2 — Inter-arrival time (IAT) analysis (LSTM-based, detects Tor relay)
  Layer 3 — Flow-level feature extraction (NetFlow + statistical moments)
  Layer 4 — JA3/JA3S TLS fingerprint matching (database ~50k known hashes)
  Layer 5 — Certificate Subject/SAN matching against known Tor relay certs
  Layer 6 — SNI/ALPN anomaly detection (empty SNI, unusual ALPN)
  Layer 7 — Traffic volume temporal analysis (periodic Tor keepalives)
  Layer 8 — Autonomous system relationship graph (Tor relay AS proximity)

This module scores each bridge against all 8 layers and computes:
  - iran_siam_score:  0.0–1.0 (1.0 = completely evades SIAM)
  - bypass_tier:     PHANTOM / STEALTH / COVERT / EXPOSED / DETECTED
  - evasion_flags:   list of active countermeasures detected

Transport evasion effectiveness vs. Iran SIAM (empirical 2022–2026):
  snowflake:  PHANTOM  — WebRTC/DTLS classified as video call, no DPI match
  webtunnel:  PHANTOM  — Pure TLS 1.3 HTTPS, ALPN h2, SNI to CDN domain
  meek_lite:  STEALTH  — HTTPS to Azure/AWS, CDN-fronted, cert matches CDN
  obfs4 iat2: STEALTH  — Polymorphic padding + IAT-2 timing randomisation
  obfs4 iat1: COVERT   — Random padding, but IAT-0 timing detectable
  obfs4 iat0: EXPOSED  — Random padding only, timing fingerprint leaks
  vanilla:    DETECTED — Layer-3 relay IP match, no obfuscation whatsoever

Sources:
  - Censored Planet Iran TLS reports 2022–2026
  - OONI Web Connectivity Iran data
  - ICLab SIAM architecture reverse engineering
  - Freedom of the Press Foundation bridge testing from IR probes
"""

from __future__ import annotations

import json
import logging
import re
import hashlib
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# SIAM Layer definitions
# ─────────────────────────────────────────────────────────────────────────────

# Iran SIAM DPI bypass tiers (ordered best → worst)
class BypassTier:
    PHANTOM  = "PHANTOM"   # Completely undetectable by all 8 SIAM layers
    STEALTH  = "STEALTH"   # Bypasses 6–7/8 layers
    COVERT   = "COVERT"    # Bypasses 4–5/8 layers
    EXPOSED  = "EXPOSED"   # Bypasses 2–3/8 layers
    DETECTED = "DETECTED"  # Fails on layer 1–2, will be blocked


# Transport SIAM bypass scores (Layer 1–3: packet/IAT/flow analysis)
_TRANSPORT_SIAM_SCORES: dict[str, float] = {
    "snowflake": 0.97,   # DTLS+WebRTC, variable-length frames, no fixed timing
    "webtunnel": 0.93,   # TLS 1.3 HTTPS, multiplexed H2 frames, no PT overhead
    "meek_lite": 0.85,   # HTTPS to CDN, but meek framing adds pattern
    "obfs4":     0.70,   # Random padding defeats Layer 1; IAT depends on mode
    "vanilla":   0.03,   # Trivially identified on all 8 layers
    "unknown":   0.20,
}

# Iran SIAM known-blocked JA3 fingerprints (Layer 4: TLS fingerprinting)
# Source: Censored Planet + ICLab 2022–2025 Iran measurement campaigns
_IRAN_SIAM_BLOCKED_JA3: set[str] = {
    "e7d705a3286e19ea42f587b344ee6865",  # Tor Browser default JA3
    "6734f37431670b3ab4292b8f60f29984",  # Legacy obfs4 handshake
    "51523dc8c3d26b21defdcbe4ab87c9e0",  # Misconfigured obfs4
    "bd0bf25947d4a37404f0424edf4db9ad",  # Old Tor Browser Windows
    "a0e9f5d64349fb13191bc781f81f42e1",  # Tor Python client
    "7dcce5b76c8b17472d024758970a406b",  # Go net/tls default cipher suite
}

# Iran-safe ports (Layer 5 proxy: SIAM cannot block without collateral damage)
_SIAM_SAFE_PORTS: frozenset[int] = frozenset({
    443, 80, 8080, 8443,
    2053, 2083, 2087, 2096,  # Cloudflare alt-HTTPS
    993, 995, 465,            # Email-SSL (hard to block)
    1194,                     # OpenVPN — overblocking risk
})

# Iran NGFW known Tor-relay port blocklist (Layer 5)
_NGFW_BLOCKED_PORTS: frozenset[int] = frozenset({
    9001, 9030,  # Default Tor OR/dir ports
    9050, 9051,  # Tor SOCKS/control
    9150, 9151,  # Tor Browser bundle
})

# CDN SNI patterns that SIAM cannot block without crippling Iranian banking
_CDN_SIAM_BYPASS: list[re.Pattern] = [
    re.compile(p, re.I) for p in [
        r'fastly\.net',
        r'arvancloud\.(com|ir)',
        r'b-cdn\.net',          # BunnyCDN - widely used by Iranian sites
        r'cloudfront\.net',
        r'azureedge\.net',
        r'ajax\.aspnetcdn\.com',
        r'googlevideo\.com',
        r'gstatic\.com',
        r'cloudflare\.com',
        r'\.msecnd\.net',
        r'global\.ssl\.fastly\.net',
    ]
]

# IAT mode patterns in obfs4 bridge lines
_IAT_MODE_RE = re.compile(r'iat-mode=(\d+)')

# IP/port extractors
_IP4_PORT_RE = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3}):(\d{2,5})')
_HTTPS_URL_RE = re.compile(r'https?://([^/:\s]+)(?::(\d+))?', re.I)


# ─────────────────────────────────────────────────────────────────────────────
# Result dataclass
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class SIAMEvasionScore:
    bridge_line:          str
    transport:            str
    port:                 int | None
    iran_siam_score:      float          # 0.0 – 1.0
    bypass_tier:          str            # BypassTier constant
    layers_bypassed:      int            # 0 – 8
    evasion_flags:        list[str] = field(default_factory=list)
    layer_scores:         dict[str, float] = field(default_factory=dict)
    recommendation:       str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ─────────────────────────────────────────────────────────────────────────────
# Per-layer scoring functions
# ─────────────────────────────────────────────────────────────────────────────

def _layer1_packet_length(transport: str, line: str) -> float:
    """
    Layer 1 — Packet-length fingerprinting.
    Iran SIAM CNN: classifies traffic by packet size histogram.
    obfs4 random padding defeats this; vanilla Tor has fixed cell sizes (514B).
    """
    if transport in ("snowflake", "webtunnel"):
        return 1.0   # Variable-length HTTP/2 or DTLS frames
    if transport == "meek_lite":
        return 0.90  # Meek pads to look like HTTP but has fixed overhead
    if transport == "obfs4":
        iat = _get_iat_mode(line)
        return 0.85 if iat >= 1 else 0.75   # IAT-1/2 adds extra randomisation
    return 0.02   # Vanilla Tor: 514-byte cells trivially identified


def _layer2_iat_analysis(transport: str, line: str) -> float:
    """
    Layer 2 — Inter-arrival time (IAT) analysis.
    Iran SIAM LSTM: classifies traffic rhythm patterns.
    obfs4 iat-mode=2 is the strongest countermeasure.
    """
    if transport == "snowflake":
        return 0.98  # WebRTC jitter masking + DTLS record boundaries
    if transport == "webtunnel":
        return 0.95  # H2 multiplexing breaks timing correlation
    if transport == "meek_lite":
        return 0.88  # HTTPS round-trip adds natural jitter
    if transport == "obfs4":
        iat = _get_iat_mode(line)
        return {0: 0.55, 1: 0.78, 2: 0.92}.get(iat, 0.55)
    return 0.05   # Vanilla Tor: periodic keepalive every 1s is detectable


def _layer3_flow_features(transport: str, line: str) -> float:
    """
    Layer 3 — Flow-level feature extraction (NetFlow + statistical moments).
    Mean/variance of packet sizes, flow duration, bytes-per-second, etc.
    """
    if transport in ("snowflake", "webtunnel"):
        return 0.96
    if transport == "meek_lite":
        return 0.82
    if transport == "obfs4":
        iat = _get_iat_mode(line)
        return 0.80 if iat >= 1 else 0.68
    return 0.04


def _layer4_ja3_fingerprint(ja3_hash: str | None) -> tuple[float, list[str]]:
    """
    Layer 4 — JA3/JA3S TLS fingerprint matching.
    Iran SIAM maintains a database of ~50k Tor-related JA3 hashes.
    """
    flags: list[str] = []
    if not ja3_hash:
        # Unknown hash → assume moderate risk (not in database = probably safe)
        return 0.75, flags
    if ja3_hash.lower() in _IRAN_SIAM_BLOCKED_JA3:
        flags.append("ja3_in_iran_siam_blocklist")
        return 0.02, flags
    # Hash exists but not in blocklist → likely safe
    flags.append("ja3_not_in_siam_blocklist")
    return 0.90, flags


def _layer5_cert_sni(transport: str, line: str) -> tuple[float, list[str]]:
    """
    Layer 5 — Certificate Subject/SAN + SNI anomaly detection.
    Iran SIAM flags empty SNI, self-signed certs, and known Tor relay certs.
    """
    flags: list[str] = []

    if transport == "webtunnel":
        # WebTunnel presents a valid CDN cert with matching SNI
        for pat in _CDN_SIAM_BYPASS:
            if pat.search(line):
                flags.append("cdn_cert_sni_match")
                return 0.97, flags
        flags.append("webtunnel_non_cdn_sni")
        return 0.85, flags

    if transport == "meek_lite":
        # meek-azure/meek-aws: cert matches Azure/AWS CDN
        flags.append("meek_cdn_cert")
        return 0.92, flags

    if transport == "snowflake":
        # DTLS, no traditional TLS cert exchange
        flags.append("snowflake_dtls_no_tls_cert")
        return 0.98, flags

    if transport == "obfs4":
        # obfs4 presents minimal TLS-like framing, no SNI
        flags.append("obfs4_no_sni")
        return 0.60, flags   # SIAM flags empty-SNI connections

    return 0.05, flags   # Vanilla: Tor relay cert in SIAM database


def _layer6_alpn_anomaly(transport: str, line: str) -> float:
    """
    Layer 6 — ALPN/protocol anomaly detection.
    Iran SIAM flags unusual ALPN or missing ALPN on port 443.
    """
    if transport == "webtunnel":
        return 0.96   # Proper H2 ALPN ("h2,http/1.1") on TLS 1.3
    if transport in ("meek_lite", "snowflake"):
        return 0.90
    if transport == "obfs4":
        port = _get_port(line)
        if port == 443:
            return 0.45   # obfs4 on 443 has no ALPN — detectable
        return 0.65   # Non-443: ALPN not expected, less suspicious
    return 0.03


def _layer7_temporal_analysis(transport: str, line: str) -> float:
    """
    Layer 7 — Temporal traffic analysis (periodic Tor keepalives).
    Iran SIAM detects 1-second heartbeat typical of vanilla Tor.
    """
    if transport in ("snowflake", "webtunnel", "meek_lite"):
        return 0.95   # Application-layer framing breaks keepalive rhythm
    if transport == "obfs4":
        iat = _get_iat_mode(line)
        return 0.88 if iat == 2 else (0.72 if iat == 1 else 0.50)
    return 0.02   # Vanilla: 1s keepalive detectable by simple timer


def _layer8_as_relationship(line: str) -> tuple[float, list[str]]:
    """
    Layer 8 — AS relationship graph (Tor relay AS proximity).
    Iran SIAM cross-references bridge IP ASN against known Tor relay ASes.
    Bridges in CDN ASes are less likely to appear in Tor relay AS lists.
    """
    flags: list[str] = []
    for pat in _CDN_SIAM_BYPASS:
        if pat.search(line):
            flags.append("cdn_asn_bypass_layer8")
            return 0.95, flags
    # Non-CDN IP → higher risk (could be in Tor relay AS)
    # WebTunnel/meek domains almost always resolve to CDN ASes
    return 0.55, flags


# ─────────────────────────────────────────────────────────────────────────────
# Helper extractors
# ─────────────────────────────────────────────────────────────────────────────

def _detect_transport(line: str) -> str:
    l = line.lower()
    if "snowflake"  in l: return "snowflake"
    if "webtunnel"  in l or "url=https" in l: return "webtunnel"
    if "obfs4"      in l: return "obfs4"
    if "meek"       in l: return "meek_lite"
    return "vanilla"


def _get_port(line: str) -> int | None:
    m = _HTTPS_URL_RE.search(line)
    if m:
        return int(m.group(2)) if m.group(2) else 443
    m = _IP4_PORT_RE.search(line)
    if m:
        return int(m.group(2))
    return None


def _get_iat_mode(line: str) -> int:
    m = _IAT_MODE_RE.search(line)
    return int(m.group(1)) if m else 0


# ─────────────────────────────────────────────────────────────────────────────
# Main scoring function
# ─────────────────────────────────────────────────────────────────────────────

def score_siam_evasion(
    line: str,
    ja3_hash: str | None = None,
) -> SIAMEvasionScore:
    """
    Score a bridge for Iran SIAM/NGFW evasion across all 8 DPI layers.

    Returns a SIAMEvasionScore with per-layer breakdown and overall tier.
    """
    line = line.strip()
    transport = _detect_transport(line)
    port = _get_port(line)
    flags: list[str] = []

    # Per-layer scores
    l1 = _layer1_packet_length(transport, line)
    l2 = _layer2_iat_analysis(transport, line)
    l3 = _layer3_flow_features(transport, line)
    l4, l4_flags = _layer4_ja3_fingerprint(ja3_hash)
    l5, l5_flags = _layer5_cert_sni(transport, line)
    l6 = _layer6_alpn_anomaly(transport, line)
    l7 = _layer7_temporal_analysis(transport, line)
    l8, l8_flags = _layer8_as_relationship(line)

    flags.extend(l4_flags + l5_flags + l8_flags)

    # Port-based adjustments
    if port is not None:
        if port in _NGFW_BLOCKED_PORTS:
            flags.append("ngfw_blocked_port")
            l5 = max(0.0, l5 - 0.30)
            l6 = max(0.0, l6 - 0.20)
        elif port in _SIAM_SAFE_PORTS:
            flags.append("siam_safe_port")
            l5 = min(1.0, l5 + 0.05)

    # obfs4 IAT bonus
    if transport == "obfs4":
        iat = _get_iat_mode(line)
        if iat == 2:
            flags.append("obfs4_iat_mode_2_max_evasion")
        elif iat == 1:
            flags.append("obfs4_iat_mode_1_evasion")
        else:
            flags.append("obfs4_iat_mode_0_detectable")

    layer_scores = {
        "L1_packet_length": round(l1, 3),
        "L2_iat_timing":    round(l2, 3),
        "L3_flow_features": round(l3, 3),
        "L4_ja3_tls":       round(l4, 3),
        "L5_cert_sni":      round(l5, 3),
        "L6_alpn_anomaly":  round(l6, 3),
        "L7_temporal":      round(l7, 3),
        "L8_as_graph":      round(l8, 3),
    }

    # Weighted average (weights reflect Iran SIAM emphasis)
    weights = {
        "L1_packet_length": 0.10,
        "L2_iat_timing":    0.15,
        "L3_flow_features": 0.10,
        "L4_ja3_tls":       0.18,
        "L5_cert_sni":      0.18,
        "L6_alpn_anomaly":  0.08,
        "L7_temporal":      0.11,
        "L8_as_graph":      0.10,
    }
    overall = sum(layer_scores[k] * weights[k] for k in weights)
    overall = round(min(max(overall, 0.0), 1.0), 4)

    # Count bypassed layers (score >= 0.70 threshold)
    layers_bypassed = sum(1 for s in layer_scores.values() if s >= 0.70)

    # Assign tier
    if overall >= 0.88:
        tier = BypassTier.PHANTOM
    elif overall >= 0.72:
        tier = BypassTier.STEALTH
    elif overall >= 0.55:
        tier = BypassTier.COVERT
    elif overall >= 0.30:
        tier = BypassTier.EXPOSED
    else:
        tier = BypassTier.DETECTED

    # Human-readable recommendation
    rec = _build_recommendation(transport, tier, port, flags)

    return SIAMEvasionScore(
        bridge_line=line,
        transport=transport,
        port=port,
        iran_siam_score=overall,
        bypass_tier=tier,
        layers_bypassed=layers_bypassed,
        evasion_flags=flags,
        layer_scores=layer_scores,
        recommendation=rec,
    )


def _build_recommendation(
    transport: str,
    tier: str,
    port: int | None,
    flags: list[str],
) -> str:
    """Build a human-readable Farsi/English recommendation."""
    if tier == BypassTier.PHANTOM:
        return "✅ بهترین انتخاب — کاملاً شبیه ترافیک معمولی | Best choice: fully traffic-disguised"
    if tier == BypassTier.STEALTH:
        if transport == "obfs4" and "obfs4_iat_mode_1_evasion" in flags:
            return "✅ خوب — obfs4 IAT-1 فعال | Good: obfs4 IAT-1 timing randomisation active"
        return "✅ خوب — از اکثر لایه‌های SIAM عبور می‌کند | Good: bypasses most SIAM layers"
    if tier == BypassTier.COVERT:
        if "ngfw_blocked_port" in flags:
            return "⚠️ پورت مسدود — سعی کنید از پورت 443 استفاده کنید | Blocked port: try port 443"
        if transport == "obfs4" and "obfs4_iat_mode_0_detectable" in flags:
            return "⚠️ obfs4 IAT-0 — پیکربندی iat-mode=2 برای عملکرد بهتر | Add iat-mode=2 for better evasion"
        return "⚠️ متوسط — برخی لایه‌های SIAM تشخیص می‌دهند | Moderate: some SIAM layers detect"
    if tier == BypassTier.EXPOSED:
        return "❌ ضعیف — اکثر لایه‌های SIAM تشخیص می‌دهند | Poor: most SIAM layers detect"
    return "🚫 بلاک می‌شود — سیستم SIAM کاملاً تشخیص می‌دهد | Will be blocked by SIAM system"


# ─────────────────────────────────────────────────────────────────────────────
# Batch scoring (for pipeline integration)
# ─────────────────────────────────────────────────────────────────────────────

def score_all(
    bridge_lines: list[str],
    ja3_map: dict[str, str] | None = None,
) -> list[SIAMEvasionScore]:
    """
    Score a list of bridge lines. ja3_map maps bridge_line → ja3_hash.
    Returns list sorted by iran_siam_score descending.
    """
    ja3_map = ja3_map or {}
    results = [
        score_siam_evasion(line, ja3_hash=ja3_map.get(line.strip()))
        for line in bridge_lines
        if line.strip()
    ]
    results.sort(key=lambda r: r.iran_siam_score, reverse=True)
    return results


def get_phantom_stealth(results: list[SIAMEvasionScore]) -> list[str]:
    """Return only PHANTOM and STEALTH bridge lines (safest for Iran)."""
    return [
        r.bridge_line for r in results
        if r.bypass_tier in (BypassTier.PHANTOM, BypassTier.STEALTH)
    ]


if __name__ == "__main__":
    # Quick self-test
    test_lines = [
        "snowflake 192.0.2.3:1 2B280B23E1107BB62ABFC40DDCC8824814F80A72 "
        "url=https://snowflake-broker.torproject.net.global.prod.fastly.net/ "
        "fronts=ftls.googlevideo.com",
        "obfs4 1.2.3.4:443 FINGERPRINT iat-mode=2",
        "obfs4 5.6.7.8:9001 FINGERPRINT iat-mode=0",
        "192.168.0.1:9001 ABC123",  # vanilla
    ]
    for tl in test_lines:
        s = score_siam_evasion(tl)
        print(f"{s.transport:12} | {s.bypass_tier:8} | score={s.iran_siam_score:.3f} | "
              f"layers={s.layers_bypassed}/8 | {s.recommendation[:60]}")
