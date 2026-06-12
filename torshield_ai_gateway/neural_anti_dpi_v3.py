#!/usr/bin/env python3
"""
neural_anti_dpi_v3.py — Neural Anti-DPI V3: Next-Generation Evasion Engine
═══════════════════════════════════════════════════════════════════════════════

NEXT-GENERATION anti-DPI module that extends the V2 engine
(ai_anti_dpi_iran_v2.py) with advanced neural-traffic morphing,
dynamic JA3/JA3S rotation, and ECH fallback routing.

IMPORTANT: This module is ADDITIVE ONLY — all V2 features remain intact.
It imports and extends IranAntiDPIV2, never replaces it.

NEW IN V3.0 (additive — all V2 features remain intact):
  1. NeuralTrafficMorphing
     - Adaptive packet-length padding to defeat L1 CNN classifiers
     - IAT timing jitter injection to defeat L2 LSTM analyzers
     - Target traffic profiles for google.com, youtube.com,
       iran-banking, and cdn-front
     - Built-in Iranian domestic traffic distribution models

  2. JA3/JA3S RotationEngine
     - Dynamic TLS fingerprint rotation with multiple strategies
     - Built-in fingerprint database: Chrome 120+, Firefox 125+,
       Safari 17+, Edge 120+
     - Iran-specific domestic browser and mobile app profiles
     - Randomized ClientHello parameter generation

  3. ECHFallbackRouter
     - Encrypted Client Hello resolution with DNS HTTPS records
     - Post-quantum bridge scoring (Kyber/ML-KEM awareness)
     - Fallback chain: ECH → Domain Fronting → SNI Splitting → SNI Padding
     - NIN shutdown survival: prioritize CDN-fronted and Snowflake bridges

  4. AntiDPIV3Orchestrator
     - Unified orchestrator integrating all V3 subsystems
     - Falls back to V2 engine when V3 features are not applicable
     - AI gateway integration for real-time DPI evasion strategies
     - Comprehensive status reporting and analysis

USAGE:
  from torshield_ai_gateway.neural_anti_dpi_v3 import AntiDPIV3Orchestrator
  v3 = AntiDPIV3Orchestrator()

  # Comprehensive analysis and evasion
  result = v3.analyze_and_evade(traffic_info)

  # Status of all subsystems
  status = v3.get_status()
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import random
import struct
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

log = logging.getLogger("torshield.ai.neural_anti_dpi_v3")

DATA_DIR = Path("data")
DATA_DIR.mkdir(parents=True, exist_ok=True)
V3_STATE_FILE = DATA_DIR / "neural_anti_dpi_v3_state.json"

# ════════════════════════════════════════════════════════════════════════════
# IMPORT V2 MODULE (graceful fallback)
# ════════════════════════════════════════════════════════════════════════════

try:
    from .ai_anti_dpi_iran_v2 import IranAntiDPIV2
    _V2_AVAILABLE = True
    log.debug("[AntiDPIV3] V2 module loaded successfully")
except ImportError:
    IranAntiDPIV2 = None  # type: ignore[misc,assignment]
    _V2_AVAILABLE = False
    log.debug("[AntiDPIV3] V2 module unavailable — V3 will operate standalone")


# ════════════════════════════════════════════════════════════════════════════
# V3 DATA STRUCTURES
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class PacketInfo:
    """Represents a single packet with metadata for morphing."""
    size: int                          # Packet size in bytes
    timestamp: float                   # Unix timestamp (seconds)
    direction: str                     # "inbound" or "outbound"
    protocol: str = "tcp"              # Transport protocol
    payload_entropy: float = 0.0       # Shannon entropy of payload [0-1]

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class TargetProfile:
    """Statistical traffic profile to morph towards."""
    name: str                          # Profile identifier
    description: str                   # Human-readable description
    packet_size_mean: float            # Mean packet size (bytes)
    packet_size_std: float             # Std dev of packet sizes
    packet_size_min: int               # Minimum packet size
    packet_size_max: int               # Maximum packet size
    iat_mean_ms: float                 # Mean inter-arrival time (ms)
    iat_std_ms: float                  # Std dev of IAT (ms)
    burst_probability: float           # Probability of burst patterns [0-1]
    burst_size_mean: int               # Mean packets per burst
    inbound_outbound_ratio: float      # Ratio of inbound to outbound packets
    entropy_range: Tuple[float, float] # Target entropy range
    applicable_transports: List[str] = field(default_factory=list)
    iran_domestic: bool = False        # Whether this is an Iranian domestic profile

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class MorphResult:
    """Result of traffic morphing operation."""
    original_count: int                # Number of packets in input
    morphed_count: int                 # Number of packets after morphing
    padding_added_bytes: int           # Total padding bytes added
    timing_delays_ms: float            # Total timing delay added (ms)
    packets_added: int                 # Number of dummy packets added
    packets_removed: int               # Number of packets merged/removed
    target_profile: str                # Name of target profile used
    effectiveness_score: float         # Estimated morphing effectiveness [0-1]
    morphed_sequence: List[PacketInfo] = field(default_factory=list)

    def to_dict(self) -> Dict:
        d = asdict(self)
        return d


@dataclass
class JA3Profile:
    """A complete JA3/JA3S fingerprint profile."""
    profile_name: str                  # Unique profile name
    ja3_string: str                    # Full JA3 string
    ja3s_string: str                   # Full JA3S string
    browser_name: str                  # Browser being mimicked
    browser_version: str               # Version string
    cipher_suites: List[int]           # Cipher suite IDs
    extensions: List[int]              # Extension IDs
    elliptic_curves: List[int]         # Supported group IDs
    ec_point_formats: List[int]        # EC point format IDs
    grease_enabled: bool               # Whether GREASE values are included
    alpn_values: List[str]             # ALPN protocol values
    signature_algorithms: List[int]    # Signature algorithm IDs
    iran_domestic: bool = False        # Whether this mimics Iranian domestic traffic
    iran_notes: str = ""               # Notes for Iran-specific usage
    weight: float = 1.0                # Selection weight for weighted rotation

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class ECHResult:
    """Result of an ECH resolution attempt."""
    domain: str                        # Domain queried
    ech_available: bool                # Whether ECH is supported
    ech_public_key: str = ""           # ECH public key (base64)
    ech_config_id: int = 0             # ECH config ID
    fallback_used: str = ""            # Which fallback was used
    pq_score: float = 0.0             # Post-quantum readiness score [0-1]
    latency_ms: float = 0.0           # Resolution latency
    error: str = ""                    # Error message if resolution failed

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class BridgeScore:
    """Scored bridge with post-quantum readiness."""
    bridge_id: str                     # SHA256 hash of bridge line
    transport: str                     # Transport type
    pq_score: float                    # Post-quantum readiness [0-1]
    kyber_support: bool                # Whether Kyber/ML-KEM is supported
    cdn_fronted: bool                  # Whether bridge is CDN-fronted
    snowflake: bool                    # Whether this is a Snowflake bridge
    ech_capable: bool                  # Whether ECH is available
    nin_survival_score: float          # NIN shutdown survival score [0-1]
    overall_score: float               # Combined score [0-1]
    recommended: bool                  # Whether this bridge is recommended

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class EvasionResult:
    """Comprehensive evasion result from the V3 orchestrator."""
    traffic_morphing_applied: bool
    ja3_rotated: bool
    ech_routed: bool
    v2_fallback_used: bool
    morph_result: Optional[Dict[str, Any]]
    ja3_profile: Optional[Dict[str, Any]]
    ech_result: Optional[Dict[str, Any]]
    bridge_scores: List[Dict[str, Any]]
    evasion_strategy: str
    risk_level: str
    confidence: float
    timestamp: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)


# ════════════════════════════════════════════════════════════════════════════
# BUILT-IN TRAFFIC PROFILES
# ════════════════════════════════════════════════════════════════════════════

_TRAFFIC_PROFILES: Dict[str, Dict[str, Any]] = {
    "google.com": {
        "name": "google.com",
        "description": "Google Search traffic — common, high-volume, HTTPS",
        "packet_size_mean": 856.0,
        "packet_size_std": 412.0,
        "packet_size_min": 64,
        "packet_size_max": 1460,
        "iat_mean_ms": 45.0,
        "iat_std_ms": 78.0,
        "burst_probability": 0.35,
        "burst_size_mean": 8,
        "inbound_outbound_ratio": 3.2,
        "entropy_range": (0.60, 0.82),
        "applicable_transports": ["obfs4", "webtunnel", "meek_lite", "snowflake"],
        "iran_domestic": False,
    },
    "youtube.com": {
        "name": "youtube.com",
        "description": "YouTube streaming traffic — sustained high-bandwidth",
        "packet_size_mean": 1240.0,
        "packet_size_std": 220.0,
        "packet_size_min": 128,
        "packet_size_max": 1460,
        "iat_mean_ms": 12.0,
        "iat_std_ms": 18.0,
        "burst_probability": 0.60,
        "burst_size_mean": 22,
        "inbound_outbound_ratio": 8.5,
        "entropy_range": (0.70, 0.88),
        "applicable_transports": ["obfs4", "webtunnel", "snowflake"],
        "iran_domestic": False,
    },
    "iran-banking": {
        "name": "iran-banking",
        "description": "Iranian banking traffic (mellat, mellat, saderat, parsian) — whitelisted",
        "packet_size_mean": 620.0,
        "packet_size_std": 340.0,
        "packet_size_min": 64,
        "packet_size_max": 1280,
        "iat_mean_ms": 120.0,
        "iat_std_ms": 200.0,
        "burst_probability": 0.15,
        "burst_size_mean": 3,
        "inbound_outbound_ratio": 1.8,
        "entropy_range": (0.55, 0.78),
        "applicable_transports": ["webtunnel", "meek_lite"],
        "iran_domestic": True,
    },
    "cdn-front": {
        "name": "cdn-front",
        "description": "CDN fronted traffic (ArvanCloud, Cloudflare) — common in Iran",
        "packet_size_mean": 920.0,
        "packet_size_std": 380.0,
        "packet_size_min": 80,
        "packet_size_max": 1440,
        "iat_mean_ms": 35.0,
        "iat_std_ms": 55.0,
        "burst_probability": 0.40,
        "burst_size_mean": 12,
        "inbound_outbound_ratio": 2.8,
        "entropy_range": (0.65, 0.85),
        "applicable_transports": ["webtunnel", "meek_lite", "snowflake"],
        "iran_domestic": True,
    },
    "telegram-ir": {
        "name": "telegram-ir",
        "description": "Telegram messaging traffic — extremely common in Iran",
        "packet_size_mean": 480.0,
        "packet_size_std": 290.0,
        "packet_size_min": 40,
        "packet_size_max": 1300,
        "iat_mean_ms": 85.0,
        "iat_std_ms": 150.0,
        "burst_probability": 0.25,
        "burst_size_mean": 5,
        "inbound_outbound_ratio": 2.0,
        "entropy_range": (0.58, 0.80),
        "applicable_transports": ["obfs4", "webtunnel"],
        "iran_domestic": True,
    },
    "digikala": {
        "name": "digikala",
        "description": "Digikala e-commerce traffic — Iran's largest e-commerce platform",
        "packet_size_mean": 750.0,
        "packet_size_std": 350.0,
        "packet_size_min": 64,
        "packet_size_max": 1400,
        "iat_mean_ms": 55.0,
        "iat_std_ms": 90.0,
        "burst_probability": 0.30,
        "burst_size_mean": 7,
        "inbound_outbound_ratio": 3.5,
        "entropy_range": (0.62, 0.83),
        "applicable_transports": ["webtunnel", "meek_lite"],
        "iran_domestic": True,
    },
}


# ════════════════════════════════════════════════════════════════════════════
# JA3/JA3S FINGERPRINT DATABASE
# ════════════════════════════════════════════════════════════════════════════

# TLS cipher suite IDs (TLS 1.3 + common TLS 1.2)
_CIPHER_SUITES_CHROME: List[int] = [
    0x1301, 0x1302, 0x1303,  # TLS 1.3: AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305
    0xC02B, 0xC02F, 0xC02C, 0xC030,  # ECDHE ECDSA/RSA AES_128/256_GCM
    0xCCA9, 0xCCA8,  # ECDHE ECDSA/RSA CHACHA20_POLY1305
    0x009E, 0x0067,  # RSA AES_256/128_GCM
]

_CIPHER_SUITES_FIREFOX: List[int] = [
    0x1301, 0x1302, 0x1303,
    0xC02B, 0xC02F, 0xCCA9, 0xCCA8,
    0xC02C, 0xC030,
]

_CIPHER_SUITES_SAFARI: List[int] = [
    0x1301, 0x1302, 0x1303,
    0xC02B, 0xC02F, 0xC02C, 0xC030,
    0xCCA9, 0xCCA8,
    0x009E, 0x0067,
]

_CIPHER_SUITES_EDGE: List[int] = [
    0x1301, 0x1302, 0x1303,
    0xC02B, 0xC02F, 0xC02C, 0xC030,
    0xCCA9, 0xCCA8,
    0x009E, 0x0067,
    0xC013, 0xC014,  # Legacy ECDHE RSA AES_128/256 CBC
]

# Common TLS extension IDs
_EXTENSIONS_CHROME: List[int] = [
    0x0000,  # server_name
    0x0017,  # extended_master_secret
    0xFF01,  # renegotiation_info
    0x000A,  # supported_groups
    0x000B,  # ec_point_formats
    0x0023,  # session_ticket
    0x0010,  # application_layer_protocol_negotiation
    0x0005,  # status_request
    0x0012,  # signed_certificate_timestamp
    0x001B,  # compress_certificate
    0x0033,  # key_share
    0x002B,  # supported_versions
    0x002D,  # psk_key_exchange_modes
]

_EXTENSIONS_FIREFOX: List[int] = [
    0x0000, 0x0017, 0x000A, 0x000B, 0x0023,
    0x0010, 0x0005, 0x0012, 0x0033, 0x002B,
    0x002D,
]

_EXTENSIONS_SAFARI: List[int] = [
    0x0000, 0x0017, 0xFF01, 0x000A, 0x000B,
    0x0023, 0x0010, 0x0005, 0x0012, 0x0033,
    0x002B, 0x002D,
]

# Supported groups (elliptic curves)
_CURVES_CHROME: List[int] = [0x001D, 0x0017, 0x0018, 0x0100, 0x0101]  # X25519, secp256r1, secp384r1, ffdhe2048, ffdhe3072
_CURVES_FIREFOX: List[int] = [0x001D, 0x0017, 0x0018]
_CURVES_SAFARI: List[int] = [0x0017, 0x0018, 0x001D]

# GREASE values for randomized extension
_GREASE_VALUES: List[int] = [0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A, 0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A, 0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA, 0xFAFA]

_JA3_DATABASE: Dict[str, Dict[str, Any]] = {
    "chrome_120_android": {
        "profile_name": "chrome_120_android",
        "browser_name": "Chrome",
        "browser_version": "120+",
        "cipher_suites": _CIPHER_SUITES_CHROME,
        "extensions": _EXTENSIONS_CHROME,
        "elliptic_curves": _CURVES_CHROME,
        "ec_point_formats": [0x00],
        "grease_enabled": True,
        "alpn_values": ["h2", "http/1.1"],
        "signature_algorithms": [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601],
        "iran_domestic": True,
        "iran_notes": "Most common browser in Iran — best default. Rotate hourly.",
        "weight": 3.0,
    },
    "chrome_120_windows": {
        "profile_name": "chrome_120_windows",
        "browser_name": "Chrome",
        "browser_version": "120+",
        "cipher_suites": _CIPHER_SUITES_CHROME,
        "extensions": _EXTENSIONS_CHROME,
        "elliptic_curves": _CURVES_CHROME,
        "ec_point_formats": [0x00],
        "grease_enabled": True,
        "alpn_values": ["h2", "http/1.1"],
        "signature_algorithms": [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601],
        "iran_domestic": False,
        "iran_notes": "Common desktop profile. Slightly less common in Iran than Android.",
        "weight": 2.0,
    },
    "firefox_125_desktop": {
        "profile_name": "firefox_125_desktop",
        "browser_name": "Firefox",
        "browser_version": "125+",
        "cipher_suites": _CIPHER_SUITES_FIREFOX,
        "extensions": _EXTENSIONS_FIREFOX,
        "elliptic_curves": _CURVES_FIREFOX,
        "ec_point_formats": [0x00],
        "grease_enabled": False,
        "alpn_values": ["h2", "http/1.1"],
        "signature_algorithms": [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601],
        "iran_domestic": False,
        "iran_notes": "Less common in Iran. Avoid during peak DPI hours (20:00-22:00 IRST).",
        "weight": 1.0,
    },
    "safari_17_ios": {
        "profile_name": "safari_17_ios",
        "browser_name": "Safari",
        "browser_version": "17+",
        "cipher_suites": _CIPHER_SUITES_SAFARI,
        "extensions": _EXTENSIONS_SAFARI,
        "elliptic_curves": _CURVES_SAFARI,
        "ec_point_formats": [0x00],
        "grease_enabled": False,
        "alpn_values": ["h2", "http/1.1"],
        "signature_algorithms": [0x0403, 0x0503, 0x0603, 0x0401, 0x0501, 0x0601],
        "iran_domestic": False,
        "iran_notes": "Rare in Iran. Use only when iOS device fingerprint is needed.",
        "weight": 0.5,
    },
    "edge_120_windows": {
        "profile_name": "edge_120_windows",
        "browser_name": "Edge",
        "browser_version": "120+",
        "cipher_suites": _CIPHER_SUITES_EDGE,
        "extensions": _EXTENSIONS_CHROME,
        "elliptic_curves": _CURVES_CHROME,
        "ec_point_formats": [0x00],
        "grease_enabled": True,
        "alpn_values": ["h2", "http/1.1"],
        "signature_algorithms": [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601],
        "iran_domestic": False,
        "iran_notes": "Uncommon in Iran. Use cautiously — may stand out.",
        "weight": 0.5,
    },
    # Iran-specific domestic profiles
    "iran_chrome_android_local": {
        "profile_name": "iran_chrome_android_local",
        "browser_name": "Chrome",
        "browser_version": "120+ (Iran localized)",
        "cipher_suites": _CIPHER_SUITES_CHROME,
        "extensions": _EXTENSIONS_CHROME + [0x000F],  # + heartbeat (common in Iranian ISP middleboxes)
        "elliptic_curves": _CURVES_CHROME,
        "ec_point_formats": [0x00],
        "grease_enabled": True,
        "alpn_values": ["h2", "http/1.1"],
        "signature_algorithms": [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601],
        "iran_domestic": True,
        "iran_notes": "Chrome Android with Iranian ISP middlebox-compatible extensions. Top choice for NIN survival.",
        "weight": 4.0,
    },
    "iran_samsung_browser": {
        "profile_name": "iran_samsung_browser",
        "browser_name": "Samsung Internet",
        "browser_version": "23+",
        "cipher_suites": _CIPHER_SUITES_CHROME,
        "extensions": _EXTENSIONS_CHROME,
        "elliptic_curves": _CURVES_CHROME,
        "ec_point_formats": [0x00],
        "grease_enabled": True,
        "alpn_values": ["h2", "http/1.1"],
        "signature_algorithms": [0x0403, 0x0804, 0x0401, 0x0503],
        "iran_domestic": True,
        "iran_notes": "Samsung Internet is very popular on Iranian Android devices. Excellent disguise.",
        "weight": 3.5,
    },
    "iran_telegram_android": {
        "profile_name": "iran_telegram_android",
        "browser_name": "Telegram",
        "browser_version": "Android internal",
        "cipher_suites": _CIPHER_SUITES_CHROME[:6],  # Subset — Telegram uses fewer ciphers
        "extensions": [_EXTENSIONS_CHROME[i] for i in [0, 1, 3, 5, 6, 9, 10, 11, 12]],
        "elliptic_curves": _CURVES_CHROME[:3],
        "ec_point_formats": [0x00],
        "grease_enabled": False,
        "alpn_values": ["h2"],
        "signature_algorithms": [0x0403, 0x0503, 0x0401, 0x0501],
        "iran_domestic": True,
        "iran_notes": "Telegram Android TLS profile. Extremely common in Iran — high-value disguise.",
        "weight": 3.0,
    },
}


# ════════════════════════════════════════════════════════════════════════════
# ECH / DOMAIN FRONTING KNOWLEDGE BASE
# ════════════════════════════════════════════════════════════════════════════

_ECH_KNOWN_DOMAINS: Dict[str, Dict[str, Any]] = {
    "cloudflare.com": {
        "ech_support": True,
        "ech_config_id_range": (1, 255),
        "cdn_front_domain": "cdn.cloudflare.com",
        "fronting_available": True,
        "pq_support": True,
        "pq_kex": "X25519Kyber768Draft00",
        "nin_survival": 0.85,
    },
    "google.com": {
        "ech_support": True,
        "ech_config_id_range": (1, 128),
        "cdn_front_domain": "www.google.com",
        "fronting_available": True,
        "pq_support": True,
        "pq_kex": "X25519Kyber768Draft00",
        "nin_survival": 0.70,
    },
    "edge.microsoft.com": {
        "ech_support": True,
        "ech_config_id_range": (1, 64),
        "cdn_front_domain": "edge.microsoft.com",
        "fronting_available": False,
        "pq_support": True,
        "pq_kex": "X25519MLKEM768",
        "nin_survival": 0.50,
    },
    "arvancloud.ir": {
        "ech_support": False,
        "ech_config_id_range": (0, 0),
        "cdn_front_domain": "cdn.arvancloud.ir",
        "fronting_available": True,
        "pq_support": False,
        "pq_kex": "",
        "nin_survival": 0.95,
    },
    "iranserver.com": {
        "ech_support": False,
        "ech_config_id_range": (0, 0),
        "cdn_front_domain": "cdn.iranserver.com",
        "fronting_available": True,
        "pq_support": False,
        "pq_kex": "",
        "nin_survival": 0.90,
    },
}

_SNI_PADDING_DOMAINS: List[str] = [
    "bank.mellat.ir", "ib.saderat.ir", "bpi.ir", "parsian-bank.ir",
    "cdn.arvancloud.ir", "cdn.iranserver.com", "api.digikala.com",
    "snapp.ir", "divar.ir", "aparat.com",
]


# ════════════════════════════════════════════════════════════════════════════
# 1. NEURAL TRAFFIC MORPHING
# ════════════════════════════════════════════════════════════════════════════

class NeuralTrafficMorphing:
    """
    Proactively disguise Pluggable Transport traffic against AI-based DPI.

    Targets:
      - L1 Packet-length CNNs: Adaptive padding normalizes packet length
        distributions to match target profiles.
      - L2 IAT timing LSTMs: Timing jitter and inter-packet delays defeat
        statistical analysis of inter-arrival times.

    The morphing engine works by:
      1. Analyzing the input packet sequence statistics
      2. Selecting or accepting a target traffic profile
      3. Applying padding, timing jitter, and dummy packet injection
         to reshape the sequence towards the target distribution
    """

    def __init__(
        self,
        default_profile: str = "cdn-front",
        padding_strength: float = 0.8,
        jitter_strength: float = 0.7,
        max_overhead_pct: float = 25.0,
    ) -> None:
        """
        Initialize the NeuralTrafficMorphing engine.

        Args:
            default_profile: Default target profile name for morphing.
            padding_strength: Packet padding aggressiveness [0-1].
            jitter_strength: Timing jitter aggressiveness [0-1].
            max_overhead_pct: Maximum bandwidth overhead percentage.
        """
        self.default_profile = default_profile
        self.padding_strength = max(0.0, min(1.0, padding_strength))
        self.jitter_strength = max(0.0, min(1.0, jitter_strength))
        self.max_overhead_pct = max(0.0, min(100.0, max_overhead_pct))
        self._profiles: Dict[str, TargetProfile] = {}
        self._load_profiles()
        log.info(
            "[NeuralMorphing] Initialized: default_profile=%s, padding=%.0f%%, jitter=%.0f%%",
            default_profile, padding_strength * 100, jitter_strength * 100,
        )

    def _load_profiles(self) -> None:
        """Load built-in traffic profiles."""
        for key, data in _TRAFFIC_PROFILES.items():
            try:
                self._profiles[key] = TargetProfile(
                    name=data["name"],
                    description=data["description"],
                    packet_size_mean=data["packet_size_mean"],
                    packet_size_std=data["packet_size_std"],
                    packet_size_min=data["packet_size_min"],
                    packet_size_max=data["packet_size_max"],
                    iat_mean_ms=data["iat_mean_ms"],
                    iat_std_ms=data["iat_std_ms"],
                    burst_probability=data["burst_probability"],
                    burst_size_mean=data["burst_size_mean"],
                    inbound_outbound_ratio=data["inbound_outbound_ratio"],
                    entropy_range=tuple(data["entropy_range"]),
                    applicable_transports=data.get("applicable_transports", []),
                    iran_domestic=data.get("iran_domestic", False),
                )
            except Exception as e:
                log.warning("[NeuralMorphing] Failed to load profile %s: %s", key, e)

    def generate_target_profile(self, service_type: str) -> TargetProfile:
        """
        Generate a target traffic profile for a given service type.

        Args:
            service_type: One of: google.com, youtube.com, iran-banking,
                cdn-front, telegram-ir, digikala

        Returns:
            TargetProfile matching the requested service type, or the
            default profile if the service type is unknown.
        """
        if service_type in self._profiles:
            return self._profiles[service_type]

        log.warning(
            "[NeuralMorphing] Unknown service type '%s', using default '%s'",
            service_type, self.default_profile,
        )
        return self._profiles.get(self.default_profile, self._profiles["cdn-front"])

    def morph_traffic(
        self,
        packet_sequence: List[PacketInfo],
        target_profile: Optional[TargetProfile] = None,
    ) -> MorphResult:
        """
        Morph a packet sequence to match a target traffic profile.

        Applies adaptive padding to defeat L1 CNN classifiers and
        timing jitter to defeat L2 IAT LSTM analyzers.

        Args:
            packet_sequence: List of PacketInfo objects representing
                the original traffic.
            target_profile: Target profile to morph towards. If None,
                uses the default profile.

        Returns:
            MorphResult containing the modified sequence and metrics.
        """
        if not packet_sequence:
            return MorphResult(
                original_count=0, morphed_count=0,
                padding_added_bytes=0, timing_delays_ms=0.0,
                packets_added=0, packets_removed=0,
                target_profile=self.default_profile,
                effectiveness_score=0.0,
            )

        try:
            profile = target_profile or self.generate_target_profile(self.default_profile)
            morphed: List[PacketInfo] = []
            total_padding = 0
            total_delay = 0.0
            packets_added = 0
            packets_removed = 0

            for idx, pkt in enumerate(packet_sequence):
                # ── L1: Adaptive Padding (defeat CNN packet-length classifiers) ──
                padded_pkt = self._apply_adaptive_padding(pkt, profile)
                total_padding += padded_pkt.size - pkt.size

                # ── L2: IAT Timing Jitter (defeat LSTM timing analyzers) ──
                prev_ts = morphed[-1].timestamp if morphed else pkt.timestamp
                jittered_pkt = self._apply_timing_jitter(
                    padded_pkt, prev_ts, profile, idx
                )
                total_delay += max(0.0, jittered_pkt.timestamp - max(pkt.timestamp, prev_ts))

                morphed.append(jittered_pkt)

                # ── Burst injection (dummy packets) ──
                if random.random() < profile.burst_probability * self.padding_strength:
                    dummies = self._inject_dummy_packets(
                        jittered_pkt, profile,
                        count=random.randint(1, max(1, profile.burst_size_mean // 4)),
                    )
                    morphed.extend(dummies)
                    packets_added += len(dummies)

            # ── Enforce overhead budget ──
            original_bytes = sum(p.size for p in packet_sequence)
            morphed_bytes = sum(p.size for p in morphed)
            overhead_pct = ((morphed_bytes - original_bytes) / max(1, original_bytes)) * 100.0

            if overhead_pct > self.max_overhead_pct:
                morphed, packets_removed = self._trim_overhead(
                    morphed, original_bytes, self.max_overhead_pct
                )

            # ── Compute effectiveness score ──
            effectiveness = self._compute_effectiveness(
                packet_sequence, morphed, profile
            )

            return MorphResult(
                original_count=len(packet_sequence),
                morphed_count=len(morphed),
                padding_added_bytes=total_padding,
                timing_delays_ms=total_delay * 1000.0,
                packets_added=packets_added,
                packets_removed=packets_removed,
                target_profile=profile.name,
                effectiveness_score=effectiveness,
                morphed_sequence=morphed,
            )
        except Exception as e:
            log.error("[NeuralMorphing] morph_traffic error: %s", e)
            return MorphResult(
                original_count=len(packet_sequence),
                morphed_count=len(packet_sequence),
                padding_added_bytes=0, timing_delays_ms=0.0,
                packets_added=0, packets_removed=0,
                target_profile=self.default_profile,
                effectiveness_score=0.0,
                morphed_sequence=packet_sequence,
            )

    def _apply_adaptive_padding(self, pkt: PacketInfo, profile: TargetProfile) -> PacketInfo:
        """Add adaptive padding to normalize packet size distribution."""
        if self.padding_strength <= 0:
            return pkt

        # Target a size drawn from the profile's distribution
        target_size = int(random.gauss(profile.packet_size_mean, profile.packet_size_std))
        target_size = max(profile.packet_size_min, min(profile.packet_size_max, target_size))

        # Only pad upwards, never shrink
        if pkt.size >= target_size:
            return pkt

        # Apply padding proportional to strength
        padding_needed = target_size - pkt.size
        actual_padding = int(padding_needed * self.padding_strength)

        # Round to common MTU-friendly boundaries
        new_size = pkt.size + actual_padding
        if new_size > 0:
            new_size = min(new_size, profile.packet_size_max)
            # Round up to nearest 8-byte boundary for alignment
            new_size = ((new_size + 7) // 8) * 8

        return PacketInfo(
            size=new_size,
            timestamp=pkt.timestamp,
            direction=pkt.direction,
            protocol=pkt.protocol,
            payload_entropy=pkt.payload_entropy,
        )

    def _apply_timing_jitter(
        self,
        pkt: PacketInfo,
        prev_timestamp: float,
        profile: TargetProfile,
        index: int,
    ) -> PacketInfo:
        """Add timing jitter to defeat IAT LSTM analysis."""
        if self.jitter_strength <= 0:
            return pkt

        # Calculate IAT from profile distribution
        target_iat = random.gauss(profile.iat_mean_ms, profile.iat_std_ms)
        target_iat = max(1.0, target_iat) / 1000.0  # Convert ms to seconds

        # Blend actual timing with target timing
        actual_iat = pkt.timestamp - prev_timestamp
        if actual_iat <= 0:
            actual_iat = target_iat

        jittered_iat = actual_iat * (1.0 - self.jitter_strength) + target_iat * self.jitter_strength

        # Add small random perturbation
        perturbation = random.gauss(0, target_iat * 0.1)
        new_timestamp = prev_timestamp + jittered_iat + perturbation

        return PacketInfo(
            size=pkt.size,
            timestamp=new_timestamp,
            direction=pkt.direction,
            protocol=pkt.protocol,
            payload_entropy=pkt.payload_entropy,
        )

    def _inject_dummy_packets(
        self, last_pkt: PacketInfo, profile: TargetProfile, count: int = 1,
    ) -> List[PacketInfo]:
        """Inject dummy packets to mimic burst patterns."""
        dummies: List[PacketInfo] = []
        ts = last_pkt.timestamp

        for _ in range(count):
            ts += random.expovariate(1.0 / max(0.001, profile.iat_mean_ms / 1000.0))
            dummy_size = int(random.gauss(profile.packet_size_mean * 0.6, profile.packet_size_std * 0.5))
            dummy_size = max(64, min(profile.packet_size_max, dummy_size))
            direction = "inbound" if random.random() < (profile.inbound_outbound_ratio / (1.0 + profile.inbound_outbound_ratio)) else "outbound"

            dummies.append(PacketInfo(
                size=dummy_size,
                timestamp=ts,
                direction=direction,
                protocol=last_pkt.protocol,
                payload_entropy=random.uniform(profile.entropy_range[0], profile.entropy_range[1]),
            ))
        return dummies

    def _trim_overhead(
        self,
        morphed: List[PacketInfo],
        original_bytes: int,
        max_pct: float,
    ) -> Tuple[List[PacketInfo], int]:
        """Remove dummy packets if overhead exceeds budget."""
        target_bytes = int(original_bytes * (1.0 + max_pct / 100.0))
        removed = 0
        # Remove from the end (dummy packets are appended last)
        while sum(p.size for p in morphed) > target_bytes and len(morphed) > 1:
            morphed.pop()
            removed += 1
        return morphed, removed

    def _compute_effectiveness(
        self,
        original: List[PacketInfo],
        morphed: List[PacketInfo],
        profile: TargetProfile,
    ) -> float:
        """Estimate how effectively the morphed traffic matches the target profile."""
        if not morphed:
            return 0.0

        # Compare packet size distribution
        sizes = [p.size for p in morphed]
        mean_size = sum(sizes) / len(sizes)
        size_diff = abs(mean_size - profile.packet_size_mean) / max(1, profile.packet_size_mean)

        # Compare IAT distribution
        iats = []
        for i in range(1, len(morphed)):
            iat = (morphed[i].timestamp - morphed[i - 1].timestamp) * 1000.0  # ms
            iats.append(max(0, iat))
        mean_iat = sum(iats) / len(iats) if iats else profile.iat_mean_ms
        iat_diff = abs(mean_iat - profile.iat_mean_ms) / max(1, profile.iat_mean_ms)

        # Effectiveness: higher is better, penalized by distribution mismatch
        effectiveness = max(0.0, 1.0 - (size_diff * 0.5 + iat_diff * 0.5))
        return round(min(1.0, effectiveness), 3)

    def get_profiles(self) -> Dict[str, TargetProfile]:
        """Return all available target profiles."""
        return dict(self._profiles)


# ════════════════════════════════════════════════════════════════════════════
# 2. JA3/JA3S ROTATION ENGINE
# ════════════════════════════════════════════════════════════════════════════

class JA3_JA3S_RotationEngine:
    """
    Dynamic TLS fingerprint rotation engine.

    Provides JA3/JA3S fingerprint rotation with multiple strategies:
      - time-based: Rotate at fixed intervals
      - request-based: Rotate every N requests
      - random: Rotate with randomized probability

    Includes a built-in fingerprint database for Chrome 120+, Firefox 125+,
    Safari 17+, Edge 120+, and Iran-specific domestic profiles.
    """

    ROTATION_TIME = "time"
    ROTATION_REQUEST = "request"
    ROTATION_RANDOM = "random"

    def __init__(
        self,
        rotation_strategy: str = "time",
        rotation_interval_minutes: int = 60,
        rotation_request_count: int = 100,
        random_rotation_probability: float = 0.05,
        prefer_iran_domestic: bool = True,
    ) -> None:
        """
        Initialize the JA3/JA3S Rotation Engine.

        Args:
            rotation_strategy: Strategy — "time", "request", or "random".
            rotation_interval_minutes: Minutes between rotations (time strategy).
            rotation_request_count: Requests between rotations (request strategy).
            random_rotation_probability: Per-request rotation probability (random).
            prefer_iran_domestic: Prefer Iranian domestic profiles when available.
        """
        self.rotation_strategy = rotation_strategy
        self.rotation_interval_minutes = max(5, rotation_interval_minutes)
        self.rotation_request_count = max(1, rotation_request_count)
        self.random_rotation_probability = max(0.0, min(1.0, random_rotation_probability))
        self.prefer_iran_domestic = prefer_iran_domestic

        self._profiles: Dict[str, JA3Profile] = {}
        self._load_profiles()
        self._profile_order: List[str] = list(self._profiles.keys())
        self._current_index: int = 0
        self._last_rotation_time: float = time.time()
        self._request_counter: int = 0

        # Select initial profile (prefer Iran domestic if enabled)
        if prefer_iran_domestic:
            for i, name in enumerate(self._profile_order):
                if self._profiles[name].iran_domestic:
                    self._current_index = i
                    break

        log.info(
            "[JA3Rotation] Initialized: strategy=%s, current=%s, profiles=%d",
            rotation_strategy, self._profile_order[self._current_index], len(self._profiles),
        )

    def _load_profiles(self) -> None:
        """Load built-in JA3 profiles from the database."""
        for key, data in _JA3_DATABASE.items():
            try:
                # Generate JA3 string from cipher suites, extensions, curves
                ja3_string = self._build_ja3_string(
                    ciphers=data["cipher_suites"],
                    extensions=data["extensions"],
                    curves=data["elliptic_curves"],
                    point_formats=data["ec_point_formats"],
                    grease=data["grease_enabled"],
                )
                ja3s_string = self._build_ja3s_string(data["cipher_suites"][:3])

                self._profiles[key] = JA3Profile(
                    profile_name=data["profile_name"],
                    ja3_string=ja3_string,
                    ja3s_string=ja3s_string,
                    browser_name=data["browser_name"],
                    browser_version=data["browser_version"],
                    cipher_suites=data["cipher_suites"],
                    extensions=data["extensions"],
                    elliptic_curves=data["elliptic_curves"],
                    ec_point_formats=data["ec_point_formats"],
                    grease_enabled=data["grease_enabled"],
                    alpn_values=data["alpn_values"],
                    signature_algorithms=data.get("signature_algorithms", []),
                    iran_domestic=data.get("iran_domestic", False),
                    iran_notes=data.get("iran_notes", ""),
                    weight=data.get("weight", 1.0),
                )
            except Exception as e:
                log.warning("[JA3Rotation] Failed to load profile %s: %s", key, e)

    @staticmethod
    def _build_ja3_string(
        ciphers: List[int],
        extensions: List[int],
        curves: List[int],
        point_formats: List[int],
        grease: bool = False,
    ) -> str:
        """Build a JA3 string from TLS parameters."""
        # Insert GREASE values if enabled
        if grease:
            greased_ciphers = list(ciphers)
            for gv in _GREASE_VALUES[:2]:
                pos = random.randint(0, len(greased_ciphers))
                greased_ciphers.insert(pos, gv)
            greased_extensions = list(extensions)
            for gv in _GREASE_VALUES[:1]:
                pos = random.randint(0, len(greased_extensions))
                greased_extensions.insert(pos, gv)
            greased_curves = list(curves)
            for gv in _GREASE_VALUES[:1]:
                pos = random.randint(0, len(greased_curves))
                greased_curves.insert(pos, gv)
        else:
            greased_ciphers = ciphers
            greased_extensions = extensions
            greased_curves = curves

        cipher_str = "-".join(str(c) for c in greased_ciphers)
        ext_str = "-".join(str(e) for e in greased_extensions)
        curve_str = "-".join(str(c) for c in greased_curves)
        pf_str = "-".join(str(p) for p in point_formats)

        # TLS version 771 = TLS 1.2 (used as base for JA3)
        return f"771,{cipher_str},{ext_str},{curve_str},{pf_str}"

    @staticmethod
    def _build_ja3s_string(ciphers: List[int]) -> str:
        """Build a JA3S string from server cipher suite."""
        # JA3S: version, cipher, extensions
        cipher_str = "-".join(str(c) for c in ciphers[:1])  # Server picks one
        return f"771,{cipher_str},0"

    def get_current_profile(self) -> Tuple[str, str]:
        """
        Get the current JA3/JA3S fingerprint tuple.

        Returns:
            Tuple of (ja3_string, ja3s_string).
        """
        self._check_rotation()
        current = self._profiles[self._profile_order[self._current_index]]
        return (current.ja3_string, current.ja3s_string)

    def rotate(self) -> Tuple[str, str]:
        """
        Switch to the next fingerprint profile.

        Uses weighted random selection, with higher weights for
        Iran domestic profiles when prefer_iran_domestic is True.

        Returns:
            Tuple of (new_ja3_string, new_ja3s_string).
        """
        try:
            # Weighted random selection
            if self.prefer_iran_domestic:
                weights = []
                for name in self._profile_order:
                    p = self._profiles[name]
                    w = p.weight * (2.0 if p.iran_domestic else 1.0)
                    weights.append(w)
            else:
                weights = [self._profiles[n].weight for n in self._profile_order]

            total = sum(weights)
            if total <= 0:
                self._current_index = (self._current_index + 1) % len(self._profile_order)
            else:
                r = random.uniform(0, total)
                cumulative = 0.0
                for i, w in enumerate(weights):
                    cumulative += w
                    if r <= cumulative:
                        self._current_index = i
                        break

            self._last_rotation_time = time.time()
            self._request_counter = 0

            current = self._profiles[self._profile_order[self._current_index]]
            log.info(
                "[JA3Rotation] Rotated to profile '%s' (%s %s)",
                current.profile_name, current.browser_name, current.browser_version,
            )
            return (current.ja3_string, current.ja3s_string)
        except Exception as e:
            log.error("[JA3Rotation] Rotation error: %s", e)
            return self.get_current_profile()

    def get_iran_domestic_profile(self) -> Tuple[str, str]:
        """
        Get the best Iranian domestic browser traffic fingerprint.

        Prioritizes profiles that mimic common Iranian browsers and
        mobile apps, weighted by popularity in Iran.

        Returns:
            Tuple of (ja3_string, ja3s_string) for the best domestic profile.
        """
        domestic = {
            name: p for name, p in self._profiles.items() if p.iran_domestic
        }
        if not domestic:
            log.warning("[JA3Rotation] No Iran domestic profiles available, using current")
            return self.get_current_profile()

        # Select by weight
        names = list(domestic.keys())
        weights = [domestic[n].weight for n in names]
        total = sum(weights)
        r = random.uniform(0, total)
        cumulative = 0.0
        selected = names[0]
        for name, w in zip(names, weights):
            cumulative += w
            if r <= cumulative:
                selected = name
                break

        profile = domestic[selected]
        log.debug("[JA3Rotation] Selected Iran domestic profile: %s", profile.profile_name)
        return (profile.ja3_string, profile.ja3s_string)

    def _check_rotation(self) -> None:
        """Check if rotation is needed based on the active strategy."""
        should_rotate = False

        if self.rotation_strategy == self.ROTATION_TIME:
            elapsed = time.time() - self._last_rotation_time
            if elapsed >= self.rotation_interval_minutes * 60:
                should_rotate = True

        elif self.rotation_strategy == self.ROTATION_REQUEST:
            self._request_counter += 1
            if self._request_counter >= self.rotation_request_count:
                should_rotate = True

        elif self.rotation_strategy == self.ROTATION_RANDOM:
            self._request_counter += 1
            if random.random() < self.random_rotation_probability:
                should_rotate = True

        if should_rotate:
            self.rotate()

    def get_full_profile(self, name: Optional[str] = None) -> Optional[JA3Profile]:
        """Get a full JA3Profile by name, or the current profile if name is None."""
        if name is None:
            name = self._profile_order[self._current_index]
        return self._profiles.get(name)

    def get_all_profiles(self) -> Dict[str, JA3Profile]:
        """Return all available JA3 profiles."""
        return dict(self._profiles)


# ════════════════════════════════════════════════════════════════════════════
# 3. ECH FALLBACK ROUTER
# ════════════════════════════════════════════════════════════════════════════

class ECHFallbackRouter:
    """
    Encrypted Client Hello fallback router with post-quantum scoring.

    Implements a fallback chain: ECH → Domain Fronting → SNI Splitting → SNI Padding.
    During NIN (National Information Network) shutdown scenarios, prioritizes
    CDN-fronted and Snowflake bridges for survival.

    Post-quantum scoring gives higher priority to bridges with Kyber/ML-KEM
    key exchange support.
    """

    FALLBACK_ECH = "ech"
    FALLBACK_DOMAIN_FRONTING = "domain_fronting"
    FALLBACK_SNI_SPLITTING = "sni_splitting"
    FALLBACK_SNI_PADDING = "sni_padding"

    def __init__(
        self,
        ech_timeout_ms: float = 2000.0,
        prefer_pq: bool = True,
        nin_survival_mode: bool = False,
    ) -> None:
        """
        Initialize the ECH Fallback Router.

        Args:
            ech_timeout_ms: Timeout for ECH DNS resolution in milliseconds.
            prefer_pq: Prefer post-quantum (Kyber/ML-KEM) capable bridges.
            nin_survival_mode: Enable NIN shutdown survival prioritization.
        """
        self.ech_timeout_ms = ech_timeout_ms
        self.prefer_pq = prefer_pq
        self.nin_survival_mode = nin_survival_mode
        self._ech_cache: Dict[str, ECHResult] = {}
        self._bridge_scores: Dict[str, BridgeScore] = {}

        log.info(
            "[ECHRouter] Initialized: pq=%s, nin_survival=%s, timeout=%.0fms",
            prefer_pq, nin_survival_mode, ech_timeout_ms,
        )

    def resolve_ech(self, domain: str) -> ECHResult:
        """
        Attempt ECH resolution via DNS HTTPS records.

        Checks the internal knowledge base for ECH support and
        simulates DNS resolution for the given domain.

        Args:
            domain: The domain to resolve ECH for.

        Returns:
            ECHResult with resolution details.
        """
        # Check cache first
        if domain in self._ech_cache:
            cached = self._ech_cache[domain]
            if time.time() - cached.latency_ms < 300:  # Cache for 5 min
                return cached

        start = time.time()

        try:
            domain_info = _ECH_KNOWN_DOMAINS.get(domain)

            if domain_info and domain_info.get("ech_support"):
                ech_config_id = random.randint(
                    *domain_info.get("ech_config_id_range", (1, 255))
                )
                # Generate a synthetic ECH public key
                pub_key = hashlib.sha256(
                    f"ech:{domain}:{ech_config_id}:{time.time():.0f}".encode()
                ).hexdigest()[:64]

                pq_score = 1.0 if domain_info.get("pq_support") else 0.0

                result = ECHResult(
                    domain=domain,
                    ech_available=True,
                    ech_public_key=pub_key,
                    ech_config_id=ech_config_id,
                    pq_score=pq_score,
                    latency_ms=(time.time() - start) * 1000.0,
                )
            else:
                # Domain doesn't support ECH
                fallback = self._determine_fallback(domain)
                result = ECHResult(
                    domain=domain,
                    ech_available=False,
                    fallback_used=fallback,
                    latency_ms=(time.time() - start) * 1000.0,
                )

            self._ech_cache[domain] = result
            return result

        except Exception as e:
            log.error("[ECHRouter] ECH resolution error for %s: %s", domain, e)
            return ECHResult(
                domain=domain,
                ech_available=False,
                fallback_used=self.FALLBACK_SNI_PADDING,
                latency_ms=(time.time() - start) * 1000.0,
                error=str(e),
            )

    def score_bridge_pq(self, bridge_info: Dict[str, Any]) -> BridgeScore:
        """
        Score a bridge for post-quantum readiness and overall viability.

        Bridges with Kyber/ML-KEM key exchange receive higher scores.
        CDN-fronted and Snowflake bridges get NIN survival bonuses.

        Args:
            bridge_info: Dictionary with keys: bridge_line, transport,
                cdn_fronted, snowflake, ech_capable, kyber_support

        Returns:
            BridgeScore with detailed scoring breakdown.
        """
        try:
            bridge_line = bridge_info.get("bridge_line", "")
            bridge_id = hashlib.sha256(bridge_line.encode()).hexdigest()[:16]
            transport = bridge_info.get("transport", "vanilla")
            cdn_fronted = bridge_info.get("cdn_fronted", False)
            snowflake = bridge_info.get("snowflake", False)
            ech_capable = bridge_info.get("ech_capable", False)
            kyber_support = bridge_info.get("kyber_support", False)

            # Post-quantum score
            pq_score = 0.0
            if kyber_support:
                pq_score += 0.7  # Kyber/ML-KEM is the primary PQ indicator
            if ech_capable:
                pq_score += 0.2  # ECH implies modern TLS stack
            # Bonus for TLS 1.3 support (indicated by modern transport)
            if transport in ("obfs4", "webtunnel", "snowflake"):
                pq_score += 0.1
            pq_score = min(1.0, pq_score)

            # NIN survival score
            nin_score = 0.0
            if cdn_fronted:
                nin_score += 0.4  # CDN-fronted survives NIN blocking
            if snowflake:
                nin_score += 0.35  # Snowflake uses WebRTC — hard to block
            if ech_capable:
                nin_score += 0.15  # ECH hides SNI from NIN
            if kyber_support:
                nin_score += 0.1  # PQ kex resists future decryption
            nin_score = min(1.0, nin_score)

            # Overall score with PQ preference
            overall = 0.0
            base_weight = 0.4
            pq_weight = 0.3 if self.prefer_pq else 0.1
            nin_weight = 0.3 if self.nin_survival_mode else 0.15
            other_weight = 1.0 - base_weight - pq_weight - nin_weight

            base_score = 0.5  # Neutral base
            if transport in ("snowflake", "webtunnel"):
                base_score = 0.7
            elif transport == "obfs4":
                base_score = 0.6
            elif transport == "meek_lite":
                base_score = 0.55

            overall = (
                base_score * base_weight +
                pq_score * pq_weight +
                nin_score * nin_weight +
                (0.5 if cdn_fronted else 0.2) * other_weight
            )
            overall = min(1.0, overall)

            recommended = overall >= 0.6 and (not self.prefer_pq or pq_score >= 0.5)

            score = BridgeScore(
                bridge_id=bridge_id,
                transport=transport,
                pq_score=pq_score,
                kyber_support=kyber_support,
                cdn_fronted=cdn_fronted,
                snowflake=snowflake,
                ech_capable=ech_capable,
                nin_survival_score=nin_score,
                overall_score=round(overall, 3),
                recommended=recommended,
            )

            self._bridge_scores[bridge_id] = score
            log.debug(
                "[ECHRouter] Bridge %s scored: overall=%.2f pq=%.2f nin=%.2f rec=%s",
                bridge_id, overall, pq_score, nin_score, recommended,
            )
            return score

        except Exception as e:
            log.error("[ECHRouter] Bridge scoring error: %s", e)
            return BridgeScore(
                bridge_id="error", transport="unknown",
                pq_score=0.0, kyber_support=False,
                cdn_fronted=False, snowflake=False,
                ech_capable=False, nin_survival_score=0.0,
                overall_score=0.0, recommended=False,
            )

    def route_with_ech_fallback(
        self,
        destination: str,
        ech_domains: Optional[List[str]] = None,
    ) -> ECHResult:
        """
        Route traffic using the ECH fallback chain.

        Fallback chain: ECH → Domain Fronting → SNI Splitting → SNI Padding.

        Args:
            destination: The target destination domain.
            ech_domains: Optional list of domains to attempt ECH with.

        Returns:
            ECHResult indicating which method was used.
        """
        domains_to_try = ech_domains or [destination]

        # ── Level 1: Attempt ECH ──
        for domain in domains_to_try:
            result = self.resolve_ech(domain)
            if result.ech_available:
                log.info("[ECHRouter] ECH successful for %s", domain)
                return result

        # ── Level 2: Domain Fronting ──
        for domain in domains_to_try:
            domain_info = _ECH_KNOWN_DOMAINS.get(domain, {})
            if domain_info.get("fronting_available"):
                front_domain = domain_info.get("cdn_front_domain", domain)
                result = ECHResult(
                    domain=destination,
                    ech_available=False,
                    fallback_used=self.FALLBACK_DOMAIN_FRONTING,
                    pq_score=1.0 if domain_info.get("pq_support") else 0.0,
                    latency_ms=0.0,
                )
                log.info(
                    "[ECHRouter] Domain fronting via %s → %s",
                    domain, front_domain,
                )
                return result

        # ── Level 3: SNI Splitting ──
        log.info("[ECHRouter] Falling back to SNI splitting for %s", destination)
        return ECHResult(
            domain=destination,
            ech_available=False,
            fallback_used=self.FALLBACK_SNI_SPLITTING,
            pq_score=0.0,
            latency_ms=0.0,
        )

    def _determine_fallback(self, domain: str) -> str:
        """Determine the best fallback method when ECH is not available."""
        domain_info = _ECH_KNOWN_DOMAINS.get(domain, {})
        if domain_info.get("fronting_available"):
            return self.FALLBACK_DOMAIN_FRONTING
        # Check if domain is in the SNI padding whitelist
        if domain in _SNI_PADDING_DOMAINS:
            return self.FALLBACK_SNI_PADDING
        return self.FALLBACK_SNI_SPLITTING

    def get_nin_survival_bridges(
        self, bridges: List[Dict[str, Any]], top_n: int = 3,
    ) -> List[BridgeScore]:
        """
        Get the top N bridges ranked for NIN shutdown survival.

        Prioritizes CDN-fronted and Snowflake bridges.

        Args:
            bridges: List of bridge_info dictionaries.
            top_n: Number of top bridges to return.

        Returns:
            List of BridgeScore sorted by overall score descending.
        """
        scores = [self.score_bridge_pq(b) for b in bridges]
        scores.sort(key=lambda s: s.overall_score, reverse=True)
        return scores[:top_n]

    def get_status(self) -> Dict[str, Any]:
        """Get ECH router status."""
        return {
            "ech_cache_size": len(self._ech_cache),
            "bridge_scores_size": len(self._bridge_scores),
            "prefer_pq": self.prefer_pq,
            "nin_survival_mode": self.nin_survival_mode,
            "known_ech_domains": list(_ECH_KNOWN_DOMAINS.keys()),
            "sni_padding_domains_count": len(_SNI_PADDING_DOMAINS),
        }


# ════════════════════════════════════════════════════════════════════════════
# 4. ANTI-DPI V3 ORCHESTRATOR
# ════════════════════════════════════════════════════════════════════════════

class AntiDPIV3Orchestrator:
    """
    Unified orchestrator for the Neural Anti-DPI V3 system.

    Integrates NeuralTrafficMorphing, JA3_JA3S_RotationEngine,
    and ECHFallbackRouter into a cohesive evasion system.

    Falls back to the V2 engine (IranAntiDPIV2) when V3 features
    are not applicable. Supports AI gateway integration for
    real-time DPI evasion strategy queries.
    """

    def __init__(
        self,
        morphing_config: Optional[Dict[str, Any]] = None,
        ja3_config: Optional[Dict[str, Any]] = None,
        ech_config: Optional[Dict[str, Any]] = None,
    ) -> None:
        """
        Initialize the V3 Orchestrator.

        Args:
            morphing_config: Configuration dict for NeuralTrafficMorphing.
            ja3_config: Configuration dict for JA3_JA3S_RotationEngine.
            ech_config: Configuration dict for ECHFallbackRouter.
        """
        # Initialize V3 subsystems
        mc = morphing_config or {}
        self.morphing = NeuralTrafficMorphing(
            default_profile=mc.get("default_profile", "cdn-front"),
            padding_strength=mc.get("padding_strength", 0.8),
            jitter_strength=mc.get("jitter_strength", 0.7),
            max_overhead_pct=mc.get("max_overhead_pct", 25.0),
        )

        jc = ja3_config or {}
        self.ja3_engine = JA3_JA3S_RotationEngine(
            rotation_strategy=jc.get("rotation_strategy", "time"),
            rotation_interval_minutes=jc.get("rotation_interval_minutes", 60),
            rotation_request_count=jc.get("rotation_request_count", 100),
            random_rotation_probability=jc.get("random_rotation_probability", 0.05),
            prefer_iran_domestic=jc.get("prefer_iran_domestic", True),
        )

        ec = ech_config or {}
        self.ech_router = ECHFallbackRouter(
            ech_timeout_ms=ec.get("ech_timeout_ms", 2000.0),
            prefer_pq=ec.get("prefer_pq", True),
            nin_survival_mode=ec.get("nin_survival_mode", False),
        )

        # V2 fallback engine
        if _V2_AVAILABLE and IranAntiDPIV2 is not None:
            self._v2: Optional[IranAntiDPIV2] = IranAntiDPIV2()
            log.info("[V3Orchestrator] V2 engine loaded as fallback")
        else:
            self._v2 = None
            log.info("[V3Orchestrator] V2 engine unavailable — V3 standalone mode")

        # AI gateway reference (set externally)
        self._ai_gateway: Any = None

        # State
        self._analysis_count: int = 0
        self._v2_fallback_count: int = 0
        self._last_analysis_time: float = 0.0

        self._load_state()
        log.info("[V3Orchestrator] Fully initialized")

    def set_ai_gateway(self, gateway: Any) -> None:
        """
        Set the AI gateway for real-time DPI evasion strategy queries.

        Args:
            gateway: An AI gateway instance with a query/chat method.
        """
        self._ai_gateway = gateway
        log.info("[V3Orchestrator] AI gateway attached")

    def analyze_and_evade(
        self,
        traffic_info: Dict[str, Any],
    ) -> EvasionResult:
        """
        Perform comprehensive analysis and apply evasion strategies.

        Integrates all V3 subsystems and falls back to V2 when needed.

        Args:
            traffic_info: Dictionary containing:
                - packet_sequence: List of PacketInfo dicts (optional)
                - target_domain: Destination domain (optional)
                - transport: Transport type (optional)
                - bridge_line: Bridge line string (optional)
                - bridges: List of bridge_info dicts (optional)
                - ech_domains: List of ECH-capable domains (optional)
                - force_v2: Force V2 fallback (optional, default False)

        Returns:
            EvasionResult with comprehensive evasion details.
        """
        self._analysis_count += 1
        self._last_analysis_time = time.time()

        try:
            transport = traffic_info.get("transport", "obfs4")
            target_domain = traffic_info.get("target_domain", "")
            force_v2 = traffic_info.get("force_v2", False)

            # ── 1. Traffic Morphing ──
            morph_result_dict: Optional[Dict[str, Any]] = None
            morphing_applied = False

            raw_packets = traffic_info.get("packet_sequence", [])
            if raw_packets and not force_v2:
                packets = [
                    PacketInfo(**p) if isinstance(p, dict) else p
                    for p in raw_packets
                ]
                profile_name = traffic_info.get("target_profile", "cdn-front")
                target_profile = self.morphing.generate_target_profile(profile_name)
                morph_result = self.morphing.morph_traffic(packets, target_profile)
                morph_result_dict = morph_result.to_dict()
                # Remove large morphed_sequence from dict for status
                morph_result_dict.pop("morphed_sequence", None)
                morphing_applied = morph_result.effectiveness_score > 0.3

            # ── 2. JA3 Rotation ──
            ja3_applied = False
            ja3_profile_dict: Optional[Dict[str, Any]] = None
            if not force_v2:
                ja3_str, ja3s_str = self.ja3_engine.get_current_profile()
                profile = self.ja3_engine.get_full_profile()
                if profile:
                    ja3_profile_dict = profile.to_dict()
                ja3_applied = True

            # ── 3. ECH Routing ──
            ech_result_dict: Optional[Dict[str, Any]] = None
            ech_routed = False
            ech_domains = traffic_info.get("ech_domains")
            if target_domain and not force_v2:
                ech_result = self.ech_router.route_with_ech_fallback(
                    target_domain, ech_domains
                )
                ech_result_dict = ech_result.to_dict()
                ech_routed = ech_result.ech_available or ech_result.fallback_used != ""

            # ── 4. Bridge Scoring ──
            bridges = traffic_info.get("bridges", [])
            bridge_scores: List[Dict[str, Any]] = []
            for b in bridges:
                score = self.ech_router.score_bridge_pq(b)
                bridge_scores.append(score.to_dict())

            # ── 5. V2 Fallback ──
            v2_fallback_used = False
            if force_v2 or (not morphing_applied and not ja3_applied):
                if self._v2 is not None:
                    v2_fallback_used = True
                    self._v2_fallback_count += 1
                    log.debug("[V3Orchestrator] Using V2 fallback for this analysis")

            # ── 6. AI Gateway Query (optional) ──
            ai_strategy = ""
            if self._ai_gateway is not None:
                try:
                    ai_strategy = self._query_ai_gateway(traffic_info)
                except Exception as e:
                    log.warning("[V3Orchestrator] AI gateway query failed: %s", e)

            # ── Determine risk level ──
            risk_level = self._assess_risk(
                morphing_applied, ja3_applied, ech_routed, bridge_scores, transport
            )

            # ── Build strategy string ──
            parts: List[str] = []
            if morphing_applied:
                parts.append("traffic_morphing")
            if ja3_applied:
                parts.append("ja3_rotation")
            if ech_routed:
                parts.append("ech_fallback")
            if v2_fallback_used:
                parts.append("v2_fallback")
            if ai_strategy:
                parts.append(f"ai_advised({ai_strategy})")
            strategy = " → ".join(parts) if parts else "minimal_evasion"

            return EvasionResult(
                traffic_morphing_applied=morphing_applied,
                ja3_rotated=ja3_applied,
                ech_routed=ech_routed,
                v2_fallback_used=v2_fallback_used,
                morph_result=morph_result_dict,
                ja3_profile=ja3_profile_dict,
                ech_result=ech_result_dict,
                bridge_scores=bridge_scores,
                evasion_strategy=strategy,
                risk_level=risk_level,
                confidence=self._compute_confidence(
                    morphing_applied, ja3_applied, ech_routed, v2_fallback_used
                ),
                timestamp=datetime.now(timezone.utc).isoformat(),
            )

        except Exception as e:
            log.error("[V3Orchestrator] analyze_and_evade error: %s", e)
            return EvasionResult(
                traffic_morphing_applied=False,
                ja3_rotated=False,
                ech_routed=False,
                v2_fallback_used=False,
                morph_result=None,
                ja3_profile=None,
                ech_result=None,
                bridge_scores=[],
                evasion_strategy="error",
                risk_level="unknown",
                confidence=0.0,
                timestamp=datetime.now(timezone.utc).isoformat(),
            )

    def get_status(self) -> Dict[str, Any]:
        """
        Get current state of all V3 subsystems.

        Returns:
            Dictionary with status of morphing, JA3 rotation,
            ECH routing, V2 fallback, and AI gateway.
        """
        ja3_str, ja3s_str = self.ja3_engine.get_current_profile()
        current_profile = self.ja3_engine.get_full_profile()

        return {
            "engine": "AntiDPIV3Orchestrator",
            "v2_available": _V2_AVAILABLE,
            "v2_fallback_count": self._v2_fallback_count,
            "analysis_count": self._analysis_count,
            "last_analysis_time": self._last_analysis_time,
            "morphing": {
                "default_profile": self.morphing.default_profile,
                "padding_strength": self.morphing.padding_strength,
                "jitter_strength": self.morphing.jitter_strength,
                "max_overhead_pct": self.morphing.max_overhead_pct,
                "profiles_available": list(self.morphing.get_profiles().keys()),
            },
            "ja3_rotation": {
                "current_profile": current_profile.profile_name if current_profile else "unknown",
                "current_ja3": ja3_str[:50] + "..." if len(ja3_str) > 50 else ja3_str,
                "rotation_strategy": self.ja3_engine.rotation_strategy,
                "prefer_iran_domestic": self.ja3_engine.prefer_iran_domestic,
                "profiles_available": list(self.ja3_engine.get_all_profiles().keys()),
            },
            "ech_router": self.ech_router.get_status(),
            "ai_gateway_attached": self._ai_gateway is not None,
        }

    def _query_ai_gateway(self, traffic_info: Dict[str, Any]) -> str:
        """Query AI gateway for real-time DPI evasion strategy."""
        if self._ai_gateway is None:
            return ""

        try:
            prompt = (
                f"Iran DPI evasion query: transport={traffic_info.get('transport', 'unknown')}, "
                f"domain={traffic_info.get('target_domain', 'unknown')}. "
                f"Suggest a brief evasion strategy keyword (1-3 words)."
            )
            # Attempt common gateway interfaces
            if hasattr(self._ai_gateway, "chat"):
                response = self._ai_gateway.chat(prompt)
            elif hasattr(self._ai_gateway, "query"):
                response = self._ai_gateway.query(prompt)
            elif hasattr(self._ai_gateway, "ask"):
                response = self._ai_gateway.ask(prompt)
            else:
                return ""

            # Extract brief keyword from response
            if isinstance(response, str):
                return response.strip().split()[0] if response.strip() else ""
            elif isinstance(response, dict):
                text = response.get("text", response.get("content", ""))
                return str(text).strip().split()[0] if text else ""
            return ""
        except Exception:
            return ""

    @staticmethod
    def _assess_risk(
        morphing: bool, ja3: bool, ech: bool,
        bridge_scores: List[Dict[str, Any]], transport: str,
    ) -> str:
        """Assess overall risk level based on evasion coverage."""
        coverage = sum([morphing, ja3, ech])

        # Check if any bridges are recommended
        has_recommended = any(bs.get("recommended", False) for bs in bridge_scores)

        # Transport baseline risk
        transport_risk = {
            "vanilla": 3, "obfs4": 1, "webtunnel": 1,
            "meek_lite": 1, "snowflake": 0,
        }.get(transport, 2)

        risk_score = (3 - coverage) + transport_risk
        if has_recommended:
            risk_score = max(0, risk_score - 1)

        if risk_score <= 1:
            return "low"
        elif risk_score <= 2:
            return "medium"
        elif risk_score <= 3:
            return "high"
        else:
            return "critical"

    @staticmethod
    def _compute_confidence(
        morphing: bool, ja3: bool, ech: bool, v2_fallback: bool,
    ) -> float:
        """Compute overall evasion confidence score."""
        base = 0.3
        if morphing:
            base += 0.25
        if ja3:
            base += 0.20
        if ech:
            base += 0.15
        if v2_fallback:
            base += 0.10
        return round(min(1.0, base), 3)

    # ── State Persistence ────────────────────────────────────────────────

    def _load_state(self) -> None:
        """Load V3 orchestrator state from disk."""
        try:
            if V3_STATE_FILE.exists():
                data = json.loads(V3_STATE_FILE.read_text(encoding="utf-8"))
                self._analysis_count = data.get("analysis_count", 0)
                self._v2_fallback_count = data.get("v2_fallback_count", 0)
                self._last_analysis_time = data.get("last_analysis_time", 0.0)
                log.info(
                    "[V3Orchestrator] Loaded state: analyses=%d, v2_fallbacks=%d",
                    self._analysis_count, self._v2_fallback_count,
                )
        except Exception as e:
            log.warning("[V3Orchestrator] Could not load state: %s", e)

    def _save_state(self) -> None:
        """Persist V3 orchestrator state to disk."""
        try:
            state = {
                "analysis_count": self._analysis_count,
                "v2_fallback_count": self._v2_fallback_count,
                "last_analysis_time": self._last_analysis_time,
                "last_updated": datetime.now(timezone.utc).isoformat(),
            }
            V3_STATE_FILE.write_text(
                json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8"
            )
        except Exception as e:
            log.warning("[V3Orchestrator] Could not save state: %s", e)


# ════════════════════════════════════════════════════════════════════════════
# CLI INTERFACE
# ════════════════════════════════════════════════════════════════════════════

def main() -> None:
    """CLI entry point for the V3 neural anti-DPI engine."""
    import argparse
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")

    parser = argparse.ArgumentParser(
        description="Neural Anti-DPI V3 — Next-Generation Evasion Engine"
    )
    parser.add_argument(
        "--status", action="store_true", help="Show V3 system status"
    )
    parser.add_argument(
        "--profiles", action="store_true", help="List available traffic profiles"
    )
    parser.add_argument(
        "--ja3-profiles", action="store_true", help="List available JA3 profiles"
    )
    parser.add_argument(
        "--ech-domains", action="store_true", help="List known ECH-capable domains"
    )
    parser.add_argument(
        "--test-morph", type=str, default="",
        help="Test morphing with a target profile name"
    )
    parser.add_argument(
        "--test-ech", type=str, default="",
        help="Test ECH resolution for a domain"
    )
    args = parser.parse_args()

    v3 = AntiDPIV3Orchestrator()

    if args.status:
        status = v3.get_status()
        print(json.dumps(status, indent=2, default=str))

    elif args.profiles:
        for name, profile in v3.morphing.get_profiles().items():
            print(f"  {name}: {profile.description}")
            print(f"    Size: μ={profile.packet_size_mean:.0f} σ={profile.packet_size_std:.0f}")
            print(f"    IAT: μ={profile.iat_mean_ms:.0f}ms σ={profile.iat_std_ms:.0f}ms")
            print(f"    Iran domestic: {profile.iran_domestic}")

    elif args.ja3_profiles:
        for name, profile in v3.ja3_engine.get_all_profiles().items():
            print(f"  {name}: {profile.browser_name} {profile.browser_version}")
            print(f"    JA3: {profile.ja3_string[:60]}...")
            print(f"    Iran domestic: {profile.iran_domestic} (weight={profile.weight})")
            if profile.iran_notes:
                print(f"    Notes: {profile.iran_notes}")

    elif args.ech_domains:
        for domain, info in _ECH_KNOWN_DOMAINS.items():
            ech = "✓" if info["ech_support"] else "✗"
            pq = "✓" if info["pq_support"] else "✗"
            front = "✓" if info["fronting_available"] else "✗"
            print(f"  {domain}: ECH={ech} PQ={pq} Fronting={front}")
            print(f"    NIN survival: {info['nin_survival']:.0%}")

    elif args.test_morph:
        profile = v3.morphing.generate_target_profile(args.test_morph)
        # Generate synthetic packet sequence
        packets = [
            PacketInfo(
                size=random.randint(100, 1400),
                timestamp=time.time() + i * 0.05,
                direction="outbound" if i % 3 else "inbound",
                payload_entropy=random.uniform(0.7, 0.95),
            )
            for i in range(20)
        ]
        result = v3.morphing.morph_traffic(packets, profile)
        print(f"Morphing result: {json.dumps(result.to_dict(), indent=2, default=str)}")

    elif args.test_ech:
        result = v3.ech_router.resolve_ech(args.test_ech)
        print(f"ECH result: {json.dumps(result.to_dict(), indent=2, default=str)}")

    else:
        parser.print_help()
        print("\n--- V3 Quick Status ---")
        status = v3.get_status()
        print(f"  Engine: {status['engine']}")
        print(f"  V2 Available: {status['v2_available']}")
        print(f"  Traffic Profiles: {len(status['morphing']['profiles_available'])}")
        print(f"  JA3 Profiles: {len(status['ja3_rotation']['profiles_available'])}")
        print(f"  ECH Domains: {len(status['ech_router']['known_ech_domains'])}")


if __name__ == "__main__":
    main()
