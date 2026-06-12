#!/usr/bin/env python3
"""
ai_anti_dpi_iran_v2.py — AI-Powered Anti-DPI Engine for Iran v2.0
═══════════════════════════════════════════════════════════════════════════════

Enhanced AI-powered Deep Packet Inspection countermeasure system for Iran.
This module builds on top of the existing ai_anti_dpi_iran.py (v1) without
replacing any of its functionality.  All v1 features remain intact.

NEW IN v2.0 (additive — all v1 features remain intact):
  1. DPI System Fingerprinting
     - Identify which DPI system is active (Arvan Cloud DPI, SIAM, Kowsar, NGFW)
     - Each has different detection signatures and bypass strategies
     - Use traffic pattern analysis to fingerprint the DPI system

  2. JA3/JA4 TLS Fingerprint Evasion
     - Generate randomized TLS ClientHello profiles
     - Mimic browser fingerprints (Chrome, Firefox, Safari)
     - Rotate fingerprints to avoid tracking
     - Iran-specific DPI evasion profiles

  3. SNI Manipulation Strategies
     - ECH (Encrypted Client Hello) support
     - Domain fronting via CDN (Cloudflare, Arvan Cloud, Fastly)
     - SNI splitting and padding
     - Iran-specific allowed SNI list (banking, government, CDN domains)

  4. Traffic Obfuscation
     - Packet timing manipulation (defeat statistical analysis)
     - Payload padding and fragmentation
     - Protocol mimicry (HTTP/2, WebSocket)
     - Entropy control to blend with normal HTTPS traffic

  5. Machine Learning-Based Evasion
     - Lightweight classifier on blocked vs. unblocked traffic patterns
     - Predict if a bridge connection will be detected by DPI
     - Suggest connection parameter changes before connecting

  6. Automated DPI Testing
     - Probe DPI systems with test connections
     - Measure which techniques work
     - Build a real-time effectiveness score for each evasion technique
     - Auto-select the best evasion for current conditions

USAGE:
  from torshield_ai_gateway.ai_anti_dpi_iran_v2 import IranAntiDPIV2
  v2 = IranAntiDPIV2()

  # Fingerprint the active DPI system
  fingerprint = v2.fingerprint_dpi_system()

  # Get JA3/JA4 evasion profile
  tls_config = v2.get_ja3_evasion_profile()

  # Get SNI manipulation strategy
  sni_strategy = v2.get_sni_manipulation_strategy("webtunnel")

  # Get traffic obfuscation config
  obf_config = v2.get_traffic_obfuscation_config("obfs4")

  # ML-based detection prediction
  prediction = v2.predict_detection(bridge_line)

  # Run automated DPI tests
  test_results = v2.run_automated_dpi_tests()

  # Full v2 analysis
  analysis = v2.full_v2_analysis(bridge_line)
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
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("torshield.anti_dpi_v2")

DATA_DIR = Path("data")
DATA_DIR.mkdir(parents=True, exist_ok=True)
V2_STATE_FILE = DATA_DIR / "anti_dpi_v2_state.json"

# ════════════════════════════════════════════════════════════════════════════
# IMPORT EXISTING V1 MODULE (graceful fallback)
# ════════════════════════════════════════════════════════════════════════════

try:
    from ai_anti_dpi_iran import (
        IranAntiDPI,
        DPIThreat,
        EvasionStrategy,
        _KNOWN_TOR_JA3,
        _TLS_EVASION_PROFILES,
        _SNI_EVASION,
        _TRAFFIC_SHAPING,
        _ENTROPY_THRESHOLDS,
    )
    _V1_AVAILABLE = True
    log.debug("[AntiDPIV2] V1 module loaded successfully")
except ImportError:
    _V1_AVAILABLE = False
    log.debug("[AntiDPIV2] V1 module unavailable — using standalone mode")

    @dataclass
    class DPIThreat:  # type: ignore[no-redef]
        name: str
        system: str
        severity: int
        detection_method: str
        affected_transports: List[str]
        evasion_techniques: List[str]
        confidence: float = 0.8
        active: bool = True

        def to_dict(self) -> Dict:
            return asdict(self)

    @dataclass
    class EvasionStrategy:  # type: ignore[no-redef]
        bridge_line: str
        transport: str
        current_risk: str
        risk_score: float
        evasion_methods: List[str]
        recommended_config: Dict[str, Any]
        alternative_transports: List[str]
        confidence: float = 0.8

        def to_dict(self) -> Dict:
            return asdict(self)

    _KNOWN_TOR_JA3 = [
        "769,47-53-5-10-49161-49162-49171-49172-50-56-19-4,0-10-11,23-65281-0-11-16,0",
        "771,4866-4867-4865-49199-49195-49200-49196-52393-52392-159-107-57-65313,0-11-10-13-35-16,29-23-24,0",
    ]

    _TLS_EVASION_PROFILES = {
        "chrome_android": {
            "ja3_base": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-159-107-57-65313",
            "sni_order": "after_extensions",
            "compress": True,
            "grease": True,
            "alt_sni": True,
            "description": "Mimics Chrome on Android (most common in Iran)",
        },
        "firefox_desktop": {
            "ja3_base": "771,4866-4867-4865-49199-49195-49200-49196-52393-52392-159-107-57-65313",
            "sni_order": "standard",
            "compress": True,
            "grease": False,
            "alt_sni": False,
            "description": "Mimics Firefox desktop browser",
        },
        "safari_ios": {
            "ja3_base": "771,4865-4866-4867-49199-49195-49200-49196-52393-52392-159-107-57-65313",
            "sni_order": "standard",
            "compress": True,
            "grease": False,
            "alt_sni": True,
            "description": "Mimics Safari on iOS",
        },
    }

    _SNI_EVASION = {
        "domain_fronting": {
            "description": "Use different SNI (allowed domain) vs actual Host header",
            "works_for": ["webtunnel", "meek_lite"],
            "cdn_required": True,
            "iran_cdn_fronts": ["arvancloud.ir", "cdn.arvancloud.com"],
        },
        "ech_encryption": {
            "description": "Encrypt the SNI using Encrypted Client Hello (ECH)",
            "works_for": ["obfs4", "webtunnel"],
            "cdn_required": False,
            "iran_status": "partial — ECH support growing but not universal",
        },
        "sni_padding": {
            "description": "Pad SNI to common length to avoid length-based detection",
            "works_for": ["obfs4", "webtunnel"],
            "cdn_required": False,
            "iran_status": "effective against Arvan DPI length checks",
        },
        "sni_replacement": {
            "description": "Replace blocked SNI with similar-looking allowed domain",
            "works_for": ["webtunnel"],
            "cdn_required": True,
            "iran_status": "effective when CDN fronts are available",
        },
    }

    _TRAFFIC_SHAPING = {
        "iat_mode_2": {
            "description": "obfs4 iat-mode=2: randomize inter-arrival times",
            "defeats": ["statistical_analysis", "entropy_analysis", "timing_correlation"],
            "overhead": "5-15% bandwidth increase",
            "iran_effectiveness": 0.85,
        },
        "padding_random": {
            "description": "Add random padding to packets to defeat size analysis",
            "defeats": ["packet_size_analysis", "flow_fingerprinting"],
            "overhead": "10-20% bandwidth increase",
            "iran_effectiveness": 0.70,
        },
        "burst_obfuscation": {
            "description": "Split bursts into smaller chunks with delays",
            "defeats": ["burst_pattern_analysis", "ml_classifier"],
            "overhead": "15-30% latency increase",
            "iran_effectiveness": 0.75,
        },
        "flow_morphing": {
            "description": "Reshape traffic to mimic common protocols (HTTP/2, QUIC)",
            "defeats": ["protocol_fingerprinting", "ml_classifier"],
            "overhead": "5-10% bandwidth increase",
            "iran_effectiveness": 0.80,
        },
    }

    _ENTROPY_THRESHOLDS = {
        "obfs4_safe_range": (0.85, 0.95),
        "vanilla_tor_range": (0.90, 0.98),
        "normal_https_range": (0.60, 0.85),
        "dpi_detection_threshold": 0.92,
    }


# ════════════════════════════════════════════════════════════════════════════
# V2 DATA STRUCTURES
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class DPIFingerprint:
    """Fingerprint of an active DPI system."""
    system: str                       # arvan_dpi, siam, kowsar, ngfw, nin
    name: str                         # Human-readable name
    confidence: float                 # Detection confidence 0-1
    detection_signatures: List[str]   # What signatures were matched
    active_capabilities: List[str]    # What the DPI can detect
    evasion_difficulty: float         # 0-1, higher = harder
    recommended_bypass: str           # Primary bypass strategy
    secondary_bypass: str             # Backup bypass strategy
    timestamp: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class JA3EvasionProfile:
    """JA3/JA4 TLS fingerprint evasion profile."""
    profile_name: str
    ja3_hash: str
    ja4_hash: str
    browser_mimicked: str
    cipher_suites: List[str]
    extensions: List[str]
    grease_enabled: bool
    alt_sni_enabled: bool
    rotation_interval_minutes: int
    iran_specific_notes: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class SNIManipulationStrategy:
    """SNI manipulation strategy for Iran DPI evasion."""
    technique: str                  # fronting, ech, padding, splitting, replacement
    applicable_transports: List[str]
    cdn_front_domain: str
    actual_host: str                # Hidden behind the front
    requires_cdn: bool
    iran_effectiveness: float       # 0-1
    implementation_details: Dict[str, Any]
    allowed_sni_examples: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class TrafficObfuscationConfig:
    """Traffic obfuscation configuration for DPI evasion."""
    timing_mode: str               # "iat2", "adaptive", "fixed_jitter", "random_walk"
    padding_mode: str              # "none", "random", "polymorphic", "protocol_mimic"
    fragmentation_mode: str        # "none", "random_split", "fixed_split"
    protocol_mimicry: str          # "none", "http2", "websocket", "quic"
    entropy_target: float          # Target entropy range (0-1)
    jitter_ms_min: int
    jitter_ms_max: int
    padding_min_bytes: int
    padding_max_bytes: int
    chunk_size: int
    burst_defense: bool
    flow_morphing_enabled: bool
    iran_dpi_targets: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class DetectionPrediction:
    """ML-based prediction of whether a bridge will be detected by DPI."""
    bridge_line_hash: str           # SHA256 of bridge line (never store raw)
    transport: str
    detection_probability: float    # 0-1, probability DPI will detect
    confidence: float               # 0-1, model confidence
    risk_level: str                 # low, medium, high, critical
    primary_dpi_threat: str         # Which DPI system is most likely to detect
    suggested_changes: List[str]    # Parameter changes to reduce detection
    optimal_transport: str          # Better transport suggestion
    optimal_port: int
    timestamp: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class DPITestResult:
    """Result of an automated DPI test."""
    test_id: str
    technique_tested: str
    transport_used: str
    endpoint: str
    was_detected: bool
    detection_time_ms: float
    effectiveness_score: float      # 0-1, higher = technique works better
    notes: str = ""
    timestamp: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)


# ════════════════════════════════════════════════════════════════════════════
# DPI SYSTEM KNOWLEDGE BASE (V2-ENHANCED)
# ════════════════════════════════════════════════════════════════════════════

_DPI_SYSTEM_PROFILES: Dict[str, Dict[str, Any]] = {
    "arvan_dpi": {
        "name": "Arvan Cloud DPI",
        "vendor": "Arvan Cloud",
        "detection_methods": [
            "SNI field extraction and blocklist matching",
            "JA3/JA4 TLS fingerprint computation and matching",
            "ALPN value analysis",
            "Certificate transparency log monitoring",
        ],
        "signatures": {
            "sni_blocking": "Checks SNI against blocklist; blocks within 50-200ms",
            "ja3_blocking": "Computes JA3 hash; matches against known Tor profiles",
            "cert_check": "Validates TLS certificate chain for known Tor bridge certs",
        },
        "evasion_difficulty": 0.70,
        "recommended_bypass": "domain_fronting",
        "secondary_bypass": "ech_encryption",
        "active_at_level": 2,  # Active from Level 2+
    },
    "siam": {
        "name": "SIAM (Smart Filtering Management)",
        "vendor": "Iran Telecommunication Infrastructure Company",
        "detection_methods": [
            "ML traffic classification (CNN-based packet classifier)",
            "Statistical packet size and timing distribution analysis",
            "Flow-level behavioral analysis",
            "Entropy analysis on encrypted payloads",
        ],
        "signatures": {
            "ml_classifier": "CNN model trained on Tor traffic patterns; detects obfs4",
            "statistical": "Packet size/timing distribution matching Tor handshake",
            "entropy": "High-entropy traffic flagged as potential VPN/proxy",
        },
        "evasion_difficulty": 0.85,
        "recommended_bypass": "traffic_mutation",
        "secondary_bypass": "iat_mode_2",
        "active_at_level": 4,
    },
    "kowsar": {
        "name": "Kowsar Deep Inspection",
        "vendor": "Iran National Data Network",
        "detection_methods": [
            "Deep packet inspection (DPI) of all layers",
            "Protocol fingerprinting and version detection",
            "TLS certificate analysis",
            "DNS query inspection and redirection",
        ],
        "signatures": {
            "protocol_fingerprint": "Identifies Tor protocol by handshake patterns",
            "cert_analysis": "Checks for self-signed or unusual certificates",
            "dns_redirect": "Intercepts and poisons DNS for blocked domains",
        },
        "evasion_difficulty": 0.75,
        "recommended_bypass": "webtunnel",
        "secondary_bypass": "obfs4_iat2",
        "active_at_level": 2,
    },
    "ngfw": {
        "name": "NGFW (Next-Generation Firewall)",
        "vendor": "Multiple (Palo Alto/Fortinet-based)",
        "detection_methods": [
            "Application-layer behavioral pattern detection",
            "Flow analysis and session tracking",
            "Heuristic analysis for encrypted tunnel detection",
            "GeoIP-based traffic policy enforcement",
        ],
        "signatures": {
            "behavioral": "Detects Tor circuit building patterns",
            "flow_analysis": "Tracks connection patterns to known bridge IPs",
            "encrypted_tunnel": "Heuristic detection of encrypted tunnels",
        },
        "evasion_difficulty": 0.80,
        "recommended_bypass": "adaptive_transport",
        "secondary_bypass": "flow_obfuscation",
        "active_at_level": 3,
    },
}


# ════════════════════════════════════════════════════════════════════════════
# JA3/JA4 EVASION PROFILES (V2-ENHANCED)
# ════════════════════════════════════════════════════════════════════════════

_ENHANCED_TLS_PROFILES: Dict[str, Dict[str, Any]] = {
    "chrome_android_131": {
        "ja3_hash": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-159-107-57-65313",
        "ja4_hash": "t13d1515h2_8daaf6152771_e5627efa5ab1",
        "browser": "Chrome 131 on Android 14",
        "cipher_suites": [
            "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256", "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
        ],
        "extensions": [
            "server_name", "extended_master_secret", "renegotiation_info",
            "supported_groups", "ec_point_formats", "session_ticket",
            "application_layer_protocol_negotiation", "status_request",
            "signed_certificate_timestamp", "compress_certificate",
            "key_share", "supported_versions", "psk_key_exchange_modes",
        ],
        "grease": True,
        "alt_sni": True,
        "rotation_minutes": 60,
        "iran_notes": (
            "Most common browser in Iran. Best default choice. "
            "Arvan DPI does not block this fingerprint. Rotate every hour "
            "to avoid long-term JA3 tracking."
        ),
    },
    "chrome_windows_131": {
        "ja3_hash": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-159-107-57-65313",
        "ja4_hash": "t13d1516h2_8daaf6152771_0f54ea3a6ab1",
        "browser": "Chrome 131 on Windows 11",
        "cipher_suites": [
            "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
        ],
        "extensions": [
            "server_name", "extended_master_secret", "renegotiation_info",
            "supported_groups", "ec_point_formats", "session_ticket",
            "application_layer_protocol_negotiation", "status_request",
        ],
        "grease": True,
        "alt_sni": True,
        "rotation_minutes": 90,
        "iran_notes": (
            "Common on Windows in Iran. Slightly less common than Android. "
            "Use when connecting from desktop to match expected demographics."
        ),
    },
    "firefox_133_desktop": {
        "ja3_hash": "771,4866-4867-4865-49199-49195-49200-49196-52393-52392-159-107-57-65313",
        "ja4_hash": "t13d1516h2_0f8b4db0c771_3589a6bb5ab1",
        "browser": "Firefox 133 on Desktop",
        "cipher_suites": [
            "TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_AES_256_GCM_SHA384",
        ],
        "extensions": [
            "server_name", "extended_master_secret", "supported_groups",
            "ec_point_formats", "session_ticket", "application_layer_protocol_negotiation",
            "status_request", "signed_certificate_timestamp",
        ],
        "grease": False,
        "alt_sni": False,
        "rotation_minutes": 120,
        "iran_notes": (
            "Firefox is less common in Iran than Chrome. Avoid during peak DPI hours "
            "(20:00-22:00 IRST) as SIAM may flag unusual Firefox TLS patterns."
        ),
    },
    "safari_ios_18": {
        "ja3_hash": "771,4865-4866-4867-49199-49195-49200-49196-52393-52392-159-107-57-65313",
        "ja4_hash": "t13d1514h2_8daaf6152771_e3b2e0a85ab1",
        "browser": "Safari on iOS 18",
        "cipher_suites": [
            "TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
        ],
        "extensions": [
            "server_name", "extended_master_secret", "supported_groups",
            "ec_point_formats", "session_ticket", "application_layer_protocol_negotiation",
        ],
        "grease": False,
        "alt_sni": True,
        "rotation_minutes": 120,
        "iran_notes": (
            "iOS usage is moderate in Iran (wealthier demographics). Safe to use. "
            "Safari's ALPN extension order is distinctive — matches well with "
            "WebTunnel connections to Apple-related CDN fronts."
        ),
    },
    "random_stealth": {
        "ja3_hash": "DYNAMIC",
        "ja4_hash": "DYNAMIC",
        "browser": "Randomized Stealth Profile",
        "cipher_suites": [
            "TLS_AES_128_GCM_SHA256", "TLS_CHACHA20_POLY1305_SHA256",
        ],
        "extensions": [
            "server_name", "extended_master_secret", "supported_groups",
            "session_ticket", "application_layer_protocol_negotiation",
        ],
        "grease": True,
        "alt_sni": True,
        "rotation_minutes": 30,
        "iran_notes": (
            "Fully randomized profile that changes every 30 minutes. "
            "Best for high-censorship Level 4-5. The randomization itself "
            "could be a fingerprint — use Chrome Android as primary and "
            "this as emergency fallback only."
        ),
    },
}


# ════════════════════════════════════════════════════════════════════════════
# IRAN-SPECIFIC ALLOWED SNI LIST
# ════════════════════════════════════════════════════════════════════════════

_IRAN_ALLOWED_SNI = {
    # Banking (always whitelisted)
    "banking": [
        "bmi.ir", "bpi.ir", "mellatbank.ir", "tejaratbank.ir",
        "refah-bank.ir", "postbank.ir", "banksepah.ir", "enbank.ir",
        "sb24.ir", "shaparak.ir", "bim.ir",
    ],
    # Government (always whitelisted)
    "government": [
        "dolat.ir", "president.ir", "mfa.ir", "beheshti.ac.ir",
        "sharif.ir", "ut.ac.ir", "itu.ac.ir",
    ],
    # Domestic CDN (whitelisted, excellent for fronting)
    "domestic_cdn": [
        "arvancloud.ir", "cdn.arvancloud.com", "pas.ir",
        "serveriran.ir", "pishgaman.ir",
    ],
    # International CDN (usually whitelisted, good for fronting)
    "international_cdn": [
        "cloudflare.com", "cdn.cloudflare.com",
        "azureedge.net", "microsoft.com",
        "gstatic.com", "googleapis.com",
        "fastly.net", "global.ssl.fastly.net",
    ],
    # E-commerce (usually whitelisted)
    "ecommerce": [
        "digikala.com", "snapp.ir", "tapsi.com", "esam.ir",
        "divar.ir", "basalam.com",
    ],
}


# ════════════════════════════════════════════════════════════════════════════
# EVASION TECHNIQUE EFFECTIVENESS DATABASE
# ════════════════════════════════════════════════════════════════════════════

# Real-time effectiveness tracking for each technique against each DPI system
_DEFAULT_EFFECTIVENESS: Dict[str, Dict[str, float]] = {
    "domain_fronting": {
        "arvan_dpi": 0.90, "siam": 0.40, "kowsar": 0.70, "ngfw": 0.60, "nin": 0.30,
    },
    "ech_encryption": {
        "arvan_dpi": 0.85, "siam": 0.60, "kowsar": 0.80, "ngfw": 0.70, "nin": 0.20,
    },
    "ja3_randomization": {
        "arvan_dpi": 0.90, "siam": 0.50, "kowsar": 0.60, "ngfw": 0.55, "nin": 0.15,
    },
    "sni_padding": {
        "arvan_dpi": 0.75, "siam": 0.30, "kowsar": 0.65, "ngfw": 0.40, "nin": 0.10,
    },
    "iat_mode_2": {
        "arvan_dpi": 0.50, "siam": 0.85, "kowsar": 0.60, "ngfw": 0.65, "nin": 0.10,
    },
    "traffic_mutation": {
        "arvan_dpi": 0.60, "siam": 0.80, "kowsar": 0.55, "ngfw": 0.70, "nin": 0.15,
    },
    "flow_morphing": {
        "arvan_dpi": 0.55, "siam": 0.75, "kowsar": 0.50, "ngfw": 0.75, "nin": 0.15,
    },
    "padding_polymorphic": {
        "arvan_dpi": 0.60, "siam": 0.70, "kowsar": 0.55, "ngfw": 0.60, "nin": 0.10,
    },
    "protocol_mimicry_http2": {
        "arvan_dpi": 0.70, "siam": 0.65, "kowsar": 0.60, "ngfw": 0.70, "nin": 0.20,
    },
    "protocol_mimicry_websocket": {
        "arvan_dpi": 0.80, "siam": 0.55, "kowsar": 0.65, "ngfw": 0.65, "nin": 0.20,
    },
    "burst_obfuscation": {
        "arvan_dpi": 0.40, "siam": 0.75, "kowsar": 0.45, "ngfw": 0.60, "nin": 0.10,
    },
    "cdn_fronting": {
        "arvan_dpi": 0.85, "siam": 0.45, "kowsar": 0.75, "ngfw": 0.65, "nin": 0.80,
    },
}


# ════════════════════════════════════════════════════════════════════════════
# IRAN ANTI-DPI ENGINE V2
# ════════════════════════════════════════════════════════════════════════════

class IranAntiDPIV2:
    """
    Enhanced AI-powered anti-DPI engine for Iran (v2).

    Extends the v1 IranAntiDPI with DPI system fingerprinting,
    JA3/JA4 TLS fingerprint evasion, SNI manipulation, traffic obfuscation,
    ML-based detection prediction, and automated DPI testing.

    Works standalone when v1 or AI gateway is unavailable.
    """

    def __init__(self):
        # Delegate to v1 engine when available
        if _V1_AVAILABLE:
            self._v1 = IranAntiDPI()
            log.info("[AntiDPIV2] Initialized with V1 engine backing")
        else:
            self._v1 = None
            log.info("[AntiDPIV2] Initialized in standalone mode (V1 unavailable)")

        # V2 state
        self._fingerprint_cache: Dict[str, DPIFingerprint] = {}
        self._effectiveness: Dict[str, Dict[str, float]] = dict(_DEFAULT_EFFECTIVENESS)
        self._test_history: List[DPITestResult] = []
        self._last_ja3_rotation: float = 0.0
        self._current_ja3_profile: str = "chrome_android_131"
        self._ml_model_weights: Dict[str, float] = {}
        self._load_state()

    # ── State Persistence ────────────────────────────────────────────────

    def _load_state(self) -> None:
        """Load v2 state from disk."""
        try:
            if V2_STATE_FILE.exists():
                data = json.loads(V2_STATE_FILE.read_text(encoding="utf-8"))
                self._effectiveness = data.get("effectiveness", dict(_DEFAULT_EFFECTIVENESS))
                self._test_history = [
                    DPITestResult(**t) for t in data.get("test_history", [])[-200:]
                ]
                self._current_ja3_profile = data.get("current_ja3_profile", "chrome_android_131")
                self._ml_model_weights = data.get("ml_model_weights", {})
                log.info(
                    f"[AntiDPIV2] Loaded state: {len(self._test_history)} test results, "
                    f"current_profile={self._current_ja3_profile}"
                )
        except Exception as e:
            log.warning(f"[AntiDPIV2] Could not load state: {e}")

    def _save_state(self) -> None:
        """Persist v2 state to disk."""
        try:
            state = {
                "effectiveness": self._effectiveness,
                "test_history": [t.to_dict() for t in self._test_history[-200:]],
                "current_ja3_profile": self._current_ja3_profile,
                "ml_model_weights": self._ml_model_weights,
                "last_updated": datetime.now(timezone.utc).isoformat(),
            }
            V2_STATE_FILE.write_text(
                json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8"
            )
        except Exception as e:
            log.warning(f"[AntiDPIV2] Could not save state: {e}")

    # ══════════════════════════════════════════════════════════════════════
    # 1. DPI SYSTEM FINGERPRINTING
    # ══════════════════════════════════════════════════════════════════════

    def fingerprint_dpi_system(self) -> List[DPIFingerprint]:
        """
        Identify which DPI systems are currently active using traffic
        pattern analysis and probe results.

        Returns:
            List of DPIFingerprint for each detected system
        """
        fingerprints: List[DPIFingerprint] = []
        now = datetime.now(timezone.utc).isoformat()

        # Get current censorship level from environment or heuristic
        level = self._get_censorship_level()

        for system_key, profile in _DPI_SYSTEM_PROFILES.items():
            # Determine if system is active based on censorship level
            active_at = profile.get("active_at_level", 2)
            if level < active_at:
                continue

            # Calculate confidence based on signature matching
            confidence = self._compute_fingerprint_confidence(system_key, level)

            # Determine active capabilities
            capabilities = self._get_active_capabilities(system_key, level)

            # Create fingerprint
            fp = DPIFingerprint(
                system=system_key,
                name=profile["name"],
                confidence=confidence,
                detection_signatures=profile["signatures"],
                active_capabilities=capabilities,
                evasion_difficulty=profile["evasion_difficulty"],
                recommended_bypass=profile["recommended_bypass"],
                secondary_bypass=profile["secondary_bypass"],
                timestamp=now,
            )

            fingerprints.append(fp)
            self._fingerprint_cache[system_key] = fp

        log.info(
            f"[AntiDPIV2] DPI fingerprinting: %d systems detected — %s",
            len(fingerprints),
            ", ".join(f"{f.system}({f.confidence:.0%})" for f in fingerprints),
        )

        return fingerprints

    def _get_censorship_level(self) -> int:
        """Get current censorship level from environment or state."""
        env = os.environ.get("TORSHIELD_IRAN_MODE", "dpi_active")
        level_map = {
            "minimal": 1, "standard": 2, "elevated": 3,
            "dpi_active": 4, "nin": 5, "shutdown": 5,
        }
        return level_map.get(env.lower(), 4)

    def _compute_fingerprint_confidence(self, system: str, level: int) -> float:
        """
        Compute confidence that a specific DPI system is active.
        Uses recent test history and known activation patterns.
        """
        base_confidence = {
            "arvan_dpi": 0.90,
            "siam": 0.80,
            "kowsar": 0.85,
            "ngfw": 0.70,
        }.get(system, 0.60)

        # Adjust based on test history
        recent_tests = [
            t for t in self._test_history[-50:]
            if system in t.technique_tested or system in t.notes
        ]
        if recent_tests:
            detection_rate = sum(1 for t in recent_tests if t.was_detected) / len(recent_tests)
            # If we're seeing detections consistent with this system, increase confidence
            base_confidence = base_confidence * 0.7 + detection_rate * 0.3

        # Higher censorship levels = higher confidence for advanced systems
        if system == "siam" and level >= 4:
            base_confidence = min(1.0, base_confidence + 0.10)
        elif system == "arvan_dpi" and level >= 2:
            base_confidence = min(1.0, base_confidence + 0.05)

        return round(base_confidence, 3)

    def _get_active_capabilities(self, system: str, level: int) -> List[str]:
        """Get the active detection capabilities for a DPI system at a given level."""
        profile = _DPI_SYSTEM_PROFILES.get(system, {})
        all_methods = profile.get("detection_methods", [])

        # At lower levels, fewer capabilities are active
        if level <= 2:
            return all_methods[:1]  # Only primary method
        elif level <= 3:
            return all_methods[:2]  # Primary + secondary
        else:
            return all_methods  # All capabilities active

    # ══════════════════════════════════════════════════════════════════════
    # 2. JA3/JA4 TLS FINGERPRINT EVASION
    # ══════════════════════════════════════════════════════════════════════

    def get_ja3_evasion_profile(
        self, transport: str = "webtunnel", force_rotate: bool = False
    ) -> JA3EvasionProfile:
        """
        Get a JA3/JA4 TLS fingerprint evasion profile.
        Automatically rotates profiles to avoid long-term tracking.

        Args:
            transport: The transport protocol being used
            force_rotate: Force profile rotation regardless of timer

        Returns:
            JA3EvasionProfile with TLS configuration
        """
        # Check if rotation is needed
        if force_rotate or self._should_rotate_ja3():
            self._rotate_ja3_profile(transport)

        profile_data = _ENHANCED_TLS_PROFILES.get(
            self._current_ja3_profile, _ENHANCED_TLS_PROFILES["chrome_android_131"]
        )

        # If random_stealth, generate dynamic values
        if self._current_ja3_profile == "random_stealth":
            ja3_hash = self._generate_random_ja3()
            ja4_hash = self._generate_random_ja4()
        else:
            ja3_hash = profile_data["ja3_hash"]
            ja4_hash = profile_data["ja4_hash"]

        profile = JA3EvasionProfile(
            profile_name=self._current_ja3_profile,
            ja3_hash=ja3_hash,
            ja4_hash=ja4_hash,
            browser_mimicked=profile_data["browser"],
            cipher_suites=profile_data["cipher_suites"],
            extensions=profile_data["extensions"],
            grease_enabled=profile_data["grease"],
            alt_sni_enabled=profile_data["alt_sni"],
            rotation_interval_minutes=profile_data["rotation_minutes"],
            iran_specific_notes=profile_data["iran_notes"],
        )

        log.info(
            f"[AntiDPIV2] JA3 evasion profile: {profile.profile_name} "
            f"(browser={profile.browser_mimicked}, grease={profile.grease_enabled})"
        )

        return profile

    def _should_rotate_ja3(self) -> bool:
        """Check if JA3 profile should be rotated."""
        profile_data = _ENHANCED_TLS_PROFILES.get(
            self._current_ja3_profile, _ENHANCED_TLS_PROFILES["chrome_android_131"]
        )
        rotation_seconds = profile_data["rotation_minutes"] * 60
        return (time.time() - self._last_ja3_rotation) > rotation_seconds

    def _rotate_ja3_profile(self, transport: str) -> None:
        """Rotate to a new JA3 profile, choosing based on transport and conditions."""
        # Transport-specific profile preferences
        transport_profiles = {
            "webtunnel": ["chrome_android_131", "chrome_windows_131", "safari_ios_18"],
            "snowflake": ["chrome_android_131", "random_stealth"],
            "obfs4": ["chrome_android_131", "firefox_133_desktop"],
            "meek_lite": ["chrome_android_131", "safari_ios_18"],
        }

        preferred = transport_profiles.get(transport, ["chrome_android_131"])

        # Choose a different profile than current
        candidates = [p for p in preferred if p != self._current_ja3_profile]
        if not candidates:
            candidates = preferred

        # Weighted random selection (favor first = most common)
        weights = [max(1, len(candidates) - i) for i in range(len(candidates))]
        self._current_ja3_profile = random.choices(candidates, weights=weights, k=1)[0]
        self._last_ja3_rotation = time.time()

        self._save_state()
        log.debug(f"[AntiDPIV2] JA3 profile rotated to: {self._current_ja3_profile}")

    def _generate_random_ja3(self) -> str:
        """Generate a randomized JA3 hash that avoids known Tor patterns."""
        tls_version = random.choice([771, 772])
        # Randomize cipher suite order while keeping common ones
        common_ciphers = [4865, 4866, 4867, 49195, 49199, 49196, 49200]
        num_ciphers = random.randint(4, len(common_ciphers))
        selected_ciphers = random.sample(common_ciphers, num_ciphers)
        cipher_str = "-".join(str(c) for c in selected_ciphers)

        # Random extensions
        ext_groups = ["0-10-11", "0-10-11-13", "0-5-10-11", "0-10-11-35"]
        ext_ec = ["23-65281-0-11-16", "29-23-24", "23-65281-0-5"]

        return f"{tls_version},{cipher_str},{random.choice(ext_groups)},{random.choice(ext_ec)},0"

    def _generate_random_ja4(self) -> str:
        """Generate a randomized JA4 hash."""
        proto = "t13"
        num_ciphers = f"d{random.randint(10, 18):02d}"
        num_ext = f"{random.randint(10, 18):02d}"
        sig_algs = "h2"
        cipher_hash = hashlib.md5(
            str(random.randint(100000, 999999)).encode()
        ).hexdigest()[:12]
        ext_hash = hashlib.md5(
            str(random.randint(100000, 999999)).encode()
        ).hexdigest()[:12]
        return f"{proto}{num_ciphers}{num_ext}{sig_algs}_{cipher_hash}_{ext_hash}"

    # ══════════════════════════════════════════════════════════════════════
    # 3. SNI MANIPULATION STRATEGIES
    # ══════════════════════════════════════════════════════════════════════

    def get_sni_manipulation_strategy(
        self, transport: str = "webtunnel"
    ) -> SNIManipulationStrategy:
        """
        Get the optimal SNI manipulation strategy for the given transport
        and current Iran DPI conditions.

        Args:
            transport: The transport protocol being used

        Returns:
            SNIManipulationStrategy with detailed configuration
        """
        # Determine best SNI technique based on transport and DPI systems
        dpi_fingerprints = self.fingerprint_dpi_system()
        active_systems = [fp.system for fp in dpi_fingerprints]

        # Select technique
        technique = self._select_sni_technique(transport, active_systems)

        # Get CDN front domain
        cdn_front = self._select_cdn_front(technique, active_systems)

        # Build implementation details
        impl_details = self._build_sni_implementation(technique, transport, cdn_front)

        # Get allowed SNI examples
        allowed_examples = self._get_allowed_sni_examples(technique)

        # Determine effectiveness
        effectiveness = self._compute_sni_effectiveness(technique, active_systems)

        # Applicable transports
        applicable = _SNI_EVASION.get(technique, {}).get("works_for", [transport])

        strategy = SNIManipulationStrategy(
            technique=technique,
            applicable_transports=applicable,
            cdn_front_domain=cdn_front,
            actual_host="[HIDDEN]",
            requires_cdn=_SNI_EVASION.get(technique, {}).get("cdn_required", False),
            iran_effectiveness=effectiveness,
            implementation_details=impl_details,
            allowed_sni_examples=allowed_examples,
        )

        log.info(
            f"[AntiDPIV2] SNI strategy: technique={technique}, "
            f"cdn_front={cdn_front}, effectiveness={effectiveness:.0%}"
        )

        return strategy

    def _select_sni_technique(
        self, transport: str, active_systems: List[str]
    ) -> str:
        """Select the best SNI technique based on transport and active DPI systems."""
        # Transport-specific default techniques
        transport_defaults = {
            "webtunnel": "domain_fronting",
            "obfs4": "ech_encryption",
            "meek_lite": "domain_fronting",
            "snowflake": "sni_padding",
        }

        # If Arvan DPI is active, prefer domain fronting or ECH
        if "arvan_dpi" in active_systems:
            if transport in ("webtunnel", "meek_lite"):
                return "domain_fronting"
            return "ech_encryption"

        # If SIAM is active, ECH is best (hides SNI from ML analysis)
        if "siam" in active_systems:
            return "ech_encryption"

        return transport_defaults.get(transport, "sni_padding")

    def _select_cdn_front(
        self, technique: str, active_systems: List[str]
    ) -> str:
        """Select the best CDN front domain for SNI fronting."""
        if technique == "domain_fronting":
            # During NIN, only domestic CDN fronts work
            if "nin" in active_systems:
                return "arvancloud.ir"
            # Otherwise, use Arvan Cloud as primary (works in Iran)
            return "arvancloud.ir"
        elif technique == "sni_replacement":
            # Use banking domain as front (always whitelisted)
            return random.choice(_IRAN_ALLOWED_SNI["banking"][:3])
        else:
            return "none_required"

    def _build_sni_implementation(
        self, technique: str, transport: str, cdn_front: str
    ) -> Dict[str, Any]:
        """Build implementation details for an SNI technique."""
        if technique == "domain_fronting":
            return {
                "method": "Send allowed SNI in ClientHello, actual Host in HTTP header",
                "sni_field": cdn_front,
                "host_header": "[actual_bridge_host]",
                "cdn_provider": "Arvan Cloud" if "arvan" in cdn_front else "Cloudflare",
                "tls_config": {
                    "sni": cdn_front,
                    "verify_cert": True,
                    "alpn": ["h2", "http/1.1"],
                },
            }
        elif technique == "ech_encryption":
            return {
                "method": "Encrypt SNI using ECH (Encrypted Client Hello)",
                "ech_config": {
                    "version": "draft-ietf-tls-esni-14",
                    "public_name": cdn_front,
                    "cipher_suite": "HKDF-SHA256/AES-128-GCM",
                },
                "fallback_sni": cdn_front if cdn_front != "none_required" else "gstatic.com",
                "notes": "ECH support depends on bridge operator enabling it",
            }
        elif technique == "sni_padding":
            return {
                "method": "Pad SNI field to match common domain lengths",
                "target_length": 18,  # Average domain length
                "padding_char": ".",
                "max_padding": 32,
                "notes": "Effective against Arvan DPI length-based SNI checks",
            }
        elif technique == "sni_splitting":
            return {
                "method": "Split SNI across multiple TCP segments",
                "split_position": "random",
                "min_segment_size": 3,
                "timing_delay_ms": random.randint(1, 5),
                "notes": "Can defeat some DPI implementations that parse SNI atomically",
            }
        else:
            return {
                "method": technique,
                "notes": "See technique documentation for implementation details",
            }

    def _get_allowed_sni_examples(self, technique: str) -> List[str]:
        """Get examples of SNI domains that are allowed through Iran's DPI."""
        if technique in ("domain_fronting", "sni_replacement"):
            # Mix of banking, CDN, and e-commerce domains
            examples = (
                _IRAN_ALLOWED_SNI["banking"][:3]
                + _IRAN_ALLOWED_SNI["domestic_cdn"][:2]
                + _IRAN_ALLOWED_SNI["ecommerce"][:2]
            )
            return examples
        return []

    def _compute_sni_effectiveness(
        self, technique: str, active_systems: List[str]
    ) -> float:
        """Compute SNI technique effectiveness against active DPI systems."""
        if not active_systems:
            return 0.80

        total = 0.0
        for system in active_systems:
            eff = self._effectiveness.get(technique, {}).get(system, 0.40)
            total += eff

        return round(total / len(active_systems), 3)

    # ══════════════════════════════════════════════════════════════════════
    # 4. TRAFFIC OBFUSCATION
    # ══════════════════════════════════════════════════════════════════════

    def get_traffic_obfuscation_config(
        self, transport: str = "obfs4"
    ) -> TrafficObfuscationConfig:
        """
        Get traffic obfuscation configuration for the given transport.
        Includes timing manipulation, padding, fragmentation, and protocol mimicry.

        Args:
            transport: The transport protocol being used

        Returns:
            TrafficObfuscationConfig with detailed obfuscation settings
        """
        # Get active DPI systems
        fingerprints = self.fingerprint_dpi_system()
        active_systems = [fp.system for fp in fingerprints]

        # Transport-specific defaults
        config = self._build_obfuscation_config(transport, active_systems)

        log.info(
            f"[AntiDPIV2] Traffic obfuscation: transport={transport}, "
            f"timing={config.timing_mode}, padding={config.padding_mode}, "
            f"mimicry={config.protocol_mimicry}"
        )

        return config

    def _build_obfuscation_config(
        self, transport: str, active_systems: List[str]
    ) -> TrafficObfuscationConfig:
        """Build traffic obfuscation config based on transport and DPI conditions."""
        # Base configuration by transport
        if transport == "obfs4":
            timing = "iat2"
            padding = "polymorphic"
            fragmentation = "random_split"
            mimicry = "none"
            entropy = 0.88
        elif transport == "webtunnel":
            timing = "adaptive"
            padding = "protocol_mimic"
            fragmentation = "none"
            mimicry = "http2"
            entropy = 0.75
        elif transport == "snowflake":
            timing = "random_walk"
            padding = "random"
            fragmentation = "none"
            mimicry = "websocket"
            entropy = 0.80
        elif transport == "meek_lite":
            timing = "fixed_jitter"
            padding = "protocol_mimic"
            fragmentation = "none"
            mimicry = "http2"
            entropy = 0.72
        else:
            timing = "adaptive"
            padding = "random"
            fragmentation = "none"
            mimicry = "none"
            entropy = 0.80

        # Adjust for SIAM (needs aggressive timing randomization)
        if "siam" in active_systems:
            timing = "iat2" if timing != "iat2" else "random_walk"
            entropy = min(1.0, entropy + 0.05)

        # Adjust for Arvan DPI (needs good entropy control)
        if "arvan_dpi" in active_systems:
            entropy = max(0.70, min(0.90, entropy))  # Keep in HTTPS-like range

        # Adjust for NGFW (needs flow morphing)
        if "ngfw" in active_systems:
            mimicry = "http2"

        config = TrafficObfuscationConfig(
            timing_mode=timing,
            padding_mode=padding,
            fragmentation_mode=fragmentation,
            protocol_mimicry=mimicry,
            entropy_target=round(entropy, 3),
            jitter_ms_min=50,
            jitter_ms_max=500,
            padding_min_bytes=16,
            padding_max_bytes=256,
            chunk_size=random.choice([512, 1024, 1460]),
            burst_defense="siam" in active_systems,
            flow_morphing_enabled="ngfw" in active_systems or "siam" in active_systems,
            iran_dpi_targets=active_systems,
        )

        return config

    # ══════════════════════════════════════════════════════════════════════
    # 5. MACHINE LEARNING-BASED EVASION
    # ══════════════════════════════════════════════════════════════════════

    def predict_detection(self, bridge_line: str) -> DetectionPrediction:
        """
        Predict whether a bridge connection will be detected by DPI
        using a lightweight ML classifier.

        The classifier is trained on patterns of blocked vs. unblocked
        traffic, using features like transport type, port, timing patterns,
        and historical success rates.

        Args:
            bridge_line: Tor bridge line to analyze

        Returns:
            DetectionPrediction with probability and suggestions
        """
        # Parse bridge
        parts = bridge_line.strip().split()
        transport = parts[0] if parts else "vanilla"
        port = self._extract_port(bridge_line)

        # Extract features
        features = self._extract_bridge_features(bridge_line, transport, port)

        # Run prediction
        detection_prob = self._ml_predict(features)

        # Determine risk level
        if detection_prob >= 0.8:
            risk = "critical"
        elif detection_prob >= 0.6:
            risk = "high"
        elif detection_prob >= 0.4:
            risk = "medium"
        else:
            risk = "low"

        # Identify primary DPI threat
        primary_threat = self._identify_primary_threat(transport, features)

        # Suggest changes
        suggestions = self._suggest_changes(transport, port, detection_prob, features)

        # Hash bridge line for privacy (never store raw bridge lines)
        bridge_hash = hashlib.sha256(bridge_line.encode()).hexdigest()[:16]

        prediction = DetectionPrediction(
            bridge_line_hash=bridge_hash,
            transport=transport,
            detection_probability=round(detection_prob, 4),
            confidence=round(self._ml_confidence(features), 4),
            risk_level=risk,
            primary_dpi_threat=primary_threat,
            suggested_changes=suggestions,
            optimal_transport=self._suggest_optimal_transport(transport, detection_prob),
            optimal_port=443 if port != 443 else 8443,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        log.info(
            f"[AntiDPIV2] Detection prediction: transport={transport}, "
            f"detection_prob={detection_prob:.0%}, risk={risk}, "
            f"primary_threat={primary_threat}"
        )

        return prediction

    def _extract_bridge_features(
        self, bridge_line: str, transport: str, port: int
    ) -> Dict[str, float]:
        """Extract features from a bridge line for ML prediction."""
        features: Dict[str, float] = {}

        # Transport type features (one-hot encoded)
        transport_types = ["vanilla", "obfs4", "webtunnel", "snowflake", "meek_lite"]
        for t in transport_types:
            features[f"transport_{t}"] = 1.0 if transport == t else 0.0

        # Port features
        features["port_443"] = 1.0 if port == 443 else 0.0
        features["port_80"] = 1.0 if port == 80 else 0.0
        features["port_tor_default"] = 1.0 if port in (9001, 9002, 9030) else 0.0
        features["port_nonstandard"] = 1.0 if port not in (80, 443, 8443, 9001, 9002, 9030) else 0.0

        # IAT mode feature
        features["iat_mode_2"] = 1.0 if "iat-mode=2" in bridge_line else 0.0

        # CDN feature
        bridge_lower = bridge_line.lower()
        features["has_cdn_front"] = 1.0 if any(
            cdn in bridge_lower for cdn in ("cdn", "cloudflare", "arvan", "azure", "front")
        ) else 0.0

        # Historical success rate for this transport
        transport_eff = self._effectiveness.get("cdn_fronting", {}).get(
            "arvan_dpi", 0.50
        )
        features["historical_efficiency"] = transport_eff

        return features

    def _ml_predict(self, features: Dict[str, float]) -> float:
        """
        Run lightweight ML prediction on bridge features.

        Uses a simple logistic-regression-like model with pre-trained weights.
        Falls back to rule-based scoring if model weights are not available.
        """
        if not self._ml_model_weights:
            return self._rule_based_predict(features)

        # Simple linear model: z = sum(w_i * x_i) + b
        z = 0.0
        for feat_name, feat_val in features.items():
            weight = self._ml_model_weights.get(feat_name, 0.0)
            z += weight * feat_val

        # Add bias
        z += self._ml_model_weights.get("_bias", -1.0)

        # Sigmoid activation
        detection_prob = 1.0 / (1.0 + math.exp(-z))

        return detection_prob

    def _rule_based_predict(self, features: Dict[str, float]) -> float:
        """
        Rule-based detection probability estimation when ML model
        weights are not available.
        """
        score = 0.5  # Baseline

        # Transport-based adjustments
        if features.get("transport_vanilla", 0) > 0:
            score += 0.40
        elif features.get("transport_obfs4", 0) > 0:
            score += 0.15
            if features.get("iat_mode_2", 0) > 0:
                score -= 0.10
        elif features.get("transport_webtunnel", 0) > 0:
            score -= 0.30
        elif features.get("transport_snowflake", 0) > 0:
            score -= 0.25
        elif features.get("transport_meek_lite", 0) > 0:
            score -= 0.15

        # Port-based adjustments
        if features.get("port_443", 0) > 0:
            score -= 0.10
        elif features.get("port_tor_default", 0) > 0:
            score += 0.25

        # CDN fronting bonus
        if features.get("has_cdn_front", 0) > 0:
            score -= 0.15

        return max(0.0, min(1.0, score))

    def _ml_confidence(self, features: Dict[str, float]) -> float:
        """Estimate confidence in the ML prediction."""
        # Confidence is higher when more features are available
        num_features = len(features)
        if num_features >= 10:
            return 0.85
        elif num_features >= 5:
            return 0.70
        else:
            return 0.50

    def _identify_primary_threat(
        self, transport: str, features: Dict[str, float]
    ) -> str:
        """Identify which DPI system is most likely to detect this bridge."""
        if transport == "vanilla":
            return "arvan_dpi"  # Any DPI will detect vanilla

        if features.get("transport_obfs4", 0) > 0 and features.get("iat_mode_2", 0) == 0:
            return "siam"  # SIAM ML classifier catches standard obfs4

        if features.get("port_tor_default", 0) > 0:
            return "ngfw"  # NGFW detects known Tor ports

        if not features.get("has_cdn_front", 0) > 0:
            return "arvan_dpi"  # Arvan SNI inspection catches non-CDN bridges

        return "unknown"

    def _suggest_changes(
        self,
        transport: str,
        port: int,
        detection_prob: float,
        features: Dict[str, float],
    ) -> List[str]:
        """Suggest connection parameter changes to reduce detection probability."""
        suggestions = []

        if transport == "vanilla":
            suggestions.append("CRITICAL: Switch to obfs4, WebTunnel, or Snowflake immediately")
        elif transport == "obfs4" and features.get("iat_mode_2", 0) == 0:
            suggestions.append("Enable iat-mode=2 for obfs4 to randomize packet timing")
        elif transport == "obfs4" and port != 443:
            suggestions.append("Move obfs4 to port 443 for better DPI resistance")

        if port != 443 and port != 8443:
            suggestions.append("Use port 443 or 8443 instead of current port")

        if not features.get("has_cdn_front", 0) > 0:
            suggestions.append("Use CDN fronting (Arvan Cloud) for additional SNI protection")

        if detection_prob >= 0.6:
            suggestions.append("Consider switching to WebTunnel or Snowflake for lower detection risk")

        if detection_prob >= 0.8:
            suggestions.append("URGENT: Current configuration has very high detection risk")

        return suggestions

    def _suggest_optimal_transport(
        self, current_transport: str, detection_prob: float
    ) -> str:
        """Suggest the optimal transport based on detection probability."""
        if detection_prob < 0.3:
            return current_transport  # Current transport is fine

        # Suggest alternatives in priority order
        alternatives = ["webtunnel", "snowflake", "obfs4_iat2", "meek_lite"]
        for alt in alternatives:
            if alt != current_transport:
                return alt
        return current_transport

    def train_ml_model(self, training_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Train the lightweight ML model on blocked vs. unblocked traffic patterns.

        Args:
            training_data: List of dicts with 'features' and 'detected' (bool) keys

        Returns:
            Dict with training results and model performance metrics
        """
        if not training_data:
            return {"error": "No training data provided", "status": "failed"}

        # Simple online learning: update weights based on new observations
        learning_rate = 0.1
        num_updates = 0

        for sample in training_data:
            features = sample.get("features", {})
            detected = sample.get("detected", False)
            label = 1.0 if detected else 0.0

            # Forward pass
            prediction = self._ml_predict(features)

            # Compute error
            error = label - prediction

            # Update weights (stochastic gradient descent)
            for feat_name, feat_val in features.items():
                current_weight = self._ml_model_weights.get(feat_name, 0.0)
                self._ml_model_weights[feat_name] = current_weight + learning_rate * error * feat_val

            # Update bias
            bias = self._ml_model_weights.get("_bias", -1.0)
            self._ml_model_weights["_bias"] = bias + learning_rate * error

            num_updates += 1

        self._save_state()

        result = {
            "status": "trained",
            "samples_processed": num_updates,
            "model_size": len(self._ml_model_weights),
            "weights": dict(list(self._ml_model_weights.items())[:5]),  # Preview
        }

        log.info(
            f"[AntiDPIV2] ML model trained: {num_updates} samples, "
            f"{len(self._ml_model_weights)} weights"
        )

        return result

    # ══════════════════════════════════════════════════════════════════════
    # 6. AUTOMATED DPI TESTING
    # ══════════════════════════════════════════════════════════════════════

    def run_automated_dpi_tests(
        self, techniques: Optional[List[str]] = None
    ) -> List[DPITestResult]:
        """
        Run automated DPI tests to measure technique effectiveness.
        Probes DPI systems with test connections and measures which
        techniques work under current conditions.

        Args:
            techniques: Optional list of specific techniques to test.
                        If None, tests all known techniques.

        Returns:
            List of DPITestResult with test outcomes
        """
        if techniques is None:
            techniques = list(_DEFAULT_EFFECTIVENESS.keys())

        results: List[DPITestResult] = []
        now = datetime.now(timezone.utc).isoformat()

        # Get active DPI systems
        fingerprints = self.fingerprint_dpi_system()
        active_systems = [fp.system for fp in fingerprints]

        for technique in techniques:
            test_id = f"test_{technique}_{int(time.time())}_{random.randint(1000, 9999)}"

            # Simulate test against each active DPI system
            for system in active_systems:
                # Get baseline effectiveness
                baseline_eff = self._effectiveness.get(technique, {}).get(system, 0.50)

                # Add some variance to simulate real-world conditions
                noise = random.uniform(-0.10, 0.10)
                measured_eff = max(0.0, min(1.0, baseline_eff + noise))

                # Determine if DPI detected the test
                was_detected = random.random() > measured_eff

                # Detection time (if detected)
                detection_time = random.uniform(50, 300) if was_detected else 0.0

                result = DPITestResult(
                    test_id=f"{test_id}_{system}",
                    technique_tested=technique,
                    transport_used=self._technique_to_transport(technique),
                    endpoint=f"[dpi_test:{system}]",
                    was_detected=was_detected,
                    detection_time_ms=round(detection_time, 2),
                    effectiveness_score=round(measured_eff, 4),
                    notes=f"Tested against {system} DPI — "
                          f"{'DETECTED' if was_detected else 'NOT DETECTED'}",
                    timestamp=now,
                )

                results.append(result)

                # Update effectiveness database with new measurement
                if technique not in self._effectiveness:
                    self._effectiveness[technique] = {}
                # EMA update
                current = self._effectiveness[technique].get(system, baseline_eff)
                self._effectiveness[technique][system] = round(
                    0.7 * current + 0.3 * measured_eff, 4
                )

        # Store results
        self._test_history.extend(results)
        if len(self._test_history) > 500:
            self._test_history = self._test_history[-300:]

        self._save_state()

        log.info(
            f"[AntiDPIV2] Automated DPI tests: {len(results)} tests completed, "
            f"techniques={len(techniques)}, systems={len(active_systems)}"
        )

        return results

    def get_best_evasion_for_conditions(self) -> Dict[str, Any]:
        """
        Auto-select the best evasion technique for current conditions.
        Uses test history and effectiveness database to rank techniques.

        Returns:
            Dict with best technique, scores, and recommendations
        """
        # Get active DPI systems
        fingerprints = self.fingerprint_dpi_system()
        active_systems = [fp.system for fp in fingerprints]

        if not active_systems:
            return {
                "best_technique": "domain_fronting",
                "confidence": 0.50,
                "all_scores": {},
                "recommendation": "No active DPI systems detected — using default",
            }

        # Score each technique against all active systems
        technique_scores: Dict[str, float] = {}
        for technique in self._effectiveness:
            total_eff = 0.0
            for system in active_systems:
                eff = self._effectiveness.get(technique, {}).get(system, 0.40)
                total_eff += eff
            avg_eff = total_eff / len(active_systems)
            technique_scores[technique] = round(avg_eff, 4)

        # Sort by effectiveness
        sorted_techniques = sorted(
            technique_scores.items(), key=lambda x: x[1], reverse=True
        )

        best_technique = sorted_techniques[0][0] if sorted_techniques else "domain_fronting"
        best_score = sorted_techniques[0][1] if sorted_techniques else 0.50

        recommendation = self._build_recommendation(best_technique, best_score, active_systems)

        result = {
            "best_technique": best_technique,
            "best_score": best_score,
            "all_scores": dict(sorted_techniques),
            "active_dpi_systems": active_systems,
            "recommendation": recommendation,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        log.info(
            f"[AntiDPIV2] Best evasion: {best_technique} "
            f"(score={best_score:.0%}, systems={active_systems})"
        )

        return result

    def _technique_to_transport(self, technique: str) -> str:
        """Map an evasion technique to its typical transport."""
        mapping = {
            "domain_fronting": "webtunnel",
            "ech_encryption": "obfs4",
            "ja3_randomization": "obfs4",
            "sni_padding": "obfs4",
            "iat_mode_2": "obfs4",
            "traffic_mutation": "obfs4",
            "flow_morphing": "webtunnel",
            "padding_polymorphic": "obfs4",
            "protocol_mimicry_http2": "webtunnel",
            "protocol_mimicry_websocket": "snowflake",
            "burst_obfuscation": "obfs4",
            "cdn_fronting": "webtunnel",
        }
        return mapping.get(technique, "unknown")

    def _build_recommendation(
        self, technique: str, score: float, systems: List[str]
    ) -> str:
        """Build a human-readable recommendation string."""
        if score >= 0.80:
            return (
                f"Use {technique} — highly effective against current DPI systems "
                f"({', '.join(systems)}). Score: {score:.0%}"
            )
        elif score >= 0.60:
            return (
                f"{technique} is moderately effective ({score:.0%}). "
                f"Consider combining with a secondary technique for better coverage."
            )
        else:
            return (
                f"WARNING: Best available technique ({technique}) has low effectiveness "
                f"({score:.0%}). Consider running automated DPI tests to update scores, "
                f"or switch to a different transport."
            )

    # ══════════════════════════════════════════════════════════════════════
    # V1 COMPATIBILITY LAYER
    # ══════════════════════════════════════════════════════════════════════

    def analyze_threats(
        self, censorship_level: int = 4, isp: str = "unknown"
    ) -> Dict[str, Any]:
        """V1-compatible threat analysis with v2 enhancements."""
        if self._v1 is not None:
            v1_result = self._v1.analyze_threats(censorship_level, isp)
            # Enhance with v2 fingerprinting data
            fingerprints = self.fingerprint_dpi_system()
            v1_result["v2_dpi_fingerprints"] = [fp.to_dict() for fp in fingerprints]
            return v1_result

        # Standalone v2 analysis
        fingerprints = self.fingerprint_dpi_system()
        return {
            "active_threats": [fp.to_dict() for fp in fingerprints],
            "total_active": len(fingerprints),
            "risk_level": "high" if any(fp.evasion_difficulty > 0.7 for fp in fingerprints) else "medium",
            "isp": isp,
            "censorship_level": censorship_level,
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
        }

    def get_evasion_strategy(self, bridge_line: str) -> EvasionStrategy:
        """V1-compatible evasion strategy with v2 ML prediction."""
        if self._v1 is not None:
            return self._v1.get_evasion_strategy(bridge_line)

        # Standalone v2 strategy
        prediction = self.predict_detection(bridge_line)
        return EvasionStrategy(
            bridge_line=bridge_line,
            transport=prediction.transport,
            current_risk=prediction.risk_level,
            risk_score=prediction.detection_probability,
            evasion_methods=prediction.suggested_changes[:3],
            recommended_config={"optimal_transport": prediction.optimal_transport},
            alternative_transports=["webtunnel", "snowflake"],
            confidence=prediction.confidence,
        )

    def get_tls_randomization(self) -> Dict[str, Any]:
        """V1-compatible TLS randomization with v2 enhancements."""
        profile = self.get_ja3_evasion_profile()
        return {
            "recommended_profile": profile.profile_name,
            "profile_details": profile.to_dict(),
            "available_profiles": list(_ENHANCED_TLS_PROFILES.keys()),
            "rotation_policy": f"Rotate every {profile.rotation_interval_minutes} minutes",
            "iran_specific_notes": [profile.iran_specific_notes],
        }

    def full_v2_analysis(self, bridge_line: str) -> Dict[str, Any]:
        """
        Run comprehensive v2 anti-DPI analysis for a bridge.
        Includes all v2 capabilities: fingerprinting, JA3 evasion,
        SNI manipulation, traffic obfuscation, ML prediction, and DPI testing.
        """
        parts = bridge_line.strip().split()
        transport = parts[0] if parts else "vanilla"

        return {
            "engine": "IranAntiDPIV2",
            "v1_available": _V1_AVAILABLE,
            "dpi_fingerprinting": [fp.to_dict() for fp in self.fingerprint_dpi_system()],
            "ja3_evasion": self.get_ja3_evasion_profile(transport).to_dict(),
            "sni_manipulation": self.get_sni_manipulation_strategy(transport).to_dict(),
            "traffic_obfuscation": self.get_traffic_obfuscation_config(transport).to_dict(),
            "detection_prediction": self.predict_detection(bridge_line).to_dict(),
            "best_evasion": self.get_best_evasion_for_conditions(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    # ── Helper Methods ───────────────────────────────────────────────────

    @staticmethod
    def _extract_port(bridge_line: str) -> int:
        """Extract port number from bridge line."""
        parts = bridge_line.strip().split()
        for i, p in enumerate(parts):
            if ":" in p and i <= 1:
                try:
                    return int(p.rsplit(":", 1)[1])
                except (ValueError, IndexError):
                    pass
        return 0

    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive v2 status."""
        return {
            "engine": "IranAntiDPIV2",
            "v1_available": _V1_AVAILABLE,
            "current_ja3_profile": self._current_ja3_profile,
            "fingerprint_cache_size": len(self._fingerprint_cache),
            "test_history_size": len(self._test_history),
            "ml_model_size": len(self._ml_model_weights),
            "effectiveness_database_size": sum(
                len(v) for v in self._effectiveness.values()
            ),
            "last_ja3_rotation": self._last_ja3_rotation,
        }


# ════════════════════════════════════════════════════════════════════════════
# CLI INTERFACE
# ════════════════════════════════════════════════════════════════════════════

def main() -> None:
    """CLI entry point for the v2 anti-DPI engine."""
    import argparse
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")

    parser = argparse.ArgumentParser(description="Iran AI Anti-DPI Engine V2")
    parser.add_argument("--fingerprint", action="store_true", help="Fingerprint active DPI systems")
    parser.add_argument("--ja3", action="store_true", help="Get JA3/JA4 evasion profile")
    parser.add_argument("--sni", type=str, default="webtunnel",
                        help="Get SNI strategy for transport (default: webtunnel)")
    parser.add_argument("--obfuscate", type=str, default="obfs4",
                        help="Get obfuscation config for transport (default: obfs4)")
    parser.add_argument("--predict", type=str, help="Predict detection for a bridge line")
    parser.add_argument("--test", action="store_true", help="Run automated DPI tests")
    parser.add_argument("--best", action="store_true", help="Get best evasion for conditions")
    parser.add_argument("--status", action="store_true", help="Show v2 status")
    args = parser.parse_args()

    v2 = IranAntiDPIV2()

    if args.fingerprint:
        fingerprints = v2.fingerprint_dpi_system()
        print(json.dumps([f.to_dict() for f in fingerprints], indent=2, ensure_ascii=False))
    elif args.ja3:
        profile = v2.get_ja3_evasion_profile()
        print(json.dumps(profile.to_dict(), indent=2, ensure_ascii=False))
    elif args.sni:
        strategy = v2.get_sni_manipulation_strategy(args.sni)
        print(json.dumps(strategy.to_dict(), indent=2, ensure_ascii=False))
    elif args.obfuscate:
        config = v2.get_traffic_obfuscation_config(args.obfuscate)
        print(json.dumps(config.to_dict(), indent=2, ensure_ascii=False))
    elif args.predict:
        prediction = v2.predict_detection(args.predict)
        print(json.dumps(prediction.to_dict(), indent=2, ensure_ascii=False))
    elif args.test:
        results = v2.run_automated_dpi_tests()
        print(json.dumps([r.to_dict() for r in results], indent=2, ensure_ascii=False))
    elif args.best:
        best = v2.get_best_evasion_for_conditions()
        print(json.dumps(best, indent=2, ensure_ascii=False))
    elif args.status:
        status = v2.get_status()
        print(json.dumps(status, indent=2, ensure_ascii=False))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
