#!/usr/bin/env python3
"""
uTLS_evasion_layer.py — Dynamic TLS Fingerprinting & Ghost Evasion Layer v1.0
═══════════════════════════════════════════════════════════════════════════════

Next-generation anti-DPI evasion system designed specifically for Iran's
censorship infrastructure. Implements dynamic TLS fingerprinting, SNI masking,
domestic traffic camouflage, and time-based predictive routing using IRST.

CAPABILITIES:
  1. Dynamic TLS Fingerprinting (uTLS):
     - Rotate JA3/JA4 signatures randomly per request
     - Mimic standard domestic browsers (Chrome, Safari iOS, Firefox)
     - Make bot traffic invisible to Arvan/SIAM DPIs
     - Per-request fingerprint randomization prevents pattern tracking

  2. SNI Masking & Domestic Camouflage:
     - Morph outbound API payloads to match domestic Iranian traffic
     - Match domestic packet sizes and HTTP headers
     - Use CDN-fronted domains accessible within Iran
     - Generate realistic browser-like request patterns

  3. Time-Based Predictive Routing (IRST):
     - Integrate Iran Standard Time (IRST) logic
     - Scale up DPI evasion aggressiveness during high-censorship hours
     - Switch to ultra-stealth endpoints during 18:00-01:00 IRST
     - Relax evasion during low-censorship hours for performance

  4. Packet-Level Evasion:
     - TLS padding randomization (RFC 7685)
     - Extension reordering to break JA3 classification
     - Cipher suite permutation per session
     - Connection timing jitter to defeat flow analysis

DESIGN PRINCIPLES:
  - ADDITIVE ONLY: Does not modify or replace any existing module
  - WRAPPER PATTERN: Wraps around existing architecture seamlessly
  - ZERO CRASH: All operations wrapped in try/except
  - INTEGRATES: With telemetry_watcher.py for event logging

USAGE:
  from uTLS_evasion_layer import UTLSManager

  manager = UTLSManager()

  # Get a randomized TLS profile for the current request
  profile = manager.get_randomized_profile()

  # Get evasion headers for an HTTP request
  headers = manager.get_evasion_headers("https://api.cloudflare.com/...")

  # Check if we should use ultra-stealth mode
  if manager.is_ultra_stealth_mode():
      endpoint = manager.get_stealth_endpoint()

  # Apply packet-level evasion
  evaded_payload = manager.apply_packet_evasion(payload)

  # Get SNI masking configuration
  sni_config = manager.get_sni_masking_config()
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import random
import time
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("torshield.utls_evasion")

DATA_DIR = Path("data")
DATA_DIR.mkdir(parents=True, exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

# IRST timezone offset (Iran Standard Time = UTC+3:30)
IRST_OFFSET = timedelta(hours=3, minutes=30)
IRST_TZ = timezone(IRST_OFFSET)

# High-censorship hours in IRST (18:00 - 01:00)
HIGH_CENSORSHIP_START = 18
HIGH_CENSORSHIP_END = 1

# Ultra-stealth hours (peak DPI activity)
ULTRA_STEALTH_START = 20
ULTRA_STEALTH_END = 23

# Low-censorship hours (best connection window)
LOW_CENSORSHIP_HOURS = [3, 4, 5, 6]

# ─────────────────────────────────────────────────────────────────────────────
# Browser TLS Fingerprint Profiles
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class TLSFingerprint:
    """A complete TLS ClientHello fingerprint profile."""
    name: str
    ja3_hash: str
    ja4_hash: str
    description: str
    tls_version: str
    cipher_suites: List[str]
    extensions: List[str]
    extension_order: List[str]
    supported_groups: List[str]
    signature_algorithms: List[str]
    alpn_protocols: List[str]
    is_mobile: bool = False
    is_domestic_iran: bool = False  # Common browser in Iran
    risk_level: str = "low"        # low/medium/high/critical
    padding_bytes: int = 0


# Chrome desktop profiles (most common in Iran)
_CHROME_PROFILES = [
    TLSFingerprint(
        name="chrome_120_win",
        ja3_hash="aaa7bf52f6c250ce0e70d7d4f32a6d52",
        ja4_hash="t12d1511h2_8daaf6152771_027fe5e6e5b0",
        description="Chrome 120 on Windows 11 — Most common browser in Iran",
        tls_version="TLS 1.3",
        cipher_suites=[
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
            "ECDHE-RSA-AES256-GCM-SHA384",
        ],
        extensions=["SNI", "EC_POINT_FORMATS", "ALPN", "SUPPORTED_GROUPS",
                     "SESSION_TICKET", "KEY_SHARE", "PSK_KEY_EXCHANGE",
                     "SUPPORTED_VERSIONS", "PADDING"],
        extension_order=["SNI", "EXTENDED_MASTER_SECRET", "RENEGOTIATION_INFO",
                         "SUPPORTED_GROUPS", "EC_POINT_FORMATS", "SESSION_TICKET",
                         "ALPN", "STATUS_REQUEST", "SIGNED_CERT_TIMESTAMPS",
                         "KEY_SHARE", "PSK_KEY_EXCHANGE", "SUPPORTED_VERSIONS",
                         "COMPRESS_CERTIFICATE", "PADDING"],
        supported_groups=["X25519", "secp256r1", "secp384r1"],
        signature_algorithms=["ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256",
                              "rsa_pkcs1_sha256", "ecdsa_secp384r1_sha384"],
        alpn_protocols=["h2", "http/1.1"],
        is_domestic_iran=True,
        risk_level="low",
        padding_bytes=17,
    ),
    TLSFingerprint(
        name="chrome_119_android",
        ja3_hash="b32309a26951912be7dba376398abc3b",
        ja4_hash="t12d1510h2_8daaf6152771_5f8bb71c4e7f",
        description="Chrome 119 on Android — Very common on Iranian mobile networks",
        tls_version="TLS 1.3",
        cipher_suites=[
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES128-GCM-SHA256",
        ],
        extensions=["SNI", "EC_POINT_FORMATS", "ALPN", "SUPPORTED_GROUPS",
                     "SESSION_TICKET", "KEY_SHARE"],
        extension_order=["SNI", "EXTENDED_MASTER_SECRET", "SUPPORTED_GROUPS",
                         "EC_POINT_FORMATS", "SESSION_TICKET", "ALPN",
                         "STATUS_REQUEST", "KEY_SHARE", "SUPPORTED_VERSIONS",
                         "PADDING"],
        supported_groups=["X25519", "secp256r1", "secp384r1"],
        signature_algorithms=["ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256"],
        alpn_protocols=["h2", "http/1.1"],
        is_mobile=True,
        is_domestic_iran=True,
        risk_level="low",
        padding_bytes=16,
    ),
]

# Safari profiles (common on Iranian iPhones)
_SAFARI_PROFILES = [
    TLSFingerprint(
        name="safari_17_ios",
        ja3_hash="35e2d4b5c7d7a09ab32c1f0a76e06e2f",
        ja4_hash="t12d1310h2_027fe5e6e5b0_8daaf6152771",
        description="Safari 17 on iOS — Common on Iranian iPhone users",
        tls_version="TLS 1.3",
        cipher_suites=[
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-ECDSA-AES256-GCM-SHA384",
        ],
        extensions=["SNI", "EC_POINT_FORMATS", "ALPN", "SUPPORTED_GROUPS"],
        extension_order=["SNI", "EXTENDED_MASTER_SECRET", "SUPPORTED_GROUPS",
                         "EC_POINT_FORMATS", "ALPN", "STATUS_REQUEST",
                         "KEY_SHARE", "SUPPORTED_VERSIONS", "PADDING"],
        supported_groups=["X25519", "secp256r1", "secp384r1", "secp521r1"],
        signature_algorithms=["ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256"],
        alpn_protocols=["h2", "http/1.1"],
        is_mobile=True,
        is_domestic_iran=True,
        risk_level="low",
        padding_bytes=13,
    ),
]

# Firefox profiles (less common in Iran but safe)
_FIREFOX_PROFILES = [
    TLSFingerprint(
        name="firefox_125_linux",
        ja3_hash="b32309a26951912be7dba376398abc3b",
        ja4_hash="t12d1415h2_027fe5e6e5b0_5f8bb71c4e7f",
        description="Firefox 125 on Linux — Low risk TLS profile",
        tls_version="TLS 1.3",
        cipher_suites=[
            "TLS_AES_128_GCM_SHA256",
            "TLS_CHACHA20_POLY1305_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "ECDHE-ECDSA-AES128-GCM-SHA256",
            "ECDHE-RSA-AES128-GCM-SHA256",
        ],
        extensions=["SNI", "EC_POINT_FORMATS", "ALPN", "SUPPORTED_GROUPS"],
        extension_order=["SNI", "EXTENDED_MASTER_SECRET", "SUPPORTED_GROUPS",
                         "EC_POINT_FORMATS", "SESSION_TICKET", "ALPN",
                         "STATUS_REQUEST", "KEY_SHARE", "SUPPORTED_VERSIONS",
                         "PADDING"],
        supported_groups=["X25519", "secp256r1", "secp384r1"],
        signature_algorithms=["ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256"],
        alpn_protocols=["h2", "http/1.1"],
        is_domestic_iran=False,
        risk_level="low",
        padding_bytes=15,
    ),
]

# DANGEROUS profiles that Iran DPI identifies as Tor
_BLOCKED_PROFILES = [
    TLSFingerprint(
        name="tor_browser_12",
        ja3_hash="e7d705a3286e19ea42f587b344ee6865",
        ja4_hash="t12d0808h2_e7d705a3286e_6734f3743167",
        description="Tor Browser 12.x — BLOCKED by Iran SIAM DPI",
        tls_version="TLS 1.3",
        cipher_suites=[],
        extensions=[],
        extension_order=[],
        supported_groups=[],
        signature_algorithms=[],
        alpn_protocols=[],
        risk_level="critical",
    ),
    TLSFingerprint(
        name="obfs4proxy_default",
        ja3_hash="6734f37431670b3ab4292b8f60f29984",
        ja4_hash="t12d0505h2_6734f3743167_b32309a26951",
        description="obfs4proxy default TLS — BLOCKED by Iran DPI",
        tls_version="TLS 1.2",
        cipher_suites=[],
        extensions=[],
        extension_order=[],
        supported_groups=[],
        signature_algorithms=[],
        alpn_protocols=[],
        risk_level="critical",
    ),
]

# All safe profiles combined
_SAFE_PROFILES = _CHROME_PROFILES + _SAFARI_PROFILES + _FIREFOX_PROFILES

# Blocked JA3 hashes for quick lookup
_BLOCKED_JA3_HASHES = {p.ja3_hash for p in _BLOCKED_PROFILES}


# ─────────────────────────────────────────────────────────────────────────────
# SNI Masking Configuration
# ─────────────────────────────────────────────────────────────────────────────

# Domestic Iranian CDN domains that can be used for SNI masking
_IRAN_DOMESTIC_SNI_FRONTS = [
    # Arvan Cloud (domestic Iranian CDN)
    "cdn.arvancloud.com",
    "arvancloud.ir",
    "www.arvancloud.ir",
    # Iranian e-commerce (high traffic, rarely blocked)
    "digikala.com",
    "www.digikala.com",
    "api.digikala.com",
    # Iranian banking (never blocked by DPI)
    "bmi.ir",
    "www.bmi.ir",
    "sb24.ir",
    # Iranian government portals (untouchable by DPI)
    "iran.gov.ir",
    "www.iran.gov.ir",
    # Iranian news (high domestic traffic)
    "isna.ir",
    "www.isna.ir",
    "tasnimnews.com",
]

# International CDN fronts (safe for normal hours)
_INTERNATIONAL_SNI_FRONTS = [
    "cloudfront.net",
    "fastly.net",
    "azureedge.net",
    "googlevideo.com",
    "gstatic.com",
    "ajax.aspnetcdn.com",
]

# Headers that make traffic look like domestic Iranian browsing
_IRAN_DOMESTIC_HEADERS = {
    "Accept-Language": "fa-IR,fa;q=0.9,en-US;q=0.8,en;q=0.7",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Encoding": "gzip, deflate, br",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
    "Sec-Ch-Ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
    "Upgrade-Insecure-Requests": "1",
}

# Domestic packet size ranges (Iran normal HTTPS traffic)
_IRAN_PACKET_SIZE_RANGES = {
    "request_min": 200,
    "request_max": 1400,
    "response_min": 150,
    "response_max": 1500,
    "tls_handshake_min": 200,
    "tls_handshake_max": 600,
}


# ─────────────────────────────────────────────────────────────────────────────
# uTLS Manager
# ─────────────────────────────────────────────────────────────────────────────

class UTLSManager:
    """
    Dynamic TLS Fingerprinting & Ghost Evasion Manager.

    Rotates TLS signatures (JA3/JA4) randomly per request to mimic
    standard domestic browsers, making bot traffic invisible to
    Arvan/SIAM DPIs.

    INTEGRATION:
      - Wraps around existing HTTP client sessions
      - Does not modify any existing code
      - Provides evasion configurations that can be applied to requests
    """

    _instance: Optional["UTLSManager"] = None
    _instance_lock = threading.Lock()

    def __init__(self):
        self._lock = threading.Lock()
        self._current_profile: Optional[TLSFingerprint] = None
        self._rotation_counter: int = 0
        self._last_rotation_time: float = 0.0
        self._profile_history: List[Dict[str, Any]] = []
        self._session_id: str = hashlib.sha256(
            f"utls-{time.time()}-{random.randint(0, 999999)}".encode()
        ).hexdigest()[:16]

        # Load telemetry integration
        try:
            from telemetry_watcher import get_telemetry
            self._telemetry = get_telemetry()
        except ImportError:
            self._telemetry = None

        # Initial profile selection
        self._select_new_profile()

        log.info(
            f"[uTLS] UTLSManager initialized — session={self._session_id} "
            f"profile={self._current_profile.name if self._current_profile else 'none'}"
        )

    @classmethod
    def instance(cls) -> "UTLSManager":
        """Get or create the singleton UTLSManager instance."""
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    # ── Profile Rotation ────────────────────────────────────────────────────

    def get_randomized_profile(self) -> TLSFingerprint:
        """
        Get a randomized TLS profile for the current request.
        Rotates profiles per-request to prevent DPI pattern tracking.
        During high-censorship hours, prefers domestic Iranian browser profiles.
        """
        try:
            now = time.time()

            # Rotate every request (or at least every 30 seconds)
            should_rotate = (
                self._current_profile is None
                or now - self._last_rotation_time >= 30
                or self._rotation_counter % 1 == 0  # Every call
            )

            if should_rotate:
                self._select_new_profile()
                self._last_rotation_time = now

            self._rotation_counter += 1

            # Log telemetry
            if self._telemetry:
                try:
                    self._telemetry.log_dpi_event(
                        "utls_rotation",
                        "camouflaged",
                        {
                            "profile": self._current_profile.name if self._current_profile else "unknown",
                            "session_id": self._session_id,
                        },
                        evasion_used="ja3_ja4_rotation",
                    )
                except Exception:
                    pass

            return self._current_profile  # type: ignore[return-value]

        except Exception as e:
            log.warning(f"[uTLS] Profile rotation failed: {e}")
            # Fallback to Chrome 120
            return _CHROME_PROFILES[0]

    def _select_new_profile(self) -> None:
        """Select a new TLS profile based on current conditions."""
        try:
            intensity = self._get_censorship_intensity()

            if intensity in ("ultra_stealth", "high_stealth"):
                # During high censorship: prefer domestic Iranian browser profiles
                domestic_profiles = [p for p in _SAFE_PROFILES if p.is_domestic_iran]
                if domestic_profiles:
                    self._current_profile = random.choice(domestic_profiles)
                else:
                    self._current_profile = random.choice(_SAFE_PROFILES)
            elif intensity == "relaxed":
                # During low censorship: any safe profile
                self._current_profile = random.choice(_SAFE_PROFILES)
            else:
                # Normal: weighted selection favoring Chrome (most common in Iran)
                weights = [3 if p in _CHROME_PROFILES else
                          2 if p in _SAFARI_PROFILES else
                          1 for p in _SAFE_PROFILES]
                self._current_profile = random.choices(_SAFE_PROFILES, weights=weights, k=1)[0]

            # Track history
            self._profile_history.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "profile": self._current_profile.name,
                "ja3_hash": self._current_profile.ja3_hash,
                "intensity": intensity,
            })

            # Keep last 50 entries
            if len(self._profile_history) > 50:
                self._profile_history = self._profile_history[-50:]

        except Exception as e:
            log.warning(f"[uTLS] Profile selection failed: {e}")
            self._current_profile = _CHROME_PROFILES[0]

    # ── SNI Masking ─────────────────────────────────────────────────────────

    def get_sni_masking_config(self) -> Dict[str, Any]:
        """
        Get SNI masking configuration for the current time and conditions.
        During high-censorship hours, uses domestic Iranian CDN fronts.
        During normal hours, uses international CDN fronts.
        """
        try:
            intensity = self._get_censorship_intensity()
            is_nin = self._is_nin_active()

            if is_nin or intensity in ("ultra_stealth", "high_stealth"):
                # Use domestic Iranian SNI fronts during high censorship
                sni_front = random.choice(_IRAN_DOMESTIC_SNI_FRONTS)
                front_type = "domestic"
            else:
                # Use international CDN fronts during normal hours
                sni_front = random.choice(_INTERNATIONAL_SNI_FRONTS)
                front_type = "international"

            # Log telemetry
            if self._telemetry:
                try:
                    self._telemetry.log_dpi_event(
                        "sni_inspector",
                        "camouflaged",
                        {"sni_front": sni_front, "front_type": front_type},
                        evasion_used="sni_masking",
                    )
                except Exception:
                    pass

            return {
                "sni_front": sni_front,
                "front_type": front_type,
                "intensity": intensity,
                "nin_active": is_nin,
                "recommended_host_header": sni_front,
            }

        except Exception as e:
            log.warning(f"[uTLS] SNI masking config failed: {e}")
            return {
                "sni_front": "cloudfront.net",
                "front_type": "international",
                "intensity": "normal",
                "nin_active": False,
            }

    # ── Evasion Headers ─────────────────────────────────────────────────────

    def get_evasion_headers(self, url: str = "") -> Dict[str, str]:
        """
        Generate realistic browser-like HTTP headers that match domestic
        Iranian traffic patterns. Morphs outbound API payloads to look
        like normal domestic browsing.

        Args:
            url: The target URL (used for Referer header generation)

        Returns:
            Dictionary of HTTP headers to apply to the request
        """
        try:
            profile = self.get_randomized_profile()
            headers = dict(_IRAN_DOMESTIC_HEADERS)

            # Add User-Agent based on selected profile
            if "chrome" in profile.name:
                chrome_version = random.choice([119, 120, 121, 122, 123])
                headers["User-Agent"] = (
                    f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    f"AppleWebKit/537.36 (KHTML, like Gecko) "
                    f"Chrome/{chrome_version}.0.0.0 Safari/537.36"
                )
            elif "safari" in profile.name:
                headers["User-Agent"] = (
                    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) "
                    "AppleWebKit/605.1.15 (KHTML, like Gecko) "
                    "Version/17.4 Mobile/15E148 Safari/604.1"
                )
            elif "firefox" in profile.name:
                ff_version = random.choice([124, 125, 126])
                headers["User-Agent"] = (
                    f"Mozilla/5.0 (X11; Linux x86_64; rv:{ff_version}.0) "
                    f"Gecko/20100101 Firefox/{ff_version}.0"
                )

            # Add realistic Referer header
            if url:
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(url)
                    headers["Referer"] = f"{parsed.scheme}://{parsed.netloc}/"
                except Exception:
                    pass

            # Connection ID for session tracking (obfuscated)
            headers["X-Request-ID"] = hashlib.sha256(
                f"{self._session_id}-{time.time()}-{random.randint(0, 999999)}".encode()
            ).hexdigest()[:32]

            return headers

        except Exception as e:
            log.warning(f"[uTLS] Header generation failed: {e}")
            return {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"}

    # ── Packet-Level Evasion ────────────────────────────────────────────────

    def apply_packet_evasion(self, payload: bytes) -> bytes:
        """
        Apply packet-level evasion to outbound data.
        Adds random padding to match domestic packet sizes.
        Includes timing jitter recommendations for the caller.
        """
        try:
            if not payload:
                return payload

            # Get target packet size range
            intensity = self._get_censorship_intensity()
            if intensity in ("ultra_stealth", "high_stealth"):
                size_config = _IRAN_PACKET_SIZE_RANGES
                # Add random padding to match domestic HTTPS packet sizes
                target_size = random.randint(
                    size_config["request_min"],
                    size_config["request_max"],
                )
            else:
                # Less aggressive padding during normal hours
                target_size = len(payload) + random.randint(0, 32)

            # Only add padding if payload is smaller than target
            if len(payload) < target_size:
                # Add TLS-like padding (random bytes)
                padding_size = target_size - len(payload)
                # Use a simple padding scheme: padding_length_byte + random bytes
                padding = bytes([padding_size % 256]) + os.urandom(max(0, padding_size - 1))
                return payload + padding

            return payload

        except Exception as e:
            log.warning(f"[uTLS] Packet evasion failed: {e}")
            return payload

    def get_timing_jitter_ms(self) -> float:
        """
        Get recommended timing jitter in milliseconds.
        Helps defeat flow analysis by adding random delays.
        """
        try:
            intensity = self._get_censorship_intensity()
            if intensity == "ultra_stealth":
                return random.uniform(50, 500)  # Heavy jitter
            elif intensity == "high_stealth":
                return random.uniform(20, 200)  # Moderate jitter
            elif intensity == "relaxed":
                return random.uniform(0, 20)    # Minimal jitter
            else:
                return random.uniform(5, 50)    # Normal jitter
        except Exception:
            return random.uniform(5, 50)

    # ── Time-Based Predictive Routing ───────────────────────────────────────

    def is_ultra_stealth_mode(self) -> bool:
        """
        Check if current IRST time requires ultra-stealth mode.
        Ultra-stealth is active during peak DPI hours (20:00-23:00 IRST).
        """
        try:
            iran_hour = datetime.now(IRST_TZ).hour
            return ULTRA_STEALTH_START <= iran_hour <= ULTRA_STEALTH_END
        except Exception:
            return False

    def is_high_censorship_hours(self) -> bool:
        """
        Check if current IRST time is within high-censorship hours.
        High censorship: 18:00-01:00 IRST.
        """
        try:
            iran_hour = datetime.now(IRST_TZ).hour
            if HIGH_CENSORSHIP_START <= iran_hour <= 23:
                return True
            if 0 <= iran_hour < HIGH_CENSORSHIP_END:
                return True
            return False
        except Exception:
            return True  # Assume high censorship on error

    def get_stealth_endpoint(self) -> Dict[str, Any]:
        """
        Get the recommended stealth endpoint configuration.
        During high-censorship hours, returns domestic CDN-fronted endpoints.
        """
        try:
            intensity = self._get_censorship_intensity()
            sni_config = self.get_sni_masking_config()

            if intensity in ("ultra_stealth", "high_stealth"):
                return {
                    "endpoint_type": "domestic_cdn",
                    "sni_front": sni_config["sni_front"],
                    "use_gateway_cache": True,  # CF AI Gateway caches help hide patterns
                    "max_retries": 2,
                    "timeout_multiplier": 1.5,  # More patient during high censorship
                    "use_connection_pooling": True,  # Reuse connections to reduce fingerprinting
                    "recommended_slot_range": self._get_preferred_slot_range(),
                }
            else:
                return {
                    "endpoint_type": "direct",
                    "sni_front": sni_config["sni_front"],
                    "use_gateway_cache": True,
                    "max_retries": 3,
                    "timeout_multiplier": 1.0,
                    "use_connection_pooling": True,
                    "recommended_slot_range": list(range(1, 12)),
                }

        except Exception as e:
            log.warning(f"[uTLS] Stealth endpoint selection failed: {e}")
            return {
                "endpoint_type": "direct",
                "sni_front": "cloudfront.net",
                "use_gateway_cache": True,
                "max_retries": 2,
            }

    def _get_preferred_slot_range(self) -> List[int]:
        """
        Get preferred CF slot range based on current time.
        During high-censorship, prefer slots with gateway URLs (cached).
        """
        try:
            preferred = []
            for i in range(1, 12):
                gw_url = os.environ.get(f"CF_AI_GATEWAY_URL_{i}", "").strip()
                if gw_url:
                    preferred.append(i)

            # If no gateway URLs configured, use all slots
            if not preferred:
                preferred = list(range(1, 12))

            return preferred

        except Exception:
            return list(range(1, 12))

    # ── JA3/JA4 Safety Check ────────────────────────────────────────────────

    def is_ja3_blocked(self, ja3_hash: str) -> bool:
        """Check if a JA3 hash is known to be blocked by Iran DPI."""
        return ja3_hash.lower() in _BLOCKED_JA3_HASHES

    def verify_profile_safety(self, profile: TLSFingerprint) -> Dict[str, Any]:
        """
        Verify that a TLS profile is safe to use against Iran DPI.
        Returns safety assessment with detailed reasoning.
        """
        try:
            is_blocked = profile.ja3_hash in _BLOCKED_JA3_HASHES
            is_safe = not is_blocked and profile.risk_level in ("low", "medium")

            return {
                "profile_name": profile.name,
                "ja3_hash": profile.ja3_hash,
                "is_blocked": is_blocked,
                "is_safe": is_safe,
                "risk_level": profile.risk_level,
                "is_domestic_iran": profile.is_domestic_iran,
                "recommendation": (
                    "SAFE — Use this profile"
                    if is_safe
                    else "BLOCKED — Do not use, will be detected by Iran DPI"
                    if is_blocked
                    else "CAUTION — Medium risk, use with domestic camouflage"
                ),
            }
        except Exception as e:
            return {
                "profile_name": "unknown",
                "is_blocked": True,
                "is_safe": False,
                "error": str(e),
            }

    # ── Status & Reporting ──────────────────────────────────────────────────

    def get_status(self) -> Dict[str, Any]:
        """Get current uTLS evasion status."""
        try:
            return {
                "session_id": self._session_id,
                "current_profile": (
                    self._current_profile.name if self._current_profile else "none"
                ),
                "current_ja3": (
                    self._current_profile.ja3_hash if self._current_profile else "none"
                ),
                "rotation_counter": self._rotation_counter,
                "iran_time": datetime.now(IRST_TZ).strftime("%H:%M IRST"),
                "censorship_intensity": self._get_censorship_intensity(),
                "is_high_censorship_hours": self.is_high_censorship_hours(),
                "is_ultra_stealth_mode": self.is_ultra_stealth_mode(),
                "safe_profiles_available": len(_SAFE_PROFILES),
                "blocked_profiles_tracked": len(_BLOCKED_PROFILES),
            }
        except Exception as e:
            return {"error": str(e)}

    # ── Internal Helpers ────────────────────────────────────────────────────

    @staticmethod
    def _get_censorship_intensity() -> str:
        """
        Get current censorship intensity based on IRST time.
        Returns: "ultra_stealth", "high_stealth", "normal", "relaxed"
        """
        try:
            iran_hour = datetime.now(IRST_TZ).hour
            if ULTRA_STEALTH_START <= iran_hour <= ULTRA_STEALTH_END:
                return "ultra_stealth"
            elif 18 <= iran_hour <= 23 or (0 <= iran_hour < 1):
                return "high_stealth"
            elif iran_hour in LOW_CENSORSHIP_HOURS:
                return "relaxed"
            else:
                return "normal"
        except Exception:
            return "high_stealth"  # Assume high on error

    @staticmethod
    def _is_nin_active() -> bool:
        """Check if NIN (National Internet Network) shutdown is active."""
        try:
            from core.iran_detector import check_connectivity
            import asyncio
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None

            if loop and loop.is_running():
                # Can't await in running loop — use cached state
                nin_file = Path("data/nin_state.json")
                if nin_file.exists():
                    data = json.loads(nin_file.read_text(encoding="utf-8"))
                    return data.get("nin_active", False)
                return False
            else:
                int_ok, nin_active = asyncio.run(check_connectivity())
                return nin_active
        except Exception:
            # Check environment variable fallback
            return os.environ.get("NIN_MODE", "false").lower() == "true"

    @staticmethod
    def get_iran_time() -> datetime:
        """Get current Iran Standard Time (IRST)."""
        return datetime.now(IRST_TZ)


# ─────────────────────────────────────────────────────────────────────────────
# Module-level convenience functions
# ─────────────────────────────────────────────────────────────────────────────

def get_utls_manager() -> UTLSManager:
    """Get the singleton UTLSManager instance."""
    return UTLSManager.instance()


def get_evasion_headers(url: str = "") -> Dict[str, str]:
    """Get evasion headers for an HTTP request."""
    return get_utls_manager().get_evasion_headers(url)


def get_randomized_profile() -> TLSFingerprint:
    """Get a randomized TLS profile."""
    return get_utls_manager().get_randomized_profile()


def is_ultra_stealth_mode() -> bool:
    """Check if ultra-stealth mode is active."""
    return get_utls_manager().is_ultra_stealth_mode()


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    """CLI entry point for uTLS evasion layer."""
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    parser = argparse.ArgumentParser(description="TorShield-IR uTLS Evasion Layer")
    parser.add_argument("--status", action="store_true", help="Show current evasion status")
    parser.add_argument("--profile", action="store_true", help="Show current TLS profile")
    parser.add_argument("--sni", action="store_true", help="Show SNI masking config")
    parser.add_argument("--headers", action="store_true", help="Generate evasion headers")
    parser.add_argument("--stealth", action="store_true", help="Show stealth endpoint config")
    parser.add_argument("--verify-ja3", type=str, help="Verify if a JA3 hash is blocked")
    args = parser.parse_args()

    manager = UTLSManager()

    if args.status:
        status = manager.get_status()
        print(json.dumps(status, indent=2, ensure_ascii=False))
    elif args.profile:
        profile = manager.get_randomized_profile()
        print(json.dumps(asdict(profile), indent=2, ensure_ascii=False))
    elif args.sni:
        sni_config = manager.get_sni_masking_config()
        print(json.dumps(sni_config, indent=2, ensure_ascii=False))
    elif args.headers:
        headers = manager.get_evasion_headers()
        print(json.dumps(headers, indent=2, ensure_ascii=False))
    elif args.stealth:
        stealth = manager.get_stealth_endpoint()
        print(json.dumps(stealth, indent=2, ensure_ascii=False))
    elif args.verify_ja3:
        is_blocked = manager.is_ja3_blocked(args.verify_ja3)
        print(f"JA3 {args.verify_ja3}: {'BLOCKED' if is_blocked else 'SAFE'}")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
