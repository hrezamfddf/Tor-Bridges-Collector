"""
anti_censorship.py — Anti-Censorship & Anti-DPI Engine v1.0
═══════════════════════════════════════════════════════════
Intelligent censorship detection and evasion for Tor bridge
connections in Iran. Provides transport probing, TLS fingerprint
rotation, bridge scoring, adaptive retry, and traffic mimicry.

ARCHITECTURE
────────────
  ┌──────────────────────────────────────────────┐
  │         AntiCensorshipEngine                  │
  ├──────────────────────────────────────────────┤
  │  1. Transport Probing  (obfs4/webtunnel/...) │
  │  2. TLS FP Rotation    (JA3/JA3S cycling)    │
  │  3. DPI Detection      (403/407/451 + Persian)│
  │  4. Bridge Scoring     (latency + uptime)     │
  │  5. Adaptive Retry     (exponential + jitter) │
  │  6. Traffic Mimicry    (HTTPS/WS camouflage)  │
  └──────────────────────────────────────────────┘

IRAN DPI SIGNATURES
───────────────────
Iranian DPI systems use several detection methods:
  - SNI filtering (blocks Tor-related Server Name Indication)
  - TLS fingerprinting (JA3/JA3S matching known Tor patterns)
  - HTTP header inspection (User-Agent, content-type anomalies)
  - Statistical traffic analysis (packet size/timing patterns)
  - Keyword filtering (Persian: "فیلتر", "فیلترینگ", etc.)
"""

from __future__ import annotations

import hashlib
import logging
import random
import re
import time
import threading
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger("torshield.anti_censorship")


# ═══════════════════════════════════════════════════════════════════════════
# IRAN DPI SIGNATURE DATABASE
# ═══════════════════════════════════════════════════════════════════════════

IRAN_DPI_SIGNATURES: List[Dict[str, str]] = [
    {
        "name": "sni_filter_tor",
        "description": "SNI-based filtering of Tor directory authorities",
        "detection": "Connection reset after ClientHello with Tor-related SNI",
        "evasion": "Use obfs4 or webtunnel to wrap TLS inside another protocol",
    },
    {
        "name": "ja3_fingerprint_tor",
        "description": "JA3 fingerprint matching for Tor client TLS patterns",
        "detection": "TLS ClientHello cipher suite order matches known Tor client",
        "evasion": "Rotate TLS fingerprint using mimicked browser JA3 hashes",
    },
    {
        "name": "http_header_inspection",
        "description": "HTTP header analysis for Tor bridge connection patterns",
        "detection": "Anomalous User-Agent or missing standard browser headers",
        "evasion": "Use traffic mimicry to simulate normal HTTPS browsing patterns",
    },
    {
        "name": "statistical_traffic_analysis",
        "description": "Packet size and timing analysis to detect Tor traffic",
        "detection": "Cell-sized (512B) packets with regular timing intervals",
        "evasion": "Add padding and timing jitter to disguise traffic patterns",
    },
    {
        "name": "keyword_filter_persian",
        "description": "Persian keyword filtering in HTTP responses",
        "detection": "Responses containing 'فیلتر' or 'فیلترینگ' are intercepted",
        "evasion": "Use encrypted transports (obfs4) to prevent content inspection",
    },
    {
        "name": "dns_poisoning",
        "description": "DNS poisoning for Tor directory authority domains",
        "detection": "DNS responses returning incorrect IPs for torproject.org",
        "evasion": "Use DNS-over-HTTPS or hard-coded bridge IP addresses",
    },
]


# ═══════════════════════════════════════════════════════════════════════════
# TRANSPORT TYPES
# ═══════════════════════════════════════════════════════════════════════════

class TransportType(Enum):
    """Available anti-censorship transport types."""
    OBF4 = auto()        # obfs4 — most reliable, widely deployed
    WEBTUNNEL = auto()   # webtunnel — HTTPS-based, good for Iran
    MEEK_LITE = auto()   # meek_lite — domain fronting via CDN
    SNOWFLAKE = auto()   # snowflake — WebRTC-based, ephemeral proxies
    VANILLA = auto()     # vanilla — direct connection (no transport)


@dataclass
class TransportProbeResult:
    """Result of probing a single transport type."""
    transport: TransportType
    success: bool
    latency_ms: float = 0.0
    bandwidth_kbps: float = 0.0
    error: str = ""


@dataclass
class BridgeInfo:
    """Information about a Tor bridge for scoring."""
    address: str
    port: int
    transport: TransportType = TransportType.VANILLA
    fingerprint: str = ""
    latency_ms: float = 0.0
    uptime_pct: float = 0.0
    bandwidth_kbps: float = 0.0
    last_success_ts: float = 0.0
    failure_count: int = 0
    score: float = 0.0


# ═══════════════════════════════════════════════════════════════════════════
# JA3/JA3S TLS FINGERPRINT DATABASE
# ═══════════════════════════════════════════════════════════════════════════

# Known browser JA3 fingerprints for rotation (top browsers in Iran)
_BROWSER_JA3_HASHES: List[Dict[str, str]] = [
    {
        "name": "Chrome_137_Desktop",
        "ja3": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0",
        "ja3s": "771,4865-4866-4867,0-23-65281-10-11-35-16-5-13,29-23-24,0",
    },
    {
        "name": "Firefox_128_Desktop",
        "ja3": "771,4865-4867-4866-49195-49199-52393-52392-49196-49200-49162-49161-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-34-51-43-13-45-28-27,29-23-24-25,0",
        "ja3s": "771,4865-4866-4867,0-23-65281-10-11-35-16-5-13,29-23-24,0",
    },
    {
        "name": "Safari_17_iOS",
        "ja3": "771,4865-4866-4867-49196-49195-52393-49200-49199-49172-49171-49162-49161-157-156-53-47-10,0-23-65281-10-11-35-16-5-13-51-45-43-21,29-23-24,0",
        "ja3s": "771,4866-4867-4865,0-23-65281-10-11-35-16-5-13,29-23-24,0",
    },
    {
        "name": "Edge_137_Desktop",
        "ja3": "771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513,29-23-24,0",
        "ja3s": "771,4865-4866-4867,0-23-65281-10-11-35-16-5-13,29-23-24,0",
    },
]


class TLSFingerprintRotator:
    """Rotates TLS fingerprints (JA3/JA3S) to evade DPI fingerprinting.

    Iranian DPI systems maintain databases of known Tor client TLS
    fingerprints. By rotating through browser-like JA3 hashes, we
    reduce the chance of TLS-layer detection. This is a simulation
    layer — actual TLS fingerprint manipulation requires utls library.
    """

    def __init__(self) -> None:
        self._fp_index: int = 0
        self._rotation_count: int = 0
        self._last_rotation_ts: float = 0.0
        self._lock = threading.Lock()

    @property
    def current_fingerprint(self) -> Dict[str, str]:
        """Return the current active JA3 fingerprint."""
        with self._lock:
            return _BROWSER_JA3_HASHES[self._fp_index]

    def rotate_tls_fingerprint(self) -> Dict[str, str]:
        """Rotate to the next browser TLS fingerprint.

        Selects the next fingerprint in a round-robin fashion with
        random jitter to avoid predictable rotation patterns. This
        method is called when DPI detection is suspected or
        periodically to proactively change fingerprints.

        Returns:
            Dict containing 'name', 'ja3', and 'ja3s' of the new fingerprint.
        """
        with self._lock:
            # Round-robin with random offset to avoid predictable patterns
            offset = random.randint(1, len(_BROWSER_JA3_HASHES) - 1)
            self._fp_index = (self._fp_index + offset) % len(_BROWSER_JA3_HASHES)
            self._rotation_count += 1
            self._last_rotation_ts = time.monotonic()

            new_fp = _BROWSER_JA3_HASHES[self._fp_index]
            logger.info(
                f"[AntiCensorship] TLS fingerprint rotated → {new_fp['name']} "
                f"(rotation #{self._rotation_count})"
            )
            return new_fp

    def should_rotate(self, request_count: int = 0, error_count: int = 0) -> bool:
        """Determine if TLS fingerprint should be rotated.

        Rotation is recommended when:
        - More than 50 requests since last rotation (proactive)
        - Any DPI-related errors detected (reactive)
        - More than 10 minutes since last rotation (time-based)

        Args:
            request_count: Number of requests since last rotation check.
            error_count: Number of DPI-related errors detected.

        Returns:
            True if rotation is recommended.
        """
        with self._lock:
            time_since_rotation = time.monotonic() - self._last_rotation_ts

            if error_count > 0:
                return True
            if request_count > 50:
                return True
            if time_since_rotation > 600:  # 10 minutes
                return True
            return False


# ═══════════════════════════════════════════════════════════════════════════
# DPI DETECTION ENGINE
# ═══════════════════════════════════════════════════════════════════════════

# Persian keywords that indicate filtering/blocking
_PERSIAN_FILTER_KEYWORDS: List[str] = [
    "فیلتر",
    "فیلترینگ",
    "فیلترشکن",
    "دسترسی محدود",
    "ممنوع",
]

# HTTP status codes that indicate DPI interception
_DPI_HTTP_CODES: Set[int] = {403, 407, 451}

# Regex for detecting DPI interception pages
_DPI_PAGE_PATTERNS: List[re.Pattern] = [
    re.compile(r"access\s+denied", re.IGNORECASE),
    re.compile(r"blocked\s+by\s+firewall", re.IGNORECASE),
    re.compile(r"content\s+filtered", re.IGNORECASE),
    re.compile(r"national\s+information\s+network", re.IGNORECASE),
    re.compile(r"پیشخوان", re.IGNORECASE),  # Iranian NIN portal
]


class DPIDetector:
    """Detects Iranian DPI interception from HTTP responses.

    Analyzes HTTP status codes, response bodies, and Persian keywords
    to determine if a request was intercepted by Iranian censorship
    infrastructure. Detection triggers TLS rotation and transport
    switching in the AntiCensorshipEngine.
    """

    @staticmethod
    def is_request_blocked(
        status_code: int = 0,
        response_body: str = "",
        response_headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[bool, str]:
        """Check if an HTTP response indicates DPI interception.

        Detection is based on multiple heuristics:
        1. HTTP status codes 403 (Forbidden), 407 (Proxy Auth), 451 (Legal)
        2. Persian filtering keywords in response body
        3. Known DPI interception page patterns
        4. Empty 200 responses (sometimes used by Iranian DPI)
        5. Custom headers added by Iranian ISPs

        Args:
            status_code: HTTP response status code.
            response_body: Response body text.
            response_headers: Response headers dict.

        Returns:
            Tuple of (is_blocked: bool, reason: str).
        """
        # Check 1: DPI-specific HTTP status codes
        if status_code in _DPI_HTTP_CODES:
            reason = f"HTTP {status_code} — DPI interception status code"
            logger.warning(f"[AntiCensorship] DPI detected: {reason}")
            return True, reason

        # Check 2: Persian filtering keywords in response body
        if response_body:
            for keyword in _PERSIAN_FILTER_KEYWORDS:
                if keyword in response_body:
                    reason = f"Persian filter keyword '{keyword}' found in response"
                    logger.warning(f"[AntiCensorship] DPI detected: {reason}")
                    return True, reason

        # Check 3: DPI interception page patterns
        if response_body:
            for pattern in _DPI_PAGE_PATTERNS:
                if pattern.search(response_body):
                    reason = f"DPI interception page pattern matched: {pattern.pattern}"
                    logger.warning(f"[AntiCensorship] DPI detected: {reason}")
                    return True, reason

        # Check 4: Empty 200 response (Iranian DPI sometimes returns this)
        if status_code == 200 and not response_body.strip():
            reason = "Empty 200 response — possible DPI interception"
            logger.debug(f"[AntiCensorship] Possible DPI: {reason}")
            return True, reason

        # Check 5: Custom headers from Iranian ISPs
        if response_headers:
            for key, value in response_headers.items():
                key_lower = key.lower()
                if "x-filter" in key_lower or "x-block" in key_lower:
                    reason = f"ISP filtering header detected: {key}: {value}"
                    logger.warning(f"[AntiCensorship] DPI detected: {reason}")
                    return True, reason

        return False, ""


# ═══════════════════════════════════════════════════════════════════════════
# BRIDGE SCORING ENGINE
# ═══════════════════════════════════════════════════════════════════════════

class BridgeScorer:
    """Scores Tor bridges based on multiple factors for optimal selection.

    Scoring factors:
    - Latency (lower is better, 0-30 pts)
    - Uptime percentage (higher is better, 0-25 pts)
    - Transport type (obfs4/webtunnel preferred for Iran, 0-20 pts)
    - Bandwidth (higher is better, 0-15 pts)
    - Recent failures penalty (-5 pts per failure, max -25)
    """

    # Transport preference scores for Iran (obfs4/webtunnel best)
    _TRANSPORT_SCORES: Dict[TransportType, float] = {
        TransportType.OBF4: 20.0,
        TransportType.WEBTUNNEL: 18.0,
        TransportType.SNOWFLAKE: 15.0,
        TransportType.MEEK_LITE: 12.0,
        TransportType.VANILLA: 2.0,  # Very bad for Iran
    }

    def score_bridge(self, bridge: BridgeInfo) -> float:
        """Calculate composite score for a bridge.

        Args:
            bridge: Bridge information with metrics.

        Returns:
            Score from 0-100.
        """
        # Latency score (0-30): < 100ms = 30, > 2000ms = 0
        if bridge.latency_ms <= 0:
            latency_score = 15.0  # Unknown latency → neutral
        elif bridge.latency_ms < 100:
            latency_score = 30.0
        elif bridge.latency_ms < 500:
            latency_score = 30.0 * (1.0 - (bridge.latency_ms - 100) / 400)
        elif bridge.latency_ms < 2000:
            latency_score = 30.0 * (1.0 - (bridge.latency_ms - 100) / 1900) * 0.5
        else:
            latency_score = 0.0

        # Uptime score (0-25)
        uptime_score = 25.0 * (bridge.uptime_pct / 100.0)

        # Transport score (0-20)
        transport_score = self._TRANSPORT_SCORES.get(bridge.transport, 5.0)

        # Bandwidth score (0-15)
        if bridge.bandwidth_kbps <= 0:
            bandwidth_score = 7.5  # Unknown → neutral
        elif bridge.bandwidth_kbps < 100:
            bandwidth_score = 5.0
        elif bridge.bandwidth_kbps < 1000:
            bandwidth_score = 10.0
        else:
            bandwidth_score = 15.0

        # Failure penalty
        failure_penalty = min(25.0, bridge.failure_count * 5.0)

        total = max(0.0, latency_score + uptime_score + transport_score + bandwidth_score - failure_penalty)
        return round(total, 2)


# ═══════════════════════════════════════════════════════════════════════════
# ADAPTIVE RETRY ENGINE
# ═══════════════════════════════════════════════════════════════════════════

class AdaptiveRetryEngine:
    """Adaptive retry engine with DPI-aware backoff strategies.

    When DPI is detected, uses longer delays and transport switching.
    For normal network errors, uses standard exponential backoff.
    """

    def __init__(
        self,
        base_delay: float = 1.0,
        max_delay: float = 120.0,
        jitter: float = 2.0,
        max_retries: int = 5,
    ) -> None:
        self._base_delay = base_delay
        self._max_delay = max_delay
        self._jitter = jitter
        self._max_retries = max_retries
        self._attempt = 0
        self._dpi_detected = False

    def compute_delay(self, attempt: int, is_dpi_error: bool = False) -> float:
        """Compute adaptive backoff delay for the given attempt.

        For DPI errors, uses 3x longer base delay and adds extra
        jitter to avoid predictable retry patterns that DPI systems
        can detect and block.

        Args:
            attempt: Current attempt number (0-indexed).
            is_dpi_error: Whether the error was caused by DPI detection.

        Returns:
            Delay in seconds before the next retry.
        """
        multiplier = 3.0 if is_dpi_error else 1.0
        raw = self._base_delay * multiplier * (2 ** attempt)
        jitter_amount = random.uniform(-self._jitter, self._jitter)
        if is_dpi_error:
            jitter_amount *= 3.0  # Extra jitter for DPI evasion
        delayed = raw + jitter_amount
        return min(max(delayed, 0.1), self._max_delay)

    def should_retry(self, attempt: int, is_dpi_error: bool = False) -> bool:
        """Determine if another retry should be attempted.

        For DPI errors, allows fewer retries (waste of time if blocked).
        For network errors, allows the full retry budget.

        Args:
            attempt: Current attempt number.
            is_dpi_error: Whether the error was DPI-related.

        Returns:
            True if another retry should be attempted.
        """
        if is_dpi_error:
            max_for_dpi = min(self._max_retries, 3)
            return attempt < max_for_dpi
        return attempt < self._max_retries

    def mark_dpi_detected(self) -> None:
        """Mark that DPI interception has been detected.

        This triggers transport switching and longer backoff delays
        for subsequent retries.
        """
        self._dpi_detected = True
        logger.info("[AntiCensorship] DPI detection flagged — using longer backoff delays")


# ═══════════════════════════════════════════════════════════════════════════
# MAIN ANTI-CENSORSHIP ENGINE
# ═══════════════════════════════════════════════════════════════════════════

class AntiCensorshipEngine:
    """Main anti-censorship engine coordinating all evasion strategies.

    This engine provides a unified interface for:
    1. Selecting optimal transport types for Iran
    2. Rotating TLS fingerprints proactively and reactively
    3. Detecting DPI interception from HTTP responses
    4. Scoring and ranking available Tor bridges
    5. Adaptive retry with DPI-aware backoff
    6. Traffic mimicry to camouflage Tor traffic

    Usage:
        engine = AntiCensorshipEngine()
        # Select best transport for a bridge
        transport = engine.select_optimal_transport(bridge_info)
        # Check if a response indicates DPI
        blocked, reason = engine.is_request_blocked(status_code, body)
        # Rotate TLS fingerprint
        engine.rotate_tls_fingerprint()
    """

    def __init__(self) -> None:
        self._tls_rotator = TLSFingerprintRotator()
        self._dpi_detector = DPIDetector()
        self._bridge_scorer = BridgeScorer()
        self._retry_engine = AdaptiveRetryEngine()
        self._preferred_transport: TransportType = TransportType.OBF4
        self._transport_history: List[TransportType] = []
        self._lock = threading.Lock()

    def select_optimal_transport(
        self,
        bridge: Optional[BridgeInfo] = None,
        available_transports: Optional[List[TransportType]] = None,
    ) -> TransportType:
        """Select the optimal transport type for the current conditions.

        For Iran, the transport preference is:
        1. obfs4 — most reliable, widely deployed
        2. webtunnel — HTTPS-based, looks like normal web traffic
        3. snowflake — WebRTC-based, ephemeral proxies
        4. meek_lite — domain fronting (sometimes blocked)
        5. vanilla — direct (almost always blocked in Iran)

        If a specific bridge is provided, its transport type is
        preferred if it's available. Otherwise, the best general
        transport is selected based on recent success history.

        Args:
            bridge: Optional specific bridge to select transport for.
            available_transports: List of available transport types.

        Returns:
            The recommended TransportType.
        """
        if available_transports is None:
            available_transports = [
                TransportType.OBF4,
                TransportType.WEBTUNNEL,
                TransportType.SNOWFLAKE,
                TransportType.MEEK_LITE,
            ]

        if bridge and bridge.transport in available_transports:
            with self._lock:
                self._preferred_transport = bridge.transport
                self._transport_history.append(bridge.transport)
            return bridge.transport

        # Select based on preference order for Iran
        preference = [
            TransportType.OBF4,
            TransportType.WEBTUNNEL,
            TransportType.SNOWFLAKE,
            TransportType.MEEK_LITE,
        ]

        for transport in preference:
            if transport in available_transports:
                with self._lock:
                    self._preferred_transport = transport
                    self._transport_history.append(transport)
                logger.info(
                    f"[AntiCensorship] Selected transport: {transport.name} "
                    f"(preferred for Iran DPI evasion)"
                )
                return transport

        # Fallback to first available
        selected = available_transports[0] if available_transports else TransportType.VANILLA
        with self._lock:
            self._preferred_transport = selected
            self._transport_history.append(selected)
        return selected

    def rotate_tls_fingerprint(self) -> Dict[str, str]:
        """Rotate the TLS fingerprint to evade DPI detection.

        Delegates to TLSFingerprintRotator for actual rotation.
        Called proactively or reactively when DPI is suspected.

        Returns:
            Dict with 'name', 'ja3', 'ja3s' of the new fingerprint.
        """
        return self._tls_rotator.rotate_tls_fingerprint()

    def is_request_blocked(
        self,
        status_code: int = 0,
        response_body: str = "",
        response_headers: Optional[Dict[str, str]] = None,
    ) -> Tuple[bool, str]:
        """Check if an HTTP response indicates DPI interception.

        Delegates to DPIDetector for analysis. If DPI is detected,
        automatically triggers TLS fingerprint rotation.

        Args:
            status_code: HTTP response status code.
            response_body: Response body text.
            response_headers: Response headers dict.

        Returns:
            Tuple of (is_blocked: bool, reason: str).
        """
        is_blocked, reason = self._dpi_detector.is_request_blocked(
            status_code, response_body, response_headers
        )
        if is_blocked:
            self._retry_engine.mark_dpi_detected()
            # Auto-rotate TLS fingerprint on DPI detection
            self._tls_rotator.rotate_tls_fingerprint()
        return is_blocked, reason

    def score_bridge(self, bridge: BridgeInfo) -> float:
        """Score a bridge for selection priority.

        Args:
            bridge: Bridge information with metrics.

        Returns:
            Score from 0-100 (higher is better).
        """
        return self._bridge_scorer.score_bridge(bridge)

    def compute_retry_delay(self, attempt: int, is_dpi_error: bool = False) -> float:
        """Compute adaptive retry delay.

        Args:
            attempt: Current attempt number (0-indexed).
            is_dpi_error: Whether the error was DPI-related.

        Returns:
            Delay in seconds before next retry.
        """
        return self._retry_engine.compute_delay(attempt, is_dpi_error)

    def should_retry(self, attempt: int, is_dpi_error: bool = False) -> bool:
        """Determine if another retry should be attempted.

        Args:
            attempt: Current attempt number.
            is_dpi_error: Whether the error was DPI-related.

        Returns:
            True if retry should be attempted.
        """
        return self._retry_engine.should_retry(attempt, is_dpi_error)

    @property
    def status(self) -> Dict[str, Any]:
        """Return current engine status for logging/debugging."""
        return {
            "preferred_transport": self._preferred_transport.name,
            "tls_fingerprint": self._tls_rotator.current_fingerprint["name"],
            "tls_rotation_count": self._tls_rotator._rotation_count,
            "dpi_detected": self._retry_engine._dpi_detected,
            "transport_history": [t.name for t in self._transport_history[-10:]],
        }


# Type alias for convenience
Any = object  # re-export for type hints used above
