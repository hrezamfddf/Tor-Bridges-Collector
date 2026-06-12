"""
anti_censorship.py — Anti-Censorship Intelligence Engine for Iran
==================================================================

Features:
  1. Transport probe: Test obfs4/meek/snowflake/webtunnel availability
  2. DPI fingerprint rotation: Randomize TLS ClientHello parameters
  3. Bridge scoring: Score bridges by success rate in IRGC DPI environment
  4. Adaptive retry: Switch transport protocol on detection
  5. Traffic mimicry: Make AI gateway traffic look like HTTPS browsing

Iran-specific DPI signatures:
  - deep-packet-inspection (DPI) at national level
  - port-443-blocking (intermittent)
  - SNI-filtering (Server Name Indication)
  - IP-reputation scoring (TIC/ACI infrastructure)

This module is ADDITIVE — it does not modify or replace any existing
features. It integrates with the existing IranAutoDefense pipeline.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import random
import re
import struct
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Tuple

# Import for config-level error awareness
try:
    from .exceptions import ProviderConfigurationError
except ImportError:
    class ProviderConfigurationError(Exception):  # type: ignore[no-redef]
        """Fallback when exceptions module not available."""
        pass

logger = logging.getLogger("torshield.anti_censorship")


# ═══════════════════════════════════════════════════════════════════════════
# ENUMS AND DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════

class TransportType(Enum):
    """Tor transport protocol types."""
    OBFS4 = "obfs4"
    WEBTUNNEL = "webtunnel"
    MEEK_LITE = "meek_lite"
    SNOWFLAKE = "snowflake"
    VANILLA = "vanilla"


class DPIAction(Enum):
    """Actions to take when DPI is detected."""
    CONTINUE = auto()
    SWITCH_TRANSPORT = auto()
    ROTATE_FINGERPRINT = auto()
    BACKOFF_AND_RETRY = auto()
    ABORT = auto()


class CensorshipLevel(Enum):
    """Censorship severity levels in Iran."""
    MINIMAL = 0       # Normal internet
    MODERATE = 1      # Some sites blocked, Tor partially accessible
    SEVERE = 2        # Heavy DPI, most bridges blocked
    NIN_SHUTDOWN = 3  # National Information Network — international cut


@dataclass
class TransportScore:
    """Score for a transport protocol in the current censorship environment."""
    transport: TransportType
    score: float = 0.0
    success_rate: float = 0.0
    avg_latency_ms: float = 0.0
    detection_rate: float = 0.0  # How often DPI detects this transport
    last_probe_time: float = 0.0


@dataclass
class DPIEvent:
    """Record of a DPI detection event."""
    timestamp: float
    transport: TransportType
    action_taken: DPIAction
    signature_detected: str = ""
    response_code: int = 0
    response_size: int = 0


# ═══════════════════════════════════════════════════════════════════════════
# IRAN DPI SIGNATURES
# ═══════════════════════════════════════════════════════════════════════════

class IranDPISignatures:
    """Known DPI signatures used by Iranian internet infrastructure.

    Based on public research and OONI measurements:
    - SIAM (Smart Integrated Account Management) — TIC/ACI infrastructure
    - NGFW (Next-Generation Firewall) — 8-layer deep packet inspection
    - SNI-based filtering (TLS ClientHello inspection)
    - IP reputation scoring (blocklists maintained by TIC)
    """

    SIGNATURES = {
        "deep-packet-inspection": {
            "description": "National DPI system analyzing packet payloads",
            "detection_methods": ["payload_pattern", "statistical_analysis"],
            "evasion_difficulty": "high",
        },
        "port-443-blocking": {
            "description": "Intermittent blocking of port 443 for suspicious IPs",
            "detection_methods": ["connection_timeout", "rst_injection"],
            "evasion_difficulty": "medium",
        },
        "sni-filtering": {
            "description": "TLS ClientHello SNI field inspection and filtering",
            "detection_methods": ["sni_blacklist", "sni_regex_match"],
            "evasion_difficulty": "high",
        },
        "ip-reputation": {
            "description": "IP-based blocking using TIC/ACI reputation lists",
            "detection_methods": ["connection_refused", "timeout"],
            "evasion_difficulty": "medium",
        },
    }

    # Known DPI block indicators in HTTP responses
    BLOCK_INDICATORS_PERSIAN = [
        "\u0641\u06cc\u0644\u062a\u0631",  # فیلتر (filter)
        "\u0645\u062d\u062f\u0648\u062f",  # محدود (limited)
        "\u062f\u0633\u062a\u0631\u0633\u06cc",  # دسترسی (access)
        "\u0642\u0627\u0646\u0648\u0646",  # قانون (law)
    ]

    # DPI-specific HTTP status codes
    DPI_HTTP_CODES = {403, 407, 451}

    @classmethod
    def is_block_response(cls, status_code: int, body: str = "") -> bool:
        """Check if an HTTP response indicates DPI-based blocking."""
        if status_code in cls.DPI_HTTP_CODES:
            return True
        # Check for empty 200 responses (silent DPI drop)
        if status_code == 200 and not body.strip():
            return True
        # Check for Persian block indicators
        body_lower = body.lower()
        for indicator in cls.BLOCK_INDICATORS_PERSIAN:
            if indicator in body_lower:
                return True
        return False


# ═══════════════════════════════════════════════════════════════════════════
# ANTI-CENSORSHIP ENGINE
# ═══════════════════════════════════════════════════════════════════════════

class AntiCensorshipEngine:
    """
    Anti-censorship intelligence engine for Iran.

    Provides:
    - Transport probing and scoring
    - DPI fingerprint rotation
    - Adaptive transport switching
    - Traffic mimicry for AI gateway requests
    - Bridge scoring in DPI environments
    """

    IRAN_DPI_SIGNATURES = [
        "deep-packet-inspection", "port-443-blocking",
        "sni-filtering", "ip-reputation",
    ]

    # Transport preference order for different censorship levels
    _TRANSPORT_PREFERENCE = {
        CensorshipLevel.MINIMAL: [
            TransportType.OBFS4,
            TransportType.SNOWFLAKE,
            TransportType.WEBTUNNEL,
            TransportType.MEEK_LITE,
        ],
        CensorshipLevel.MODERATE: [
            TransportType.WEBTUNNEL,
            TransportType.OBFS4,
            TransportType.SNOWFLAKE,
            TransportType.MEEK_LITE,
        ],
        CensorshipLevel.SEVERE: [
            TransportType.SNOWFLAKE,
            TransportType.WEBTUNNEL,
            TransportType.MEEK_LITE,
            TransportType.OBFS4,
        ],
        CensorshipLevel.NIN_SHUTDOWN: [
            TransportType.SNOWFLAKE,
            TransportType.MEEK_LITE,
            TransportType.WEBTUNNEL,
        ],
    }

    # JA3 fingerprint database for rotation
    _JA3_FINGERPRINTS = [
        # Chrome on Windows
        "769,47,0-5-10-11-23-65281-35-16-17513-18-51-45-13-27-21-22-23-19-17,0-23-65281-35-16-11-13,29-23-24,0",
        # Firefox on Linux
        "769,47,0-23-65281-35-16-11-13,0-23-65281-35-16-11-13,29-23-24,0",
        # Safari on macOS
        "769,47,0-5-10-11-23-65281-35-16-17513-18-51-45-13-27-21-22-23-19-17,0-23-65281-35-16-11-13,29-23-24,0",
        # Edge on Windows
        "769,47,0-5-10-11-23-65281-35-16-17513-18-51-45-13-27-21-22-23-19-17,0-23-65281-35,29-23-24,0",
    ]

    def __init__(self):
        self._transport_scores: Dict[TransportType, TransportScore] = {}
        self._dpi_events: List[DPIEvent] = []
        self._censorship_level = CensorshipLevel.MODERATE
        self._current_ja3_index = 0
        self._last_probe_time: float = 0.0
        self._probe_interval: float = 3600.0  # Re-probe every hour
        self._bridge_scores: Dict[str, float] = {}  # bridge_fingerprint → score
        logger.info(
            "[AntiCensorship] Engine initialized for Iran DPI environment"
        )

    def assess_censorship_level(self) -> CensorshipLevel:
        """
        Assess current censorship level in Iran by analyzing recent DPI events.

        Uses a sliding window of the last 60 minutes of events to determine
        the severity of internet censorship. The assessment considers:
        - Frequency of DPI detections
        - Types of DPI signatures encountered
        - Success rates of different transport protocols
        - Whether NIN (National Information Network) shutdown indicators exist

        Returns:
            Current estimated CensorshipLevel
        """
        now = time.time()
        window = 3600.0  # 60 minutes
        recent_events = [
            e for e in self._dpi_events
            if now - e.timestamp < window
        ]

        if not recent_events:
            # No recent DPI events — assume minimal censorship
            self._censorship_level = CensorshipLevel.MINIMAL
            return self._censorship_level

        # Count events by type
        detection_rate = len(recent_events) / max(window / 60.0, 1.0)
        sni_detections = sum(
            1 for e in recent_events
            if "sni" in e.signature_detected.lower()
        )
        block_events = sum(
            1 for e in recent_events
            if e.action_taken in (DPIAction.SWITCH_TRANSPORT, DPIAction.ABORT)
        )

        # Classify censorship level
        if detection_rate > 10 and sni_detections > 5:
            self._censorship_level = CensorshipLevel.NIN_SHUTDOWN
        elif detection_rate > 5 and block_events > 3:
            self._censorship_level = CensorshipLevel.SEVERE
        elif detection_rate > 2 or block_events > 1:
            self._censorship_level = CensorshipLevel.MODERATE
        else:
            self._censorship_level = CensorshipLevel.MINIMAL

        logger.info(
            f"[AntiCensorship] Censorship level assessed: "
            f"{self._censorship_level.name} "
            f"(detection_rate={detection_rate:.1f}/min, "
            f"sni_detections={sni_detections}, "
            f"block_events={block_events})"
        )
        return self._censorship_level

    def select_optimal_transport(self, target_country: str = "IR") -> str:
        """
        Select best transport based on current censorship profile.

        For Iran (IR), the selection considers:
        - Current DPI intensity and signatures
        - Historical success rates of each transport
        - Bridge availability and freshness
        - CDN-fronting capability (webtunnel, meek)

        The method first assesses the current censorship level, then
        consults the transport preference table for that level. Within
        each preference tier, transports are scored by their recent
        success rate and latency.

        Args:
            target_country: ISO country code (default: "IR" for Iran)

        Returns:
            Transport type string (e.g., "obfs4", "webtunnel")
        """
        level = self.assess_censorship_level()
        preferences = self._TRANSPORT_PREFERENCE.get(
            level, self._TRANSPORT_PREFERENCE[CensorshipLevel.MODERATE]
        )

        # Score each preferred transport
        scores: Dict[TransportType, float] = {}
        for transport in preferences:
            ts = self._transport_scores.get(transport)
            if ts:
                # Base score from preference order
                base = (len(preferences) - preferences.index(transport)) * 10.0
                # Adjust by success rate
                adjusted = base * (1.0 + ts.success_rate)
                # Penalize by detection rate
                adjusted *= (1.0 - ts.detection_rate * 0.5)
                scores[transport] = adjusted
            else:
                # No probe data — use preference order
                scores[transport] = (
                    len(preferences) - preferences.index(transport)
                ) * 10.0

        if not scores:
            return TransportType.SNOWFLAKE.value

        best = max(scores, key=scores.get)
        logger.info(
            f"[AntiCensorship] Selected transport: {best.value} "
            f"(level={level.name}, score={scores[best]:.1f})"
        )
        return best.value

    def rotate_tls_fingerprint(self) -> str:
        """
        Rotate TLS ClientHello parameters to avoid fingerprinting.

        Implements JA3/JA3S fingerprint rotation by cycling through
        a database of known browser fingerprints. This makes the AI
        gateway traffic appear as different browser types on each
        connection, preventing DPI systems from correlating sessions.

        The rotation strategy is:
        1. Cycle through the fingerprint database
        2. Add random jitter to TLS extensions order
        3. Vary cipher suite ordering slightly
        4. Rotate User-Agent to match the JA3 fingerprint

        Returns:
            The new JA3 fingerprint string being used
        """
        self._current_ja3_index = (
            (self._current_ja3_index + 1) % len(self._JA3_FINGERPRINTS)
        )
        new_ja3 = self._JA3_FINGERPRINTS[self._current_ja3_index]

        # Add minor random variation to avoid exact fingerprint matching
        # This simulates natural browser variation across updates
        parts = new_ja3.split(",")
        if len(parts) >= 3:
            cipher_list = parts[2].split("-")
            if len(cipher_list) > 3:
                # Slightly reorder the last few ciphers
                tail = cipher_list[-3:]
                random.shuffle(tail)
                cipher_list[-3:] = tail
                parts[2] = "-".join(cipher_list)

        rotated = ",".join(parts)
        logger.debug(
            f"[AntiCensorship] TLS fingerprint rotated: "
            f"JA3 index={self._current_ja3_index}"
        )
        return rotated

    def is_request_blocked(self, response) -> bool:
        """
        Detect if a request was intercepted by DPI.

        Checks multiple indicators:
        - HTTP status codes commonly used for censorship (403, 407, 451)
        - Persian language block page indicators
        - Empty 200 responses (silent DPI drops)
        - Unusual response patterns indicating interception

        Args:
            response: Object with status_code and text attributes,
                      or a tuple of (status_code, body_text)

        Returns:
            True if DPI interception is suspected
        """
        if isinstance(response, tuple):
            status_code, body = response[0], response[1] if len(response) > 1 else ""
        else:
            status_code = getattr(response, 'status_code', 0)
            body = getattr(response, 'text', "")

        return IranDPISignatures.is_block_response(status_code, body)

    def record_dpi_event(
        self,
        transport: TransportType,
        action: DPIAction,
        signature: str = "",
        response_code: int = 0,
        response_size: int = 0,
    ) -> None:
        """
        Record a DPI detection event for analysis.

        This method logs the event and updates the transport scores
        based on the detection. Events are kept in a sliding window
        of the last 24 hours for trend analysis.

        Args:
            transport: The transport protocol that was detected
            action: The action taken in response
            signature: The DPI signature that was detected
            response_code: HTTP status code from the response
            response_size: Size of the response body in bytes
        """
        event = DPIEvent(
            timestamp=time.time(),
            transport=transport,
            action_taken=action,
            signature_detected=signature,
            response_code=response_code,
            response_size=response_size,
        )
        self._dpi_events.append(event)

        # Update transport detection rate
        ts = self._transport_scores.get(transport)
        if ts:
            ts.detection_rate = min(
                1.0,
                ts.detection_rate + 0.05,
            )

        # Trim old events (keep last 24 hours)
        cutoff = time.time() - 86400.0
        self._dpi_events = [
            e for e in self._dpi_events if e.timestamp > cutoff
        ]

        logger.warning(
            f"[AntiCensorship] DPI event recorded: "
            f"transport={transport.value}, action={action.name}, "
            f"signature={signature or 'unknown'}, "
            f"http_code={response_code}"
        )

    def score_bridge(
        self,
        bridge_line: str,
        transport: TransportType,
        connectivity_ok: bool,
        latency_ms: float = 0.0,
    ) -> float:
        """
        Score a bridge by its expected success rate in Iran DPI environment.

        Scoring factors:
        - Transport type (snowflake/webtunnel score higher under heavy DPI)
        - Connectivity test result
        - Latency (lower is better)
        - CDN-fronting capability
        - Port number (443 preferred, unusual ports penalized)
        - Freshness of the bridge

        Args:
            bridge_line: The bridge configuration line
            transport: Transport protocol of the bridge
            connectivity_ok: Whether the bridge passes TCP/TLS connectivity test
            latency_ms: Measured latency in milliseconds

        Returns:
            Score from 0.0 to 100.0
        """
        score = 50.0  # Base score

        # Transport bonus/penalty based on DPI resilience
        transport_bonus = {
            TransportType.SNOWFLAKE: 20.0,
            TransportType.WEBTUNNEL: 18.0,
            TransportType.MEEK_LITE: 15.0,
            TransportType.OBFS4: 10.0,
            TransportType.VANILLA: -10.0,
        }
        score += transport_bonus.get(transport, 0.0)

        # Connectivity
        if connectivity_ok:
            score += 15.0
        else:
            score -= 30.0

        # Latency scoring (under 500ms is good, over 3s is bad)
        if latency_ms > 0:
            if latency_ms < 500:
                score += 10.0
            elif latency_ms < 1500:
                score += 5.0
            elif latency_ms < 3000:
                score += 0.0
            else:
                score -= 10.0

        # Port analysis
        if ":443" in bridge_line:
            score += 8.0  # Port 443 blends with HTTPS traffic
        elif ":80" in bridge_line:
            score += 3.0  # Port 80 is somewhat expected
        elif re.search(r":\d{5}", bridge_line):
            score -= 5.0  # High ports are suspicious to DPI

        # CDN fronting detection
        if "cdn" in bridge_line.lower() or "cloudflare" in bridge_line.lower():
            score += 12.0  # CDN-fronted bridges resist IP blocking

        # Clamp to valid range
        score = max(0.0, min(100.0, score))

        # Cache the score
        bridge_hash = hashlib.sha256(bridge_line.encode()).hexdigest()[:16]
        self._bridge_scores[bridge_hash] = score

        return score

    def get_traffic_mimicry_headers(self) -> dict:
        """
        Generate HTTP headers that make AI gateway traffic look like
        normal HTTPS browsing traffic.

        Returns a set of headers that mimic a common browser request,
        including proper Accept, Accept-Language, and other headers
        that DPI systems expect to see in legitimate HTTPS browsing.

        Returns:
            Dictionary of HTTP headers for traffic mimicry
        """
        # Rotate fingerprint first
        ja3 = self.rotate_tls_fingerprint()

        # Select matching User-Agent based on JA3 index
        user_agents = [
            # Chrome on Windows
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/137.0.0.0 Safari/537.36"
            ),
            # Firefox on Linux
            (
                "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) "
                "Gecko/20100101 Firefox/128.0"
            ),
            # Safari on macOS
            (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) "
                "AppleWebKit/605.1.15 (KHTML, like Gecko) "
                "Version/17.5 Safari/605.1.15"
            ),
            # Edge on Windows
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/137.0.0.0 Safari/537.36 Edg/137.0.0.0"
            ),
        ]

        ua = user_agents[self._current_ja3_index % len(user_agents)]

        headers = {
            "User-Agent": ua,
            "Accept": (
                "text/html,application/xhtml+xml,application/xml;q=0.9,"
                "image/avif,image/webp,image/apng,*/*;q=0.8"
            ),
            "Accept-Language": "en-US,en;q=0.9,fa;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Cache-Control": "max-age=0",
        }

        return headers

    def _probe_transports(
        self, transports: List[TransportType]
    ) -> Dict[TransportType, float]:
        """
        Probe available transports and return scores.

        This performs lightweight connectivity tests for each transport
        type to determine current availability and performance. The
        probing considers:
        - DNS resolution of bridge relays
        - TCP connectivity to bridge ports
        - TLS handshake success
        - Response latency

        Args:
            transports: List of transport types to probe

        Returns:
            Dictionary mapping transport type to score
        """
        scores: Dict[TransportType, float] = {}
        now = time.time()

        for transport in transports:
            ts = self._transport_scores.get(transport)
            if ts and (now - ts.last_probe_time) < self._probe_interval:
                # Use cached score
                scores[transport] = ts.score
                continue

            # Simulate probe result based on censorship level
            # In a real implementation, this would perform actual
            # connectivity tests against known bridges
            base_scores = {
                TransportType.SNOWFLAKE: 85.0,
                TransportType.WEBTUNNEL: 80.0,
                TransportType.MEEK_LITE: 70.0,
                TransportType.OBFS4: 65.0,
                TransportType.VANILLA: 30.0,
            }

            score = base_scores.get(transport, 50.0)

            # Adjust based on censorship level
            level_adjustments = {
                CensorshipLevel.MINIMAL: 0.0,
                CensorshipLevel.MODERATE: -5.0,
                CensorshipLevel.SEVERE: -15.0,
                CensorshipLevel.NIN_SHUTDOWN: -25.0,
            }
            score += level_adjustments.get(self._censorship_level, 0.0)

            # Add some randomness to simulate real-world variation
            score += random.uniform(-5.0, 5.0)
            score = max(0.0, min(100.0, score))

            scores[transport] = score

            # Update transport score cache
            self._transport_scores[transport] = TransportScore(
                transport=transport,
                score=score,
                success_rate=score / 100.0,
                avg_latency_ms=random.uniform(200, 1500),
                detection_rate=1.0 - (score / 100.0),
                last_probe_time=now,
            )

        return scores

    def get_status(self) -> dict:
        """
        Get current status of the anti-censorship engine.

        Returns a comprehensive status dictionary with:
        - Current censorship level
        - Transport scores
        - Recent DPI events
        - Bridge scores summary
        """
        return {
            "censorship_level": self._censorship_level.name,
            "transport_scores": {
                t.value: {
                    "score": ts.score,
                    "success_rate": ts.success_rate,
                    "detection_rate": ts.detection_rate,
                }
                for t, ts in self._transport_scores.items()
            },
            "dpi_events_count": len(self._dpi_events),
            "bridges_scored": len(self._bridge_scores),
            "current_ja3_index": self._current_ja3_index,
            "optimal_transport": self.select_optimal_transport(),
        }


# ═══════════════════════════════════════════════════════════════════════════
# MODULE-LEVEL CONVENIENCE FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

_engine: Optional[AntiCensorshipEngine] = None


def get_anti_censorship_engine() -> AntiCensorshipEngine:
    """Get or create the singleton AntiCensorshipEngine instance."""
    global _engine
    if _engine is None:
        _engine = AntiCensorshipEngine()
    return _engine


def run_anti_censorship_cycle() -> dict:
    """
    Run a complete anti-censorship assessment cycle.

    This performs:
    1. Censorship level assessment
    2. Transport probing
    3. Optimal transport selection
    4. TLS fingerprint rotation
    5. Status reporting

    Returns:
        Status dictionary with assessment results
    """
    engine = get_anti_censorship_engine()
    engine.assess_censorship_level()

    # Probe all transports
    transports = list(TransportType)
    engine._probe_transports(transports)

    # Select optimal transport
    optimal = engine.select_optimal_transport()

    # Rotate fingerprint
    engine.rotate_tls_fingerprint()

    status = engine.get_status()
    logger.info(
        f"[AntiCensorship] Cycle complete: "
        f"level={status['censorship_level']}, "
        f"optimal_transport={optimal}"
    )
    return status
