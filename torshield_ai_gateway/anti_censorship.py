"""
Anti-DPI and anti-censorship layer for Iranian network filtering.
Uses Tor Pluggable Transports + AI-driven traffic shaping.

v1.0 — FG-DS-DDH Edition

ARCHITECTURE:
  ┌──────────────────────────────────────────────────────────┐
  │  AntiDPIEngine                                           │
  │  ┌────────────────┐  ┌─────────────────────────────────┐│
  │  │ Traffic Profiles│  │ AI Adaptation Engine            ││
  │  │ • telegram      │  │ • Detection history tracking    ││
  │  │ • instagram     │  │ • Auto-switch profiles          ││
  │  │ • https_generic │  │ • Pattern avoidance             ││
  │  └────────────────┘  └─────────────────────────────────┘│
  └──────────────────────────────────────────────────────────┘

  ┌──────────────────────────────────────────────────────────┐
  │  SmartBridgeSelector                                     │
  │  ┌─────────────────────┐  ┌────────────────────────────┐│
  │  │ Transport Priority   │  │ Success Rate Tracker       ││
  │  │ 1. snowflake         │  │ • EMA per transport        ││
  │  │ 2. meek_azure        │  │ • Auto-block detection     ││
  │  │ 3. obfs4             │  │ • Reset on full block      ││
  │  │ 4. webtunnel         │  │                            ││
  │  │ 5. vanilla           │  │                            ││
  │  └─────────────────────┘  └────────────────────────────┘│
  └──────────────────────────────────────────────────────────┘

IRAN DPI CONTEXT:
  Iran uses a multi-layered DPI system (SIAM/NGFW) that:
  - Performs deep packet inspection on all HTTPS traffic
  - Blocks known Tor ports (9001, 9030, 9050)
  - Detects Tor handshake patterns via timing analysis
  - Uses machine learning to classify encrypted traffic
  - Implements SNI-based filtering for TLS connections

  This module provides countermeasures:
  - Traffic morphing to mimic popular services (Telegram, Instagram)
  - Timing jitter to defeat statistical analysis
  - Intelligent bridge selection based on real-world success rates
  - Automatic profile switching when detection is suspected
"""
import asyncio
import random
import time
import logging
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Callable, Awaitable

logger = logging.getLogger("torshield.anti_censorship")

# ═══════════════════════════════════════════════════════════════════════════
# IRAN DPI FINGERPRINT PATTERNS TO AVOID
# ═══════════════════════════════════════════════════════════════════════════

IRAN_DPI_PATTERNS = {
    "packet_size_threshold": 1500,     # MTU-level inspection
    "timing_patterns": [0.1, 0.3],     # detected intervals (seconds)
    "header_signatures": [             # blocked header patterns
        "X-Tor-Stream",
        "X-Bridge-Request",
    ],
    "port_blacklist": [9001, 9030, 9050],  # known Tor ports
}


@dataclass
class TrafficProfile:
    """Mimics normal HTTPS traffic to fool DPI.

    Each profile models the traffic characteristics of a popular service
    that is allowed through Iran's filtering system. By mimicking these
    patterns, Tor bridge traffic becomes indistinguishable from legitimate
    service traffic to the DPI system.

    Attributes:
        name: Profile identifier (e.g., 'telegram', 'instagram')
        avg_packet_size: Average packet size in bytes
        timing_jitter: Variance in inter-packet timing (seconds)
        burst_pattern: Packet count per burst (models request/response behavior)
    """
    name: str
    avg_packet_size: int     # bytes
    timing_jitter: float     # seconds variance
    burst_pattern: list      # packet count per burst


# Traffic profiles modeled after popular services that are allowed in Iran.
# These services have distinctive traffic patterns that DPI systems expect
# to see. By mimicking these patterns, we can evade DPI detection.
PROFILES: Dict[str, TrafficProfile] = {
    "telegram": TrafficProfile(
        name="telegram",
        avg_packet_size=512,
        timing_jitter=0.05,
        burst_pattern=[3, 1, 4, 1, 5],
    ),
    "instagram": TrafficProfile(
        name="instagram",
        avg_packet_size=1024,
        timing_jitter=0.1,
        burst_pattern=[5, 2, 8, 1],
    ),
    "https_generic": TrafficProfile(
        name="https_generic",
        avg_packet_size=800,
        timing_jitter=0.08,
        burst_pattern=[2, 2, 2, 2],
    ),
    "whatsapp": TrafficProfile(
        name="whatsapp",
        avg_packet_size=640,
        timing_jitter=0.06,
        burst_pattern=[4, 1, 3, 2],
    ),
    "google_services": TrafficProfile(
        name="google_services",
        avg_packet_size=1200,
        timing_jitter=0.04,
        burst_pattern=[6, 3, 2, 1],
    ),
}


class AntiDPIEngine:
    """AI-driven Deep Packet Inspection bypass engine.

    Automatically adapts to Iran's filtering patterns by:
    1. Morphing traffic to mimic allowed services
    2. Adding timing jitter to defeat statistical analysis
    3. Monitoring for detection events
    4. Switching traffic profiles when detection rate is high

    The engine maintains a history of detection events and uses this
    information to adapt its strategy. If too many detections occur
    within a 5-minute window, it automatically switches to a different
    traffic profile to evade the DPI system's pattern matching.

    Usage:
        engine = AntiDPIEngine(profile="https_generic")
        chunks = engine.obfuscate_request(payload)
        success = await engine.send_with_timing(chunks, send_fn)
    """

    def __init__(self, profile: str = "https_generic"):
        self.profile = PROFILES.get(profile, PROFILES["https_generic"])
        self.detection_history: List[Dict] = []
        self.current_strategy = "normal"
        self._detection_count = 0
        self._profile_switch_count = 0

    def obfuscate_request(self, payload: bytes) -> List[bytes]:
        """Split payload into chunks that mimic normal HTTPS traffic.

        Prevents Iran's DPI from identifying Tor/bridge patterns by
        splitting the payload into variable-size chunks that match
        the current traffic profile's burst pattern and packet sizes.

        The chunk sizes are randomized around the profile's average
        packet size to add further unpredictability. Each burst in
        the profile generates a corresponding set of chunks, with
        any remaining bytes added as a final chunk.

        Args:
            payload: Raw data to be obfuscated

        Returns:
            List of byte chunks mimicking normal service traffic
        """
        chunks = []
        pos = 0
        for burst_count in self.profile.burst_pattern:
            for _ in range(burst_count):
                # Randomize chunk size near target profile
                jitter = random.randint(-64, 64)
                size = max(64, self.profile.avg_packet_size + jitter)
                chunk = payload[pos:pos + size]
                if chunk:
                    chunks.append(chunk)
                pos += size
            if pos >= len(payload):
                break
        # Add any remaining bytes
        if pos < len(payload):
            chunks.append(payload[pos:])
        return chunks

    async def send_with_timing(
        self,
        chunks: List[bytes],
        send_fn: Callable[[bytes], Awaitable[bool]],
    ) -> bool:
        """Send chunks with human-like timing to evade DPI timing analysis.

        Iran's DPI system uses statistical timing analysis to detect
        automated/bot traffic. This method adds jitter to inter-chunk
        delays that mimics human/browser interaction patterns, making
        the traffic appear as normal HTTPS browsing activity.

        If a send failure occurs, the engine records it as a potential
        detection event and automatically adapts its strategy if the
        detection rate is too high.

        Args:
            chunks: List of byte chunks to send
            send_fn: Async function that sends a single chunk and returns success

        Returns:
            True if all chunks sent successfully, False if any failed
        """
        for i, chunk in enumerate(chunks):
            # Jitter timing to mimic human/browser patterns
            jitter = random.uniform(
                -self.profile.timing_jitter,
                self.profile.timing_jitter,
            )
            delay = abs(0.05 + jitter)  # base 50ms + jitter
            await asyncio.sleep(delay)

            success = await send_fn(chunk)
            if not success:
                self.detection_history.append({
                    "time": time.time(),
                    "chunk": i,
                    "strategy": self.current_strategy,
                })
                self._detection_count += 1
                # AI adaptation: switch profile if detected
                self._adapt_strategy()
                return False
        return True

    def _adapt_strategy(self):
        """Auto-adapt if too many detections occur.

        Monitors detection events in the last 5 minutes. If 3 or more
        detections occur within this window, the engine automatically
        switches to a different traffic profile to evade the DPI
        system's pattern matching. This creates a moving target that
        makes it difficult for the DPI system to classify the traffic.

        The profile switching is cyclical — it goes through all available
        profiles before returning to the original one, giving the DPI
        system time to reset its detection models.
        """
        recent = [d for d in self.detection_history
                  if time.time() - d["time"] < 300]  # last 5 min

        if len(recent) >= 3:
            # High detection rate -> switch to more disguised profile
            profiles = list(PROFILES.keys())
            current_idx = profiles.index(self.profile.name) \
                          if self.profile.name in profiles else 0
            next_profile = profiles[(current_idx + 1) % len(profiles)]
            self.profile = PROFILES[next_profile]
            self.current_strategy = f"switched_to_{next_profile}"
            self._profile_switch_count += 1
            logger.warning(
                f"[AntiDPI] Detection rate high -> "
                f"switched to profile: {next_profile} "
                f"(switch #{self._profile_switch_count})"
            )

    def get_stats(self) -> Dict:
        """Return engine statistics for monitoring."""
        return {
            "current_profile": self.profile.name,
            "current_strategy": self.current_strategy,
            "total_detections": self._detection_count,
            "profile_switches": self._profile_switch_count,
            "recent_detections": len([
                d for d in self.detection_history
                if time.time() - d["time"] < 300
            ]),
        }


class SmartBridgeSelector:
    """AI-powered Tor bridge selector for Iranian network conditions.

    Automatically chooses the best pluggable transport based on:
    1. Real-world success rates tracked via exponential moving average
    2. Transport priorities optimized for Iran's filtering
    3. Automatic blocking detection and transport fallback
    4. Smart reset when all transports are blocked

    Iran's filtering targets different transports at different times
    and with varying intensity. This selector learns which transports
    are currently working and prioritizes them accordingly.

    Transport Priority for Iran (highest to lowest):
    1. snowflake   — uses WebRTC/domain fronting, hardest to block
    2. meek_azure  — domain fronting via Microsoft Azure
    3. obfs4       — traffic obfuscation protocol
    4. webtunnel   — mimics HTTPS websites
    5. vanilla     — plain Tor (often blocked in Iran, last resort)

    Usage:
        selector = SmartBridgeSelector()
        best = selector.get_best_transport()
        selector.report_result(best, success=True)
    """

    TRANSPORT_PRIORITY_IRAN = [
        "snowflake",    # best for Iran — uses WebRTC/domain fronting
        "meek_azure",   # domain fronting via Microsoft
        "obfs4",        # traffic obfuscation protocol
        "webtunnel",    # mimics HTTPS websites
        "vanilla",      # plain Tor (often blocked in Iran)
    ]

    def __init__(self):
        self.blocked_transports: set = set()
        self.success_rates: Dict[str, float] = {
            t: 1.0 for t in self.TRANSPORT_PRIORITY_IRAN
        }
        self._attempt_counts: Dict[str, int] = {
            t: 0 for t in self.TRANSPORT_PRIORITY_IRAN
        }

    def get_best_transport(self) -> str:
        """Select transport with highest success rate (not blocked).

        Returns the transport with the highest current success rate
        among transports that are not currently marked as blocked.
        If all transports are blocked, performs a smart reset and
        retries all of them (the blocking may have been temporary).

        The selection uses exponential moving average (EMA) success
        rates, so recent results have more weight than older ones.
        This allows the selector to quickly adapt to changing
        filtering conditions in Iran.

        Returns:
            Transport name string (e.g., 'snowflake', 'obfs4')
        """
        available = [t for t in self.TRANSPORT_PRIORITY_IRAN
                     if t not in self.blocked_transports]
        if not available:
            # All transports blocked — reset and retry all
            # This handles temporary blocking that may have been lifted
            self.blocked_transports.clear()
            available = list(self.TRANSPORT_PRIORITY_IRAN)
            logger.warning(
                "[BridgeSelector] All transports were blocked — "
                "resetting to retry all. Filtering conditions may have changed."
            )

        # Weight by success rate
        best = max(available, key=lambda t: self.success_rates.get(t, 0))
        return best

    def report_result(self, transport: str, success: bool):
        """Update success rate — AI learns which transports work.

        Uses exponential moving average (EMA) with alpha=0.3 to track
        the success rate of each transport. This gives more weight to
        recent results while still considering historical data.

        If a transport's success rate drops below 10%, it is automatically
        marked as blocked and will not be selected until all transports
        are blocked (triggering a full reset) or the blocking is lifted.

        Args:
            transport: Transport name (e.g., 'snowflake')
            success: Whether the connection attempt succeeded
        """
        current = self.success_rates.get(transport, 1.0)
        # Exponential moving average
        alpha = 0.3
        new_rate = alpha * (1.0 if success else 0.0) + (1 - alpha) * current
        self.success_rates[transport] = new_rate
        self._attempt_counts[transport] = self._attempt_counts.get(transport, 0) + 1

        if new_rate < 0.1:  # < 10% success -> mark as blocked
            self.blocked_transports.add(transport)
            logger.warning(
                f"[BridgeSelector] {transport} appears blocked "
                f"in Iran (success={new_rate:.1%}, "
                f"attempts={self._attempt_counts[transport]})"
            )

    def get_stats(self) -> Dict:
        """Return selector statistics for monitoring."""
        return {
            "success_rates": dict(self.success_rates),
            "blocked_transports": list(self.blocked_transports),
            "attempt_counts": dict(self._attempt_counts),
            "current_best": self.get_best_transport(),
        }


# ═══════════════════════════════════════════════════════════════════════════
# SINGLETON INSTANCES
# ═══════════════════════════════════════════════════════════════════════════

anti_dpi = AntiDPIEngine(profile="https_generic")
bridge_selector = SmartBridgeSelector()
