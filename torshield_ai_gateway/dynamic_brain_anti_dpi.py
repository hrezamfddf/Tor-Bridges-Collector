"""
dynamic_brain_anti_dpi.py — AI-Powered Anti-DPI Integration for Dynamic Model Brain
=====================================================================================

Intelligent Deep Packet Inspection (DPI) countermeasures specifically designed
for Iran's national filtering infrastructure. This module integrates with
DynamicModelBrain to dynamically adapt model selection, traffic patterns,
and communication strategies based on real-time DPI threat assessment.

CAPABILITIES:
  1. Iran DPI Signature Detection — identifies known DPI patterns used by
     Iran's national internet filtering system (Siam/Filternet)
  2. Adaptive Model Selection — automatically switches to models that generate
     traffic patterns less susceptible to DPI fingerprinting
  3. Traffic Morphing Coordination — works with existing anti-DPI modules
     to reshape API traffic to look like normal HTTPS browsing
  4. Circuit Breaker for DPI Thresholds — when DPI intensity spikes,
     automatically reduces traffic volume and switches to stealthiest models
  5. Time-Based Evasion — adjusts strategy based on Iran's known DPI
     scheduling patterns (business hours = more aggressive filtering)

INTEGRATION:
  - Reads from existing: ai_anti_dpi_iran.py, iran_smart_anti_filter.py,
    neural_anti_dpi_v3.py, anti_censorship.py
  - Feeds into: DynamicModelBrain for model scoring adjustments
  - Zero deletion of existing capabilities — pure additive module

Version: Fix-16.0 / Feature: DYNAMIC-BRAIN-ANTI-DPI
"""

from __future__ import annotations

import os
import re
import time
import math
import random
import logging
import threading
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any, Callable

logger = logging.getLogger("torshield.ai.dynamic_brain.anti_dpi")


# ──────────────────────────────────────────────────────────────
# 1. DPI THREAT LEVEL CLASSIFICATION
# ──────────────────────────────────────────────────────────────


class DPIThreatLevel(str, Enum):
    """Iran DPI threat level classification."""
    NONE      = "none"       # No DPI detected
    LOW       = "low"        # Baseline filtering (keyword-based)
    MEDIUM    = "medium"     # Active DPI with TLS fingerprinting
    HIGH      = "high"       # Aggressive DPI with traffic analysis
    CRITICAL  = "critical"   # Full-scale internet throttling / shutdown


class DPIPatternType(str, Enum):
    """Types of DPI patterns used by Iran's filtering system."""
    TLS_FINGERPRINT   = "tls_fingerprint"    # JA3/JA3S fingerprinting
    SNI_INSPECTION    = "sni_inspection"      # Server Name Indication inspection
    TRAFFIC_ANALYSIS  = "traffic_analysis"    # Flow size/timing analysis
    DNS_POISONING     = "dns_poisoning"       # DNS response manipulation
    IP_BLACKLIST      = "ip_blacklist"        # Destination IP blocking
    DEEP_CONTENT      = "deep_content"        # Payload content inspection
    PROTOCOL_DETECT   = "protocol_detect"     # Protocol identification (Tor, VPN)
    BANDWIDTH_THROTTLE = "bandwidth_throttle" # Bandwidth-based throttling


# ──────────────────────────────────────────────────────────────
# 2. DPI THREAT ASSESSOR
# ──────────────────────────────────────────────────────────────


@dataclass
class DPIAssessment:
    """Result of a DPI threat assessment."""
    threat_level: DPIThreatLevel = DPIThreatLevel.NONE
    detected_patterns: List[DPIPatternType] = field(default_factory=list)
    confidence: float = 0.0         # 0.0-1.0 confidence in assessment
    recommended_action: str = ""     # Human-readable recommendation
    model_preference: str = "cf_hosted"  # Preferred model source
    max_response_tokens: int = 2048  # Limit response size for stealth
    latency_budget_ms: int = 5000   # Max acceptable latency
    timestamp: float = 0.0

    def __post_init__(self):
        if self.timestamp == 0.0:
            self.timestamp = time.time()


class IranDPIAssessor:
    """
    Assesses Iran DPI threat level using multiple signal sources:
    - Existing anti-DPI module outputs
    - Time-of-day heuristics (Iran timezone)
    - Environment variable flags
    - Network behavior patterns
    - Historical DPI intensity data
    """

    # Iran Standard Time offset (UTC+3:30)
    IRAN_TZ_OFFSET_HOURS = 3.5

    # Known DPI intensity patterns by hour (Iran time)
    # Higher value = more aggressive filtering expected
    # Based on documented patterns of Iran's filtering schedule
    _HOURLY_DPI_INTENSITY: Dict[int, float] = {
        0: 0.3,   1: 0.2,   2: 0.2,   3: 0.15,  4: 0.15,  5: 0.2,
        6: 0.3,   7: 0.5,   8: 0.7,   9: 0.85,  10: 0.9,  11: 0.9,
        12: 0.8,  13: 0.85, 14: 0.9,  15: 0.85, 16: 0.8,  17: 0.7,
        18: 0.6,  19: 0.55, 20: 0.5,  21: 0.45, 22: 0.4,  23: 0.35,
    }

    # Known Iran DPI signatures and their associated threat patterns
    _IRAN_DPI_SIGNATURES: Dict[str, DPIPatternType] = {
        "siam_filternet":       DPIPatternType.DEEP_CONTENT,
        "national_filternet":   DPIPatternType.SNI_INSPECTION,
        "tci_dpi":              DPIPatternType.TLS_FINGERPRINT,
        "mci_dpi":              DPIPatternType.TRAFFIC_ANALYSIS,
        "rightel_dpi":          DPIPatternType.PROTOCOL_DETECT,
        "irancell_dpi":         DPIPatternType.BANDWIDTH_THROTTLE,
        "dsi_dpi":              DPIPatternType.DNS_POISONING,
    }

    def __init__(self):
        self._last_assessment: Optional[DPIAssessment] = None
        self._assessment_count: int = 0
        self._high_threat_timestamps: List[float] = []
        self._lock = threading.Lock()

    def _iran_hour(self) -> int:
        """Get current hour in Iran timezone."""
        utc_now = time.time()
        utc_hour = int((utc_now % 86400) // 3600)
        iran_hour = (utc_hour + int(self.IRAN_TZ_OFFSET_HOURS)) % 24
        return iran_hour

    def _time_based_threat(self) -> float:
        """Estimate DPI threat intensity based on Iran time of day.
        Business hours (8-17) have higher DPI activity.
        Late night (2-5) has lowest DPI activity.
        """
        hour = self._iran_hour()
        return self._HOURLY_DPI_INTENSITY.get(hour, 0.5)

    def _check_env_signals(self) -> tuple:
        """Check environment variables for DPI-related signals."""
        detected_patterns = []
        threat_score = 0.0

        # Explicit Iran mode flag
        iran_mode = os.environ.get("TORSHIELD_IRAN_MODE", "").lower()
        if iran_mode in ("1", "true", "yes"):
            threat_score += 0.3

        # DPI intensity flag
        dpi_level = os.environ.get("TORSHIELD_DPI_LEVEL", "").lower()
        if dpi_level in ("high", "critical", "severe"):
            threat_score += 0.4
            detected_patterns.append(DPIPatternType.TRAFFIC_ANALYSIS)
        elif dpi_level in ("medium", "moderate"):
            threat_score += 0.2
            detected_patterns.append(DPIPatternType.SNI_INSPECTION)

        # Specific pattern flags
        if os.environ.get("TORSHIELD_TLS_BLOCKED", "").lower() in ("1", "true"):
            detected_patterns.append(DPIPatternType.TLS_FINGERPRINT)
            threat_score += 0.2
        if os.environ.get("TORSHIELD_DNS_POISONED", "").lower() in ("1", "true"):
            detected_patterns.append(DPIPatternType.DNS_POISONING)
            threat_score += 0.15
        if os.environ.get("TORSHIELD_BANDWIDTH_THROTTLED", "").lower() in ("1", "true"):
            detected_patterns.append(DPIPatternType.BANDWIDTH_THROTTLE)
            threat_score += 0.1

        return threat_score, detected_patterns

    def _check_existing_modules(self) -> tuple:
        """Check existing anti-DPI modules for active threat indicators."""
        threat_score = 0.0
        detected_patterns = []

        # Try IranIntelligence module
        try:
            from torshield_ai_gateway.iran_intelligence import IranIntelligence
            intel = IranIntelligence()
            if hasattr(intel, 'is_dpi_active') and callable(intel.is_dpi_active):
                if intel.is_dpi_active():
                    threat_score += 0.3
                    detected_patterns.append(DPIPatternType.PROTOCOL_DETECT)
            if hasattr(intel, 'get_dpi_level'):
                level = intel.get_dpi_level()
                if level and str(level).lower() in ("severe", "high", "critical"):
                    threat_score += 0.3
        except (ImportError, AttributeError, Exception):
            pass

        # Try AntiCensorshipEngine
        try:
            from torshield_ai_gateway.anti_censorship import get_anti_censorship_engine
            engine = get_anti_censorship_engine()
            if engine:
                if hasattr(engine, 'censorship_level'):
                    level = getattr(engine, 'censorship_level', None)
                    if level and str(level).lower() in ("severe", "high", "critical"):
                        threat_score += 0.3
                        detected_patterns.append(DPIPatternType.DEEP_CONTENT)
        except (ImportError, AttributeError, Exception):
            pass

        # Try IranAutoDefense
        try:
            from torshield_ai_gateway.iran_auto_defense import get_auto_defense
            defense = get_auto_defense()
            if defense and hasattr(defense, 'active_threats'):
                threats = getattr(defense, 'active_threats', [])
                if threats:
                    threat_score += min(0.3, len(threats) * 0.1)
                    for t in threats:
                        t_lower = str(t).lower()
                        if "tls" in t_lower:
                            detected_patterns.append(DPIPatternType.TLS_FINGERPRINT)
                        elif "dns" in t_lower:
                            detected_patterns.append(DPIPatternType.DNS_POISONING)
                        elif "bandwidth" in t_lower or "throttle" in t_lower:
                            detected_patterns.append(DPIPatternType.BANDWIDTH_THROTTLE)
        except (ImportError, AttributeError, Exception):
            pass

        # Try NeuralAntiDPI v3
        try:
            from torshield_ai_gateway.neural_anti_dpi_v3 import AntiDPIV3Orchestrator
            # The v3 orchestrator may have live threat assessment
            if hasattr(AntiDPIV3Orchestrator, 'get_current_threat_level'):
                level = AntiDPIV3Orchestrator.get_current_threat_level()
                if level and level > 0.7:
                    threat_score += 0.3
                    detected_patterns.append(DPIPatternType.TRAFFIC_ANALYSIS)
        except (ImportError, AttributeError, Exception):
            pass

        return threat_score, detected_patterns

    def assess(self) -> DPIAssessment:
        """
        Perform a comprehensive DPI threat assessment.

        Combines signals from:
        1. Time-of-day heuristics (Iran business hours = higher DPI)
        2. Environment variable flags
        3. Existing anti-DPI module outputs
        4. Historical DPI intensity patterns

        Returns a DPIAssessment with recommended model selection strategy.
        """
        with self._lock:
            # Gather signals
            time_score = self._time_based_threat()
            env_score, env_patterns = self._check_env_signals()
            module_score, module_patterns = self._check_existing_modules()

            # Combine scores (weighted)
            # Environment signals get highest weight (explicit configuration)
            # Module outputs get second-highest weight (live detection)
            # Time-based prediction is lowest weight (heuristic only)
            combined_score = (
                time_score * 0.2   # 20% weight on time-based prediction
                + env_score * 0.5  # 50% weight on env signals (most reliable)
                + module_score * 0.3  # 30% weight on module outputs
            )

            # Merge detected patterns
            all_patterns = list(set(env_patterns + module_patterns))

            # Classify threat level
            if combined_score >= 0.8:
                threat_level = DPIThreatLevel.CRITICAL
            elif combined_score >= 0.6:
                threat_level = DPIThreatLevel.HIGH
            elif combined_score >= 0.4:
                threat_level = DPIThreatLevel.MEDIUM
            elif combined_score >= 0.2:
                threat_level = DPIThreatLevel.LOW
            else:
                threat_level = DPIThreatLevel.NONE

            # Determine model preference based on threat level
            if threat_level in (DPIThreatLevel.HIGH, DPIThreatLevel.CRITICAL):
                model_pref = "cf_hosted"
                max_tokens = 512     # Short responses = less traffic analysis surface
                latency_budget = 3000  # Must be fast
                recommended = (
                    "HIGH DPI detected: Using CF-hosted models only, "
                    "short responses, minimal metadata leakage"
                )
            elif threat_level == DPIThreatLevel.MEDIUM:
                model_pref = "cf_hosted"
                max_tokens = 1024
                latency_budget = 5000
                recommended = (
                    "MODERATE DPI: Preferring CF-hosted models, "
                    "moderate response length"
                )
            elif threat_level == DPIThreatLevel.LOW:
                model_pref = "any"   # Any source is fine
                max_tokens = 2048
                latency_budget = 8000
                recommended = (
                    "LOW DPI: All model sources available, "
                    "standard response length"
                )
            else:
                model_pref = "any"
                max_tokens = 4096
                latency_budget = 10000
                recommended = "No DPI detected: Full model selection"

            # Track high-threat events
            now = time.time()
            if threat_level in (DPIThreatLevel.HIGH, DPIThreatLevel.CRITICAL):
                self._high_threat_timestamps.append(now)

            # Clean old timestamps (keep last 24 hours)
            cutoff = now - 86400
            self._high_threat_timestamps = [
                t for t in self._high_threat_timestamps if t > cutoff
            ]

            assessment = DPIAssessment(
                threat_level=threat_level,
                detected_patterns=all_patterns,
                confidence=min(combined_score + 0.2, 1.0),
                recommended_action=recommended,
                model_preference=model_pref,
                max_response_tokens=max_tokens,
                latency_budget_ms=latency_budget,
                timestamp=now,
            )

            self._last_assessment = assessment
            self._assessment_count += 1

            return assessment

    def get_last_assessment(self) -> Optional[DPIAssessment]:
        """Return the most recent DPI assessment."""
        return self._last_assessment

    def get_high_threat_frequency(self) -> float:
        """
        Calculate the frequency of high-threat events in the last 24 hours.
        Returns events per hour. Used to detect escalation patterns.
        """
        now = time.time()
        cutoff = now - 86400
        recent = [t for t in self._high_threat_timestamps if t > cutoff]
        if not recent:
            return 0.0
        return len(recent) / 24.0  # events per hour


# ──────────────────────────────────────────────────────────────
# 3. DYNAMIC BRAIN DPI ADAPTER
# ──────────────────────────────────────────────────────────────


class DynamicBrainDPIAdapter:
    """
    Bridges DynamicModelBrain with Iran DPI assessment.
    Automatically adjusts the brain's scoring based on DPI threat level.

    This is the key integration point: when DPI is detected, the adapter
    modifies the brain's model selection strategy to:
    - Prefer CF-hosted models (no cross-border traffic)
    - Limit response sizes (less traffic analysis surface)
    - Select models with minimal metadata leakage
    - Adjust latency requirements based on DPI intensity
    """

    def __init__(self):
        self._assessor = IranDPIAssessor()
        self._last_adaptation: Optional[DPIAssessment] = None
        self._adaptation_count: int = 0
        self._lock = threading.Lock()

    def adapt_brain(self) -> DPIAssessment:
        """
        Assess DPI threat and adapt the DynamicModelBrain accordingly.

        Returns the current DPI assessment.
        """
        with self._lock:
            assessment = self._assessor.assess()

            # Import brain and apply DPI mode
            from torshield_ai_gateway.dynamic_model_brain import get_brain
            brain = get_brain()

            if assessment.threat_level in (DPIThreatLevel.HIGH, DPIThreatLevel.CRITICAL):
                if not brain.anti_dpi_mode:
                    brain.enable_anti_dpi()
                    logger.info(
                        f"[DPI-Adapter] Activating anti-DPI mode: "
                        f"threat={assessment.threat_level.value}, "
                        f"confidence={assessment.confidence:.1%}"
                    )
            else:
                if brain.anti_dpi_mode and assessment.threat_level == DPIThreatLevel.NONE:
                    brain.disable_anti_dpi()
                    logger.info("[DPI-Adapter] Deactivating anti-DPI mode: threat cleared")

            self._last_adaptation = assessment
            self._adaptation_count += 1

            return assessment

    def get_recommended_max_tokens(self, default: int = 2048) -> int:
        """Get the recommended max_tokens based on current DPI threat."""
        if self._last_adaptation:
            return self._last_adaptation.max_response_tokens
        return default

    def get_recommended_model_source(self) -> str:
        """Get the recommended model source based on current DPI threat."""
        if self._last_adaptation:
            return self._last_adaptation.model_preference
        return "any"

    def summary(self) -> Dict[str, Any]:
        """Return a summary of the DPI adapter state."""
        return {
            "last_threat_level": (
                self._last_adaptation.threat_level.value
                if self._last_adaptation else "unknown"
            ),
            "detected_patterns": (
                [p.value for p in self._last_adaptation.detected_patterns]
                if self._last_adaptation else []
            ),
            "confidence": (
                self._last_adaptation.confidence
                if self._last_adaptation else 0.0
            ),
            "recommended_model_source": self.get_recommended_model_source(),
            "recommended_max_tokens": self.get_recommended_max_tokens(),
            "adaptation_count": self._adaptation_count,
            "high_threat_frequency": self._assessor.get_high_threat_frequency(),
        }


# ──────────────────────────────────────────────────────────────
# 4. SINGLETON + CONVENIENCE
# ──────────────────────────────────────────────────────────────

_dpi_adapter: Optional[DynamicBrainDPIAdapter] = None


def get_dpi_adapter() -> DynamicBrainDPIAdapter:
    """Get or create the singleton DPI adapter."""
    global _dpi_adapter
    if _dpi_adapter is None:
        _dpi_adapter = DynamicBrainDPIAdapter()
    return _dpi_adapter


def run_dpi_assessment() -> DPIAssessment:
    """Run a DPI assessment and adapt the brain. Convenience function."""
    adapter = get_dpi_adapter()
    return adapter.adapt_brain()


# ──────────────────────────────────────────────────────────────
# 5. CLI SELF-TEST
# ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import json
    logging.basicConfig(level=logging.INFO)

    print("=== Iran DPI Assessment Self-Test ===\n")

    # Run assessment
    adapter = get_dpi_adapter()
    assessment = adapter.adapt_brain()

    print(f"Threat Level: {assessment.threat_level.value}")
    print(f"Confidence:   {assessment.confidence:.1%}")
    print(f"Patterns:     {[p.value for p in assessment.detected_patterns]}")
    print(f"Model Source: {assessment.model_preference}")
    print(f"Max Tokens:   {assessment.max_response_tokens}")
    print(f"Latency:      {assessment.latency_budget_ms}ms")
    print(f"Action:       {assessment.recommended_action}")

    print("\n=== Adapter Summary ===")
    print(json.dumps(adapter.summary(), indent=2, default=str))


# ─────────────────────────────────────────────────────────────────────────────
# FIX-18.0: Iran DPI Shield v4 integration
# ─────────────────────────────────────────────────────────────────────────────

def get_shield_v4():
    """Get IranDPIShieldV4 singleton — v4 advanced evasion engine."""
    try:
        from .iran_dpi_shield_v4 import IranDPIShieldV4
        return IranDPIShieldV4.instance()
    except Exception as exc:
        logger.debug(f"[AntiDPI] Shield v4 not available: {exc}")
        return None


def run_dpi_assessment_v4():
    """Run v4 threat assessment with JA3, H2, NIN, and timing analysis."""
    shield = get_shield_v4()
    if shield:
        return shield.assess()
    return run_dpi_assessment()  # fallback to v1
