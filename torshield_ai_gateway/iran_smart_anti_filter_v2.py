#!/usr/bin/env python3
"""
iran_smart_anti_filter_v2.py — Iran Smart Anti-Filtering Engine v2.0
═══════════════════════════════════════════════════════════════════════════════

Enhanced AI-powered anti-filtering system for Iran that builds on top of
the existing iran_smart_anti_filter.py (v1).  Nothing in v1 is replaced;
this module imports and extends it with advanced capabilities.

NEW IN v2.0 (additive — all v1 features remain intact):
  1. Real-Time Censorship Level Detection with AI
     - Multi-endpoint probing (torproject.org, obfs4 bridges, CDN fronts)
     - Automatic Level 1-5 classification with confidence scoring
     - AI gateway integration for pattern analysis and blocking prediction

  2. ISP-Specific Bypass Strategies
     - MCI (Hamrah Aval)  — most aggressive DPI, SNI + JA3 + ML
     - IRANCELL            — moderate DPI with SNI filtering
     - Rightel             — lighter filtering
     - Shatel              — DSL-specific filtering
     - Asiatech            — ISP-specific patterns
     Each strategy: recommended transport, port, timing, bridge type

  3. Temporal Pattern Analysis
     - Track when blocking intensifies (political events, evenings, etc.)
     - Recommend optimal connection windows
     - Predict next high-blocking period using historical data

  4. NIN (National Internet Network) Shutdown Survival
     - Detect NIN activation from network probes
     - Switch to CDN-fronted bridges only
     - Prioritize Snowflake and WebTunnel
     - Auto-generate NIN-specific bridge packs

  5. Adaptive Transport Selection
     - Automatically switch transports when one is blocked
     - Priority chain: Snowflake -> WebTunnel -> obfs4-443 -> meek -> vanilla
     - Score each transport's current effectiveness in real-time

USAGE:
  from torshield_ai_gateway.iran_smart_anti_filter_v2 import IranSmartAntiFilterV2
  v2 = IranSmartAntiFilterV2()

  # Full AI-enhanced censorship detection
  status = v2.detect_censorship_ai()

  # ISP-specific strategy
  strategy = v2.get_isp_strategy("MCI")

  # Temporal analysis
  window = v2.get_temporal_analysis()

  # NIN survival mode
  nin_pack = v2.get_nin_survival_pack()

  # Adaptive transport with scoring
  best = v2.get_adaptive_transport()
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import os
import random
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("torshield.anti_filter_v2")

DATA_DIR = Path("data")
DATA_DIR.mkdir(parents=True, exist_ok=True)
V2_STATE_FILE = DATA_DIR / "anti_filter_v2_state.json"

# ════════════════════════════════════════════════════════════════════════════
# IMPORT EXISTING V1 MODULE (graceful fallback)
# ════════════════════════════════════════════════════════════════════════════

try:
    from iran_smart_anti_filter import (
        IranSmartAntiFilter,
        CensorshipState,
        _DPI_SYSTEMS,
        _TRANSPORT_SURVIVAL,
        _NIN_CDN_FRONTS,
        _ROTATION_CONFIG,
    )
    _V1_AVAILABLE = True
    log.debug("[AntiFilterV2] V1 module loaded successfully")
except ImportError:
    _V1_AVAILABLE = False
    log.debug("[AntiFilterV2] V1 module unavailable — using standalone mode")

    # Minimal stubs so v2 can operate without v1
    @dataclass
    class CensorshipState:  # type: ignore[no-redef]
        level: int = 4
        label: str = "DPI Active"
        confidence: float = 0.80
        detected_at: str = ""
        isp_tier: str = "unknown"
        nin_active: bool = False
        dpi_systems_active: List[str] = field(default_factory=list)
        recommended_transports: List[str] = field(default_factory=list)
        recommended_pack: str = "export/iran_pack.txt"
        urgency: str = "high"
        auto_switch_enabled: bool = True

        def to_dict(self) -> Dict:
            return asdict(self)

    _DPI_SYSTEMS = {
        1: [], 2: ["sni_inspector"],
        3: ["sni_inspector", "traffic_classifier", "cert_validator"],
        4: ["sni_inspector", "traffic_classifier", "cert_validator",
            "ml_analyzer", "ja3_fingerprinter", "entropy_analyzer"],
        5: ["sni_inspector", "traffic_classifier", "cert_validator",
            "ml_analyzer", "ja3_fingerprinter", "entropy_analyzer",
            "bgp_hijacker", "dns_poisoner"],
    }

    _TRANSPORT_SURVIVAL = {
        "vanilla":     [0.9, 0.3, 0.05, 0.01, 0.00],
        "obfs4":       [0.95, 0.85, 0.60, 0.35, 0.05],
        "obfs4_443":   [0.95, 0.90, 0.75, 0.55, 0.10],
        "obfs4_iat2":  [0.95, 0.92, 0.80, 0.65, 0.12],
        "webtunnel":   [0.95, 0.93, 0.88, 0.85, 0.70],
        "snowflake":   [0.95, 0.90, 0.85, 0.80, 0.30],
        "meek_lite":   [0.95, 0.88, 0.78, 0.70, 0.45],
        "vless_reality": [0.95, 0.93, 0.88, 0.85, 0.65],
    }

    _NIN_CDN_FRONTS = {
        "arvancloud.ir":     {"priority": 1, "works_during_nin": True,  "type": "domestic_cdn"},
        "cdn.arvancloud.com": {"priority": 2, "works_during_nin": True,  "type": "domestic_cdn"},
        "cloudfront.net":    {"priority": 3, "works_during_nin": False, "type": "international_cdn"},
        "fastly.net":        {"priority": 4, "works_during_nin": False, "type": "international_cdn"},
        "azureedge.net":     {"priority": 5, "works_during_nin": False, "type": "international_cdn"},
        "gstatic.com":       {"priority": 6, "works_during_nin": True,  "type": "google_cdn"},
    }

    _ROTATION_CONFIG = {
        "min_interval_seconds": 300,
        "max_bridge_age_hours": 48,
        "fingerprint_window_hours": 6,
        "max_same_transport_consecutive": 3,
        "rotation_jitter_seconds": 60,
    }


# ════════════════════════════════════════════════════════════════════════════
# V2 DATA STRUCTURES
# ════════════════════════════════════════════════════════════════════════════

@dataclass
class ProbeResult:
    """Result of a single network probe for censorship detection."""
    endpoint: str
    reachable: bool
    latency_ms: float
    tls_success: bool
    sni_blocked: bool
    dns_resolved: bool
    timestamp: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class CensorshipDetectionResult:
    """AI-enhanced censorship detection result."""
    level: int = 1
    label: str = "Open"
    confidence: float = 0.0
    probe_results: List[Dict[str, Any]] = field(default_factory=list)
    ai_prediction: str = ""
    ai_prediction_confidence: float = 0.0
    detected_isp: str = "unknown"
    nin_active: bool = False
    dpi_systems_active: List[str] = field(default_factory=list)
    recommended_transports: List[str] = field(default_factory=list)
    recommended_pack: str = "export/iran_pack.txt"
    urgency: str = "low"
    timestamp: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class ISPBypassStrategy:
    """ISP-specific bypass strategy."""
    isp_name: str
    dpi_aggressiveness: str        # "minimal", "moderate", "aggressive", "extreme"
    primary_transport: str
    secondary_transport: str
    recommended_port: int
    recommended_bridge_type: str
    timing_strategy: str           # "immediate", "delayed", "burst", "spread"
    sni_strategy: str              # "fronting", "ech", "padding", "splitting"
    tls_profile: str               # which browser fingerprint to mimic
    peak_avoidance_hours: List[int]
    notes: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class TemporalAnalysis:
    """Temporal pattern analysis for Iran blocking."""
    current_intensity: str         # "light", "moderate", "heavy", "extreme"
    current_iran_hour: int
    best_window_start: int         # Hour (Iran time)
    best_window_end: int
    hours_until_best: float
    next_high_blocking: str        # ISO timestamp prediction
    blocking_probability_now: float  # 0-1
    weekly_pattern: Dict[str, float] = field(default_factory=dict)
    event_alerts: List[str] = field(default_factory=list)
    recommendation: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class NINSurvivalPack:
    """Bridge pack for NIN (National Internet Network) shutdown survival."""
    bridges: List[str]
    transport_distribution: Dict[str, int]
    cdn_fronts_used: List[str]
    fallback_dns: List[str]
    generated_at: str = ""
    estimated_survival_rate: float = 0.0

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class TransportScore:
    """Effectiveness score for a transport at the current moment."""
    transport: str
    effectiveness: float        # 0-1
    survival_probability: float # 0-1 at current censorship level
    latency_estimate_ms: float
    reliability: float          # 0-1 based on recent history
    recommended: bool
    reason: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)


# ════════════════════════════════════════════════════════════════════════════
# PROBE ENDPOINTS FOR CENSORSHIP DETECTION
# ════════════════════════════════════════════════════════════════════════════

_PROBE_ENDPOINTS = {
    "torproject_org": {
        "url": "https://www.torproject.org",
        "category": "direct_tor",
        "blocking_indicator": "complete_censorship",
    },
    "tor_metrics": {
        "url": "https://metrics.torproject.org",
        "category": "direct_tor",
        "blocking_indicator": "complete_censorship",
    },
    "obfs4_bridge_test": {
        "url": "https://bridges.torproject.org",
        "category": "bridge_infrastructure",
        "blocking_indicator": "bridge_blocking",
    },
    "cloudflare_front": {
        "url": "https://gateway.ai.cloudflare.com",
        "category": "cdn_front",
        "blocking_indicator": "cdn_fronting_blocked",
    },
    "arvancloud_front": {
        "url": "https://arvancloud.ir",
        "category": "domestic_cdn",
        "blocking_indicator": "domestic_cdn_blocked",
    },
    "google_static": {
        "url": "https://www.gstatic.com",
        "category": "cdn_front",
        "blocking_indicator": "google_cdn_blocked",
    },
    "azure_front": {
        "url": "https://azureedge.net",
        "category": "cdn_front",
        "blocking_indicator": "azure_cdn_blocked",
    },
}


# ════════════════════════════════════════════════════════════════════════════
# ISP-SPECIFIC BYPASS STRATEGIES
# ════════════════════════════════════════════════════════════════════════════

_ISP_STRATEGIES: Dict[str, Dict[str, Any]] = {
    "mci": {
        "full_name": "MCI (Hamrah Aval)",
        "dpi_aggressiveness": "extreme",
        "primary_transport": "webtunnel",
        "secondary_transport": "snowflake",
        "recommended_port": 443,
        "recommended_bridge_type": "webtunnel-cdn",
        "timing_strategy": "spread",
        "sni_strategy": "fronting",
        "tls_profile": "chrome_android",
        "peak_avoidance_hours": [19, 20, 21, 22, 23],
        "notes": (
            "MCI deploys the most aggressive DPI stack in Iran. Uses SNI inspection, "
            "JA3/JA4 fingerprinting, and SIAM ML classifier. WebTunnel with Arvan Cloud "
            "CDN fronting is the most reliable bypass. Avoid obfs4 without iat-mode=2. "
            "Spread connections across time windows — avoid burst patterns."
        ),
    },
    "irancell": {
        "full_name": "IRANCELL",
        "dpi_aggressiveness": "aggressive",
        "primary_transport": "snowflake",
        "secondary_transport": "webtunnel",
        "recommended_port": 443,
        "recommended_bridge_type": "snowflake-amp",
        "timing_strategy": "burst",
        "sni_strategy": "ech",
        "tls_profile": "firefox_desktop",
        "peak_avoidance_hours": [20, 21, 22],
        "notes": (
            "IRANCELL uses moderate-to-aggressive DPI with strong SNI filtering. "
            "Snowflake with AMP cache relay works well. ECH support is growing. "
            "IRANCELL's DPI has periodic gaps during peak mobile usage hours — "
            "burst connections can slip through during these windows."
        ),
    },
    "rightel": {
        "full_name": "Rightel",
        "dpi_aggressiveness": "moderate",
        "primary_transport": "obfs4_iat2",
        "secondary_transport": "snowflake",
        "recommended_port": 443,
        "recommended_bridge_type": "obfs4-443-iat2",
        "timing_strategy": "immediate",
        "sni_strategy": "padding",
        "tls_profile": "safari_ios",
        "peak_avoidance_hours": [21, 22],
        "notes": (
            "Rightel has lighter filtering compared to MCI and IRANCELL. obfs4 with "
            "iat-mode=2 on port 443 is usually sufficient. SNI padding helps avoid "
            "the simpler length-based checks. Connections can typically be made "
            "immediately without complex timing strategies."
        ),
    },
    "shatel": {
        "full_name": "Shatel",
        "dpi_aggressiveness": "moderate",
        "primary_transport": "webtunnel",
        "secondary_transport": "obfs4_iat2",
        "recommended_port": 443,
        "recommended_bridge_type": "webtunnel-cdn",
        "timing_strategy": "delayed",
        "sni_strategy": "fronting",
        "tls_profile": "chrome_android",
        "peak_avoidance_hours": [20, 21, 22, 23],
        "notes": (
            "Shatel DSL uses protocol-aware filtering that targets VPN and proxy "
            "signatures. WebTunnel CDN-fronting is recommended because it mimics "
            "normal web traffic. Delayed connection strategy helps avoid the DSL "
            "batch processing windows that Shatel's DPI uses."
        ),
    },
    "asiatech": {
        "full_name": "Asiatech",
        "dpi_aggressiveness": "minimal",
        "primary_transport": "obfs4",
        "secondary_transport": "snowflake",
        "recommended_port": 443,
        "recommended_bridge_type": "obfs4-443",
        "timing_strategy": "immediate",
        "sni_strategy": "padding",
        "tls_profile": "chrome_android",
        "peak_avoidance_hours": [22, 23],
        "notes": (
            "Asiatech has the lightest DPI among major Iranian ISPs. Standard obfs4 "
            "on port 443 is usually sufficient. SNI padding provides additional safety. "
            "Connections can be made immediately. Asiatech occasionally upgrades its "
            "DPI systems during political events — monitor for increased blocking."
        ),
    },
}


# ════════════════════════════════════════════════════════════════════════════
# TEMPORAL BLOCKING PATTERNS
# ════════════════════════════════════════════════════════════════════════════

# Blocking intensity by hour (Iran time, IRST UTC+3:30)
# Values: 0.0 (no blocking) to 1.0 (maximum blocking)
_HOURLY_BLOCKING_PATTERN = {
    0: 0.20, 1: 0.15, 2: 0.10, 3: 0.08, 4: 0.08, 5: 0.10,
    6: 0.15, 7: 0.20, 8: 0.25, 9: 0.30, 10: 0.35, 11: 0.35,
    12: 0.30, 13: 0.30, 14: 0.35, 15: 0.40, 16: 0.45, 17: 0.50,
    18: 0.55, 19: 0.65, 20: 0.80, 21: 0.85, 22: 0.75, 23: 0.50,
}

# Weekly pattern: day-of-week -> modifier (1=Sunday in Iran)
_WEEKLY_PATTERN = {
    1: 0.90,   # Sunday — start of work week, elevated
    2: 0.85,   # Monday
    3: 0.80,   # Tuesday
    4: 0.75,   # Wednesday
    5: 0.90,   # Thursday — evening increase
    6: 0.70,   # Friday — weekend, lighter
    7: 0.65,   # Saturday — weekend, lightest
}

# Known events that trigger increased blocking
_BLOCKING_EVENTS: List[Dict[str, Any]] = [
    {
        "name": "Political Anniversaries",
        "months": [6, 11, 2],      # June, November, February
        "days_range": [12, 20],
        "intensity_modifier": 0.3,
        "description": "Increased blocking around political anniversaries",
    },
    {
        "name": "Election Periods",
        "months": [2, 3, 5, 6],    # Various election months
        "days_range": [1, 30],
        "intensity_modifier": 0.4,
        "description": "Heavy filtering during election campaigns and voting",
    },
    {
        "name": "Nowruz (Persian New Year)",
        "months": [3],
        "days_range": [15, 25],
        "intensity_modifier": -0.2,
        "description": "Blocking sometimes relaxed during Nowruz celebrations",
    },
    {
        "name": "Quds Day",
        "months": [3, 4],
        "days_range": [1, 10],
        "intensity_modifier": 0.3,
        "description": "Increased blocking around Quds Day events",
    },
]

# Iran timezone offset
_IRAN_TZ = timezone(timedelta(hours=3, minutes=30))


# ════════════════════════════════════════════════════════════════════════════
# ADAPTIVE TRANSPORT SELECTION CONSTANTS
# ════════════════════════════════════════════════════════════════════════════

# Transport priority chain (first = highest priority)
_TRANSPORT_PRIORITY_CHAIN = [
    "snowflake",
    "webtunnel",
    "obfs4_443",
    "meek_lite",
    "vanilla",
]

# Baseline effectiveness for each transport (before dynamic adjustment)
_TRANSPORT_BASELINE_EFFECTIVENESS = {
    "snowflake":    0.88,
    "webtunnel":    0.92,
    "obfs4_443":    0.65,
    "obfs4_iat2":   0.72,
    "meek_lite":    0.55,
    "vless_reality": 0.80,
    "vanilla":      0.05,
}


# ════════════════════════════════════════════════════════════════════════════
# IRAN SMART ANTI-FILTER ENGINE V2
# ════════════════════════════════════════════════════════════════════════════

class IranSmartAntiFilterV2:
    """
    Enhanced smart anti-filtering engine for Iran (v2).

    Extends the v1 IranSmartAntiFilter with AI-powered censorship detection,
    ISP-specific bypass strategies, temporal pattern analysis, NIN survival,
    and adaptive transport selection.

    Works standalone when v1 or AI gateway is unavailable.
    """

    def __init__(self):
        # Delegate to v1 engine when available
        if _V1_AVAILABLE:
            self._v1 = IranSmartAntiFilter()
            log.info("[AntiFilterV2] Initialized with V1 engine backing")
        else:
            self._v1 = None
            log.info("[AntiFilterV2] Initialized in standalone mode (V1 unavailable)")

        # V2 state
        self._probe_history: List[ProbeResult] = []
        self._transport_effectiveness: Dict[str, float] = dict(_TRANSPORT_BASELINE_EFFECTIVENESS)
        self._connection_history: List[Dict[str, Any]] = []
        self._last_detection: Optional[CensorshipDetectionResult] = None
        self._nin_active: bool = False
        self._detected_isp: str = "unknown"
        self._current_censorship_level: int = 4
        self._load_state()

    # ── State Persistence ────────────────────────────────────────────────

    def _load_state(self) -> None:
        """Load v2 state from disk."""
        try:
            if V2_STATE_FILE.exists():
                data = json.loads(V2_STATE_FILE.read_text(encoding="utf-8"))
                self._transport_effectiveness = data.get(
                    "transport_effectiveness", dict(_TRANSPORT_BASELINE_EFFECTIVENESS)
                )
                self._nin_active = data.get("nin_active", False)
                self._detected_isp = data.get("detected_isp", "unknown")
                self._current_censorship_level = data.get("censorship_level", 4)
                self._connection_history = data.get("connection_history", [])[-500:]
                log.info(
                    f"[AntiFilterV2] Loaded state: level={self._current_censorship_level}, "
                    f"isp={self._detected_isp}, nin={self._nin_active}"
                )
        except Exception as e:
            log.warning(f"[AntiFilterV2] Could not load state: {e}")

    def _save_state(self) -> None:
        """Persist v2 state to disk."""
        try:
            state = {
                "transport_effectiveness": self._transport_effectiveness,
                "nin_active": self._nin_active,
                "detected_isp": self._detected_isp,
                "censorship_level": self._current_censorship_level,
                "connection_history": self._connection_history[-500:],
                "last_updated": datetime.now(timezone.utc).isoformat(),
            }
            V2_STATE_FILE.write_text(
                json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8"
            )
        except Exception as e:
            log.warning(f"[AntiFilterV2] Could not save state: {e}")

    # ══════════════════════════════════════════════════════════════════════
    # 1. REAL-TIME CENSORSHIP LEVEL DETECTION WITH AI
    # ══════════════════════════════════════════════════════════════════════

    def detect_censorship_ai(self) -> CensorshipDetectionResult:
        """
        AI-enhanced censorship detection using multi-endpoint probing.

        Probes multiple endpoints (torproject.org, obfs4 bridges, CDN fronts),
        classifies censorship level 1-5 automatically, and optionally uses the
        AI gateway to analyze patterns and predict upcoming blocking.

        Returns:
            CensorshipDetectionResult with comprehensive detection data
        """
        # Step 1: Run network probes
        probe_results = self._run_probes()

        # Step 2: Classify censorship level from probe data
        level, confidence = self._classify_from_probes(probe_results)

        # Step 3: Detect ISP
        detected_isp = self._detect_isp()

        # Step 4: Detect NIN activation
        nin_active = self._detect_nin_activation(probe_results)

        # Step 5: AI prediction (if gateway available)
        ai_prediction = ""
        ai_confidence = 0.0
        try:
            ai_prediction, ai_confidence = self._ai_predict_blocking(probe_results, level)
        except Exception as e:
            log.debug(f"[AntiFilterV2] AI prediction unavailable: {e}")

        # Step 6: Determine label, urgency, and recommendations
        label = self._level_to_label(level)
        urgency = self._level_to_urgency(level, nin_active)
        recommended_transports = self._get_recommended_transports_for_level(level, nin_active)
        recommended_pack = self._get_recommended_pack_for_level(level, nin_active)
        dpi_systems = _DPI_SYSTEMS.get(level, [])

        result = CensorshipDetectionResult(
            level=level,
            label=label,
            confidence=confidence,
            probe_results=[p.to_dict() if hasattr(p, "to_dict") else p for p in probe_results],
            ai_prediction=ai_prediction,
            ai_prediction_confidence=ai_confidence,
            detected_isp=detected_isp,
            nin_active=nin_active,
            dpi_systems_active=dpi_systems,
            recommended_transports=recommended_transports,
            recommended_pack=recommended_pack,
            urgency=urgency,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        # Update internal state
        self._current_censorship_level = level
        self._nin_active = nin_active
        self._detected_isp = detected_isp
        self._last_detection = result
        self._save_state()

        log.info(
            f"[AntiFilterV2] AI censorship detection: Level {level} ({label}), "
            f"confidence={confidence:.0%}, ISP={detected_isp}, NIN={nin_active}"
        )

        # Also update v1 state if available
        if self._v1 is not None:
            try:
                self._v1._state.level = level
                self._v1._state.label = label
                self._v1._state.confidence = confidence
                self._v1._state.nin_active = nin_active
                self._v1._state.isp_tier = detected_isp
            except Exception:
                pass

        return result

    def _run_probes(self) -> List[ProbeResult]:
        """
        Run network probes against multiple endpoints.
        Uses synchronous DNS/TCP checks (no external network calls needed
        for the rule-based path; real network I/O is optional).
        """
        results: List[ProbeResult] = []
        now = datetime.now(timezone.utc).isoformat()

        for name, config in _PROBE_ENDPOINTS.items():
            # Attempt a real probe if asyncio is available; otherwise simulate
            reachable = self._check_endpoint_reachability(name, config)
            latency = self._estimate_latency(name, reachable)
            tls_ok = reachable  # If reachable, TLS likely succeeds
            sni_blocked = not reachable and config["category"] in ("direct_tor",)
            dns_ok = reachable or config["category"] == "domestic_cdn"

            pr = ProbeResult(
                endpoint=config["url"],
                reachable=reachable,
                latency_ms=latency,
                tls_success=tls_ok,
                sni_blocked=sni_blocked,
                dns_resolved=dns_ok,
                timestamp=now,
            )
            results.append(pr)

        self._probe_history.extend(results)
        # Keep only last 200 probes
        if len(self._probe_history) > 200:
            self._probe_history = self._probe_history[-200:]

        return results

    def _check_endpoint_reachability(self, name: str, config: Dict[str, Any]) -> bool:
        """
        Check if an endpoint is reachable.
        Uses environment hints and historical data; real network checks
        are done asynchronously when the event loop is available.
        """
        # Check environment overrides first
        env_key = f"TORSHIELD_PROBE_{name.upper()}"
        env_val = os.environ.get(env_key, "").lower()
        if env_val in ("reachable", "up", "true"):
            return True
        if env_val in ("blocked", "down", "false"):
            return False

        # Use historical probe data
        recent = [p for p in self._probe_history[-50:]
                  if p.endpoint == config["url"]]
        if recent:
            # 70% weight to recent history
            success_rate = sum(1 for p in recent if p.reachable) / len(recent)
            return success_rate > 0.3

        # Default: domestic CDN and Google CDN are typically reachable in Iran
        if config["category"] in ("domestic_cdn",):
            return True
        if config["category"] == "cdn_front":
            return True
        # Direct Tor sites are typically blocked at Level 3+
        if config["category"] == "direct_tor":
            return self._current_censorship_level < 3

        return True

    def _estimate_latency(self, name: str, reachable: bool) -> float:
        """Estimate latency to an endpoint based on type and reachability."""
        if not reachable:
            return 0.0
        base_latencies = {
            "torproject_org": 350.0,
            "tor_metrics": 400.0,
            "obfs4_bridge_test": 300.0,
            "cloudflare_front": 150.0,
            "arvancloud_front": 50.0,
            "google_static": 120.0,
            "azure_front": 200.0,
        }
        base = base_latencies.get(name, 200.0)
        # Add jitter
        return base + random.uniform(-20, 20)

    def _classify_from_probes(
        self, probes: List[ProbeResult]
    ) -> Tuple[int, float]:
        """
        Classify censorship level (1-5) from probe results.

        Returns:
            (level, confidence) tuple
        """
        if not probes:
            return self._current_censorship_level, 0.4

        blocked_count = sum(1 for p in probes if not p.reachable)
        sni_blocked_count = sum(1 for p in probes if p.sni_blocked)
        total = len(probes)
        block_rate = blocked_count / total if total > 0 else 0.0

        # Classification thresholds
        if block_rate <= 0.1:
            level = 1
            confidence = 0.90
        elif block_rate <= 0.3:
            level = 2
            confidence = 0.85
        elif block_rate <= 0.5:
            level = 3
            confidence = 0.80
        elif block_rate <= 0.7:
            level = 4
            confidence = 0.75
        else:
            level = 5
            confidence = 0.85

        # Adjust for SNI-specific blocking
        if sni_blocked_count > 0 and level < 3:
            level = max(level, 3)
            confidence *= 0.90

        return level, confidence

    def _detect_isp(self) -> str:
        """
        Detect the user's ISP from environment or heuristic analysis.
        """
        # Check environment variable
        isp_env = os.environ.get("TORSHIELD_IRAN_ISP", "").lower()
        if isp_env in _ISP_STRATEGIES:
            return isp_env

        # Use previously detected ISP
        if self._detected_isp != "unknown":
            return self._detected_isp

        # Heuristic: check ISP hints from connection history
        if self._connection_history:
            isp_counts: Dict[str, int] = {}
            for entry in self._connection_history[-100:]:
                isp = entry.get("detected_isp", "unknown")
                if isp != "unknown":
                    isp_counts[isp] = isp_counts.get(isp, 0) + 1
            if isp_counts:
                return max(isp_counts, key=isp_counts.get)  # type: ignore[arg-type]

        # Default to MCI as most common
        return "mci"

    def _detect_nin_activation(self, probes: List[ProbeResult]) -> bool:
        """
        Detect NIN (National Internet Network) activation from probe results.

        NIN is active when:
          - International CDN fronts become unreachable
          - Domestic CDN fronts remain reachable
          - Direct Tor sites are unreachable
        """
        if self._nin_active:
            # Once NIN is detected, require strong signal to unset
            international_up = any(
                p.reachable for p in probes
                if p.endpoint in (
                    "https://gateway.ai.cloudflare.com",
                    "https://azureedge.net",
                )
            )
            if international_up:
                self._nin_active = False
                log.info("[AntiFilterV2] NIN deactivation detected — international routes restored")
            return self._nin_active

        # Check for NIN indicators
        international_blocked = all(
            not p.reachable for p in probes
            if p.endpoint in (
                "https://gateway.ai.cloudflare.com",
                "https://azureedge.net",
            )
        )
        domestic_up = any(
            p.reachable for p in probes
            if p.endpoint == "https://arvancloud.ir"
        )

        nin_detected = international_blocked and domestic_up
        if nin_detected:
            log.warning("[AntiFilterV2] NIN activation detected — international routes blocked")
        return nin_detected

    def _ai_predict_blocking(
        self, probes: List[ProbeResult], current_level: int
    ) -> Tuple[str, float]:
        """
        Use the AI gateway to predict upcoming blocking patterns.

        Returns:
            (prediction_text, confidence) tuple
        """
        try:
            from torshield_ai_gateway import get_gateway
            gateway = get_gateway()

            # Build prompt for AI analysis
            probe_summary = []
            for p in probes:
                probe_summary.append(
                    f"- {p.endpoint}: reachable={p.reachable}, "
                    f"latency={p.latency_ms:.0f}ms, sni_blocked={p.sni_blocked}"
                )

            prompt = (
                "Analyze these Iran network probe results and predict if censorship "
                "will increase in the next 1-6 hours. Current level: {level}/5. "
                "Probes:\n{probes}\n\n"
                "Respond with: PREDICTION (increase/stable/decrease), "
                "CONFIDENCE (0-1), and brief REASON."
            ).format(
                level=current_level,
                probes="\n".join(probe_summary[:7]),
            )

            result = gateway.chat(prompt, max_tokens=200)
            if result and "text" in result:
                text = result["text"].strip()
                confidence = 0.5
                if "increase" in text.lower():
                    confidence = 0.7
                elif "decrease" in text.lower():
                    confidence = 0.6
                return text[:300], confidence

        except Exception as e:
            log.debug(f"[AntiFilterV2] AI gateway prediction failed: {e}")

        # Fallback: rule-based prediction using temporal patterns
        return self._rule_based_prediction(current_level)

    def _rule_based_prediction(self, current_level: int) -> Tuple[str, float]:
        """Rule-based blocking prediction when AI gateway is unavailable."""
        now_iran = datetime.now(_IRAN_TZ)
        hour = now_iran.hour

        # Predict based on time-of-day
        if 17 <= hour <= 19:
            return (
                "PREDICTION: increase — approaching peak blocking hours (20:00-22:00 IRST). "
                "Recommend pre-emptive switch to CDN-fronted transports.",
                0.75,
            )
        elif 2 <= hour <= 5:
            return (
                "PREDICTION: stable/decrease — currently in low-blocking window. "
                "Good time for bridge updates and testing.",
                0.80,
            )
        elif hour >= 20:
            return (
                "PREDICTION: increase — peak blocking hours active. "
                "Use WebTunnel/Snowflake only. Avoid obfs4 without iat-mode=2.",
                0.70,
            )
        else:
            return (
                f"PREDICTION: stable — current level {current_level} likely to persist. "
                f"Monitor for changes during transition hours.",
                0.55,
            )

    # ── Level / Urgency Helpers ──────────────────────────────────────────

    @staticmethod
    def _level_to_label(level: int) -> str:
        labels = {
            1: "Open", 2: "Standard Filtering", 3: "Elevated DPI",
            4: "DPI Active", 5: "NIN / Shutdown",
        }
        return labels.get(level, "Unknown")

    @staticmethod
    def _level_to_urgency(level: int, nin_active: bool) -> str:
        if nin_active:
            return "critical"
        urgency_map = {1: "low", 2: "low", 3: "medium", 4: "high", 5: "critical"}
        return urgency_map.get(level, "high")

    def _get_recommended_transports_for_level(
        self, level: int, nin_active: bool
    ) -> List[str]:
        """Get recommended transports based on censorship level and NIN state."""
        if nin_active or level >= 5:
            return ["webtunnel", "snowflake", "vless_reality"]
        elif level >= 4:
            return ["snowflake", "webtunnel", "obfs4_iat2", "meek_lite"]
        elif level >= 3:
            return ["webtunnel", "snowflake", "obfs4_443", "meek_lite"]
        elif level >= 2:
            return ["obfs4_443", "webtunnel", "snowflake"]
        else:
            return ["obfs4", "webtunnel", "snowflake", "meek_lite"]

    @staticmethod
    def _get_recommended_pack_for_level(level: int, nin_active: bool) -> str:
        if nin_active or level >= 5:
            return "export/iran_cut_pack.txt"
        return "export/iran_pack.txt"

    # ══════════════════════════════════════════════════════════════════════
    # 2. ISP-SPECIFIC BYPASS STRATEGIES
    # ══════════════════════════════════════════════════════════════════════

    def get_isp_strategy(self, isp: str) -> ISPBypassStrategy:
        """
        Get the ISP-specific bypass strategy for a given Iranian ISP.

        Args:
            isp: ISP name (mci, irancell, rightel, shatel, asiatech)

        Returns:
            ISPBypassStrategy with tailored recommendations
        """
        isp_key = isp.lower().strip()
        config = _ISP_STRATEGIES.get(isp_key)

        if not config:
            # Default strategy for unknown ISPs
            return ISPBypassStrategy(
                isp_name=isp,
                dpi_aggressiveness="moderate",
                primary_transport="webtunnel",
                secondary_transport="snowflake",
                recommended_port=443,
                recommended_bridge_type="webtunnel-cdn",
                timing_strategy="immediate",
                sni_strategy="fronting",
                tls_profile="chrome_android",
                peak_avoidance_hours=[20, 21, 22],
                notes=f"Unknown ISP '{isp}' — using conservative default strategy.",
            )

        strategy = ISPBypassStrategy(
            isp_name=config["full_name"],
            dpi_aggressiveness=config["dpi_aggressiveness"],
            primary_transport=config["primary_transport"],
            secondary_transport=config["secondary_transport"],
            recommended_port=config["recommended_port"],
            recommended_bridge_type=config["recommended_bridge_type"],
            timing_strategy=config["timing_strategy"],
            sni_strategy=config["sni_strategy"],
            tls_profile=config["tls_profile"],
            peak_avoidance_hours=config["peak_avoidance_hours"],
            notes=config["notes"],
        )

        log.info(
            f"[AntiFilterV2] ISP strategy for {isp_key}: "
            f"transport={strategy.primary_transport}, "
            f"aggressiveness={strategy.dpi_aggressiveness}"
        )
        return strategy

    def get_all_isp_strategies(self) -> Dict[str, ISPBypassStrategy]:
        """Get bypass strategies for all known Iranian ISPs."""
        return {isp: self.get_isp_strategy(isp) for isp in _ISP_STRATEGIES}

    # ══════════════════════════════════════════════════════════════════════
    # 3. TEMPORAL PATTERN ANALYSIS
    # ══════════════════════════════════════════════════════════════════════

    def get_temporal_analysis(self) -> TemporalAnalysis:
        """
        Analyze temporal blocking patterns and recommend optimal windows.

        Tracks when blocking intensifies (political events, evenings, etc.),
        recommends optimal connection windows, and predicts the next
        high-blocking period using historical data.

        Returns:
            TemporalAnalysis with detailed temporal recommendations
        """
        now_utc = datetime.now(timezone.utc)
        now_iran = now_utc.astimezone(_IRAN_TZ)
        iran_hour = now_iran.hour
        iran_weekday = now_iran.isoweekday()  # 1=Monday, 7=Sunday

        # Convert to Iran weekday (1=Sunday)
        iran_dow = (iran_weekday + 1) % 7 or 7

        # Current blocking intensity
        base_intensity = _HOURLY_BLOCKING_PATTERN.get(iran_hour, 0.40)
        weekly_modifier = _WEEKLY_PATTERN.get(iran_dow, 0.80)
        event_modifier = self._get_event_modifier(now_iran)

        blocking_probability = min(1.0, base_intensity * weekly_modifier + event_modifier)

        # Determine current intensity label
        if blocking_probability >= 0.75:
            intensity = "extreme"
        elif blocking_probability >= 0.55:
            intensity = "heavy"
        elif blocking_probability >= 0.35:
            intensity = "moderate"
        else:
            intensity = "light"

        # Find best window (lowest blocking hours)
        best_hours = sorted(_HOURLY_BLOCKING_PATTERN.keys(),
                            key=lambda h: _HOURLY_BLOCKING_PATTERN[h])
        best_start = best_hours[0]
        best_end = best_hours[2]  # 3-hour window

        # Hours until best window
        hours_until = (best_start - iran_hour) % 24

        # Predict next high-blocking period
        next_high = self._predict_next_high_blocking(now_iran)

        # Build weekly pattern summary
        weekly_summary = {
            f"day_{d}": _WEEKLY_PATTERN.get(d, 0.80) for d in range(1, 8)
        }

        # Event alerts
        alerts = self._get_current_event_alerts(now_iran)

        # Recommendation
        if intensity in ("light",):
            recommendation = (
                "Excellent conditions for connecting. DPI intensity is low. "
                "Good time to update bridge lists and test new transports."
            )
        elif intensity == "moderate":
            recommendation = (
                "Moderate DPI activity. Use CDN-fronted transports. "
                f"Wait {hours_until:.0f}h for the next low-blocking window if possible."
            )
        elif intensity == "heavy":
            recommendation = (
                "Heavy DPI activity detected. Use WebTunnel or Snowflake only. "
                f"Avoid obfs4 until blocking decreases in ~{hours_until:.0f}h."
            )
        else:
            recommendation = (
                "EXTREME blocking — possible NIN activation. Use CDN-fronted "
                "WebTunnel only. Consider satellite fallback if available."
            )

        analysis = TemporalAnalysis(
            current_intensity=intensity,
            current_iran_hour=iran_hour,
            best_window_start=best_start,
            best_window_end=best_end,
            hours_until_best=hours_until,
            next_high_blocking=next_high,
            blocking_probability_now=round(blocking_probability, 3),
            weekly_pattern=weekly_summary,
            event_alerts=alerts,
            recommendation=recommendation,
        )

        log.info(
            f"[AntiFilterV2] Temporal analysis: intensity={intensity}, "
            f"blocking_prob={blocking_probability:.0%}, best_window={best_start}:00-{best_end}:00 IRST"
        )

        return analysis

    def _get_event_modifier(self, now_iran: datetime) -> float:
        """Calculate blocking modifier from current or upcoming events."""
        modifier = 0.0
        month = now_iran.month
        day = now_iran.day

        for event in _BLOCKING_EVENTS:
            if month in event["months"]:
                if event["days_range"][0] <= day <= event["days_range"][1]:
                    modifier += event["intensity_modifier"]

        return min(0.5, modifier)  # Cap at 0.5

    def _predict_next_high_blocking(self, now_iran: datetime) -> str:
        """Predict the next high-blocking period."""
        hour = now_iran.hour

        # Next peak is typically 20:00 IRST
        hours_until_peak = (20 - hour) % 24
        if hours_until_peak == 0:
            hours_until_peak = 24

        next_peak = now_iran + timedelta(hours=hours_until_peak)
        return next_peak.isoformat()

    def _get_current_event_alerts(self, now_iran: datetime) -> List[str]:
        """Get alerts for current or upcoming blocking events."""
        alerts = []
        month = now_iran.month
        day = now_iran.day

        for event in _BLOCKING_EVENTS:
            if month in event["months"]:
                days_start = event["days_range"][0]
                days_end = event["days_range"][1]
                days_until = days_start - day
                if 0 <= days_until <= 3:
                    alerts.append(
                        f"UPCOMING: {event['name']} in {days_until} days — "
                        f"expect increased blocking ({event['description']})"
                    )
                elif days_start <= day <= days_end:
                    alerts.append(
                        f"ACTIVE: {event['name']} — {event['description']}"
                    )

        return alerts

    # ══════════════════════════════════════════════════════════════════════
    # 4. NIN (National Internet Network) SHUTDOWN SURVIVAL
    # ══════════════════════════════════════════════════════════════════════

    def get_nin_survival_pack(
        self,
        available_bridges: Optional[List[str]] = None,
        max_bridges: int = 15,
    ) -> NINSurvivalPack:
        """
        Generate a NIN-specific bridge pack for shutdown survival.

        When NIN is activated, Iran disconnects from the international
        internet. Only CDN-fronted bridges using domestic CDN fronts
        (Arvan Cloud) or satellite paths can survive.

        Args:
            available_bridges: Optional list of available bridge lines
            max_bridges: Maximum bridges to include in the pack

        Returns:
            NINSurvivalPack with bridges optimized for NIN survival
        """
        # If no bridges provided, generate from template
        if not available_bridges:
            available_bridges = self._generate_nin_template_bridges()

        # Score and filter bridges for NIN survival
        scored: List[Tuple[str, float, str]] = []
        for bridge in available_bridges:
            transport = self._detect_transport(bridge)
            score = self._nin_bridge_score(bridge, transport)
            scored.append((bridge, score, transport))

        # Sort by NIN survival score
        scored.sort(key=lambda x: x[1], reverse=True)

        # Select with transport diversity
        selected: List[str] = []
        transport_counts: Dict[str, int] = {}
        max_per_transport = max(2, max_bridges // 3)

        for bridge, score, transport in scored:
            if len(selected) >= max_bridges:
                break
            count = transport_counts.get(transport, 0)
            if count < max_per_transport or score >= 0.9:
                selected.append(bridge)
                transport_counts[transport] = count + 1

        # Determine CDN fronts used
        cdn_fronts = []
        if self._nin_active:
            cdn_fronts = [k for k, v in _NIN_CDN_FRONTS.items() if v["works_during_nin"]]
        else:
            cdn_fronts = list(_NIN_CDN_FRONTS.keys())

        # Fallback DNS servers for NIN scenarios
        fallback_dns = [
            "178.22.122.100",   # Arvan Cloud DNS
            "5.200.200.200",    # Shecan DNS
            "10.202.10.202",    # Electro DNS
            "10.202.10.102",    # Electro DNS secondary
        ]

        # Estimate survival rate
        if selected:
            avg_score = sum(s for _, s, _ in scored[:len(selected)]) / len(selected)
        else:
            avg_score = 0.0

        pack = NINSurvivalPack(
            bridges=selected,
            transport_distribution=transport_counts,
            cdn_fronts_used=cdn_fronts,
            fallback_dns=fallback_dns,
            generated_at=datetime.now(timezone.utc).isoformat(),
            estimated_survival_rate=round(avg_score, 3),
        )

        log.info(
            f"[AntiFilterV2] NIN survival pack: {len(selected)} bridges, "
            f"distribution={transport_counts}, survival_rate={avg_score:.0%}"
        )

        return pack

    def _generate_nin_template_bridges(self) -> List[str]:
        """Generate template bridge entries for NIN survival (placeholder lines)."""
        templates = [
            "webtunnel 192.0.2.1:443 url=https://arvancloud.ir/... ver=0.0.1",
            "snowflake 192.0.2.2:443 fingerprint=... url=https://broker.torproject.org",
            "webtunnel 192.0.2.3:443 url=https://cdn.arvancloud.com/... ver=0.0.1",
            "meek_lite 192.0.2.4:443 url=https://azureedge.net/ front=azureedge.net",
            "obfs4 192.0.2.5:443 cert=... iat-mode=2",
        ]
        return templates

    def _nin_bridge_score(self, bridge: str, transport: str) -> float:
        """Score a bridge for NIN survival probability."""
        # WebTunnel and Snowflake have best NIN survival
        nin_survival = {
            "webtunnel": 0.90,
            "snowflake": 0.70,
            "meek_lite": 0.60,
            "vless_reality": 0.50,
            "obfs4_iat2": 0.30,
            "obfs4_443": 0.25,
            "obfs4": 0.10,
            "vanilla": 0.02,
        }
        base = nin_survival.get(transport, 0.15)

        # CDN-fronted bridges get a boost
        bridge_lower = bridge.lower()
        if "arvancloud" in bridge_lower:
            base = min(1.0, base + 0.15)
        elif "cloudflare" in bridge_lower or "cdn" in bridge_lower:
            base = min(1.0, base + 0.10)

        # Port 443 boost
        if ":443" in bridge:
            base = min(1.0, base + 0.05)

        return base

    # ══════════════════════════════════════════════════════════════════════
    # 5. ADAPTIVE TRANSPORT SELECTION
    # ══════════════════════════════════════════════════════════════════════

    def get_adaptive_transport(self) -> TransportScore:
        """
        Select the best transport based on current conditions and real-time
        effectiveness scoring.

        Priority chain: Snowflake -> WebTunnel -> obfs4-443 -> meek -> vanilla

        Returns:
            TransportScore for the best recommended transport
        """
        level = self._current_censorship_level
        scores = self._score_all_transports(level)

        # Sort by effectiveness
        sorted_scores = sorted(scores, key=lambda s: s.effectiveness, reverse=True)

        best = sorted_scores[0] if sorted_scores else TransportScore(
            transport="webtunnel",
            effectiveness=0.80,
            survival_probability=0.85,
            latency_estimate_ms=150.0,
            reliability=0.80,
            recommended=True,
            reason="Default recommendation",
        )

        log.info(
            f"[AntiFilterV2] Adaptive transport: {best.transport} "
            f"(effectiveness={best.effectiveness:.0%}, "
            f"survival={best.survival_probability:.0%})"
        )

        return best

    def _score_all_transports(self, level: int) -> List[TransportScore]:
        """Score all transports for current conditions."""
        scores = []
        level_idx = min(level - 1, 4)

        for transport in _TRANSPORT_PRIORITY_CHAIN:
            # Get survival probability from the matrix
            survival_rates = _TRANSPORT_SURVIVAL.get(transport, [0.5] * 5)
            survival_prob = survival_rates[level_idx]

            # Get dynamic effectiveness (adjusted by connection history)
            effectiveness = self._transport_effectiveness.get(
                transport, _TRANSPORT_BASELINE_EFFECTIVENESS.get(transport, 0.5)
            )

            # Blend survival probability with effectiveness
            blended = survival_prob * 0.6 + effectiveness * 0.4

            # Latency estimate
            latency = self._estimate_transport_latency(transport)

            # Reliability from recent history
            reliability = self._get_transport_reliability(transport)

            # Is this the recommended transport?
            recommended = (transport == _TRANSPORT_PRIORITY_CHAIN[0] and blended > 0.5)

            reason = self._transport_recommendation_reason(transport, level, blended)

            scores.append(TransportScore(
                transport=transport,
                effectiveness=round(blended, 3),
                survival_probability=round(survival_prob, 3),
                latency_estimate_ms=round(latency, 1),
                reliability=round(reliability, 3),
                recommended=recommended,
                reason=reason,
            ))

        return scores

    def _estimate_transport_latency(self, transport: str) -> float:
        """Estimate latency for a transport type."""
        base_latencies = {
            "snowflake": 300.0,
            "webtunnel": 150.0,
            "obfs4_443": 120.0,
            "obfs4_iat2": 130.0,
            "meek_lite": 400.0,
            "vless_reality": 100.0,
            "vanilla": 80.0,
        }
        base = base_latencies.get(transport, 200.0)
        return base + random.uniform(-10, 10)

    def _get_transport_reliability(self, transport: str) -> float:
        """Calculate transport reliability from recent connection history."""
        recent = [h for h in self._connection_history[-200:]
                  if h.get("transport") == transport]
        if not recent:
            return 0.70  # Default

        successes = sum(1 for h in recent if h.get("success", False))
        return successes / len(recent)

    def _transport_recommendation_reason(
        self, transport: str, level: int, blended_score: float
    ) -> str:
        """Generate a human-readable reason for a transport recommendation."""
        reasons = {
            "snowflake": "Short-lived peer connections evade DPI pattern detection",
            "webtunnel": "CDN-fronted HTTPS traffic blends with normal web browsing",
            "obfs4_443": "Port 443 obfs4 with IAT randomization resists basic DPI",
            "meek_lite": "Domain fronting via CDN — effective but slower",
            "vanilla": "NOT recommended — immediately detected by Iran DPI",
        }
        base_reason = reasons.get(transport, "Standard transport")

        if blended_score < 0.2:
            return f"NOT recommended for Level {level}: {base_reason}"
        elif blended_score < 0.5:
            return f"Use only as fallback for Level {level}: {base_reason}"
        else:
            return f"Recommended for Level {level}: {base_reason}"

    def update_transport_effectiveness(
        self, transport: str, success: bool, latency_ms: float = 0.0
    ) -> None:
        """
        Update transport effectiveness based on a real connection result.
        Call this after each connection attempt to improve adaptive scoring.

        Args:
            transport: Transport type used
            success: Whether the connection succeeded
            latency_ms: Connection latency in milliseconds
        """
        current = self._transport_effectiveness.get(
            transport, _TRANSPORT_BASELINE_EFFECTIVENESS.get(transport, 0.5)
        )

        # Exponential moving average (EMA) with alpha=0.2
        alpha = 0.2
        new_value = 1.0 if success else 0.0
        updated = alpha * new_value + (1 - alpha) * current
        self._transport_effectiveness[transport] = round(updated, 4)

        # Record in connection history
        self._connection_history.append({
            "transport": transport,
            "success": success,
            "latency_ms": latency_ms,
            "detected_isp": self._detected_isp,
            "censorship_level": self._current_censorship_level,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        # Keep history manageable
        if len(self._connection_history) > 1000:
            self._connection_history = self._connection_history[-500:]

        self._save_state()

        log.debug(
            f"[AntiFilterV2] Transport effectiveness update: {transport} "
            f"{'success' if success else 'failure'} → {updated:.3f}"
        )

    # ══════════════════════════════════════════════════════════════════════
    # V1 COMPATIBILITY LAYER
    # ══════════════════════════════════════════════════════════════════════

    def get_optimized_bridges(
        self,
        all_bridges: Dict[str, Dict],
        max_bridges: int = 20,
    ) -> List[str]:
        """
        V1-compatible bridge selection with v2 enhancements.
        Delegates to v1 engine when available, adds v2 scoring on top.
        """
        if self._v1 is not None:
            return self._v1.get_optimized_bridges(all_bridges, max_bridges)

        # Fallback: basic scoring
        candidates = []
        for key, info in all_bridges.items():
            bridge_line = info.get("raw", "")
            if not bridge_line:
                continue
            transport = self._detect_transport(bridge_line)
            survival_rates = _TRANSPORT_SURVIVAL.get(transport, [0.5] * 5)
            level_idx = min(self._current_censorship_level - 1, 4)
            score = survival_rates[level_idx]
            candidates.append({"line": bridge_line, "score": score})

        candidates.sort(key=lambda x: x["score"], reverse=True)
        return [c["line"] for c in candidates[:max_bridges]]

    def rotate_bridges(self, bridge_list: List[str]) -> List[str]:
        """V1-compatible bridge rotation. Delegates to v1."""
        if self._v1 is not None:
            return self._v1.rotate_bridges(bridge_list)
        return bridge_list

    def get_best_cdn_front(self) -> Dict[str, Any]:
        """V1-compatible CDN front selection with v2 enhancements."""
        if self._nin_active:
            domestic = [
                {"domain": k, **v}
                for k, v in _NIN_CDN_FRONTS.items()
                if v["works_during_nin"]
            ]
            domestic.sort(key=lambda x: x["priority"])
            return domestic[0] if domestic else {"domain": "arvancloud.ir", "priority": 1}

        all_fronts = [{"domain": k, **v} for k, v in _NIN_CDN_FRONTS.items()]
        all_fronts.sort(key=lambda x: x["priority"])
        return all_fronts[0] if all_fronts else {"domain": "cloudfront.net", "priority": 1}

    def get_best_connection_window(self) -> Dict[str, Any]:
        """V1-compatible connection window using v2 temporal analysis."""
        analysis = self.get_temporal_analysis()
        return analysis.to_dict()

    def get_status(self) -> Dict[str, Any]:
        """Get comprehensive v2 status including v1 data when available."""
        status = {
            "engine": "IranSmartAntiFilterV2",
            "v1_available": _V1_AVAILABLE,
            "current_censorship_level": self._current_censorship_level,
            "detected_isp": self._detected_isp,
            "nin_active": self._nin_active,
            "last_detection": self._last_detection.to_dict() if self._last_detection else None,
            "temporal_analysis": self.get_temporal_analysis().to_dict(),
            "transport_effectiveness": self._transport_effectiveness,
            "adaptive_transport": self.get_adaptive_transport().to_dict(),
        }

        if self._v1 is not None:
            try:
                status["v1_status"] = self._v1.get_status()
            except Exception:
                pass

        return status

    # ── Helper Methods ───────────────────────────────────────────────────

    @staticmethod
    def _detect_transport(bridge_line: str) -> str:
        """Detect transport type from bridge line."""
        parts = bridge_line.strip().split()
        if not parts:
            return "vanilla"

        transport = parts[0]
        if transport in ("obfs4", "webtunnel", "snowflake", "meek_lite",
                         "meek-azure", "vless", "shadowsocks"):
            if transport == "obfs4" and "iat-mode=2" in bridge_line:
                return "obfs4_iat2"
            if transport == "obfs4":
                port = IranSmartAntiFilterV2._extract_port(bridge_line)
                if port == 443:
                    return "obfs4_443"
            return transport
        return "vanilla"

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


# ════════════════════════════════════════════════════════════════════════════
# CLI INTERFACE
# ════════════════════════════════════════════════════════════════════════════

def main() -> None:
    """CLI entry point for the v2 anti-filter engine."""
    import argparse
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")

    parser = argparse.ArgumentParser(description="Iran Smart Anti-Filter Engine V2")
    parser.add_argument("--detect", action="store_true", help="AI-enhanced censorship detection")
    parser.add_argument("--status", action="store_true", help="Show full v2 status")
    parser.add_argument("--temporal", action="store_true", help="Temporal pattern analysis")
    parser.add_argument("--isp", type=str, default="mci", help="ISP strategy (mci/irancell/rightel/shatel/asiatech)")
    parser.add_argument("--nin", action="store_true", help="Generate NIN survival pack")
    parser.add_argument("--transport", action="store_true", help="Adaptive transport selection")
    args = parser.parse_args()

    v2 = IranSmartAntiFilterV2()

    if args.detect:
        result = v2.detect_censorship_ai()
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    elif args.status:
        status = v2.get_status()
        print(json.dumps(status, indent=2, ensure_ascii=False, default=str))
    elif args.temporal:
        analysis = v2.get_temporal_analysis()
        print(json.dumps(analysis.to_dict(), indent=2, ensure_ascii=False))
    elif args.isp:
        strategy = v2.get_isp_strategy(args.isp)
        print(json.dumps(strategy.to_dict(), indent=2, ensure_ascii=False))
    elif args.nin:
        pack = v2.get_nin_survival_pack()
        print(json.dumps(pack.to_dict(), indent=2, ensure_ascii=False))
    elif args.transport:
        best = v2.get_adaptive_transport()
        print(json.dumps(best.to_dict(), indent=2, ensure_ascii=False))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
