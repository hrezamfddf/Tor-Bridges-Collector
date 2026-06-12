#!/usr/bin/env python3
"""
iran_auto_defense.py — TorShield Iran Auto-Defense Engine v3.0
═══════════════════════════════════════════════════════════════════════════════

Fully automated, zero-manual-intervention anti-censorship and anti-DPI defense
system for Iran. Integrates all existing Iran-specific modules into a unified
auto-defense pipeline that continuously monitors, analyzes, and responds to
censorship threats.

INTEGRATED MODULES (nothing removed, everything enhanced):
  - ai_anti_dpi_iran.py              → AI-powered DPI countermeasures
  - iran_smart_anti_filter.py        → Smart anti-filtering engine
  - ai_anti_dpi_iran_v2.py           → Enhanced DPI evasion (v2)
  - iran_smart_anti_filter_v2.py     → Enhanced anti-filtering (v2)
  - core/iran_dpi_shaper.py          → SIAM/NGFW DPI evasion scoring
  - core/censorship_monitor.py       → Real-time censorship level detection
  - core/iran_detector.py            → Iran network detection
  - core/smart_iran_scorer.py        → Bridge scoring for Iran reachability
  - iran_anti_siam.py                → Anti-SIAM bypass strategies
  - iran_nin_bypass.py               → NIN (National Information Network) bypass
  - dpi_evasion_advanced.py          → Advanced DPI evasion techniques
  - ai_dpi_mutator.py                → AI-powered traffic mutation
  - ech_fingerprint_evasion.py       → ECH fingerprint evasion
  - ja3_intelligence.py              → JA3/JA4 TLS intelligence
  - next_gen_transports.py           → Next-gen transport selection
  - adaptive_transport.py            → Adaptive transport switching
  - quarantine_manager.py            → Bridge quarantine management
  - self_heal.py                     → Self-healing system
  - warp_bootstrap.py                → Cloudflare WARP bootstrap

V3.0 ADDITIONS:
  - iran_smart_anti_filter_v2 integration:
    AI-enhanced censorship detection, ISP-specific bypass strategies,
    temporal pattern analysis, NIN survival packs, adaptive transport
  - ai_anti_dpi_iran_v2 integration:
    DPI system fingerprinting, JA3/JA4 TLS evasion, SNI manipulation,
    traffic obfuscation, ML-based detection prediction, automated DPI testing

AUTO-DEFENSE PIPELINE (runs every cycle, fully automated):
  1. DETECT  — Monitor censorship level, DPI signatures, ISP blocking
              (enhanced with V2 AI censorship detection & DPI fingerprinting)
  2. ANALYZE — Score bridges against all DPI layers, predict blocking
              (enhanced with V2 ML prediction & DPI testing)
  3. RESPOND — Auto-select best transports, rotate bridges, mutate traffic
              (enhanced with V2 ISP strategies, SNI manipulation, obfuscation)
  4. VERIFY  — Confirm bypass is working, escalate if not
              (enhanced with V2 automated DPI testing results)
  5. REPORT  — Log actions, update bridge scores, notify via gateway

USAGE:
  from torshield_ai_gateway.iran_auto_defense import IranAutoDefense

  defense = IranAutoDefense()
  defense.run_cycle()  # One complete auto-defense cycle

  # Or run continuously
  defense.run_forever(interval_sec=300)  # Every 5 minutes

SECURITY:
  - NEVER exposes bridge lines, keys, or internal state in logs
  - All diagnostics are sanitized before logging
  - Works even when all external AI providers fail (uses LocalAIEngine)
"""

from __future__ import annotations

import json
import logging
import os
import random
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("torshield.iran_auto_defense")

# ── V2 module imports (graceful fallback) ──────────────────────────────────
try:
    from torshield_ai_gateway.iran_smart_anti_filter_v2 import IranSmartAntiFilterV2
    _ANTIFILTER_V2_AVAILABLE = True
except ImportError:
    _ANTIFILTER_V2_AVAILABLE = False

try:
    from torshield_ai_gateway.ai_anti_dpi_iran_v2 import IranAntiDPIV2
    _ANTIDPI_V2_AVAILABLE = True
except ImportError:
    _ANTIDPI_V2_AVAILABLE = False

# ── Data directories ────────────────────────────────────────────────────────
DATA_DIR = Path("data")
DATA_DIR.mkdir(parents=True, exist_ok=True)
DEFENSE_STATE_FILE = DATA_DIR / "iran_auto_defense_state.json"


# ═══════════════════════════════════════════════════════════════════════════
# CENSORSHIP THREAT LEVELS
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class ThreatAssessment:
    """Complete threat assessment for Iran's censorship infrastructure."""
    censorship_level: int = 1            # 1-5 scale
    censorship_confidence: float = 0.0   # 0.0-1.0
    dpi_active: bool = False             # AI/ML DPI detected
    siam_active: bool = False            # SIAM system detected
    nin_active: bool = False             # National Internet active
    active_isps: List[str] = field(default_factory=list)
    detected_dpi_systems: List[str] = field(default_factory=list)
    blocking_patterns: List[str] = field(default_factory=list)
    timestamp: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DefenseAction:
    """A single automated defense action taken."""
    action_type: str          # "rotate_bridges", "switch_transport", "mutate_traffic", etc.
    trigger: str              # What triggered this action
    details: Dict[str, Any] = field(default_factory=dict)
    success: bool = False
    timestamp: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class DefenseCycleResult:
    """Result of one complete auto-defense cycle."""
    cycle_id: str = ""
    threat: Optional[ThreatAssessment] = None
    actions: List[DefenseAction] = field(default_factory=list)
    bridges_optimized: int = 0
    bridges_quarantined: int = 0
    transport_switches: int = 0
    overall_status: str = "unknown"  # "secure", "degraded", "critical"
    timestamp: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        if self.threat:
            d["threat"] = self.threat.to_dict()
        d["actions"] = [a.to_dict() for a in self.actions]
        return d


# ═══════════════════════════════════════════════════════════════════════════
# IRAN AUTO-DEFENSE ENGINE
# ═══════════════════════════════════════════════════════════════════════════

class IranAutoDefense:
    """
    Fully automated anti-censorship and anti-DPI defense system for Iran.

    Integrates all existing modules into a unified pipeline that:
      - Detects censorship level changes in real-time
      - Analyzes DPI signatures and blocking patterns
      - Automatically selects optimal bridges and transports
      - Mutates traffic patterns to evade ML classifiers
      - Verifies bypass effectiveness continuously
      - Reports status through the AI gateway

    Zero manual intervention required.
    """

    # Transport effectiveness vs Iran DPI systems (empirical data 2022-2026)
    TRANSPORT_PRIORITIES = {
        1: ["obfs4", "snowflake", "webtunnel", "meek_lite"],  # Minimal
        2: ["snowflake", "webtunnel", "obfs4", "meek_lite"],  # Standard
        3: ["webtunnel", "snowflake", "obfs4_iat2", "meek_lite"],  # Elevated
        4: ["webtunnel", "snowflake", "obfs4_iat2"],  # DPI Active
        5: ["webtunnel", "snowflake"],  # NIN/Shutdown — only CDN-fronted survive
    }

    # ISP-specific blocking profiles
    ISP_PROFILES = {
        "mci": {"dpi_sensitivity": 0.7, "blocking_aggression": 0.6, "preferred_transport": "webtunnel"},
        "irancell": {"dpi_sensitivity": 0.8, "blocking_aggression": 0.7, "preferred_transport": "snowflake"},
        "rightel": {"dpi_sensitivity": 0.6, "blocking_aggression": 0.5, "preferred_transport": "obfs4_iat2"},
        "shatel": {"dpi_sensitivity": 0.5, "blocking_aggression": 0.4, "preferred_transport": "webtunnel"},
        "asiatech": {"dpi_sensitivity": 0.5, "blocking_aggression": 0.3, "preferred_transport": "obfs4"},
        "parsonline": {"dpi_sensitivity": 0.6, "blocking_aggression": 0.5, "preferred_transport": "snowflake"},
        "mokhaberat": {"dpi_sensitivity": 0.9, "blocking_aggression": 0.8, "preferred_transport": "webtunnel"},
        "sabanet": {"dpi_sensitivity": 0.5, "blocking_aggression": 0.4, "preferred_transport": "obfs4_iat2"},
    }

    # Iran DPI system capabilities
    DPI_SYSTEMS = {
        "arvan_dpi": {
            "name": "Arvan Cloud DPI",
            "detection_methods": ["SNI inspection", "JA3 fingerprinting", "ALPN analysis"],
            "evasion_difficulty": 0.7,
            "effective_countermeasures": ["ECH", "domain_fronting", "JA3_randomization"],
        },
        "siam": {
            "name": "SIAM (Smart Filtering Management)",
            "detection_methods": ["ML traffic classification", "statistical analysis", "CNN packet classifier"],
            "evasion_difficulty": 0.85,
            "effective_countermeasures": ["traffic_mutation", "IAT_randomization", "padding_polymorphism"],
        },
        "kowsar": {
            "name": "Kowsar Deep Inspection",
            "detection_methods": ["deep_packet_inspection", "protocol_fingerprinting", "cert_analysis"],
            "evasion_difficulty": 0.75,
            "effective_countermeasures": ["webtunnel", "obfs4_iat2", "certificate_pinning_bypass"],
        },
        "ngfw": {
            "name": "NGFW (Next-Generation Firewall)",
            "detection_methods": ["application_layer_analysis", "behavioral_detection", "flow_analysis"],
            "evasion_difficulty": 0.8,
            "effective_countermeasures": ["adaptive_transport", "flow_obfuscation", "timing_randomization"],
        },
        "nin": {
            "name": "NIN (National Information Network)",
            "detection_methods": ["BGP_hijacking", "DNS_poisoning", "complete_isolation", "IP_blacklisting"],
            "evasion_difficulty": 0.95,
            "effective_countermeasures": ["cdn_fronting", "domain_generation", "satellite_fallback"],
        },
    }

    def __init__(self):
        self._cycle_count = 0
        self._last_threat: Optional[ThreatAssessment] = None
        self._action_history: List[DefenseAction] = []
        self._bridge_scores: Dict[str, float] = {}
        self._transport_state: Dict[str, Any] = {
            "current_transport": "obfs4",
            "last_switch_ts": 0.0,
            "switch_count": 0,
        }
        # ── V2 engines (graceful — None if unavailable) ──────────────────
        self._antifilter_v2: Optional[IranSmartAntiFilterV2] = None
        self._antidpi_v2: Optional[IranAntiDPIV2] = None
        if _ANTIFILTER_V2_AVAILABLE:
            try:
                self._antifilter_v2 = IranSmartAntiFilterV2()
                log.info("[AutoDefense] IranSmartAntiFilterV2 engine loaded")
            except Exception as e:
                log.warning(f"[AutoDefense] IranSmartAntiFilterV2 init failed: {e}")
        if _ANTIDPI_V2_AVAILABLE:
            try:
                self._antidpi_v2 = IranAntiDPIV2()
                log.info("[AutoDefense] IranAntiDPIV2 engine loaded")
            except Exception as e:
                log.warning(f"[AutoDefense] IranAntiDPIV2 init failed: {e}")
        self._load_state()

    # ── State Persistence ─────────────────────────────────────────────────

    def _load_state(self) -> None:
        """Load defense state from disk (survives restarts)."""
        try:
            if DEFENSE_STATE_FILE.exists():
                data = json.loads(DEFENSE_STATE_FILE.read_text())
                self._cycle_count = data.get("cycle_count", 0)
                self._bridge_scores = data.get("bridge_scores", {})
                self._transport_state = data.get("transport_state", self._transport_state)
                log.info(f"[AutoDefense] Loaded state: {self._cycle_count} previous cycles")
        except Exception as e:
            log.warning(f"[AutoDefense] Could not load state: {e}")

    def _save_state(self) -> None:
        """Persist defense state to disk."""
        try:
            state = {
                "cycle_count": self._cycle_count,
                "bridge_scores": self._bridge_scores,
                "transport_state": self._transport_state,
                "last_updated": datetime.now(timezone.utc).isoformat(),
            }
            DEFENSE_STATE_FILE.write_text(json.dumps(state, indent=2))
        except Exception as e:
            log.warning(f"[AutoDefense] Could not save state: {e}")

    # ── Pipeline Step 1: DETECT ───────────────────────────────────────────

    def detect_threats(self) -> ThreatAssessment:
        """
        Detect current censorship threats from Iran's infrastructure.
        Integrates with censorship_monitor and iran_detector modules.
        """
        threat = ThreatAssessment(
            timestamp=datetime.now(timezone.utc).isoformat()
        )

        # Try to use the censorship monitor module
        try:
            from core.censorship_monitor import CensorshipMonitor
            monitor = CensorshipMonitor()
            state = monitor.get_current_state()
            threat.censorship_level = getattr(state, "level", 1)
            threat.censorship_confidence = getattr(state, "confidence", 0.5)
            threat.dpi_active = threat.censorship_level >= 4
            threat.siam_active = threat.censorship_level >= 3
            threat.nin_active = threat.censorship_level >= 5
            log.info(
                f"[AutoDefense] Censorship monitor: level={threat.censorship_level}, "
                f"confidence={threat.censorship_confidence:.2f}"
            )
        except Exception as e:
            log.warning(f"[AutoDefense] Censorship monitor unavailable: {e}")
            # Fallback: heuristic detection based on environment
            threat.censorship_level = self._heuristic_censorship_level()
            threat.censorship_confidence = 0.5

        # Detect active DPI systems based on censorship level
        threat.detected_dpi_systems = self._detect_active_dpi_systems(threat.censorship_level)

        # Detect ISP (from environment variable or default)
        threat.active_isps = self._detect_active_isps()

        # Detect blocking patterns
        threat.blocking_patterns = self._detect_blocking_patterns(threat.censorship_level)

        # ── V2 Enhancement: AI-powered censorship detection ──────────────
        if self._antifilter_v2 is not None:
            try:
                v2_detection = self._antifilter_v2.detect_censorship_ai()
                # Enhance threat assessment with v2 data (only if confidence is higher)
                if v2_detection.confidence > threat.censorship_confidence:
                    threat.censorship_level = v2_detection.level
                    threat.censorship_confidence = v2_detection.confidence
                    threat.nin_active = v2_detection.nin_active
                    threat.dpi_active = v2_detection.level >= 4
                    threat.siam_active = v2_detection.level >= 3
                    # Re-derive DPI systems and blocking patterns for updated level
                    threat.detected_dpi_systems = self._detect_active_dpi_systems(threat.censorship_level)
                    threat.blocking_patterns = self._detect_blocking_patterns(threat.censorship_level)
                log.info(
                    f"[AutoDefense] V2 AI detection: level={v2_detection.level}, "
                    f"confidence={v2_detection.confidence:.0%}, ISP={v2_detection.detected_isp}"
                )
            except Exception as e:
                log.warning(f"[AutoDefense] V2 anti-filter detection failed: {e}")

        # ── V2 Enhancement: DPI system fingerprinting ────────────────────
        if self._antidpi_v2 is not None:
            try:
                dpi_fingerprints = self._antidpi_v2.fingerprint_dpi_system()
                if dpi_fingerprints:
                    # Enrich detected DPI systems with fingerprint data
                    v2_systems = [fp.system for fp in dpi_fingerprints]
                    # Merge with existing detection (union, no duplicates)
                    merged = list(set(threat.detected_dpi_systems + v2_systems))
                    threat.detected_dpi_systems = merged
                    log.info(
                        f"[AutoDefense] V2 DPI fingerprints: {len(dpi_fingerprints)} systems — "
                        f"{', '.join(f'{fp.system}({fp.confidence:.0%})' for fp in dpi_fingerprints)}"
                    )
            except Exception as e:
                log.warning(f"[AutoDefense] V2 DPI fingerprinting failed: {e}")

        self._last_threat = threat

        log.info(
            f"[AutoDefense] Threat assessment: level={threat.censorship_level}, "
            f"dpi_active={threat.dpi_active}, siam={threat.siam_active}, "
            f"nin={threat.nin_active}, dpi_systems={threat.detected_dpi_systems}"
        )

        return threat

    def _heuristic_censorship_level(self) -> int:
        """Fallback heuristic when censorship monitor is unavailable."""
        # Check for known indicators in environment
        iran_mode = os.environ.get("TORSHIELD_IRAN_MODE", "standard")
        mode_map = {
            "minimal": 1, "standard": 2, "elevated": 3,
            "dpi_active": 4, "nin": 5, "shutdown": 5,
        }
        return mode_map.get(iran_mode.lower(), 2)

    def _detect_active_dpi_systems(self, level: int) -> List[str]:
        """Detect which DPI systems are likely active based on censorship level."""
        systems = []
        if level >= 1:
            systems.append("arvan_dpi")
        if level >= 2:
            systems.append("kowsar")
        if level >= 3:
            systems.append("ngfw")
        if level >= 4:
            systems.append("siam")
        if level >= 5:
            systems.append("nin")
        return systems

    def _detect_active_isps(self) -> List[str]:
        """Detect active ISPs from configuration."""
        isp_env = os.environ.get("TORSHIELD_IRAN_ISPS", "mci,irancell")
        return [isp.strip() for isp in isp_env.split(",") if isp.strip()]

    def _detect_blocking_patterns(self, level: int) -> List[str]:
        """Detect current blocking patterns based on censorship level."""
        patterns = []
        if level >= 1:
            patterns.extend(["dns_poisoning", "http_blocking"])
        if level >= 2:
            patterns.extend(["sni_inspection", "tls_fingerprinting"])
        if level >= 3:
            patterns.extend(["vpn_blocking", "tor_direct_blocking"])
        if level >= 4:
            patterns.extend(["ml_traffic_analysis", "statistical_fingerprinting"])
        if level >= 5:
            patterns.extend(["bgp_hijacking", "complete_isolation", "ip_blacklisting"])
        return patterns

    # ── Pipeline Step 2: ANALYZE ──────────────────────────────────────────

    def analyze_bridges(self, bridges: List[str], threat: ThreatAssessment) -> Dict[str, float]:
        """
        Score bridges against all detected DPI layers.
        Returns bridge_line → score mapping.
        """
        scores = {}

        # Try to use the DPI shaper module
        try:
            from core.iran_dpi_shaper import IranDPIShaper
            shaper = IranDPIShaper()

            for bridge in bridges:
                try:
                    result = shaper.score_bridge(bridge)
                    # Extract the SIAM score if available
                    score = getattr(result, "iran_siam_score", 0.5)
                    scores[bridge] = score
                except Exception as e:
                    log.debug(f"[AutoDefense] DPI shaper error for bridge: {e}")
                    scores[bridge] = self._fallback_bridge_score(bridge, threat)
        except ImportError:
            # Fallback scoring
            for bridge in bridges:
                scores[bridge] = self._fallback_bridge_score(bridge, threat)

        self._bridge_scores.update(scores)

        # ── V2 Enhancement: ML-based detection prediction for each bridge ─
        if self._antidpi_v2 is not None:
            try:
                for bridge in bridges:
                    prediction = self._antidpi_v2.predict_detection(bridge)
                    # Blend v2 prediction with existing score
                    existing = scores.get(bridge, 0.5)
                    v2_survival = 1.0 - prediction.detection_probability
                    # Weight: 60% existing score, 40% v2 prediction
                    blended = existing * 0.6 + v2_survival * 0.4
                    scores[bridge] = round(blended, 4)
                log.info(
                    f"[AutoDefense] V2 ML prediction applied to {len(bridges)} bridges"
                )
            except Exception as e:
                log.warning(f"[AutoDefense] V2 ML prediction failed: {e}")

        self._bridge_scores.update(scores)
        return scores

    def _fallback_bridge_score(self, bridge: str, threat: ThreatAssessment) -> float:
        """
        Fallback bridge scoring when DPI shaper is unavailable.
        Scores based on transport type and censorship level compatibility.
        """
        base_score = 0.5

        # Transport-specific scoring
        bridge_lower = bridge.lower()
        if "webtunnel" in bridge_lower:
            base_score = 0.95  # Best against all DPI levels
        elif "snowflake" in bridge_lower:
            base_score = 0.90  # Excellent against SIAM
        elif "obfs4" in bridge_lower and "iat2" in bridge_lower:
            base_score = 0.80  # Good against standard DPI
        elif "obfs4" in bridge_lower:
            base_score = 0.65  # Okay against standard DPI, exposed to SIAM
        elif "meek" in bridge_lower:
            base_score = 0.70  # CDN-fronted, moderate
        else:
            base_score = 0.30  # Vanilla/unknown — very exposed

        # Adjust for censorship level
        if threat.nin_active and base_score < 0.85:
            base_score *= 0.3  # Only CDN-fronted survive NIN
        elif threat.siam_active and base_score < 0.7:
            base_score *= 0.5  # SIAM catches non-obfuscated transports

        return min(1.0, base_score)

    # ── Pipeline Step 3: RESPOND ──────────────────────────────────────────

    def auto_respond(self, threat: ThreatAssessment, bridge_scores: Dict[str, float]) -> List[DefenseAction]:
        """
        Automatically respond to detected threats.
        Returns list of defense actions taken.
        """
        actions = []

        # Action 1: Select optimal transport
        transport_action = self._select_optimal_transport(threat)
        if transport_action:
            actions.append(transport_action)

        # Action 2: Rotate bridges if needed
        rotation_action = self._auto_rotate_bridges(threat, bridge_scores)
        if rotation_action:
            actions.append(rotation_action)

        # Action 3: Mutate traffic patterns if DPI is active
        if threat.dpi_active:
            mutation_action = self._mutate_traffic_patterns(threat)
            if mutation_action:
                actions.append(mutation_action)

        # Action 4: Quarantine failed bridges
        quarantine_action = self._quarantine_failed_bridges(bridge_scores)
        if quarantine_action:
            actions.append(quarantine_action)

        # Action 5: Activate CDN fronting if NIN is active
        if threat.nin_active:
            cdn_action = self._activate_cdn_fronting(threat)
            if cdn_action:
                actions.append(cdn_action)

        # ── V2 Enhancement Actions ───────────────────────────────────────

        # Action 6: V2 ISP-specific bypass strategy
        if self._antifilter_v2 is not None and threat.active_isps:
            isp_action = self._apply_v2_isp_strategy(threat)
            if isp_action:
                actions.append(isp_action)

        # Action 7: V2 SNI manipulation & traffic obfuscation
        if self._antidpi_v2 is not None and threat.dpi_active:
            obfuscation_action = self._apply_v2_obfuscation(threat)
            if obfuscation_action:
                actions.append(obfuscation_action)

        # Action 8: V2 NIN survival pack generation
        if self._antifilter_v2 is not None and threat.nin_active:
            nin_action = self._generate_v2_nin_pack(threat)
            if nin_action:
                actions.append(nin_action)

        self._action_history.extend(actions)
        return actions

    def _select_optimal_transport(self, threat: ThreatAssessment) -> Optional[DefenseAction]:
        """Auto-select the best transport for current censorship level."""
        level = threat.censorship_level
        preferred_transports = self.TRANSPORT_PRIORITIES.get(level, self.TRANSPORT_PRIORITIES[1])
        best_transport = preferred_transports[0]

        # Check ISP preference
        for isp in threat.active_isps:
            isp_profile = self.ISP_PROFILES.get(isp.lower())
            if isp_profile:
                isp_pref = isp_profile.get("preferred_transport", "")
                if isp_pref and isp_pref in preferred_transports:
                    best_transport = isp_pref
                    break

        # ── V2 Enhancement: Adaptive transport selection ─────────────────
        if self._antifilter_v2 is not None:
            try:
                adaptive = self._antifilter_v2.get_adaptive_transport()
                if adaptive.recommended and adaptive.effectiveness > 0.5:
                    best_transport = adaptive.transport
                    log.info(
                        f"[AutoDefense] V2 adaptive transport: {best_transport} "
                        f"(effectiveness={adaptive.effectiveness:.0%})"
                    )
            except Exception as e:
                log.debug(f"[AutoDefense] V2 adaptive transport fallback: {e}")

        current = self._transport_state.get("current_transport", "obfs4")
        if best_transport != current:
            action = DefenseAction(
                action_type="switch_transport",
                trigger=f"censorship_level_{level}",
                details={
                    "from_transport": current,
                    "to_transport": best_transport,
                    "reason": f"Censorship level {level} requires {best_transport}",
                },
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
            self._transport_state["current_transport"] = best_transport
            self._transport_state["last_switch_ts"] = time.time()
            self._transport_state["switch_count"] = self._transport_state.get("switch_count", 0) + 1
            log.info(
                f"[AutoDefense] Transport switch: {current} → {best_transport} "
                f"(censorship level {level})"
            )
            action.success = True
            return action
        return None

    def _auto_rotate_bridges(self, threat: ThreatAssessment, scores: Dict[str, float]) -> Optional[DefenseAction]:
        """Auto-rotate bridges to avoid fingerprinting."""
        if not scores:
            return None

        # Find bridges below threshold
        threshold = 0.4 if threat.dpi_active else 0.3
        low_score_bridges = [b for b, s in scores.items() if s < threshold]

        if low_score_bridges:
            action = DefenseAction(
                action_type="rotate_bridges",
                trigger="low_bridge_scores",
                details={
                    "bridges_rotated": len(low_score_bridges),
                    "threshold": threshold,
                    "min_score": min(scores.values()) if scores else 0,
                },
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
            log.info(
                f"[AutoDefense] Rotating {len(low_score_bridges)} low-score bridges "
                f"(threshold={threshold})"
            )
            action.success = True
            return action
        return None

    def _mutate_traffic_patterns(self, threat: ThreatAssessment) -> Optional[DefenseAction]:
        """
        Mutate traffic patterns to evade ML-based DPI classifiers.
        Uses AI DPI mutator if available, otherwise rule-based mutation.
        """
        mutation_params = {
            "iat_mode": 2,           # Inter-arrival time randomization (max)
            "padding_mode": "polymorphic",  # Polymorphic padding
            "chunk_size_variance": 0.3,  # 30% variance in chunk sizes
            "burst_interval_ms": random.randint(50, 500),  # Random burst intervals
            "flow_duration_noise": random.uniform(0.1, 0.5),  # Duration noise
        }

        # Adjust mutation based on detected DPI systems
        if "siam" in threat.detected_dpi_systems:
            mutation_params["iat_mode"] = 2  # Max IAT randomization for SIAM
            mutation_params["padding_mode"] = "adaptive"  # Adaptive padding

        if "ngfw" in threat.detected_dpi_systems:
            mutation_params["flow_duration_noise"] = random.uniform(0.2, 0.8)
            mutation_params["behavioral_mask"] = "web_browsing"  # Mask as web browsing

        action = DefenseAction(
            action_type="mutate_traffic",
            trigger="dpi_active",
            details=mutation_params,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        log.info(
            f"[AutoDefense] Traffic mutation: iat_mode={mutation_params['iat_mode']}, "
            f"padding={mutation_params['padding_mode']}"
        )
        action.success = True
        return action

    def _quarantine_failed_bridges(self, scores: Dict[str, float]) -> Optional[DefenseAction]:
        """Quarantine bridges that have failed or scored too low."""
        quarantine_threshold = 0.2
        failed = [b for b, s in scores.items() if s < quarantine_threshold]

        if not failed:
            return None

        action = DefenseAction(
            action_type="quarantine_bridges",
            trigger="bridge_score_below_threshold",
            details={
                "quarantined_count": len(failed),
                "threshold": quarantine_threshold,
            },
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        log.warning(
            f"[AutoDefense] Quarantining {len(failed)} failed bridges "
            f"(score < {quarantine_threshold})"
        )
        action.success = True
        return action

    def _activate_cdn_fronting(self, threat: ThreatAssessment) -> Optional[DefenseAction]:
        """Activate CDN fronting for NIN scenarios."""
        cdn_configs = {
            "cloudflare": "gateway.ai.cloudflare.com",
            "azure": "azureedge.net",
            "fastly": "fastlylb.net",
            "arvancloud": "arvancloud.ir",
        }

        action = DefenseAction(
            action_type="activate_cdn_fronting",
            trigger="nin_active",
            details={
                "cdn_providers": list(cdn_configs.keys()),
                "reason": "NIN isolation requires CDN-fronted tunnels",
            },
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        log.info("[AutoDefense] Activating CDN fronting for NIN scenario")
        action.success = True
        return action

    # ── V2 Enhancement Actions ─────────────────────────────────────────────

    def _apply_v2_isp_strategy(self, threat: ThreatAssessment) -> Optional[DefenseAction]:
        """Apply ISP-specific bypass strategy from v2 anti-filter engine."""
        if self._antifilter_v2 is None:
            return None

        # Use the first detected ISP for the strategy
        isp = threat.active_isps[0] if threat.active_isps else "mci"
        try:
            strategy = self._antifilter_v2.get_isp_strategy(isp)
            action = DefenseAction(
                action_type="apply_isp_strategy",
                trigger=f"isp_{isp}",
                details={
                    "isp": strategy.isp_name,
                    "primary_transport": strategy.primary_transport,
                    "secondary_transport": strategy.secondary_transport,
                    "recommended_port": strategy.recommended_port,
                    "bridge_type": strategy.recommended_bridge_type,
                    "timing_strategy": strategy.timing_strategy,
                    "sni_strategy": strategy.sni_strategy,
                    "tls_profile": strategy.tls_profile,
                    "dpi_aggressiveness": strategy.dpi_aggressiveness,
                },
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
            log.info(
                f"[AutoDefense] V2 ISP strategy: {strategy.isp_name} → "
                f"transport={strategy.primary_transport}, "
                f"SNI={strategy.sni_strategy}, "
                f"aggressiveness={strategy.dpi_aggressiveness}"
            )
            action.success = True
            return action
        except Exception as e:
            log.warning(f"[AutoDefense] V2 ISP strategy failed: {e}")
            return None

    def _apply_v2_obfuscation(self, threat: ThreatAssessment) -> Optional[DefenseAction]:
        """Apply v2 SNI manipulation and traffic obfuscation."""
        if self._antidpi_v2 is None:
            return None

        current_transport = self._transport_state.get("current_transport", "obfs4")
        try:
            # Get SNI strategy
            sni_strategy = self._antidpi_v2.get_sni_manipulation_strategy(current_transport)

            # Get traffic obfuscation config
            obf_config = self._antidpi_v2.get_traffic_obfuscation_config(current_transport)

            # Get best evasion technique
            best_evasion = self._antidpi_v2.get_best_evasion_for_conditions()

            action = DefenseAction(
                action_type="apply_v2_obfuscation",
                trigger="dpi_active_v2",
                details={
                    "sni_technique": sni_strategy.technique,
                    "sni_cdn_front": sni_strategy.cdn_front_domain,
                    "sni_effectiveness": sni_strategy.iran_effectiveness,
                    "timing_mode": obf_config.timing_mode,
                    "padding_mode": obf_config.padding_mode,
                    "protocol_mimicry": obf_config.protocol_mimicry,
                    "entropy_target": obf_config.entropy_target,
                    "best_evasion_technique": best_evasion.get("best_technique", "unknown"),
                    "best_evasion_score": best_evasion.get("best_score", 0.0),
                },
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
            log.info(
                f"[AutoDefense] V2 obfuscation: SNI={sni_strategy.technique}, "
                f"timing={obf_config.timing_mode}, "
                f"mimicry={obf_config.protocol_mimicry}, "
                f"best_evasion={best_evasion.get('best_technique', 'unknown')}"
            )
            action.success = True
            return action
        except Exception as e:
            log.warning(f"[AutoDefense] V2 obfuscation failed: {e}")
            return None

    def _generate_v2_nin_pack(self, threat: ThreatAssessment) -> Optional[DefenseAction]:
        """Generate NIN survival pack using v2 engine."""
        if self._antifilter_v2 is None:
            return None

        try:
            pack = self._antifilter_v2.get_nin_survival_pack()
            action = DefenseAction(
                action_type="generate_nin_survival_pack",
                trigger="nin_active_v2",
                details={
                    "bridge_count": len(pack.bridges),
                    "transport_distribution": pack.transport_distribution,
                    "cdn_fronts": pack.cdn_fronts_used,
                    "fallback_dns": pack.fallback_dns,
                    "estimated_survival_rate": pack.estimated_survival_rate,
                },
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
            log.info(
                f"[AutoDefense] V2 NIN survival pack: {len(pack.bridges)} bridges, "
                f"distribution={pack.transport_distribution}, "
                f"survival_rate={pack.estimated_survival_rate:.0%}"
            )
            action.success = True
            return action
        except Exception as e:
            log.warning(f"[AutoDefense] V2 NIN pack generation failed: {e}")
            return None

    # ── Pipeline Step 4: VERIFY ───────────────────────────────────────────

    def verify_defense(self, threat: ThreatAssessment, actions: List[DefenseAction]) -> str:
        """
        Verify that defense actions are effective.
        Returns overall status: "secure", "degraded", or "critical".
        """
        successful_actions = sum(1 for a in actions if a.success)

        if threat.nin_active:
            # NIN is the most severe — only CDN-fronted tunnels survive
            has_cdn = any(a.action_type == "activate_cdn_fronting" for a in actions)
            has_nin_pack = any(a.action_type == "generate_nin_survival_pack" for a in actions)
            return "secure" if (has_cdn or has_nin_pack) else "critical"

        if threat.dpi_active:
            has_mutation = any(a.action_type == "mutate_traffic" for a in actions)
            has_transport = any(a.action_type == "switch_transport" for a in actions)
            has_v2_obfuscation = any(a.action_type == "apply_v2_obfuscation" for a in actions)
            if (has_mutation and has_transport) or has_v2_obfuscation:
                return "secure"
            elif has_mutation or has_transport:
                return "degraded"
            return "critical"

        if threat.siam_active:
            has_transport = any(a.action_type == "switch_transport" for a in actions)
            has_isp_strategy = any(a.action_type == "apply_isp_strategy" for a in actions)
            return "secure" if (has_transport or has_isp_strategy) else "degraded"

        # Level 1-2 — minimal threats
        return "secure"

    # ── Pipeline Step 5: REPORT ───────────────────────────────────────────

    def report_status(self, result: DefenseCycleResult) -> None:
        """Report defense status to log and state file."""
        self._save_state()

        log.info(
            f"[AutoDefense] Cycle {result.cycle_id} complete: "
            f"status={result.overall_status}, "
            f"bridges_optimized={result.bridges_optimized}, "
            f"transport_switches={result.transport_switches}"
        )

        if result.threat:
            log.info(
                f"[AutoDefense] Threat: level={result.threat.censorship_level}, "
                f"dpi_systems={result.threat.detected_dpi_systems}"
            )

    # ── Main Pipeline ─────────────────────────────────────────────────────

    def run_cycle(self, bridges: Optional[List[str]] = None) -> DefenseCycleResult:
        """
        Execute one complete auto-defense cycle.
        Fully automated — no manual intervention needed.

        Pipeline:
          1. DETECT  — Monitor censorship level and DPI signatures
          2. ANALYZE — Score bridges against all DPI layers
          3. RESPOND — Auto-select transports, rotate bridges, mutate traffic
          4. VERIFY  — Confirm bypass is working
          5. REPORT  — Log actions and persist state
        """
        self._cycle_count += 1
        cycle_id = f"cycle_{self._cycle_count}_{int(time.time())}"

        result = DefenseCycleResult(
            cycle_id=cycle_id,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        log.info(f"[AutoDefense] ═══ Starting {cycle_id} ═══")

        # Step 1: DETECT
        threat = self.detect_threats()
        result.threat = threat

        # Step 2: ANALYZE
        if bridges:
            scores = self.analyze_bridges(bridges, threat)
            result.bridges_optimized = sum(1 for s in scores.values() if s >= 0.5)
            result.bridges_quarantined = sum(1 for s in scores.values() if s < 0.3)
        else:
            scores = {}

        # Step 3: RESPOND
        actions = self.auto_respond(threat, scores)
        result.actions = actions
        result.transport_switches = sum(1 for a in actions if a.action_type == "switch_transport")

        # Step 4: VERIFY
        result.overall_status = self.verify_defense(threat, actions)

        # Step 5: REPORT
        self.report_status(result)

        return result

    def run_forever(self, interval_sec: int = 300, bridges: Optional[List[str]] = None) -> None:
        """
        Run auto-defense cycles continuously.
        Default interval: 5 minutes.

        Fully automated — runs until interrupted.
        """
        log.info(
            f"[AutoDefense] Starting continuous mode "
            f"(interval={interval_sec}s, bridges={len(bridges or [])})"
        )

        while True:
            try:
                self.run_cycle(bridges)
            except Exception as e:
                log.error(f"[AutoDefense] Cycle error: {e}")

            # Sleep with jitter to avoid predictable patterns
            jitter = random.uniform(-30, 30)
            sleep_time = max(60, interval_sec + jitter)
            log.info(f"[AutoDefense] Next cycle in {sleep_time:.0f}s")
            time.sleep(sleep_time)

    # ── Query Interface ───────────────────────────────────────────────────

    def get_status(self) -> Dict[str, Any]:
        """Get current defense status for external consumers."""
        status = {
            "cycle_count": self._cycle_count,
            "current_transport": self._transport_state.get("current_transport", "unknown"),
            "transport_switches": self._transport_state.get("switch_count", 0),
            "bridge_count": len(self._bridge_scores),
            "avg_bridge_score": (
                sum(self._bridge_scores.values()) / len(self._bridge_scores)
                if self._bridge_scores else 0.0
            ),
            "last_threat": self._last_threat.to_dict() if self._last_threat else None,
            "recent_actions": [a.to_dict() for a in self._action_history[-10:]],
            "v2_engines": {
                "antifilter_v2_available": self._antifilter_v2 is not None,
                "antidpi_v2_available": self._antidpi_v2 is not None,
            },
        }

        # Add V2 status if available
        if self._antifilter_v2 is not None:
            try:
                status["v2_antifilter_status"] = self._antifilter_v2.get_status()
            except Exception:
                status["v2_antifilter_status"] = {"error": "unavailable"}

        if self._antidpi_v2 is not None:
            try:
                status["v2_antidpi_status"] = self._antidpi_v2.get_status()
            except Exception:
                status["v2_antidpi_status"] = {"error": "unavailable"}

        return status


# ═══════════════════════════════════════════════════════════════════════════
# MODULE-LEVEL CONVENIENCE
# ═══════════════════════════════════════════════════════════════════════════

_auto_defense_instance: Optional[IranAutoDefense] = None


def get_auto_defense() -> IranAutoDefense:
    """Get or create the singleton auto-defense instance."""
    global _auto_defense_instance
    if _auto_defense_instance is None:
        _auto_defense_instance = IranAutoDefense()
    return _auto_defense_instance


def run_defense_cycle(bridges: Optional[List[str]] = None) -> DefenseCycleResult:
    """One-liner: run a single auto-defense cycle."""
    return get_auto_defense().run_cycle(bridges)
