"""
local_ai_engine.py — TorShield Local AI Fallback Engine v1.0
═══════════════════════════════════════════════════════════════════════════

Provides a zero-dependency local AI fallback when ALL external AI providers
(Cerebras, Portkey, Cloudflare) are unavailable (403/400 errors).

This engine uses rule-based intelligence with pre-built knowledge bases
specifically optimized for Iran's DPI infrastructure, censorship patterns,
and bridge survival analysis. It requires NO external API calls.

CAPABILITIES:
  - Bridge scoring for Iran reachability (rule-based scoring)
  - Censorship level detection (Level 1-5)
  - DPI evasion strategy recommendation
  - NIN survival prediction
  - Transport stack recommendation
  - ISP-specific blocking predictions
  - Workflow failure pattern matching and fix suggestion
  - obfs4 parameter mutation hints

USAGE:
  from torshield_ai_gateway.local_ai_engine import LocalAIEngine
  engine = LocalAIEngine()
  result = engine.score_bridge("obfs4 1.2.3.4:443 ...")
"""

from __future__ import annotations

import json
import logging
import re
import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("torshield.ai.local")

# ════════════════════════════════════════════════════════════════════════════
# IRAN DPI KNOWLEDGE BASE (updated June 2026)
# ════════════════════════════════════════════════════════════════════════════

# Iran DPI infrastructure components
_IRAN_DPI_SYSTEMS = {
    "arvan_dpi": {
        "name": "Arvan Cloud DPI",
        "detection_methods": ["SNI inspection", "TLS fingerprinting (JA3)", "HTTP header analysis"],
        "blocks": ["Direct Tor", "obfs4 (non-443 ports)", "vanilla Tor", "OpenVPN"],
        "bypasses": ["obfs4 port 443 with iat-mode=2", "WebTunnel CDN-fronted", "Snowflake", "meek-lite"],
        "active_since": "2023-Q3",
    },
    "siam": {
        "name": "SIAM (Smart Integrated Access Management)",
        "detection_methods": ["ML traffic classification", "Statistical packet analysis", "Flow duration patterns"],
        "blocks": ["obfs4 (some)", "Shadowsocks (some)", "WireGuard"],
        "bypasses": ["WebTunnel via CDN", "Snowflake with AMP cache", "VLESS-Reality"],
        "active_since": "2024-Q1",
    },
    "nin": {
        "name": "National Internet Network (NIN) shutdown",
        "detection_methods": ["Complete international cut", "DNS hijacking", "BGP route withdrawal"],
        "blocks": ["ALL international traffic", "Direct VPN", "obfs4 non-CDN", "Snowflake (partial)"],
        "bypasses": ["CDN-fronted WebTunnel", "Arvan/Cloudflare CDN tunnels", "Domestic bridge relays"],
        "active_since": "2019 (intermittent)",
    },
    "kowsar": {
        "name": "Kowsar National Firewall",
        "detection_methods": ["Deep packet inspection", "Protocol fingerprinting", "Entropy analysis"],
        "blocks": ["Tor directory authorities", "obfs4 with known cert patterns", "SSH tunneling"],
        "bypasses": ["obfs4 with iat-mode=2", "WebTunnel HTTPS", "XTLS-Reality"],
        "active_since": "2024-Q2",
    },
    "ngfw": {
        "name": "NGFW (Next-Generation Firewall)",
        "detection_methods": ["Application-layer analysis", "Behavioral analysis", "Certificate pinning bypass detection"],
        "blocks": ["Some obfs4 bridges", "Unusual TLS patterns", "Known bridge IPs"],
        "bypasses": ["Snowflake (short-lived)", "meek-lite via Azure/Amazon", "WebTunnel"],
        "active_since": "2025-Q1",
    },
}

# ISP-specific blocking data (updated June 2026)
_IRAN_ISP_DATA = {
    "MCI": {
        "full_name": "Hamrah Aval (Mobile Communication Company of Iran)",
        "type": "mobile",
        "dpi_level": 4,
        "blocks": {
            "vanilla": "blocked",
            "obfs4": "degraded",
            "webtunnel": "works",
            "snowflake": "works",
            "meek_lite": "degraded",
        },
        "notes": "Heaviest DPI on mobile networks; obfs4 on port 443 sometimes works",
    },
    "IRANCELL": {
        "full_name": "Irancell (MTN Irancell)",
        "type": "mobile",
        "dpi_level": 4,
        "blocks": {
            "vanilla": "blocked",
            "obfs4": "degraded",
            "webtunnel": "works",
            "snowflake": "works",
            "meek_lite": "works",
        },
        "notes": "Slightly less aggressive than MCI; meek-lite often works",
    },
    "Rightel": {
        "full_name": "Rightel",
        "type": "mobile",
        "dpi_level": 3,
        "blocks": {
            "vanilla": "blocked",
            "obfs4": "works",
            "webtunnel": "works",
            "snowflake": "works",
            "meek_lite": "works",
        },
        "notes": "Lighter DPI than MCI/IRANCELL; obfs4 generally works",
    },
    "Shatel": {
        "full_name": "Shatel (Aftabeh Pars)",
        "type": "fixed",
        "dpi_level": 3,
        "blocks": {
            "vanilla": "blocked",
            "obfs4": "works",
            "webtunnel": "works",
            "snowflake": "works",
            "meek_lite": "works",
        },
        "notes": "Fixed-line ISP; generally less aggressive filtering",
    },
    "Asiatech": {
        "full_name": "Asiatech Data Transfer",
        "type": "fixed",
        "dpi_level": 3,
        "blocks": {
            "vanilla": "blocked",
            "obfs4": "degraded",
            "webtunnel": "works",
            "snowflake": "works",
            "meek_lite": "works",
        },
        "notes": "Some obfs4 bridges blocked; WebTunnel preferred",
    },
}

# Transport scoring weights for Iran (higher = better for Iran)
_IRAN_TRANSPORT_SCORES = {
    "snowflake":     {"base": 0.92, "nin_survival": 0.30, "dpi_resist": 0.95, "reason": "Short-lived proxies, hard to block"},
    "webtunnel":     {"base": 0.88, "nin_survival": 0.75, "dpi_resist": 0.90, "reason": "CDN-fronted HTTPS, survives NIN"},
    "meek_lite":     {"base": 0.82, "nin_survival": 0.55, "dpi_resist": 0.85, "reason": "Domain fronting via cloud CDNs"},
    "obfs4":         {"base": 0.72, "nin_survival": 0.20, "dpi_resist": 0.60, "reason": "Effective but DPI can detect patterns"},
    "obfs4_443":     {"base": 0.80, "nin_survival": 0.25, "dpi_resist": 0.75, "reason": "obfs4 on port 443 reduces detection"},
    "vanilla":       {"base": 0.10, "nin_survival": 0.05, "dpi_resist": 0.05, "reason": "Immediately detected and blocked"},
    "vless_reality": {"base": 0.90, "nin_survival": 0.70, "dpi_resist": 0.92, "reason": "XTLS Reality, strong DPI resistance"},
}

# Port scoring for Iran
_IRAN_PORT_SCORES = {
    443:   1.0,   # HTTPS — best, allowed by DPI
    80:    0.7,   # HTTP — allowed but inspected
    8080:  0.6,   # HTTP alt — sometimes allowed
    8443:  0.8,   # HTTPS alt — usually allowed
    2083:  0.75,  # cPanel HTTPS — often allowed
    2087:  0.75,  # cPanel HTTPS — often allowed
    2096:  0.70,  # cPanel HTTPS — often allowed
    9001:  0.3,   # Tor default — usually blocked
    993:   0.5,   # IMAPS — sometimes allowed
    995:   0.5,   # POP3S — sometimes allowed
}

# Temporal blocking patterns (Iran Standard Time = UTC+3:30)
_TEMPORAL_PATTERNS = {
    "peak_block_hours": [20, 21, 22, 23],     # Evening heavy DPI
    "low_block_hours":  [3, 4, 5, 6],          # Early morning light
    "weekend_modifier": "lighter",              # Weekends less aggressive
    "event_sensitivity": "high",                # Political events = heavy
    "best_window": "03:00-06:00 IRST",
}

# Known workflow failure patterns and fixes
_WORKFLOW_FIXES = {
    "ModuleNotFoundError": {
        "root_cause": "missing_python_dependency",
        "fix_type": "yaml_patch",
        "fix": "Add 'pip install -r requirements.txt' step before the failing step",
        "confidence": 0.95,
    },
    "SyntaxError": {
        "root_cause": "python_syntax_error",
        "fix_type": "python_patch",
        "fix": "Fix the syntax error in the reported file and line",
        "confidence": 0.90,
    },
    "HTTP Error 403": {
        "root_cause": "api_key_invalid_or_expired",
        "fix_type": "env_fix",
        "fix": "Rotate or update the API key in GitHub Secrets",
        "confidence": 0.85,
    },
    "HTTP Error 400": {
        "root_cause": "invalid_request_format",
        "fix_type": "python_patch",
        "fix": "Check request payload format; model ID may be deprecated",
        "confidence": 0.80,
    },
    "HTTP Error 429": {
        "root_cause": "rate_limit_exceeded",
        "fix_type": "yaml_patch",
        "fix": "Add rate limiting or use account rotation",
        "confidence": 0.90,
    },
    "cargo build failed": {
        "root_cause": "rust_compilation_error",
        "fix_type": "shell_fix",
        "fix": "Check Cargo.toml dependencies and Rust toolchain version",
        "confidence": 0.75,
    },
    "zipfile.BadZipFile": {
        "root_cause": "corrupted_artifact",
        "fix_type": "yaml_patch",
        "fix": "Add artifact integrity check and retry logic",
        "confidence": 0.70,
    },
    "Connection refused": {
        "root_cause": "service_unreachable",
        "fix_type": "env_fix",
        "fix": "Check network connectivity; may need proxy configuration",
        "confidence": 0.65,
    },
}


# ════════════════════════════════════════════════════════════════════════════
# LOCAL AI ENGINE
# ════════════════════════════════════════════════════════════════════════════

class LocalAIEngine:
    """
    Zero-dependency local AI engine for Iran bridge intelligence.
    Activated automatically when ALL external AI providers fail.
    Provides rule-based scoring, censorship detection, and fix suggestions.
    """

    def __init__(self):
        self._cache: Dict[str, Any] = {}
        log.info("[LocalAI] Initialized — zero external dependencies")

    # ── Bridge Parsing ────────────────────────────────────────────────────

    @staticmethod
    def _parse_bridge_line(bridge_line: str) -> Dict[str, Any]:
        """Extract transport type, address, port, and parameters from a bridge line."""
        parts = bridge_line.strip().split()
        transport = "vanilla"
        addr = ""
        port = 0
        params: Dict[str, str] = {}

        if not parts:
            return {"transport": transport, "addr": addr, "port": port, "params": params}

        # First part could be transport name or IP
        if parts[0] in ("obfs4", "webtunnel", "snowflake", "meek_lite",
                         "meek-azure", "vanilla", "vless", "shadowsocks"):
            transport = parts[0]
            if len(parts) > 1:
                addr_part = parts[1]
            else:
                addr_part = ""
        else:
            addr_part = parts[0]

        # Parse address:port
        if addr_part:
            if ":" in addr_part:
                addr, port_str = addr_part.rsplit(":", 1)
                try:
                    port = int(port_str)
                except ValueError:
                    port = 0
            else:
                addr = addr_part

        # Parse key=value parameters
        for p in parts[2:]:
            if "=" in p:
                k, v = p.split("=", 1)
                params[k] = v

        # Adjust transport for obfs4 on port 443
        if transport == "obfs4" and port == 443:
            transport = "obfs4_443"

        # Detect iat-mode
        iat_mode = params.get("iat-mode", "")
        if iat_mode == "2" and transport == "obfs4":
            transport = "obfs4_443"  # iat-mode=2 is best for Iran

        return {
            "transport": transport,
            "addr": addr,
            "port": port,
            "params": params,
        }

    # ── Bridge Scoring ────────────────────────────────────────────────────

    def score_bridge(self, bridge_line: str, censorship_level: int = 4) -> Dict[str, Any]:
        """
        Score a single bridge for Iran reachability using rule-based analysis.

        Args:
            bridge_line: Tor bridge line (e.g., "obfs4 1.2.3.4:443 cert=... iat-mode=2")
            censorship_level: Current Iran censorship level (1-5)

        Returns:
            {score, transport_ok, dpi_bypass_rating, nin_survival,
             isp_block_risk, recommendation, mutation_hint}
        """
        parsed = self._parse_bridge_line(bridge_line)
        transport = parsed["transport"]
        port = parsed["port"]

        # Get base transport scores
        t_scores = _IRAN_TRANSPORT_SCORES.get(transport, _IRAN_TRANSPORT_SCORES["vanilla"])

        # Port bonus
        port_bonus = _IRAN_PORT_SCORES.get(port, 0.3)

        # Censorship level modifier
        level_mod = max(0.1, 1.0 - (censorship_level - 1) * 0.15)

        # Compute composite score
        base_score = t_scores["base"] * 0.5 + port_bonus * 0.2 + t_scores["dpi_resist"] * 0.3
        score = min(1.0, base_score * level_mod)

        # Determine recommendation
        if score >= 0.75:
            recommendation = "use"
        elif score >= 0.45:
            recommendation = "test"
        else:
            recommendation = "avoid"

        # ISP block risk
        if t_scores["dpi_resist"] >= 0.85:
            isp_risk = "low"
        elif t_scores["dpi_resist"] >= 0.60:
            isp_risk = "medium"
        else:
            isp_risk = "high"

        # Mutation hint
        mutation_hint = ""
        if transport == "obfs4":
            iat_mode = parsed["params"].get("iat-mode", "0")
            if iat_mode != "2":
                mutation_hint = "Set iat-mode=2 for better DPI evasion"
            if port != 443:
                mutation_hint += "; move to port 443 if possible"
        elif transport == "vanilla":
            mutation_hint = "Switch to obfs4, WebTunnel, or Snowflake"

        return {
            "score": round(score, 3),
            "transport_ok": score > 0.4,
            "dpi_bypass_rating": round(t_scores["dpi_resist"], 3),
            "nin_survival": round(t_scores["nin_survival"], 3),
            "isp_block_risk": isp_risk,
            "recommendation": recommendation,
            "mutation_hint": mutation_hint,
            "source": "local_ai_engine",
        }

    def rank_bridges(self, bridge_lines: List[str], censorship_level: int = 4) -> List[Dict[str, Any]]:
        """Rank bridges from best to worst for Iran."""
        scored = []
        for line in bridge_lines:
            result = self.score_bridge(line, censorship_level)
            result["bridge_line"] = line
            scored.append(result)
        scored.sort(key=lambda x: x["score"], reverse=True)
        for i, s in enumerate(scored):
            s["rank"] = i + 1
        return scored

    # ── Censorship Detection ──────────────────────────────────────────────

    def detect_censorship_level(
        self,
        probe_results: Optional[Dict[str, str]] = None,
        nin_active: Optional[bool] = None,
    ) -> Dict[str, Any]:
        """
        Detect Iran censorship level (1-5) based on probe results.

        Args:
            probe_results: Dict of probe_category -> "ok"/"fail"
            nin_active: Whether NIN is detected as active

        Returns:
            {level, confidence, label, best_transports, pack_file, urgency, reasoning}
        """
        if nin_active:
            level = 5
            label = "NIN/Shutdown"
            best_transports = ["webtunnel", "vless_reality"]
            pack_file = "export/iran_cut_pack.txt"
            urgency = "critical"
            reasoning = "NIN detected: international internet cut. Only CDN-fronted tunnels viable."
        elif probe_results:
            fails = sum(1 for v in probe_results.values() if v == "fail")
            total = len(probe_results)

            if fails == 0:
                level = 1
                label = "Minimal"
                best_transports = ["obfs4", "snowflake", "webtunnel"]
                pack_file = "export/iran_pack.txt"
                urgency = "low"
                reasoning = "No blocking detected. All transports viable."
            elif fails <= total * 0.3:
                level = 2
                label = "Standard"
                best_transports = ["obfs4_443", "snowflake", "webtunnel"]
                pack_file = "export/iran_pack.txt"
                urgency = "low"
                reasoning = "Light blocking detected. obfs4 on port 443 recommended."
            elif fails <= total * 0.6:
                level = 3
                label = "Elevated"
                best_transports = ["snowflake", "webtunnel", "meek_lite"]
                pack_file = "export/iran_pack.txt"
                urgency = "medium"
                reasoning = "Elevated blocking. Direct Tor and some obfs4 blocked."
            elif fails <= total * 0.8:
                level = 4
                label = "DPI Active"
                best_transports = ["snowflake", "webtunnel", "meek_lite"]
                pack_file = "export/iran_pack.txt"
                urgency = "high"
                reasoning = "Active DPI with AI/ML analysis. obfs4 degraded."
            else:
                level = 5
                label = "NIN/Shutdown"
                best_transports = ["webtunnel", "vless_reality"]
                pack_file = "export/iran_cut_pack.txt"
                urgency = "critical"
                reasoning = "Near-total blocking. Only CDN-fronted tunnels viable."
        else:
            # Default assumption for Iran: DPI Level 4
            level = 4
            label = "DPI Active (assumed)"
            best_transports = ["snowflake", "webtunnel", "meek_lite"]
            pack_file = "export/iran_pack.txt"
            urgency = "high"
            reasoning = "No probe data. Assuming DPI Level 4 for Iran (conservative)."

        return {
            "level": level,
            "confidence": 0.85 if probe_results else 0.60,
            "label": label,
            "best_transports": best_transports,
            "pack_file": pack_file,
            "urgency": urgency,
            "reasoning": reasoning,
            "isp_notes": "MCI/IRANCELL have heaviest DPI; Rightel/Shatel lighter",
            "source": "local_ai_engine",
        }

    # ── ISP Block Matrix ──────────────────────────────────────────────────

    def isp_block_matrix(
        self, transport_types: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Return per-ISP blocking predictions for each transport type."""
        transports = transport_types or ["vanilla", "obfs4", "webtunnel", "snowflake", "meek_lite"]
        result = {}
        for isp, data in _IRAN_ISP_DATA.items():
            result[isp] = {t: data["blocks"].get(t, "unknown") for t in transports}
        result["updated_hint"] = "Based on OONI/Censored Planet data June 2026 (local KB)"
        result["source"] = "local_ai_engine"
        return result

    # ── Transport Recommendation ──────────────────────────────────────────

    def recommend_transport_stack(
        self,
        censorship_level: int = 4,
        isp: str = "unknown",
        nin_active: bool = False,
    ) -> Dict[str, Any]:
        """Recommend optimal transport chain for current Iran conditions."""

        if nin_active or censorship_level >= 5:
            return {
                "primary_transport": "webtunnel",
                "fallback_transport": "vless_reality",
                "last_resort": "meek_lite",
                "avoid": ["vanilla", "obfs4", "snowflake"],
                "bridge_selection_hint": "Prefer CDN-fronted WebTunnel bridges (Arvan/Cloudflare)",
                "config_hints": {
                    "webtunnel": {"cdn_front": "arvancloud.ir", "verify": True},
                    "obfs4": {"iat-mode": 2, "prefer_port": 443},
                },
                "confidence": 0.80,
                "reasoning": "NIN active: only CDN-fronted tunnels survive international cut",
                "source": "local_ai_engine",
            }

        if censorship_level >= 4:
            return {
                "primary_transport": "snowflake",
                "fallback_transport": "webtunnel",
                "last_resort": "obfs4_443",
                "avoid": ["vanilla"],
                "bridge_selection_hint": "Snowflake short-lived + WebTunnel CDN-fronted for fallback",
                "config_hints": {
                    "obfs4": {"iat-mode": 2, "prefer_port": 443},
                    "snowflake": {"broker": "cdn", "ampcache": True},
                    "webtunnel": {"cdn_front": True},
                },
                "confidence": 0.78,
                "reasoning": "DPI Level 4: AI/ML traffic analysis active. Snowflake and WebTunnel best.",
                "source": "local_ai_engine",
            }

        if censorship_level >= 3:
            return {
                "primary_transport": "webtunnel",
                "fallback_transport": "snowflake",
                "last_resort": "obfs4_443",
                "avoid": ["vanilla"],
                "bridge_selection_hint": "WebTunnel primary; obfs4 on 443 as backup",
                "config_hints": {
                    "obfs4": {"iat-mode": 2, "prefer_port": 443},
                },
                "confidence": 0.75,
                "reasoning": "Elevated blocking: WebTunnel + obfs4 port 443 viable",
                "source": "local_ai_engine",
            }

        return {
            "primary_transport": "obfs4_443",
            "fallback_transport": "snowflake",
            "last_resort": "webtunnel",
            "avoid": ["vanilla"],
            "bridge_selection_hint": "obfs4 on port 443 with iat-mode=2 recommended",
            "config_hints": {
                "obfs4": {"iat-mode": 2, "prefer_port": 443},
            },
            "confidence": 0.82,
            "reasoning": "Standard/Light blocking: most transports work; prefer obfs4 port 443",
            "source": "local_ai_engine",
        }

    # ── NIN Survival ──────────────────────────────────────────────────────

    def predict_nin_survival(self, bridge_type: str, transport: str) -> Dict[str, Any]:
        """Predict bridge survival during NIN internet-cut events."""
        t_scores = _IRAN_TRANSPORT_SCORES.get(transport, _IRAN_TRANSPORT_SCORES["vanilla"])
        nin_surv = t_scores["nin_survival"]

        survives = nin_surv > 0.4
        reason = (
            f"{transport} has NIN survival rating {nin_surv:.0%}. "
            f"{'CDN-fronted tunnels may survive NIN.' if survives else 'NIN cuts international connectivity; only CDN-fronted tunnels survive.'}"
        )

        return {
            "survives": survives,
            "confidence": 0.75,
            "reason": reason,
            "source": "local_ai_engine",
        }

    # ── obfs4 Mutation ────────────────────────────────────────────────────

    def generate_obfs4_mutation(
        self, existing_cert: str, existing_iat_mode: int
    ) -> Dict[str, Any]:
        """Generate obfs4 parameter mutation hints for DPI evasion."""
        hints = []

        if existing_iat_mode != 2:
            hints.append("Change iat-mode to 2 (spreads timing to defeat DPI statistical analysis)")
        else:
            hints.append("iat-mode=2 is already optimal for Iran DPI evasion")

        if existing_cert:
            # Analyze cert length (longer = more entropy = harder to fingerprint)
            cert_len = len(existing_cert)
            if cert_len < 30:
                hints.append("Consider regenerating cert — shorter certs are easier to fingerprint")
            else:
                hints.append("Cert length looks adequate")

        return {
            "cert": existing_cert,
            "iat_mode": 2,
            "fingerprint_delta": "high" if existing_iat_mode != 2 else "none",
            "hints": hints,
            "source": "local_ai_engine",
        }

    # ── Temporal Pattern ──────────────────────────────────────────────────

    def temporal_block_pattern(
        self, transport: str = "obfs4", isp: str = "MCI"
    ) -> Dict[str, Any]:
        """Predict time-of-day blocking intensity for Iran."""
        now = datetime.now(timezone.utc)
        iran_offset_hours = 3.5
        iran_hour = (now.hour + iran_offset_hours) % 24

        peak_hours = _TEMPORAL_PATTERNS["peak_block_hours"]
        low_hours = _TEMPORAL_PATTERNS["low_block_hours"]

        if int(iran_hour) in peak_hours:
            current = "heavy"
        elif int(iran_hour) in low_hours:
            current = "light"
        else:
            current = "normal"

        return {
            "peak_block_hours": peak_hours,
            "low_block_hours": low_hours,
            "weekend_modifier": _TEMPORAL_PATTERNS["weekend_modifier"],
            "event_sensitivity": _TEMPORAL_PATTERNS["event_sensitivity"],
            "current_estimate": current,
            "best_connection_window": _TEMPORAL_PATTERNS["best_window"],
            "current_iran_hour": int(iran_hour),
            "confidence": 0.70,
            "source": "local_ai_engine",
        }

    # ── Workflow Failure Analysis ─────────────────────────────────────────

    def analyze_workflow_failure(
        self, workflow_name: str, error_log: str
    ) -> Dict[str, Any]:
        """Analyze a GitHub Actions workflow failure using pattern matching."""
        best_match = None
        best_confidence = 0.0

        for pattern, fix_info in _WORKFLOW_FIXES.items():
            if pattern.lower() in error_log.lower():
                if fix_info["confidence"] > best_confidence:
                    best_match = fix_info
                    best_confidence = fix_info["confidence"]

        if best_match:
            return {
                "root_cause": best_match["root_cause"],
                "fix_type": best_match["fix_type"],
                "patch": best_match["fix"],
                "confidence": best_match["confidence"],
                "additive_only": True,
                "source": "local_ai_engine",
            }

        # Default analysis for unknown patterns
        return {
            "root_cause": "unknown",
            "fix_type": "manual",
            "patch": "",
            "confidence": 0.3,
            "additive_only": True,
            "reasoning": "No pattern match found in local knowledge base",
            "source": "local_ai_engine",
        }

    # ── Batch Scoring ─────────────────────────────────────────────────────

    def batch_ai_score(
        self,
        bridge_lines: List[str],
        censorship_level: int = 4,
    ) -> List[Dict[str, Any]]:
        """Score multiple bridges for Iran reachability."""
        results = []
        for line in bridge_lines:
            parsed = self._parse_bridge_line(line)
            score_result = self.score_bridge(line, censorship_level)
            results.append({
                "bridge_line": line,
                "score": score_result["score"],
                "transport": parsed["transport"],
                "port": parsed["port"],
                "recommendation": score_result["recommendation"],
                "tier": "excellent" if score_result["score"] >= 0.80
                        else "good" if score_result["score"] >= 0.60
                        else "capable" if score_result["score"] >= 0.40
                        else "poor",
            })
        results.sort(key=lambda x: x["score"], reverse=True)
        return results

    # ── Chat Completion (gateway-compatible interface) ─────────────────────

    def chat_complete(
        self,
        messages: List[Dict[str, str]],
        task: str = "general",
    ) -> str:
        """
        Gateway-compatible chat completion interface.
        Analyzes the user message and returns structured JSON response.

        IMPORTANT: For health check probes ("Reply with exactly: TORSHIELD_OK"),
        this engine honestly responds that it is a LOCAL fallback — NOT a primary
        provider. This allows the health check to correctly identify that no
        primary provider is available.
        """
        user_msg = ""
        for m in messages:
            if m.get("role") == "user":
                user_msg += m.get("content", "")

        # ── Health check probe detection ──────────────────────────────────
        # If this is a health check probe asking for TORSHIELD_OK,
        # respond honestly that this is the local engine (DEGRADED mode).
        # The health check script uses this to distinguish primary_ok from
        # degraded_local responses.
        if "TORSHIELD_OK" in user_msg.upper():
            return json.dumps({
                "status": "degraded_local",
                "message": "LOCAL_AI_ENGINE: No primary AI provider available. "
                           "This is a rule-based fallback, not a cloud AI provider.",
                "source": "local_ai_engine",
                "primary_available": False,
            })

        # Route to appropriate method based on message content
        if "score" in user_msg.lower() and "bridge" in user_msg.lower():
            # Try to extract bridge line from message
            bridge_match = re.search(r'(obfs4|webtunnel|snowflake|meek_lite|vanilla)\s+\S+:\d+', user_msg)
            if bridge_match:
                result = self.score_bridge(bridge_match.group(0))
                return json.dumps(result)

        if "censorship" in user_msg.lower() or "level" in user_msg.lower():
            result = self.detect_censorship_level()
            return json.dumps(result)

        if "isp" in user_msg.lower() and "block" in user_msg.lower():
            result = self.isp_block_matrix()
            return json.dumps(result)

        if "transport" in user_msg.lower() and "recommend" in user_msg.lower():
            result = self.recommend_transport_stack()
            return json.dumps(result)

        if "nin" in user_msg.lower() and "survival" in user_msg.lower():
            result = self.predict_nin_survival("tor", "obfs4")
            return json.dumps(result)

        if "workflow" in user_msg.lower() or "failure" in user_msg.lower():
            result = self.analyze_workflow_failure("unknown", user_msg)
            return json.dumps(result)

        # Default: return general Iran intelligence
        return json.dumps({
            "status": "local_ai_engine_active",
            "message": "External AI providers unavailable. Using local rule-based engine.",
            "iran_dpi_systems": list(_IRAN_DPI_SYSTEMS.keys()),
            "available_methods": [
                "score_bridge", "detect_censorship_level", "isp_block_matrix",
                "recommend_transport_stack", "predict_nin_survival",
                "analyze_workflow_failure", "batch_ai_score",
            ],
        })
