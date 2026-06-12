"""
anti_censorship — Iran anti-censorship modules

Re-exports from all Iran-specific anti-censorship and anti-DPI modules,
providing convenient access from the organized enterprise structure.

This package unifies the following anti-censorship capabilities:
  - Smart anti-filtering engine (IranSmartAntiFilter)
  - AI-powered anti-DPI engine (IranAntiDPI)
  - SIAM/NGFW evasion scoring
  - NIN bypass engine
  - DPI evasion advanced techniques
  - Anti-AI DPI scoring
  - Smart bypass engine (SmartBypassEngine)
  - Auto-defense system (IranAutoDefense)
  - Iran intelligence layer (IranIntelligenceLayer)

Usage:
    from anti_censorship import IranSmartAntiFilter
    from anti_censorship import IranAntiDPI
    from anti_censorship import SmartBypassEngine

All original imports remain functional:
    from iran_smart_anti_filter import IranSmartAntiFilter  # still works
    from torshield_ai_gateway.smart_bypass_engine import SmartBypassEngine  # still works
"""

import importlib
import sys
import os

# Ensure project root is on sys.path
_project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

# ── Root-level Iran/DPI modules ─────────────────────────────────────────────

_iran_smart_anti_filter = importlib.import_module("iran_smart_anti_filter")
IranSmartAntiFilter = _iran_smart_anti_filter.IranSmartAntiFilter
CensorshipState = _iran_smart_anti_filter.CensorshipState

_ai_anti_dpi_iran = importlib.import_module("ai_anti_dpi_iran")
IranAntiDPI = _ai_anti_dpi_iran.IranAntiDPI
DPIThreat = _ai_anti_dpi_iran.DPIThreat
EvasionStrategy = _ai_anti_dpi_iran.EvasionStrategy

_dpi_evasion = importlib.import_module("dpi_evasion_advanced")
dpi_score = _dpi_evasion.dpi_score
dpi_resistance_tier = _dpi_evasion.dpi_resistance_tier
update_dpi_report = _dpi_evasion.update_dpi_report

_anti_ai_dpi = importlib.import_module("anti_ai_dpi")
score_anti_ai_dpi = _anti_ai_dpi.score_anti_ai_dpi
IRAN_BLOCKED_JA3 = _anti_ai_dpi.IRAN_BLOCKED_JA3
TRANSPORT_DPI_SCORES = _anti_ai_dpi.TRANSPORT_DPI_SCORES

_iran_nin_bypass = importlib.import_module("iran_nin_bypass")
detect_nin_status = _iran_nin_bypass.detect_nin_status

# ── TorShield AI Gateway Iran modules ───────────────────────────────────────

_smart_bypass = importlib.import_module("torshield_ai_gateway.smart_bypass_engine")
SmartBypassEngine = _smart_bypass.SmartBypassEngine

_iran_auto_defense = importlib.import_module("torshield_ai_gateway.iran_auto_defense")
IranAutoDefense = _iran_auto_defense.IranAutoDefense
get_auto_defense = _iran_auto_defense.get_auto_defense
run_defense_cycle = _iran_auto_defense.run_defense_cycle

_iran_intel = importlib.import_module("torshield_ai_gateway.iran_intelligence")
IranIntelligenceLayer = _iran_intel.IranIntelligenceLayer

__all__ = [
    # Iran Smart Anti-Filter
    "IranSmartAntiFilter",
    "CensorshipState",
    # AI Anti-DPI
    "IranAntiDPI",
    "DPIThreat",
    "EvasionStrategy",
    # DPI Evasion Advanced
    "dpi_score",
    "dpi_resistance_tier",
    "update_dpi_report",
    # Anti-AI DPI
    "score_anti_ai_dpi",
    "IRAN_BLOCKED_JA3",
    "TRANSPORT_DPI_SCORES",
    # NIN Bypass
    "detect_nin_status",
    # Smart Bypass Engine
    "SmartBypassEngine",
    # Iran Auto Defense
    "IranAutoDefense",
    "get_auto_defense",
    "run_defense_cycle",
    # Iran Intelligence
    "IranIntelligenceLayer",
]
