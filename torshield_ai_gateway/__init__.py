"""
torshield_ai_gateway — v16.0 Ultra-Quantum Edition
Dynamic multi-provider AI gateway with automatic model selection,
exponential backoff retry, anti-DPI, smart Iran bypass, and auto-defense.

v16.0 CHANGES:
  - FIX-1: All GitHub Actions updated to Node.js 24 compatible versions
    (checkout@v5, setup-python@v6, upload-artifact@v6, NODE_NO_WARNINGS)
  - FIX-2: CF slot pre-flight screening — invalid credentials detected at init
    time, dead slots silently skipped, HTTP 400 empty body kills slot permanently
  - FIX-3: Portkey pre-flight key format gate — non-pk- keys skipped entirely,
    no HTTP 401 attempts for invalid format keys
  - FIX-4: Health check response validation — flexible TORSHIELD_OK matching,
    accept substring presence with length cap instead of exact match
  - FIX-5: ModelSelector live fetch — downgrade 0-model warning to INFO,
    extract @cf/ canonical names from UUID and @hf/ model objects
  - FIX-6: Added llama-4-maverick to KNOWN_GOOD_MODELS set
  - Added anti_censorship.py — AntiCensorshipEngine with DPI detection,
    TLS fingerprint rotation, bridge scoring, adaptive retry, traffic mimicry
  - Added auto_debugger.py — AutoDebugger with FixAction enum,
    automatic diagnosis and fix recommendations for provider errors
  - Added scripts/package.sh — packaging script for tar.gz distribution

v15.0 CHANGES (preserved):
  - Added neural_anti_dpi_v3 module
  - PYEOF heredoc syntax fixed in all 4 GitHub Actions workflows
  - Auth failure codes (401/403) NEVER retried in _post_json_with_retry
  - Comprehensive audit scripts added (dead code, security, dependencies)
  - 314 automated tests
"""
from .gateway import TorShieldAIGateway, get_gateway
from .model_selector import (
    CloudflareModelSelector,
    best_cf_model,
    ranked_cf_models,
    model_selector_status,
)
from .local_ai_engine import LocalAIEngine
from .smart_bypass_engine import SmartBypassEngine
from .iran_auto_defense import IranAutoDefense, get_auto_defense, run_defense_cycle

# V2 modules (graceful — import errors are non-fatal)
try:
    from .iran_smart_anti_filter_v2 import IranSmartAntiFilterV2
except ImportError:
    IranSmartAntiFilterV2 = None  # type: ignore[misc,assignment]

try:
    from .ai_anti_dpi_iran_v2 import IranAntiDPIV2
except ImportError:
    IranAntiDPIV2 = None  # type: ignore[misc,assignment]

# V3 modules (graceful — import errors are non-fatal)
try:
    from .neural_anti_dpi_v3 import (
        NeuralTrafficMorphing,
        JA3_JA3S_RotationEngine,
        ECHFallbackRouter,
        AntiDPIV3Orchestrator,
    )
except ImportError:
    NeuralTrafficMorphing = None  # type: ignore[misc,assignment]
    JA3_JA3S_RotationEngine = None  # type: ignore[misc,assignment]
    ECHFallbackRouter = None  # type: ignore[misc,assignment]
    AntiDPIV3Orchestrator = None  # type: ignore[misc,assignment]

# v16.0 modules (graceful — import errors are non-fatal)
try:
    from .anti_censorship import AntiCensorshipEngine
except ImportError:
    AntiCensorshipEngine = None  # type: ignore[misc,assignment]

try:
    from .auto_debugger import AutoDebugger, FixAction, DiagnosticResult
except ImportError:
    AutoDebugger = None  # type: ignore[misc,assignment]
    FixAction = None  # type: ignore[misc,assignment]
    DiagnosticResult = None  # type: ignore[misc,assignment]

__all__ = [
    "TorShieldAIGateway",
    "get_gateway",
    "CloudflareModelSelector",
    "best_cf_model",
    "ranked_cf_models",
    "model_selector_status",
    "LocalAIEngine",
    "SmartBypassEngine",
    "IranAutoDefense",
    "get_auto_defense",
    "run_defense_cycle",
    "IranSmartAntiFilterV2",
    "IranAntiDPIV2",
    "NeuralTrafficMorphing",
    "JA3_JA3S_RotationEngine",
    "ECHFallbackRouter",
    "AntiDPIV3Orchestrator",
    "AntiCensorshipEngine",
    "AutoDebugger",
    "FixAction",
    "DiagnosticResult",
]
