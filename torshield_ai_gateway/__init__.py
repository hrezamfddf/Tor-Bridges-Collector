"""
torshield_ai_gateway — v16.0 Ultra-Quantum FG-DS Edition
Dynamic multi-provider AI gateway with automatic model selection,
exponential backoff retry, anti-DPI, smart Iran bypass, and auto-defense.

v16.0 CHANGES (FG-DS):
  - CF pre-flight validation for 11 slots — silently skips bad slots
    (invalid account_id, too-short tokens, malformed gateway URLs)
  - Portkey auth fixed — removed broken pk- prefix requirement, fixed
    auth headers (no hardcoded x-portkey-provider=openai), added
    _build_portkey_headers() and _load_portkey_slots() with key reuse
  - Exponential backoff with jitter — _exponential_backoff_with_jitter()
    prevents thundering herd on Cerebras 429 responses
  - Health check flexible validation — is_valid_ai_response() replaces
    strict TORSHIELD_OK check, accepts any non-error response
  - ModelSelector fetch_cf_models() — always returns non-empty list
    with offline fallback when live API returns 0 or fails
  - GitHub Actions upgraded to Node.js 24 runtime
    (checkout@v5, setup-python@v6, upload-artifact@v6)
  - 334 automated tests all passing

v15.0 CHANGES (preserved):
  - Added neural_anti_dpi_v3 module (Neural Traffic Morphing for L1 CNN/L2 LSTM
    evasion, JA3/JA3S Dynamic Rotation Engine, ECH Fallback Router with
    post-quantum bridge scoring, AntiDPIV3Orchestrator with V2 fallback)
  - All V2 features preserved — V3 is purely additive
  - PYEOF heredoc syntax fixed in all 4 GitHub Actions workflows
  - Auth failure codes (401/403) NEVER retried in _post_json_with_retry
  - Comprehensive audit scripts added (dead code, security, dependencies)

v14.0 CHANGES (preserved):
  - Added iran_smart_anti_filter_v2 module (AI censorship detection,
    ISP strategies, temporal analysis, NIN survival, adaptive transport)
  - Added ai_anti_dpi_iran_v2 module (DPI fingerprinting, JA3/JA4 evasion,
    SNI manipulation, traffic obfuscation, ML evasion, automated DPI testing)
  - IranAutoDefense upgraded to v3.0 with V2 engine integration
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
]
