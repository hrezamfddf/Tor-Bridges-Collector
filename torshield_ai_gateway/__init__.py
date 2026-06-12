"""
torshield_ai_gateway — v17.0 Ultra-Quantum FG-DS-DDH Edition
Dynamic multi-provider AI gateway with automatic model selection,
exponential backoff retry, anti-DPI, smart Iran bypass, and auto-defense.

v17.0 CHANGES (FG-DS-DDH):
  - AntiDPIEngine: AI-driven DPI bypass with traffic morphing profiles
    (telegram, instagram, https_generic, whatsapp, google_services)
  - SmartBridgeSelector: AI-powered bridge selection for Iran with
    EMA success rate tracking and automatic blocking detection
  - Auto-self-healing: run_with_auto_healing() with escalating model
    fallback and automatic root cause logging
  - Flexible response validation: is_valid_response() accepts any
    non-empty, non-error response as provider alive signal
  - CF slot pre-flight logging: shows which slots were skipped
  - Portkey diagnostics: fixed x-portkey-provider header issue
  - 314+ automated tests all passing

v16.0 CHANGES (FG-DS) — preserved:
  - CF pre-flight validation for 11 slots — silently skips bad slots
  - Portkey auth fixed — removed broken pk- prefix requirement
  - Exponential backoff with jitter — prevents thundering herd
  - Health check flexible validation — is_valid_ai_response()
  - ModelSelector fetch_cf_models() — always returns non-empty list
  - GitHub Actions upgraded to Node.js 24 runtime
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

# Anti-censorship module (graceful — import errors are non-fatal)
try:
    from .anti_censorship import (
        AntiDPIEngine,
        SmartBridgeSelector,
        TrafficProfile,
        PROFILES,
        IRAN_DPI_PATTERNS,
        anti_dpi,
        bridge_selector,
    )
except ImportError:
    AntiDPIEngine = None  # type: ignore[misc,assignment]
    SmartBridgeSelector = None  # type: ignore[misc,assignment]
    TrafficProfile = None  # type: ignore[misc,assignment]
    PROFILES = {}  # type: ignore[misc,assignment]
    IRAN_DPI_PATTERNS = {}  # type: ignore[misc,assignment]
    anti_dpi = None  # type: ignore[misc,assignment]
    bridge_selector = None  # type: ignore[misc,assignment]

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
    "AntiDPIEngine",
    "SmartBridgeSelector",
    "TrafficProfile",
    "PROFILES",
    "IRAN_DPI_PATTERNS",
    "anti_dpi",
    "bridge_selector",
]
