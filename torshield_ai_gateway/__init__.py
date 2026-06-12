"""
torshield_ai_gateway — v18.0 Ultra-Quantum Edition
Dynamic multi-provider AI gateway with automatic model selection,
exponential backoff retry, anti-DPI, smart Iran bypass, and auto-defense.

v18.0 CHANGES (Correction 7: URL Path + Response Parser + Config Errors):
  - CF AI Gateway URL uses OpenAI-compatible endpoint:
    {gateway_base}/workers-ai/v1/chat/completions with model in request body
  - CF Workers AI direct URL uses OpenAI-compatible endpoint:
    https://api.cloudflare.com/client/v4/accounts/{acct}/ai/v1/chat/completions
  - _extract_text() NEVER returns str(response) — always extracts content properly
  - ProviderConfigurationError for permanent config failures (no retry)
  - _dead_slots with threading.Lock for thread-safe dead slot tracking
  - CF slot 400+empty-body → dead-listed, ONE warning per slot
  - Health check max_tokens=100, prompt tightened
  - Portkey raises ProviderConfigurationError when ALL keys lack 'pk-' prefix
  - Health check distinguishes no_response vs wrong_response
  - Health check counts 'skipped' as non-failure in exit code
  - ModelSelector: llama-4-maverick in KNOWN_GOOD_MODELS
  - ModelSelector: 0 usable models logged at INFO (not WARNING)
  - ModelSelector: canonical name extraction from name field with @cf/ prefix
  - upload-artifact@v6 in all workflows
"""
from .gateway import TorShieldAIGateway, get_gateway
from .exceptions import ProviderConfigurationError
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

# V3 Anti-Filter + Anti-DPI (graceful — import errors are non-fatal)
try:
    from .iran_anti_filter_v3 import (
        SmartAntiFilterEngine,
        FilterType,
        EvasionStrategy,
        get_anti_filter_engine,
        run_anti_filter_cycle,
    )
except ImportError:
    SmartAntiFilterEngine = None  # type: ignore[misc,assignment]
    FilterType = None  # type: ignore[misc,assignment]
    EvasionStrategy = None  # type: ignore[misc,assignment]
    get_anti_filter_engine = None  # type: ignore[misc,assignment]
    run_anti_filter_cycle = None  # type: ignore[misc,assignment]

# Anti-Censorship Engine (graceful — import errors are non-fatal)
try:
    from .anti_censorship import (
        AntiCensorshipEngine,
        TransportType,
        DPIAction,
        CensorshipLevel,
        IranDPISignatures,
        get_anti_censorship_engine,
        run_anti_censorship_cycle,
    )
except ImportError:
    AntiCensorshipEngine = None  # type: ignore[misc,assignment]
    TransportType = None  # type: ignore[misc,assignment]
    DPIAction = None  # type: ignore[misc,assignment]
    CensorshipLevel = None  # type: ignore[misc,assignment]
    IranDPISignatures = None  # type: ignore[misc,assignment]
    get_anti_censorship_engine = None  # type: ignore[misc,assignment]
    run_anti_censorship_cycle = None  # type: ignore[misc,assignment]

# Auto-Debugger (graceful — import errors are non-fatal)
try:
    from .auto_debugger import (
        AutoDebugger,
        FixAction,
        DiagnosticResult,
        get_auto_debugger,
    )
except ImportError:
    AutoDebugger = None  # type: ignore[misc,assignment]
    FixAction = None  # type: ignore[misc,assignment]
    DiagnosticResult = None  # type: ignore[misc,assignment]
    get_auto_debugger = None  # type: ignore[misc,assignment]

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
    "SmartAntiFilterEngine",
    "FilterType",
    "EvasionStrategy",
    "get_anti_filter_engine",
    "run_anti_filter_cycle",
    "AntiCensorshipEngine",
    "TransportType",
    "DPIAction",
    "CensorshipLevel",
    "IranDPISignatures",
    "get_anti_censorship_engine",
    "run_anti_censorship_cycle",
    "AutoDebugger",
    "FixAction",
    "DiagnosticResult",
    "get_auto_debugger",
    "ProviderConfigurationError",
]
