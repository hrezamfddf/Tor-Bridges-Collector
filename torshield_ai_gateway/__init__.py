"""
torshield_ai_gateway — v16.0 Ultra-Quantum Edition
Dynamic multi-provider AI gateway with automatic model selection,
exponential backoff retry, anti-DPI, smart Iran bypass, and auto-defense.

v16.0 CHANGES (Correction 6: Pre-flight Screening):
  - Pre-flight screening for broken Cloudflare slots — validates token length,
    account_id format, and gateway URL BEFORE sending requests
  - Session-level blacklisting for CF slots that fail all models at runtime
  - Per-account model cache — remembers which models worked on which account
  - CF AI Gateway URL duplicate account_id detection
  - WRONG_RESPONSE false positive validator improvement
  - All CF secrets now supported up to slot 11 in ALL workflows
  - Added iran_anti_filter_v3 module (Smart Anti-Filtering + AI Anti-DPI V3)
    with real-time filter detection, adaptive evasion strategy selection,
    DPI fingerprint rotation, NIN survival mode, and auto-debugging

v15.0 CHANGES (preserved):
  - Added neural_anti_dpi_v3 module (Neural Traffic Morphing for L1 CNN/L2 LSTM
    evasion, JA3/JA3S Dynamic Rotation Engine, ECH Fallback Router with
    post-quantum bridge scoring, AntiDPIV3Orchestrator with V2 fallback)
  - All V2 features preserved — V3 is purely additive
  - PYEOF heredoc syntax fixed in all 4 GitHub Actions workflows
  - Auth failure codes (401/403) NEVER retried in _post_json_with_retry
  - Comprehensive audit scripts added (dead code, security, dependencies)
  - 314 automated tests (126 new: integration, e2e, V3 anti-DPI)

v14.0 CHANGES (preserved):
  - Added iran_smart_anti_filter_v2 module (AI censorship detection,
    ISP strategies, temporal analysis, NIN survival, adaptive transport)
  - Added ai_anti_dpi_iran_v2 module (DPI fingerprinting, JA3/JA4 evasion,
    SNI manipulation, traffic obfuscation, ML evasion, automated DPI testing)
  - IranAutoDefense upgraded to v3.0 with V2 engine integration
  - CF AI Gateway URL now includes account_id in workers-ai path
  - Cerebras model name corrected (llama3.3-70b)
  - Portkey model name updated (meta/llama-3.1-70b-instruct)
  - Cross-slot model skip reduces cascade failures
  - WRONG_RESPONSE treated as failure, not degraded
  - Auth errors (400/401/403) not retried in health check
  - Health check timeout reduced from 20min to ~5min
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
]
