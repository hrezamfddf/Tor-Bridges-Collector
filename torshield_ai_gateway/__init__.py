"""
torshield_ai_gateway — v21.0 Ultra-Quantum Edition + Iran DPI Shield v4
Dynamic multi-provider AI gateway with automatic model selection,
exponential backoff retry, AI-powered anti-DPI, smart Iran bypass, and auto-defense.

v21.0 CHANGES (Fix-18.0: Brain URL fix + CF Gateway native fallback + DPI Shield v4):
  - FIX: dynamic_model_brain.py — removed wrong ?task=text-generation filter
    that caused ALL 11 CF accounts to return 0 models. Now uses ?per_page=500
    (same as model_selector.py) with Python-side task filtering. Returns 25+
    models instead of 0.
  - FIX: Brain offline fallback — loads _OFFLINE_MODELS from model_selector
    when all CF accounts return 0 models (e.g. 403 permission issue).
  - FIX: CF AI Gateway — now tries BOTH OpenAI-compat AND native CF format
    as fallback when /v1/chat/completions returns 400. Also tries model
    names with and without @cf/ prefix. Logs actual 400 error body.
  - FIX: CF AI Gateway — added cf-aig-authorization header support for
    gateway-specific token (CF_AI_GATEWAY_TOKEN_{n} env var).
  - FIX: Portkey — added x-portkey-provider: cerebras + x-portkey-custom-host
    headers so Portkey knows which backend to route to. Previously missing
    this header caused HTTP 400 on ALL Portkey requests.
  - FIX: Portkey — uses CEREBRAS_API_KEY_1 as provider key when available,
    making Portkey work as a Cerebras proxy even without PORTKEY_PROVIDER_KEY.
  - FIX: GitHub Actions workflow — Pre-flight now validates ALL 11 CF slots
    (was only validating 3). Also passes CEREBRAS_API_KEY_1 to health check.
  - NEW: iran_dpi_shield_v4.py — AI-powered Iran DPI Shield v4.0
    JA3/TLS fingerprint mutation, H2 fingerprint randomization,
    NIN bypass routing, ISP-specific evasion profiles, timing jitter engine,
    real-time threat assessment with adaptive provider selection.
  - ZERO DELETIONS: All v1–v3 modules fully preserved.
"""
from .gateway import TorShieldAIGateway, get_gateway
from .exceptions import ProviderConfigurationError, BadRequestError

from .gateway import TorShieldAIGateway, get_gateway
from .exceptions import ProviderConfigurationError, BadRequestError
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
        IranDPIEvasionV2,
        get_dpi_evasion_v2,
    )
except ImportError:
    AntiCensorshipEngine = None  # type: ignore[misc,assignment]
    TransportType = None  # type: ignore[misc,assignment]
    DPIAction = None  # type: ignore[misc,assignment]
    CensorshipLevel = None  # type: ignore[misc,assignment]
    IranDPISignatures = None  # type: ignore[misc,assignment]
    get_anti_censorship_engine = None  # type: ignore[misc,assignment]
    run_anti_censorship_cycle = None  # type: ignore[misc,assignment]
    IranDPIEvasionV2 = None  # type: ignore[misc,assignment]
    get_dpi_evasion_v2 = None  # type: ignore[misc,assignment]

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

# Dynamic Model Brain (Fix-16.0 — graceful, import errors are non-fatal)
try:
    from .dynamic_model_brain import (
        DynamicModelBrain,
        LiveModel,
        ModelSource,
        get_brain,
        ranked_cf_models_live,
        best_portkey_model_live,
        best_cf_model_live,
        globally_strongest_model_live,
        refresh_brain_sync,
        activate_anti_dpi_if_needed,
        score_model,
        score_model_anti_dpi,
    )
except ImportError:
    DynamicModelBrain = None  # type: ignore[misc,assignment]
    LiveModel = None  # type: ignore[misc,assignment]
    ModelSource = None  # type: ignore[misc,assignment]
    get_brain = None  # type: ignore[misc,assignment]
    ranked_cf_models_live = None  # type: ignore[misc,assignment]
    best_portkey_model_live = None  # type: ignore[misc,assignment]
    best_cf_model_live = None  # type: ignore[misc,assignment]
    globally_strongest_model_live = None  # type: ignore[misc,assignment]
    refresh_brain_sync = None  # type: ignore[misc,assignment]
    activate_anti_dpi_if_needed = None  # type: ignore[misc,assignment]
    score_model = None  # type: ignore[misc,assignment]
    score_model_anti_dpi = None  # type: ignore[misc,assignment]

# Dynamic Brain Anti-DPI (Fix-16.0 — graceful, import errors are non-fatal)
try:
    from .dynamic_brain_anti_dpi import (
        DynamicBrainDPIAdapter,
        IranDPIAssessor,
        DPIAssessment,
        DPIThreatLevel,
        DPIPatternType,
        get_dpi_adapter,
        run_dpi_assessment,
    )
except ImportError:
    DynamicBrainDPIAdapter = None  # type: ignore[misc,assignment]
    IranDPIAssessor = None  # type: ignore[misc,assignment]
    DPIAssessment = None  # type: ignore[misc,assignment]
    DPIThreatLevel = None  # type: ignore[misc,assignment]
    DPIPatternType = None  # type: ignore[misc,assignment]
    get_dpi_adapter = None  # type: ignore[misc,assignment]
    run_dpi_assessment = None  # type: ignore[misc,assignment]

# Iran Quantum Shield — Ultra-Advanced AI Anti-Filtering & Anti-DPI (graceful)
try:
    from .iran_quantum_shield import (
        IranQuantumShield,
        DPIPattern,
        EvasionStrategy as QuantumEvasionStrategy,
        ThreatLevel as QuantumThreatLevel,
        TransportType as QuantumTransportType,
        DPIAssessment as QuantumDPIAssessment,
        TLSProfile,
        BridgeScore,
        get_quantum_shield,
        run_quantum_assessment,
        run_quantum_diagnosis,
        score_bridge_for_iran,
    )
except ImportError:
    IranQuantumShield = None  # type: ignore[misc,assignment]
    DPIPattern = None  # type: ignore[misc,assignment]
    QuantumEvasionStrategy = None  # type: ignore[misc,assignment]
    QuantumThreatLevel = None  # type: ignore[misc,assignment]
    QuantumTransportType = None  # type: ignore[misc,assignment]
    QuantumDPIAssessment = None  # type: ignore[misc,assignment]
    TLSProfile = None  # type: ignore[misc,assignment]
    BridgeScore = None  # type: ignore[misc,assignment]
    get_quantum_shield = None  # type: ignore[misc,assignment]
    run_quantum_assessment = None  # type: ignore[misc,assignment]
    run_quantum_diagnosis = None  # type: ignore[misc,assignment]
    score_bridge_for_iran = None  # type: ignore[misc,assignment]

# v4 NEW: uTLS Evasion, Elite Registry, Circuit Breaker, Telemetry
# (graceful — import errors are non-fatal)
try:
    from uTLS_evasion_layer import (
        UTLSManager,
        TLSFingerprint,
        get_utls_manager,
        get_evasion_headers,
        get_randomized_profile,
        is_ultra_stealth_mode,
    )
except ImportError:
    UTLSManager = None  # type: ignore[misc,assignment]
    TLSFingerprint = None  # type: ignore[misc,assignment]
    get_utls_manager = None  # type: ignore[misc,assignment]
    get_evasion_headers = None  # type: ignore[misc,assignment]
    get_randomized_profile = None  # type: ignore[misc,assignment]
    is_ultra_stealth_mode = None  # type: ignore[misc,assignment]

try:
    from elite_registry import (
        EliteRegistry,
        ModelEntry,
        get_registry,
        get_best_model as registry_get_best_model,
        get_ranked_models as registry_get_ranked_models,
    )
except ImportError:
    EliteRegistry = None  # type: ignore[misc,assignment]
    ModelEntry = None  # type: ignore[misc,assignment]
    get_registry = None  # type: ignore[misc,assignment]
    registry_get_best_model = None  # type: ignore[misc,assignment]
    registry_get_ranked_models = None  # type: ignore[misc,assignment]

try:
    from circuit_breaker_11slot import (
        CircuitBreaker11Slot,
        SlotState,
        get_circuit_breaker,
        get_next_slot,
        mark_slot_failed,
        mark_slot_success,
    )
except ImportError:
    CircuitBreaker11Slot = None  # type: ignore[misc,assignment]
    SlotState = None  # type: ignore[misc,assignment]
    get_circuit_breaker = None  # type: ignore[misc,assignment]
    get_next_slot = None  # type: ignore[misc,assignment]
    mark_slot_failed = None  # type: ignore[misc,assignment]
    mark_slot_success = None  # type: ignore[misc,assignment]

try:
    from telemetry_watcher import (
        TelemetryWatcher,
        DailyAggregation,
        get_telemetry,
        log_dpi_event,
        log_slot_failure,
        log_self_heal,
        generate_daily_report,
    )
except ImportError:
    TelemetryWatcher = None  # type: ignore[misc,assignment]
    DailyAggregation = None  # type: ignore[misc,assignment]
    get_telemetry = None  # type: ignore[misc,assignment]
    log_dpi_event = None  # type: ignore[misc,assignment]
    log_slot_failure = None  # type: ignore[misc,assignment]
    log_self_heal = None  # type: ignore[misc,assignment]
    generate_daily_report = None  # type: ignore[misc,assignment]

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
    "IranDPIEvasionV2",
    "get_dpi_evasion_v2",
    "AutoDebugger",
    "FixAction",
    "DiagnosticResult",
    "get_auto_debugger",
    "ProviderConfigurationError",
    "BadRequestError",
    # Dynamic Brain (Fix-16.0)
    "DynamicModelBrain",
    "LiveModel",
    "ModelSource",
    "get_brain",
    "ranked_cf_models_live",
    "best_portkey_model_live",
    "best_cf_model_live",
    "globally_strongest_model_live",
    "refresh_brain_sync",
    "activate_anti_dpi_if_needed",
    "score_model",
    "score_model_anti_dpi",
    # Dynamic Brain Anti-DPI (Fix-16.0)
    "DynamicBrainDPIAdapter",
    "IranDPIAssessor",
    "DPIAssessment",
    "DPIThreatLevel",
    "DPIPatternType",
    "get_dpi_adapter",
    "run_dpi_assessment",
    # Iran Quantum Shield (v1.0)
    "IranQuantumShield",
    "DPIPattern",
    "QuantumEvasionStrategy",
    "QuantumThreatLevel",
    "QuantumTransportType",
    "QuantumDPIAssessment",
    "TLSProfile",
    "BridgeScore",
    "get_quantum_shield",
    "run_quantum_assessment",
    "run_quantum_diagnosis",
    "score_bridge_for_iran",
    # v4 NEW: uTLS Evasion Layer
    "UTLSManager",
    "TLSFingerprint",
    "get_utls_manager",
    "get_evasion_headers",
    "get_randomized_profile",
    "is_ultra_stealth_mode",
    # v4 NEW: Elite Registry
    "EliteRegistry",
    "ModelEntry",
    "get_registry",
    "registry_get_best_model",
    "registry_get_ranked_models",
    # v4 NEW: Circuit Breaker 11-Slot
    "CircuitBreaker11Slot",
    "SlotState",
    "get_circuit_breaker",
    "get_next_slot",
    "mark_slot_failed",
    "mark_slot_success",
    # v4 NEW: Telemetry Watcher
    "TelemetryWatcher",
    "DailyAggregation",
    "get_telemetry",
    "log_dpi_event",
    "log_slot_failure",
    "log_self_heal",
    "generate_daily_report",
]
