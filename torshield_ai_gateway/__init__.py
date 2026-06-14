"""
torshield_ai_gateway — v20.0 Ultra-Quantum Edition + Dynamic Brain
Dynamic multi-provider AI gateway with automatic model selection,
exponential backoff retry, anti-DPI, smart Iran bypass, and auto-defense.

v20.0 CHANGES (Fix-16.0: Dynamic Model Brain):
  - NEW: dynamic_model_brain.py — Live model fetcher + intelligent scorer
    Fetches models from all 11 CF accounts + Portkey APIs concurrently.
    Scores models automatically (params, capabilities, context, recency).
    Replaces hardcoded model IDs with live, scored, dynamic ranking.
    Falls back to existing model_selector.py on any failure.
  - NEW: dynamic_brain_anti_dpi.py — AI-powered anti-DPI integration
    Detects Iran DPI threat level using multiple signal sources.
    Automatically adjusts model selection for anti-DPI stealth.
    Prefers CF-hosted models when DPI is active.
    Limits response sizes to reduce traffic analysis surface.
  - INTEGRATED: All providers now try Dynamic Brain first,
    falling back to existing model_selector on any error.
  - INTEGRATED: Health check Step 0 refreshes brain before checks.
  - INTEGRATED: CI workflow uses live model ranking step.
  - ZERO DELETIONS: All existing modules, functions, classes preserved.

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
  - Portkey key validation: prefix check removed, length-only check (>=16 chars)
  - BadRequestError for HTTP 400 — separated from auth failures
  - normalize_cf_gateway_url() auto-fixes bare gateway URLs
  - Circuit breaker threshold raised to max(n_slots, 20)
  - Health check max_tokens=256, prompt simplified
"""
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
