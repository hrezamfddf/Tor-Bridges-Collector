#!/usr/bin/env python3
"""
feature_flags.py — Feature Flag Configuration v1.0
═══════════════════════════════════════════════════════════════════════════════

Centralized feature flags for all new capabilities.
All new behavior is feature-flagged and disabled by default,
ensuring zero regression in existing functionality.

Feature flags are controlled via environment variables.
ALL existing functionality is preserved WITHOUT any feature flag.
"""

import os
from typing import Dict

# ─────────────────────────────────────────────────────────────────────────────
# Feature Flags — All new capabilities are OFF by default
# ─────────────────────────────────────────────────────────────────────────────

# Endpoint Validation Layer
ENABLE_ENDPOINT_VALIDATION: bool = os.getenv(
    "ENABLE_ENDPOINT_VALIDATION", "true"
).lower() == "true"

# Circuit Breaker (enhanced per-slot)
ENABLE_CIRCUIT_BREAKER: bool = os.getenv(
    "ENABLE_CIRCUIT_BREAKER", "true"
).lower() == "true"

# Model Registry (dynamic discovery)
ENABLE_MODEL_REGISTRY: bool = os.getenv(
    "ENABLE_MODEL_REGISTRY", "true"
).lower() == "true"

# Retry & Failover Engine (enhanced)
ENABLE_RETRY_FAILOVER: bool = os.getenv(
    "ENABLE_RETRY_FAILOVER", "true"
).lower() == "true"

# Self-Healing Engine
ENABLE_SELF_HEALING: bool = os.getenv(
    "ENABLE_SELF_HEALING", "true"
).lower() == "true"

# Structured Logging
ENABLE_STRUCTURED_LOGGING: bool = os.getenv(
    "ENABLE_STRUCTURED_LOGGING", "true"
).lower() == "true"

# Report Generation
ENABLE_REPORT_GENERATION: bool = os.getenv(
    "ENABLE_REPORT_GENERATION", "true"
).lower() == "true"

# Anti-DPI Iran (enhanced)
ENABLE_ANTI_DPI_IRAN: bool = os.getenv(
    "ENABLE_ANTI_DPI_IRAN", "true"
).lower() == "true"

# uTLS Evasion Layer
ENABLE_UTLS_EVASION: bool = os.getenv(
    "ENABLE_UTLS_EVASION", "true"
).lower() == "true"

# IRST Time-Based Predictive Routing
ENABLE_IRST_ROUTING: bool = os.getenv(
    "ENABLE_IRST_ROUTING", "true"
).lower() == "true"

# CF AI Gateway URL Path Fix (/compat/ instead of /workers-ai/)
ENABLE_COMPAT_PATH_FIX: bool = os.getenv(
    "ENABLE_COMPAT_PATH_FIX", "true"
).lower() == "true"

# Telemetry Watcher
ENABLE_TELEMETRY: bool = os.getenv(
    "ENABLE_TELEMETRY", "true"
).lower() == "true"

# ─────────────────────────────────────────────────────────────────────────────
# Configuration Parameters
# ─────────────────────────────────────────────────────────────────────────────

# Circuit Breaker
CIRCUIT_BREAKER_FAILURE_THRESHOLD: int = int(
    os.getenv("CIRCUIT_BREAKER_FAILURE_THRESHOLD", "3")
)
CIRCUIT_BREAKER_COOLDOWN_SECS: float = float(
    os.getenv("CIRCUIT_BREAKER_COOLDOWN_SECS", "60")
)
CIRCUIT_BREAKER_HALF_OPEN_MAX_PROBES: int = int(
    os.getenv("CIRCUIT_BREAKER_HALF_OPEN_MAX_PROBES", "1")
)

# Retry Engine
RETRY_MAX_ATTEMPTS_400: int = int(os.getenv("RETRY_MAX_ATTEMPTS_400", "0"))  # 0 = no retry for 400, rotate instead
RETRY_MAX_ATTEMPTS_429: int = int(os.getenv("RETRY_MAX_ATTEMPTS_429", "5"))
RETRY_MAX_ATTEMPTS_5XX: int = int(os.getenv("RETRY_MAX_ATTEMPTS_5XX", "3"))
RETRY_BACKOFF_CAP_SECS: float = float(os.getenv("RETRY_BACKOFF_CAP_SECS", "60"))

# Self-Healing
SELF_HEAL_TRIGGER_THRESHOLD: int = int(os.getenv("SELF_HEAL_TRIGGER_THRESHOLD", "2"))
SELF_HEAL_COOLDOWN_SECS: float = float(os.getenv("SELF_HEAL_COOLDOWN_SECS", "300"))

# Model Registry
MODEL_REGISTRY_REFRESH_HOURS: int = int(os.getenv("MODEL_REGISTRY_REFRESH_HOURS", "6"))

# IRST High-Censorship Hours
IRST_HIGH_CENSORSHIP_START: int = int(os.getenv("IRST_HIGH_CENSORSHIP_START", "18"))
IRST_HIGH_CENSORSHIP_END: int = int(os.getenv("IRST_HIGH_CENSORSHIP_END", "1"))
IRST_ULTRA_STEALTH_START: int = int(os.getenv("IRST_ULTRA_STEALTH_START", "20"))
IRST_ULTRA_STEALTH_END: int = int(os.getenv("IRST_ULTRA_STEALTH_END", "23"))

# Provider Fallback Order
PROVIDER_FALLBACK_ORDER: list = os.getenv(
    "PROVIDER_FALLBACK_ORDER",
    "cloudflare_ai_gateway,cloudflare_workers_ai,cerebras,portkey"
).split(",")

# Logging
LOG_DIR: str = os.getenv("LOG_DIR", "logs")
LOG_MAX_MB: int = int(os.getenv("LOG_MAX_MB", "10"))


def get_all_flags() -> Dict[str, bool]:
    """Return a dictionary of all feature flags and their current values."""
    return {
        "ENABLE_ENDPOINT_VALIDATION": ENABLE_ENDPOINT_VALIDATION,
        "ENABLE_CIRCUIT_BREAKER": ENABLE_CIRCUIT_BREAKER,
        "ENABLE_MODEL_REGISTRY": ENABLE_MODEL_REGISTRY,
        "ENABLE_RETRY_FAILOVER": ENABLE_RETRY_FAILOVER,
        "ENABLE_SELF_HEALING": ENABLE_SELF_HEALING,
        "ENABLE_STRUCTURED_LOGGING": ENABLE_STRUCTURED_LOGGING,
        "ENABLE_REPORT_GENERATION": ENABLE_REPORT_GENERATION,
        "ENABLE_ANTI_DPI_IRAN": ENABLE_ANTI_DPI_IRAN,
        "ENABLE_UTLS_EVASION": ENABLE_UTLS_EVASION,
        "ENABLE_IRST_ROUTING": ENABLE_IRST_ROUTING,
        "ENABLE_COMPAT_PATH_FIX": ENABLE_COMPAT_PATH_FIX,
        "ENABLE_TELEMETRY": ENABLE_TELEMETRY,
    }


def get_all_config() -> Dict:
    """Return all configuration parameters."""
    return {
        "feature_flags": get_all_flags(),
        "circuit_breaker": {
            "failure_threshold": CIRCUIT_BREAKER_FAILURE_THRESHOLD,
            "cooldown_secs": CIRCUIT_BREAKER_COOLDOWN_SECS,
            "half_open_max_probes": CIRCUIT_BREAKER_HALF_OPEN_MAX_PROBES,
        },
        "retry": {
            "max_attempts_400": RETRY_MAX_ATTEMPTS_400,
            "max_attempts_429": RETRY_MAX_ATTEMPTS_429,
            "max_attempts_5xx": RETRY_MAX_ATTEMPTS_5XX,
            "backoff_cap_secs": RETRY_BACKOFF_CAP_SECS,
        },
        "self_healing": {
            "trigger_threshold": SELF_HEAL_TRIGGER_THRESHOLD,
            "cooldown_secs": SELF_HEAL_COOLDOWN_SECS,
        },
        "model_registry": {
            "refresh_hours": MODEL_REGISTRY_REFRESH_HOURS,
        },
        "irst": {
            "high_censorship_start": IRST_HIGH_CENSORSHIP_START,
            "high_censorship_end": IRST_HIGH_CENSORSHIP_END,
            "ultra_stealth_start": IRST_ULTRA_STEALTH_START,
            "ultra_stealth_end": IRST_ULTRA_STEALTH_END,
        },
        "provider_fallback_order": PROVIDER_FALLBACK_ORDER,
        "logging": {
            "log_dir": LOG_DIR,
            "log_max_mb": LOG_MAX_MB,
        },
    }
