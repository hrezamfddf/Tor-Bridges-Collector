"""
torshield_ai_gateway — v11.0 Ultra-Quantum Edition
Dynamic multi-provider AI gateway with automatic model selection,
exponential backoff retry, anti-DPI, and smart Iran bypass.
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

__all__ = [
    "TorShieldAIGateway",
    "get_gateway",
    "CloudflareModelSelector",
    "best_cf_model",
    "ranked_cf_models",
    "model_selector_status",
    "LocalAIEngine",
    "SmartBypassEngine",
]
