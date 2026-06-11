"""
torshield_ai_gateway — v9.0
Dynamic multi-provider AI gateway with automatic model selection.
"""
from .gateway import TorShieldAIGateway, get_gateway
from .model_selector import (
    CloudflareModelSelector,
    best_cf_model,
    ranked_cf_models,
    model_selector_status,
)

__all__ = [
    "TorShieldAIGateway",
    "get_gateway",
    "CloudflareModelSelector",
    "best_cf_model",
    "ranked_cf_models",
    "model_selector_status",
]
