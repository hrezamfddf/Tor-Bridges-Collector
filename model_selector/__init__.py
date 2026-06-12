"""
model_selector — Re-exports from torshield_ai_gateway.model_selector

Provides convenient access to the Cloudflare Model Selector
from the organized enterprise structure.

Usage:
    from model_selector import CloudflareModelSelector, best_cf_model

All original imports remain functional:
    from torshield_ai_gateway.model_selector import CloudflareModelSelector  # still works
"""

from torshield_ai_gateway.model_selector import (
    CloudflareModelSelector,
    ModelInfo,
    ProviderAwareModelSelector,
    best_cf_model,
    ranked_cf_models,
    model_selector_status,
)

__all__ = [
    "CloudflareModelSelector",
    "ModelInfo",
    "ProviderAwareModelSelector",
    "best_cf_model",
    "ranked_cf_models",
    "model_selector_status",
]
