"""
torshield_ai_gateway — v12.0 Ultra-Quantum Edition
Dynamic multi-provider AI gateway with automatic model selection,
exponential backoff retry, anti-DPI, smart Iran bypass, and auto-defense.

v12.0 CHANGES:
  - User-Agent header set on all HTTP requests (fixes Cloudflare 1010)
  - Model selector filters UUID-format IDs (fixes 400 errors)
  - Cloudflare bot protection (403/1010) is now retryable
  - IranAutoDefense integration for automated anti-censorship
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
]
