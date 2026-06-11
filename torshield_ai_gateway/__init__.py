"""
torshield_ai_gateway — v13.0 Ultra-Quantum Edition
Dynamic multi-provider AI gateway with automatic model selection,
exponential backoff retry, anti-DPI, smart Iran bypass, and auto-defense.

v13.0 CHANGES:
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
