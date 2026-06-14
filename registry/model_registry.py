#!/usr/bin/env python3
"""
model_registry.py — Dynamic Model Registry with Fitness Scoring v1.0
═══════════════════════════════════════════════════════════════════════════════

Dynamic model discovery and scoring system that:
  - Fetches available models via Cloudflare AI API at startup
  - Falls back to static model list if fetch fails
  - Scores models: availability x reliability x latency x success_rate
  - Refreshes scores every 6 hours asynchronously

Wraps around existing elite_registry.py — ADDITIVE ONLY.

DESIGN PRINCIPLES:
  - ADDITIVE ONLY: Does not modify existing model_selector or elite_registry
  - WRAPPER PATTERN: Enhances existing model selection
  - ZERO CRASH: All operations wrapped in try/except
  - Feature-flagged: ENABLE_MODEL_REGISTRY=true
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("torshield.model_registry")


@dataclass
class ModelEntry:
    """A single model entry with fitness scoring."""
    model_id: str
    provider: str = "cloudflare"
    
    # Fitness scoring dimensions
    availability: float = 1.0      # 0.0-1.0, is model currently available
    reliability: float = 0.8       # 0.0-1.0, historical success rate
    latency_score: float = 0.8     # 0.0-1.0, inverse of latency (1.0 = fastest)
    success_rate: float = 0.8      # 0.0-1.0, recent success rate
    dpi_resistance: float = 0.8    # 0.0-1.0, ability to bypass DPI
    
    # Raw metrics
    avg_latency_ms: float = 200.0
    total_requests: int = 0
    total_successes: int = 0
    total_failures: int = 0
    
    # Metadata
    last_tested: float = 0.0
    is_available: bool = True
    task_affinity: str = "general"  # general, reasoning, coding, fast
    
    @property
    def fitness_score(self) -> float:
        """
        Composite fitness score: 0.0-1.0
        Formula: availability * reliability * latency * success_rate * dpi_resistance
        """
        return (
            self.availability
            * self.reliability
            * self.latency_score
            * self.success_rate
            * self.dpi_resistance
        )
    
    @property
    def display_success_rate(self) -> float:
        if self.total_requests == 0:
            return 1.0
        return self.total_successes / self.total_requests


class ModelRegistry:
    """
    Dynamic model registry with fitness scoring.
    
    Fetches available models from Cloudflare AI API at startup.
    Falls back to static model list if fetch fails.
    Scores models and refreshes every 6 hours.
    """
    
    _instance: Optional["ModelRegistry"] = None
    _instance_lock = threading.Lock()
    
    # Static fallback models
    STATIC_MODELS = [
        "@cf/meta/llama-3.1-8b-instruct",
        "@cf/meta/llama-3.2-11b-vision-instruct",
        "@cf/mistral/mistral-7b-instruct-v0.1",
        "@cf/meta/llama-3.2-3b-instruct",
        "@cf/meta/llama-3.2-1b-instruct",
        "@cf/qwen/qwen1.5-14b-chat-awq",
        "@cf/google/gemma-2b-it-lora",
        "@cf/mistral/mistral-7b-instruct-v0.2-lora",
        "@hf/thebloke/llama-2-13b-chat-awq",
        "@hf/thebloke/zephyr-7b-beta-awq",
        "@cf/deepseek-ai/deepseek-math-7b-instruct",
        "@cf/openchat/openchat-3.5-0106",
    ]
    
    def __init__(self):
        self._lock = threading.Lock()
        self._models: Dict[str, ModelEntry] = {}
        self._last_refresh: float = 0.0
        self._refresh_interval_hrs = int(os.getenv("MODEL_REGISTRY_REFRESH_HOURS", "6"))
        self._refresh_interval_secs = self._refresh_interval_hrs * 3600
        self._initialized = False
        
        # Initialize with static models
        self._init_static_models()
        
        # Try live fetch at startup
        try:
            self._fetch_models_live()
        except Exception as e:
            logger.warning(f"[ModelRegistry] Live fetch failed at startup: {e}")
        
        self._initialized = True
    
    @classmethod
    def instance(cls) -> "ModelRegistry":
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance
    
    def _init_static_models(self) -> None:
        """Initialize registry with static model list."""
        for model_id in self.STATIC_MODELS:
            self._models[model_id] = ModelEntry(
                model_id=model_id,
                provider="cloudflare",
                availability=1.0,
                reliability=0.7,
                latency_score=0.7,
                success_rate=0.7,
                dpi_resistance=0.7,
            )
        logger.info(f"[ModelRegistry] Initialized with {len(self.STATIC_MODELS)} static models")
    
    def _fetch_models_live(self) -> None:
        """Fetch available models from Cloudflare AI API."""
        try:
            # Try to get account credentials
            for i in range(1, 12):
                account_id = os.getenv(f"CF_ACCOUNT_ID_{i}", "").strip()
                api_token = os.getenv(f"CF_API_TOKEN_{i}", "").strip()
                if account_id and api_token:
                    self._fetch_cf_models(account_id, api_token)
                    break
            
            # Also try Cerebras
            cerebras_key = os.getenv("CEREBRAS_API_KEY_1", os.getenv("CEREBRAS_API_KEY", "")).strip()
            if cerebras_key:
                self._fetch_cerebras_models(cerebras_key)
            
            self._last_refresh = time.time()
        except Exception as e:
            logger.warning(f"[ModelRegistry] Live fetch error: {e}")
    
    def _fetch_cf_models(self, account_id: str, api_token: str) -> None:
        """Fetch models from Cloudflare Workers AI API."""
        try:
            url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/models/search"
            headers = {
                "Authorization": f"Bearer {api_token}",
                "User-Agent": "TorShield-ModelRegistry/1.0",
            }
            req = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            
            models = data.get("result", [])
            if isinstance(models, list):
                for item in models:
                    model_id = item.get("id", "")
                    if model_id and model_id not in self._models:
                        self._models[model_id] = ModelEntry(
                            model_id=model_id,
                            provider="cloudflare",
                            availability=1.0,
                            reliability=0.7,
                            latency_score=0.7,
                            success_rate=0.7,
                            dpi_resistance=0.7,
                            task_affinity=self._infer_task_affinity(model_id),
                        )
                
                logger.info(f"[ModelRegistry] Fetched {len(models)} CF models")
        except Exception as e:
            logger.warning(f"[ModelRegistry] CF model fetch failed: {e}")
    
    def _fetch_cerebras_models(self, api_key: str) -> None:
        """Fetch models from Cerebras API."""
        try:
            url = "https://api.cerebras.ai/v1/models"
            headers = {
                "Authorization": f"Bearer {api_key}",
                "User-Agent": "TorShield-ModelRegistry/1.0",
            }
            req = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            
            for item in data.get("data", []):
                model_id = item.get("id", "")
                if model_id and model_id not in self._models:
                    self._models[model_id] = ModelEntry(
                        model_id=model_id,
                        provider="cerebras",
                        availability=1.0,
                        reliability=0.8,
                        latency_score=0.9,  # Cerebras is fast
                        success_rate=0.8,
                        dpi_resistance=0.7,
                        task_affinity=self._infer_task_affinity(model_id),
                    )
        except Exception as e:
            logger.warning(f"[ModelRegistry] Cerebras model fetch failed: {e}")
    
    def _infer_task_affinity(self, model_id: str) -> str:
        """Infer task affinity from model name."""
        model_lower = model_id.lower()
        if "code" in model_lower or "coder" in model_lower:
            return "coding"
        if "math" in model_lower:
            return "reasoning"
        if "vision" in model_lower or "vl" in model_lower:
            return "vision"
        if "1b" in model_lower or "3b" in model_lower:
            return "fast"
        return "general"
    
    def get_best_model(self, task: str = "general") -> Optional[str]:
        """Get the best model for the given task based on fitness score."""
        try:
            # Check if refresh is needed
            if time.time() - self._last_refresh > self._refresh_interval_secs:
                try:
                    self._fetch_models_live()
                except Exception:
                    pass
            
            with self._lock:
                candidates = [
                    m for m in self._models.values()
                    if m.is_available and m.task_affinity in (task, "general")
                ]
                
                if not candidates:
                    candidates = [m for m in self._models.values() if m.is_available]
                
                if not candidates:
                    return self.STATIC_MODELS[0] if self.STATIC_MODELS else None
                
                # Sort by fitness score (highest first)
                candidates.sort(key=lambda m: m.fitness_score, reverse=True)
                return candidates[0].model_id
        except Exception as e:
            logger.error(f"[ModelRegistry] get_best_model error: {e}")
            return self.STATIC_MODELS[0] if self.STATIC_MODELS else None
    
    def get_ranked_models(self, task: str = "general", limit: int = 10) -> List[ModelEntry]:
        """Get ranked list of models by fitness score."""
        try:
            with self._lock:
                candidates = [m for m in self._models.values() if m.is_available]
                candidates.sort(key=lambda m: m.fitness_score, reverse=True)
                return candidates[:limit]
        except Exception:
            return []
    
    def mark_model_success(self, model_id: str, latency_ms: float = 200.0) -> None:
        """Record a successful model request."""
        try:
            with self._lock:
                entry = self._models.get(model_id)
                if entry:
                    entry.total_requests += 1
                    entry.total_successes += 1
                    entry.success_rate = entry.display_success_rate
                    entry.availability = 1.0
                    entry.last_tested = time.time()
                    
                    # Update latency score (inverse, normalized)
                    alpha = 0.25
                    entry.avg_latency_ms = alpha * latency_ms + (1 - alpha) * entry.avg_latency_ms
                    entry.latency_score = max(0.1, 1.0 - (entry.avg_latency_ms / 5000.0))
        except Exception:
            pass
    
    def mark_model_failure(self, model_id: str) -> None:
        """Record a failed model request."""
        try:
            with self._lock:
                entry = self._models.get(model_id)
                if entry:
                    entry.total_requests += 1
                    entry.total_failures += 1
                    entry.success_rate = entry.display_success_rate
                    entry.reliability = max(0.1, entry.reliability - 0.05)
                    entry.last_tested = time.time()
                    
                    # If too many failures, mark as unavailable
                    if entry.total_requests > 5 and entry.display_success_rate < 0.2:
                        entry.is_available = False
        except Exception:
            pass
    
    def refresh(self) -> None:
        """Force refresh from live API."""
        try:
            self._fetch_models_live()
        except Exception as e:
            logger.warning(f"[ModelRegistry] Refresh failed: {e}")
    
    def get_status(self) -> Dict:
        """Get registry status."""
        try:
            with self._lock:
                available = sum(1 for m in self._models.values() if m.is_available)
                cache_age_hrs = (time.time() - self._last_refresh) / 3600
                
                top_5 = sorted(
                    self._models.values(),
                    key=lambda m: m.fitness_score,
                    reverse=True,
                )[:5]
                
                return {
                    "total_models": len(self._models),
                    "available_models": available,
                    "last_refresh": self._last_refresh,
                    "cache_age_hours": round(cache_age_hrs, 1),
                    "refresh_interval_hours": self._refresh_interval_hrs,
                    "top_5_models": [
                        {
                            "model_id": m.model_id,
                            "fitness_score": round(m.fitness_score, 3),
                            "availability": round(m.availability, 3),
                            "reliability": round(m.reliability, 3),
                            "latency_score": round(m.latency_score, 3),
                            "success_rate": round(m.success_rate, 3),
                            "dpi_resistance": round(m.dpi_resistance, 3),
                        }
                        for m in top_5
                    ],
                }
        except Exception as e:
            return {"error": str(e)}


def get_model_registry() -> ModelRegistry:
    """Get the singleton ModelRegistry instance."""
    return ModelRegistry.instance()
