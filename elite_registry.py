#!/usr/bin/env python3
"""
elite_registry.py — Dynamic Discovery & Intelligence: Elite Model Registry v1.0
═══════════════════════════════════════════════════════════════════════════════

Autonomous model discovery and fitness scoring system. Queries Cloudflare
Workers AI and Portkey APIs to discover available models, then ranks them
using a multi-dimensional fitness scoring algorithm.

CAPABILITIES:
  - Live model fetch from CF Workers AI (/ai/models) every 6 hours
  - Live model fetch from Portkey (/models) every 6 hours
  - Multi-dimensional fitness scoring algorithm:
    1. DPI_Resistance_Index (Primary: Success rate bypassing Iran's firewall)
    2. Response_Latency (Secondary: Sub-second API response)
    3. Context_Window_Utility (Tertiary: Bridge extraction capacity)
  - Elite-Registry: Dynamically ranked model list with auto-refresh
  - Static-Baseline fallback: 12 hardcoded curated models
  - Cross-slot model deduplication and health tracking
  - Integrates with telemetry_watcher.py for event logging

DESIGN PRINCIPLES:
  - ADDITIVE ONLY: Does not modify or replace any existing module
  - WRAPPER PATTERN: Wraps around existing model_selector.py
  - ZERO CRASH: All operations wrapped in try/except
  - GRACEFUL FALLBACK: Falls back to existing model_selector on any error

USAGE:
  from elite_registry import EliteRegistry

  registry = EliteRegistry()

  # Get the best model for the current task
  best = registry.get_best_model(task="general")

  # Get ranked model list
  ranked = registry.get_ranked_models()

  # Force refresh from APIs
  registry.refresh()

  # Get registry status
  status = registry.get_status()
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("torshield.elite_registry")

DATA_DIR = Path("data")
DATA_DIR.mkdir(parents=True, exist_ok=True)

REGISTRY_CACHE_PATH = DATA_DIR / "elite_registry_cache.json"

# Refresh interval: 6 hours (in seconds)
REFRESH_INTERVAL = 6 * 3600

# ─────────────────────────────────────────────────────────────────────────────
# Data Classes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ModelEntry:
    """A model entry in the Elite-Registry with fitness scoring."""
    model_id: str
    source: str              # "cf_workers_ai", "cf_ai_gateway", "portkey"
    display_name: str = ""
    description: str = ""

    # Fitness scores (0.0 - 1.0)
    dpi_resistance_index: float = 0.5    # Primary: ability to bypass Iran DPI
    response_latency: float = 0.5        # Secondary: 1.0 = instant, 0.0 = timeout
    context_window_utility: float = 0.5  # Tertiary: bridge extraction capacity

    # Composite fitness score
    fitness_score: float = 0.0

    # Metadata
    parameter_count: str = ""    # e.g., "70b", "120b"
    context_window: int = 0     # tokens
    is_uuid_format: bool = False  # CF sometimes returns UUIDs (invalid for API)
    last_seen: str = ""
    slot_index: int = 0         # Which CF slot discovered this model
    is_available: bool = True
    error_count: int = 0

    # Weight configuration for composite score
    _WEIGHT_DPI: float = 0.50
    _WEIGHT_LATENCY: float = 0.30
    _WEIGHT_CONTEXT: float = 0.20

    def compute_fitness(self) -> float:
        """Compute composite fitness score from multi-dimensional vector."""
        self.fitness_score = (
            self.dpi_resistance_index * self._WEIGHT_DPI +
            self.response_latency * self._WEIGHT_LATENCY +
            self.context_window_utility * self._WEIGHT_CONTEXT
        )
        return self.fitness_score

    def to_dict(self) -> Dict[str, Any]:
        return {
            "model_id": self.model_id,
            "source": self.source,
            "display_name": self.display_name,
            "dpi_resistance_index": round(self.dpi_resistance_index, 4),
            "response_latency": round(self.response_latency, 4),
            "context_window_utility": round(self.context_window_utility, 4),
            "fitness_score": round(self.fitness_score, 4),
            "parameter_count": self.parameter_count,
            "context_window": self.context_window,
            "slot_index": self.slot_index,
            "is_available": self.is_available,
        }


# ─────────────────────────────────────────────────────────────────────────────
# Static Baseline Models (Hardcoded Fallback)
# ─────────────────────────────────────────────────────────────────────────────

STATIC_BASELINE: List[ModelEntry] = [
    ModelEntry(
        model_id="@cf/meta/llama-3.3-70b-instruct-fp8-fast",
        source="cf_workers_ai",
        display_name="Llama 3.3 70B Instruct (Fast)",
        description="Meta's Llama 3.3 70B instruction-tuned, FP8 quantized for speed",
        dpi_resistance_index=0.85,
        response_latency=0.90,
        context_window_utility=0.75,
        parameter_count="70b",
        context_window=8192,
    ),
    ModelEntry(
        model_id="@cf/meta/llama-3.3-70b-instruct",
        source="cf_workers_ai",
        display_name="Llama 3.3 70B Instruct",
        description="Meta's Llama 3.3 70B instruction-tuned model",
        dpi_resistance_index=0.85,
        response_latency=0.80,
        context_window_utility=0.80,
        parameter_count="70b",
        context_window=8192,
    ),
    ModelEntry(
        model_id="@cf/meta/llama-4-scout-17b-16e-instruct",
        source="cf_workers_ai",
        display_name="Llama 4 Scout 17B MoE",
        description="Meta's Llama 4 Scout with Mixture of Experts",
        dpi_resistance_index=0.80,
        response_latency=0.85,
        context_window_utility=0.70,
        parameter_count="17b-moe",
        context_window=8192,
    ),
    ModelEntry(
        model_id="@cf/mistralai/mistral-small-3.1-24b-instruct",
        source="cf_workers_ai",
        display_name="Mistral Small 3.1 24B",
        description="Mistral's efficient 24B instruction model",
        dpi_resistance_index=0.80,
        response_latency=0.88,
        context_window_utility=0.65,
        parameter_count="24b",
        context_window=32768,
    ),
    ModelEntry(
        model_id="@cf/qwen/qwen3-32b",
        source="cf_workers_ai",
        display_name="Qwen 3 32B",
        description="Alibaba's Qwen 3 32B model",
        dpi_resistance_index=0.78,
        response_latency=0.82,
        context_window_utility=0.72,
        parameter_count="32b",
        context_window=32768,
    ),
    ModelEntry(
        model_id="@cf/deepseek-ai/deepseek-r1-distill-qwen-32b",
        source="cf_workers_ai",
        display_name="DeepSeek R1 Distill Qwen 32B",
        description="DeepSeek's reasoning model distilled to 32B",
        dpi_resistance_index=0.78,
        response_latency=0.75,
        context_window_utility=0.78,
        parameter_count="32b",
        context_window=16384,
    ),
    ModelEntry(
        model_id="@cf/google/gemma-3-27b-it",
        source="cf_workers_ai",
        display_name="Google Gemma 3 27B IT",
        description="Google's Gemma 3 instruction-tuned 27B",
        dpi_resistance_index=0.75,
        response_latency=0.83,
        context_window_utility=0.68,
        parameter_count="27b",
        context_window=8192,
    ),
    ModelEntry(
        model_id="@cf/meta/llama-3.1-8b-instruct",
        source="cf_workers_ai",
        display_name="Llama 3.1 8B Instruct",
        description="Meta's lightweight 8B instruction model — fastest",
        dpi_resistance_index=0.90,  # Smallest payload = hardest to detect
        response_latency=0.95,
        context_window_utility=0.50,
        parameter_count="8b",
        context_window=8192,
    ),
    ModelEntry(
        model_id="@cf/mistralai/mistral-7b-instruct-v0.2-lora",
        source="cf_workers_ai",
        display_name="Mistral 7B Instruct v0.2 LoRA",
        description="Mistral 7B with LoRA adaptation",
        dpi_resistance_index=0.92,
        response_latency=0.95,
        context_window_utility=0.45,
        parameter_count="7b",
        context_window=4096,
    ),
    ModelEntry(
        model_id="llama3.3-70b",
        source="cerebras",
        display_name="Llama 3.3 70B (Cerebras)",
        description="Cerebras-hosted Llama 3.3 70B — ultra-fast inference",
        dpi_resistance_index=0.60,  # Direct API, easier for DPI to fingerprint
        response_latency=0.98,
        context_window_utility=0.75,
        parameter_count="70b",
        context_window=8192,
    ),
    ModelEntry(
        model_id="meta/llama-3.1-70b-instruct",
        source="portkey",
        display_name="Llama 3.1 70B Instruct (Portkey)",
        description="Portkey-routed Llama 3.1 70B",
        dpi_resistance_index=0.70,  # Portkey acts as proxy, adds some cover
        response_latency=0.75,
        context_window_utility=0.72,
        parameter_count="70b",
        context_window=8192,
    ),
    ModelEntry(
        model_id="gpt-oss-120b",
        source="cf_workers_ai",
        display_name="GPT-OSS 120B",
        description="Open-source GPT variant, 120B parameters",
        dpi_resistance_index=0.72,
        response_latency=0.65,
        context_window_utility=0.88,
        parameter_count="120b",
        context_window=16384,
    ),
]


# ─────────────────────────────────────────────────────────────────────────────
# Elite Registry
# ─────────────────────────────────────────────────────────────────────────────

class EliteRegistry:
    """
    Dynamic model discovery and fitness scoring registry.

    Queries CF Workers AI and Portkey APIs every 6 hours to discover
    available models, then ranks them using a multi-dimensional fitness
    scoring algorithm.

    FALLBACK: If dynamic discovery fails, falls back to the existing
    model_selector.py or the static baseline.
    """

    _instance: Optional["EliteRegistry"] = None
    _instance_lock = threading.Lock()

    def __init__(self):
        self._lock = threading.Lock()
        self._registry: Dict[str, ModelEntry] = {}
        self._last_refresh: float = 0.0
        self._refresh_count: int = 0
        self._is_refreshing: bool = False

        # Load telemetry integration
        try:
            from telemetry_watcher import get_telemetry
            self._telemetry = get_telemetry()
        except ImportError:
            self._telemetry = None

        # Initialize with static baseline
        for entry in STATIC_BASELINE:
            entry.compute_fitness()
            self._registry[entry.model_id] = entry

        # Try to load cached registry
        self._load_cache()

        log.info(
            f"[EliteRegistry] Initialized with {len(self._registry)} models "
            f"(static baseline: {len(STATIC_BASELINE)})"
        )

    @classmethod
    def instance(cls) -> "EliteRegistry":
        """Get or create the singleton EliteRegistry instance."""
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    # ── Model Discovery ─────────────────────────────────────────────────────

    def refresh(self, force: bool = False) -> int:
        """
        Refresh the registry by querying CF Workers AI and Portkey APIs.
        Returns the number of new models discovered.
        """
        try:
            now = time.time()

            # Check if refresh is needed (every 6 hours)
            if not force and (now - self._last_refresh) < REFRESH_INTERVAL:
                log.debug("[EliteRegistry] Cache still fresh, skipping refresh")
                return 0

            if self._is_refreshing:
                log.debug("[EliteRegistry] Refresh already in progress")
                return 0

            self._is_refreshing = True
            new_count = 0

            try:
                # Discover from CF Workers AI (all 11 slots)
                cf_models = self._discover_cf_models()
                for model in cf_models:
                    model_id = model.model_id
                    if model_id not in self._registry:
                        model.compute_fitness()
                        self._registry[model_id] = model
                        new_count += 1
                        log.info(f"[EliteRegistry] NEW model: {model_id} from {model.source}")
                    else:
                        # Update existing entry
                        existing = self._registry[model_id]
                        existing.last_seen = datetime.now(timezone.utc).isoformat()
                        existing.is_available = True
                        existing.slot_index = model.slot_index

                # Discover from Portkey
                portkey_models = self._discover_portkey_models()
                for model in portkey_models:
                    model_id = model.model_id
                    if model_id not in self._registry:
                        model.compute_fitness()
                        self._registry[model_id] = model
                        new_count += 1
                        log.info(f"[EliteRegistry] NEW model: {model_id} from {model.source}")
                    else:
                        existing = self._registry[model_id]
                        existing.last_seen = datetime.now(timezone.utc).isoformat()
                        existing.is_available = True

                self._last_refresh = now
                self._refresh_count += 1

                # Re-rank all models
                self._rerank_all()

                # Save cache
                self._save_cache()

                # Log telemetry
                if self._telemetry:
                    try:
                        self._telemetry.log_self_heal(
                            "registry_refresh",
                            {
                                "new_models": new_count,
                                "total_models": len(self._registry),
                                "refresh_count": self._refresh_count,
                            },
                            success=True,
                        )
                    except Exception:
                        pass

                log.info(
                    f"[EliteRegistry] Refresh complete: {new_count} new models, "
                    f"{len(self._registry)} total"
                )

            finally:
                self._is_refreshing = False

            return new_count

        except Exception as e:
            log.warning(f"[EliteRegistry] Refresh failed: {e}")
            if self._telemetry:
                try:
                    self._telemetry.log_self_heal(
                        "registry_refresh_failed",
                        {"error": str(e)},
                        success=False,
                    )
                except Exception:
                    pass
            return 0

    def _discover_cf_models(self) -> List[ModelEntry]:
        """
        Discover models from Cloudflare Workers AI across all 11 slots.
        Queries the /ai/models endpoint for each configured slot.
        """
        discovered = []

        for i in range(1, 12):
            try:
                account_id = os.environ.get(f"CF_ACCOUNT_ID_{i}", "").strip()
                api_token = os.environ.get(f"CF_API_TOKEN_{i}", "").strip()

                if not account_id or not api_token:
                    continue

                models = self._fetch_cf_models(account_id, api_token, i)
                discovered.extend(models)

            except Exception as e:
                log.debug(f"[EliteRegistry] CF slot {i} discovery failed: {e}")

        return discovered

    def _fetch_cf_models(
        self, account_id: str, api_token: str, slot_index: int
    ) -> List[ModelEntry]:
        """Fetch model list from a single CF account."""
        models = []

        try:
            import urllib.request
            import urllib.error

            url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/models/search"
            headers = {
                "Authorization": f"Bearer {api_token}",
                "Content-Type": "application/json",
                "User-Agent": "TorShield-IR/1.0",
            }

            req = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            if not data.get("success"):
                return []

            for model_info in data.get("result", []):
                try:
                    model_id = model_info.get("id", "")
                    if not model_id:
                        continue

                    # Skip UUID-format IDs (they cause 400 errors)
                    is_uuid = (
                        len(model_id) == 36
                        and model_id.count("-") == 4
                    )
                    if is_uuid:
                        continue

                    # Extract metadata
                    name = model_info.get("name", model_id)
                    description = model_info.get("description", "")

                    # Score the model
                    entry = self._score_model_entry(
                        model_id=model_id,
                        source="cf_workers_ai",
                        display_name=name,
                        description=description,
                        slot_index=slot_index,
                        model_info=model_info,
                    )

                    models.append(entry)

                except Exception as e:
                    log.debug(f"[EliteRegistry] CF model parse failed: {e}")

        except Exception as e:
            log.debug(f"[EliteRegistry] CF slot {slot_index} fetch failed: {e}")

        return models

    def _discover_portkey_models(self) -> List[ModelEntry]:
        """Discover models from Portkey API."""
        models = []

        try:
            portkey_key = os.environ.get("PORTKEY_API_KEY", "").strip()
            if not portkey_key:
                return []

            import urllib.request
            import urllib.error

            gateway_url = os.environ.get(
                "PORTKEY_GATEWAY_URL", "https://api.portkey.ai/v1"
            )
            url = f"{gateway_url}/models"
            headers = {
                "x-portkey-api-key": portkey_key,
                "Content-Type": "application/json",
                "User-Agent": "TorShield-IR/1.0",
            }

            req = urllib.request.Request(url, headers=headers, method="GET")
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            for model_info in data.get("data", []):
                try:
                    model_id = model_info.get("id", "")
                    if not model_id:
                        continue

                    entry = self._score_model_entry(
                        model_id=model_id,
                        source="portkey",
                        display_name=model_info.get("name", model_id),
                        description=model_info.get("description", ""),
                        slot_index=0,
                        model_info=model_info,
                    )

                    models.append(entry)

                except Exception as e:
                    log.debug(f"[EliteRegistry] Portkey model parse failed: {e}")

        except Exception as e:
            log.debug(f"[EliteRegistry] Portkey discovery failed: {e}")

        return models

    def _score_model_entry(
        self,
        model_id: str,
        source: str,
        display_name: str,
        description: str,
        slot_index: int,
        model_info: Dict[str, Any],
    ) -> ModelEntry:
        """
        Score a model using the multi-dimensional fitness algorithm.

        Dimensions:
          1. DPI_Resistance_Index (Primary: 50% weight)
          2. Response_Latency (Secondary: 30% weight)
          3. Context_Window_Utility (Tertiary: 20% weight)
        """
        entry = ModelEntry(
            model_id=model_id,
            source=source,
            display_name=display_name,
            description=description,
            slot_index=slot_index,
            last_seen=datetime.now(timezone.utc).isoformat(),
        )

        # ── DPI Resistance Index ────────────────────────────────────────────
        # CF-hosted models get high DPI resistance because they go through
        # CF's own CDN infrastructure, which Iran cannot block wholesale
        if source == "cf_workers_ai" or source == "cf_ai_gateway":
            # CF models: traffic looks like normal CF CDN requests
            entry.dpi_resistance_index = 0.80
            # Smaller models produce smaller payloads → harder to fingerprint
            if "7b" in model_id or "8b" in model_id:
                entry.dpi_resistance_index = 0.92
            elif "70b" in model_id or "72b" in model_id:
                entry.dpi_resistance_index = 0.80
            elif "120b" in model_id:
                entry.dpi_resistance_index = 0.70  # Larger responses easier to classify
            # Fast models complete faster → less traffic for DPI to analyze
            if "fast" in model_id or "fp8" in model_id:
                entry.dpi_resistance_index += 0.05
        elif source == "cerebras":
            # Direct API, easier for DPI to fingerprint the endpoint
            entry.dpi_resistance_index = 0.60
        elif source == "portkey":
            # Portkey acts as proxy, adds some cover
            entry.dpi_resistance_index = 0.70
        else:
            entry.dpi_resistance_index = 0.50

        # ── Response Latency ────────────────────────────────────────────────
        if source == "cerebras":
            entry.response_latency = 0.95  # Cerebras is fastest
        elif "fast" in model_id or "fp8" in model_id:
            entry.response_latency = 0.90
        elif "7b" in model_id or "8b" in model_id:
            entry.response_latency = 0.88
        elif "24b" in model_id or "27b" in model_id:
            entry.response_latency = 0.82
        elif "70b" in model_id or "72b" in model_id:
            entry.response_latency = 0.75
        elif "120b" in model_id:
            entry.response_latency = 0.60
        else:
            entry.response_latency = 0.65

        # ── Context Window Utility ──────────────────────────────────────────
        # Larger context windows = better for bridge extraction
        ctx = model_info.get("context_window", 0)
        if ctx > 0:
            entry.context_window = ctx
            if ctx >= 32768:
                entry.context_window_utility = 0.90
            elif ctx >= 16384:
                entry.context_window_utility = 0.80
            elif ctx >= 8192:
                entry.context_window_utility = 0.70
            elif ctx >= 4096:
                entry.context_window_utility = 0.55
            else:
                entry.context_window_utility = 0.40
        else:
            # Estimate from model name
            if "120b" in model_id:
                entry.context_window_utility = 0.88
                entry.context_window = 16384
            elif "70b" in model_id or "72b" in model_id:
                entry.context_window_utility = 0.75
                entry.context_window = 8192
            elif "32b" in model_id:
                entry.context_window_utility = 0.72
                entry.context_window = 32768
            elif "24b" in model_id or "27b" in model_id:
                entry.context_window_utility = 0.65
                entry.context_window = 32768
            elif "8b" in model_id:
                entry.context_window_utility = 0.50
                entry.context_window = 8192
            else:
                entry.context_window_utility = 0.50
                entry.context_window = 4096

        # Extract parameter count from model ID
        for suffix in ["120b", "70b", "72b", "32b", "27b", "24b", "8b", "7b"]:
            if suffix in model_id.lower():
                entry.parameter_count = suffix
                break

        entry.compute_fitness()
        return entry

    # ── Model Selection ─────────────────────────────────────────────────────

    def get_best_model(self, task: str = "general") -> str:
        """
        Get the best model for the given task.
        Falls back to existing model_selector.py on any error.
        """
        try:
            # Auto-refresh if needed
            self.refresh()

            # Get ranked models
            ranked = self.get_ranked_models()

            if ranked:
                # Select based on task
                if task == "fast":
                    # Prefer models with high response_latency
                    fast_models = sorted(
                        ranked,
                        key=lambda m: m.response_latency,
                        reverse=True,
                    )
                    return fast_models[0].model_id
                elif task == "reasoning":
                    # Prefer large models with high context utility
                    reasoning_models = sorted(
                        ranked,
                        key=lambda m: m.context_window_utility,
                        reverse=True,
                    )
                    return reasoning_models[0].model_id
                else:
                    # General: use composite fitness score
                    return ranked[0].model_id

        except Exception as e:
            log.warning(f"[EliteRegistry] Best model selection failed: {e}")

        # Fallback to existing model_selector
        try:
            from torshield_ai_gateway.model_selector import best_cf_model
            return best_cf_model()
        except Exception:
            pass

        # Ultimate fallback
        return STATIC_BASELINE[0].model_id

    def get_ranked_models(self) -> List[ModelEntry]:
        """Get all models ranked by fitness score (descending)."""
        try:
            with self._lock:
                available = [m for m in self._registry.values() if m.is_available]
                available.sort(key=lambda m: m.fitness_score, reverse=True)
                return available
        except Exception:
            return list(STATIC_BASELINE)

    def get_models_by_source(self, source: str) -> List[ModelEntry]:
        """Get models filtered by source."""
        try:
            with self._lock:
                return [
                    m for m in self._registry.values()
                    if m.source == source and m.is_available
                ]
        except Exception:
            return []

    def mark_model_error(self, model_id: str) -> None:
        """Mark a model as having an error (decreases its fitness)."""
        try:
            with self._lock:
                if model_id in self._registry:
                    entry = self._registry[model_id]
                    entry.error_count += 1

                    # If too many errors, mark as unavailable
                    if entry.error_count >= 5:
                        entry.is_available = False
                        log.warning(
                            f"[EliteRegistry] Model {model_id} marked unavailable "
                            f"after {entry.error_count} errors"
                        )

                    # Reduce fitness score
                    penalty = min(0.05 * entry.error_count, 0.5)
                    entry.fitness_score = max(0.0, entry.fitness_score - penalty)

            # Log telemetry
            if self._telemetry:
                try:
                    self._telemetry.log_slot_failure(
                        slot_index=0,
                        env_var=f"model_{model_id}",
                        error_type="model_error",
                        error_detail=f"errors={self._registry.get(model_id, ModelEntry(model_id='', source='')).error_count}",
                    )
                except Exception:
                    pass

        except Exception as e:
            log.debug(f"[EliteRegistry] Mark model error failed: {e}")

    def mark_model_success(self, model_id: str, latency_ms: float = 200.0) -> None:
        """Mark a model as having a successful response (increases fitness)."""
        try:
            with self._lock:
                if model_id in self._registry:
                    entry = self._registry[model_id]
                    entry.error_count = max(0, entry.error_count - 1)

                    # Update latency score based on actual measurement
                    if latency_ms < 500:
                        entry.response_latency = 0.95
                    elif latency_ms < 1000:
                        entry.response_latency = 0.80
                    elif latency_ms < 2000:
                        entry.response_latency = 0.60
                    else:
                        entry.response_latency = 0.40

                    entry.compute_fitness()
        except Exception:
            pass

    # ── Internal Methods ────────────────────────────────────────────────────

    def _rerank_all(self) -> None:
        """Re-compute fitness scores and re-rank all models."""
        try:
            with self._lock:
                for entry in self._registry.values():
                    entry.compute_fitness()
        except Exception:
            pass

    def _save_cache(self) -> None:
        """Save registry cache to disk."""
        try:
            cache_data = {
                "last_refresh": self._last_refresh,
                "refresh_count": self._refresh_count,
                "models": {
                    k: v.to_dict() for k, v in self._registry.items()
                },
                "saved_at": datetime.now(timezone.utc).isoformat(),
            }

            REGISTRY_CACHE_PATH.write_text(
                json.dumps(cache_data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except Exception:
            # GRACEFUL FAIL-SAFE
            pass

    def _load_cache(self) -> None:
        """Load registry cache from disk."""
        try:
            if not REGISTRY_CACHE_PATH.exists():
                return

            data = json.loads(REGISTRY_CACHE_PATH.read_text(encoding="utf-8"))

            self._last_refresh = data.get("last_refresh", 0)
            self._refresh_count = data.get("refresh_count", 0)

            for model_id, model_data in data.get("models", {}).items():
                try:
                    entry = ModelEntry(
                        model_id=model_data.get("model_id", model_id),
                        source=model_data.get("source", "unknown"),
                        display_name=model_data.get("display_name", ""),
                        description=model_data.get("description", ""),
                        dpi_resistance_index=model_data.get("dpi_resistance_index", 0.5),
                        response_latency=model_data.get("response_latency", 0.5),
                        context_window_utility=model_data.get("context_window_utility", 0.5),
                        parameter_count=model_data.get("parameter_count", ""),
                        context_window=model_data.get("context_window", 0),
                        slot_index=model_data.get("slot_index", 0),
                        is_available=model_data.get("is_available", True),
                        error_count=model_data.get("error_count", 0),
                        last_seen=model_data.get("last_seen", ""),
                    )
                    entry.compute_fitness()
                    # Only add if not already in static baseline
                    if model_id not in self._registry:
                        self._registry[model_id] = entry
                except Exception:
                    pass

            log.info(
                f"[EliteRegistry] Loaded cache: {len(data.get('models', {}))} models"
            )

        except Exception as e:
            log.debug(f"[EliteRegistry] Cache load failed: {e}")

    def get_status(self) -> Dict[str, Any]:
        """Get current registry status."""
        try:
            ranked = self.get_ranked_models()
            return {
                "total_models": len(self._registry),
                "available_models": sum(1 for m in self._registry.values() if m.is_available),
                "last_refresh": datetime.fromtimestamp(
                    self._last_refresh, tz=timezone.utc
                ).isoformat() if self._last_refresh > 0 else "never",
                "refresh_count": self._refresh_count,
                "top_5_models": [m.to_dict() for m in ranked[:5]],
                "static_baseline_count": len(STATIC_BASELINE),
                "cache_age_hours": round(
                    (time.time() - self._last_refresh) / 3600, 1
                ) if self._last_refresh > 0 else -1,
            }
        except Exception as e:
            return {"error": str(e)}


# ─────────────────────────────────────────────────────────────────────────────
# Module-level convenience functions
# ─────────────────────────────────────────────────────────────────────────────

def get_registry() -> EliteRegistry:
    """Get the singleton EliteRegistry instance."""
    return EliteRegistry.instance()


def get_best_model(task: str = "general") -> str:
    """Get the best model for a task."""
    return get_registry().get_best_model(task)


def get_ranked_models() -> List[ModelEntry]:
    """Get ranked model list."""
    return get_registry().get_ranked_models()


# ─────────────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    """CLI entry point for elite registry."""
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    parser = argparse.ArgumentParser(description="TorShield-IR Elite Registry")
    parser.add_argument("--status", action="store_true", help="Show registry status")
    parser.add_argument("--refresh", action="store_true", help="Force refresh from APIs")
    parser.add_argument("--best", type=str, default=None, help="Get best model for task")
    parser.add_argument("--ranked", action="store_true", help="Show ranked model list")
    args = parser.parse_args()

    registry = EliteRegistry()

    if args.status:
        status = registry.get_status()
        print(json.dumps(status, indent=2, ensure_ascii=False))
    elif args.refresh:
        count = registry.refresh(force=True)
        print(f"Refreshed: {count} new models discovered")
    elif args.best:
        best = registry.get_best_model(task=args.best)
        print(f"Best model for '{args.best}': {best}")
    elif args.ranked:
        ranked = registry.get_ranked_models()
        for i, m in enumerate(ranked[:20], 1):
            print(f"{i:2d}. [{m.fitness_score:.3f}] {m.model_id} ({m.source})")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
