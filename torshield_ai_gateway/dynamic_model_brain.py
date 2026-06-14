"""
dynamic_model_brain.py — Live Model Fetcher + Intelligent Scorer for TorShield AI Gateway
===========================================================================================

Fetches LIVE model lists from Cloudflare (11 accounts) + Portkey APIs,
scores each model automatically, and picks the highest-scoring model per task.
Self-updating as providers release new models. Never needs manual updates.

ARCHITECTURE (Fix-17.0 — 100% synchronous, zero external HTTP deps):
  ┌──────────────────────────────────────────────────┐
  │  DynamicModelBrain.get_globally_strongest()      │
  └──────────────────┬───────────────────────────────┘
                     │
       ┌─────────────▼──────────────────┐
       │  1. Fetch CF models (11 accts) │  urllib sync fetch
       │  2. Fetch Portkey models       │  urllib sync fetch
       │  3. Score each model           │  Multi-factor 0-100
       │  4. Rank & select              │  Top model wins
       │  5. Cache with TTL=30min       │  Avoid repeated fetches
       └─────────────┬──────────────────┘
                     │ FAIL?
       ┌─────────────▼──────────────────┐
       │   Offline Fallback             │  existing model_selector.py
       └────────────────────────────────┘

SCORING FORMULA (0-100 scale):
  param_score      = log2(params+1) * 8        max ~80
  context_bonus    = log2(ctx_k+1) * 2         max ~20
  reasoning_bonus  = 15 if has_reasoning
  fc_bonus         = 8  if has_function_calling
  vision_bonus     = 5  if has_vision
  newest_bonus     = 10 if is_newest/featured
  hosted_bonus     = 5  if CF-hosted (lower latency)
  speed_penalty    = tier*5 if task=="fast" (negative = bonus for fast models)

ANTI-DPI INTEGRATION:
  When Iran DPI is detected, the brain automatically:
  - Prefers CF-hosted models (no cross-border API calls)
  - Boosts fast/low-latency models to reduce traffic analysis surface
  - Deprioritizes models requiring long streaming responses

Fix-17.0 CHANGES:
  - BUG-1 FIX: Removed ALL async/await/aiohttp references.
    Replaced with synchronous urllib-based _http_get().
    Zero external HTTP dependencies — urllib is Python stdlib.
  - BUG-2 FIX: Added empty-list guards in every method that
    accesses list by index. Never crashes on empty results.
  - refresh() is now synchronous — no asyncio.run() needed.

Version: Fix-17.0 / Feature: DYNAMIC-BRAIN
"""

from __future__ import annotations

import os
import re
import time
import math
import json as _json
import ssl
import logging
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from enum import Enum

logger = logging.getLogger("torshield.ai.dynamic_brain")

# ──────────────────────────────────────────────────────────────
# 1. DATA STRUCTURES
# ──────────────────────────────────────────────────────────────


class ModelSource(str, Enum):
    CLOUDFLARE_HOSTED  = "cf_hosted"    # @cf/... runs on CF GPUs
    CLOUDFLARE_PROXIED = "cf_proxied"   # CF gateway -> third-party
    PORTKEY            = "portkey"      # portkey.ai gateway


@dataclass
class LiveModel:
    """Represents a single model discovered from a live API fetch."""
    id: str                             # full model identifier
    source: ModelSource
    provider: str = "unknown"           # "meta", "openai", etc.
    param_b: float = 0.0                # parameter count in billions
    context_k: int = 0                  # context window in K tokens
    has_reasoning: bool = False
    has_function_calling: bool = False
    has_vision: bool = False
    is_newest: bool = False             # pinned/featured by provider
    score: float = 0.0                  # computed after fetch
    latency_tier: int = 2               # 1=fast 2=normal 3=slow
    account_id: str = ""                # CF account that has this model


# ──────────────────────────────────────────────────────────────
# 2. PURE STDLIB HTTP GET (urllib — zero import failures)
# ──────────────────────────────────────────────────────────────

def _http_get(url: str, headers: dict, timeout: int = 12) -> dict:
    """
    Pure stdlib HTTP GET -> parsed JSON dict.
    Falls back to empty dict on any error. Never raises.
    """
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read()
            return _json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as e:
        logger.warning(f"[Brain] HTTP {e.code} for {_mask(url, 6)}")
        return {}
    except Exception as exc:
        logger.warning(f"[Brain] GET failed: {exc}")
        return {}


# ──────────────────────────────────────────────────────────────
# 3. CLOUDFLARE LIVE MODEL FETCHER (11 ACCOUNTS, SYNC)
# ──────────────────────────────────────────────────────────────

# Number of CF account slots
CF_N_SLOTS = 11

# Known parameter counts for scoring (updated June 2026)
CF_KNOWN_PARAMS: Dict[str, float] = {
    "@cf/moonshotai/kimi-k2.6":                              1000.0,
    "@cf/moonshotai/kimi-k2.5":                              1000.0,
    "@cf/openai/gpt-oss-120b":                                120.0,
    "@cf/nvidia/nemotron-3-120b-a12b":                        120.0,
    "@cf/meta/llama-4-scout-17b-16e-instruct":                 17.0,
    "@cf/meta/llama-4-scout-17b-16e-instruct-fp8":             17.0,
    "@cf/meta/llama-4-maverick-17b-128e-instruct-fp8":         17.0,
    "@cf/meta/llama-3.3-70b-instruct-fp8-fast":                70.0,
    "@cf/meta/llama-3.1-70b-instruct":                         70.0,
    "@cf/meta/llama-3.2-90b-vision-instruct":                  90.0,
    "@cf/deepseek-ai/deepseek-r1-distill-qwen-32b":            32.0,
    "@cf/deepseek-ai/deepseek-r1-distill-llama-70b":           70.0,
    "@cf/qwen/qwq-32b":                                        32.0,
    "@cf/zai-org/glm-4.7-flash":                                7.0,
    "@cf/mistral/mistral-large-2407":                          123.0,
    "@cf/google/gemma-3-27b-it":                               27.0,
    "@cf/microsoft/phi-4":                                     14.0,
}

CF_KNOWN_CONTEXT_K: Dict[str, int] = {
    "@cf/moonshotai/kimi-k2.6":   262,
    "@cf/moonshotai/kimi-k2.5":   256,
    "@cf/openai/gpt-oss-120b":    128,
    "@cf/meta/llama-4-scout-17b-16e-instruct": 10485,  # 10M tokens
    "@cf/meta/llama-4-maverick-17b-128e-instruct-fp8": 10485,
    "@cf/meta/llama-3.3-70b-instruct-fp8-fast": 128,
    "@cf/meta/llama-3.1-70b-instruct": 128,
    "@cf/deepseek-ai/deepseek-r1-distill-qwen-32b": 128,
    "@cf/deepseek-ai/deepseek-r1-distill-llama-70b": 128,
    "@cf/qwen/qwq-32b": 32,
    "@cf/zai-org/glm-4.7-flash":  131,
    "@cf/mistral/mistral-large-2407": 128,
    "@cf/google/gemma-3-27b-it": 128,
}


def _infer_params(model_id: str) -> float:
    """Look up known params or infer from model name."""
    if model_id in CF_KNOWN_PARAMS:
        return CF_KNOWN_PARAMS[model_id]
    # MoE pattern: 17b-16e -> 17.0 (active params)
    moe_match = re.search(r"(\d+(?:\.\d+)?)b[_\-](\d+)e", model_id.lower())
    if moe_match:
        return float(moe_match.group(1))
    # Standard dense: first plain Nb occurrence
    for part in model_id.replace("-", " ").split():
        if part.endswith("b") and part[:-1].replace(".", "").isdigit():
            try:
                return float(part[:-1])
            except ValueError:
                pass
    return 0.0


def _mask(val: str, visible: int = 4) -> str:
    """Mask a sensitive value for logging."""
    if not val:
        return "<EMPTY>"
    if len(val) <= visible * 2:
        return f"{val[:2]}***"
    return f"{val[:visible]}...{val[-visible:]}"


def fetch_cf_models_sync(
    account_id: str,
    api_token: str,
) -> List[LiveModel]:
    """Fetch live text-gen models from Cloudflare Workers AI REST API.
    Pure synchronous — uses urllib only.
    """
    # BUG-FIX-18.0: Remove ?task=text-generation filter — it returns 0 models.
    # CF API uses different internal task identifiers. model_selector.py uses
    # ?per_page=500 with no task filter and gets 25 models; we do the same,
    # then filter text-gen models in Python by checking the task name field.
    url = (
        f"https://api.cloudflare.com/client/v4/accounts"
        f"/{account_id}/ai/models/search"
        f"?per_page=500&search=instruct"
    )
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
        "User-Agent": "TorShieldAIGateway/18.0",
    }
    data = _http_get(url, headers)
    # If first query fails or returns empty, try without search filter
    if not data or not data.get("result"):
        url_fallback = (
            f"https://api.cloudflare.com/client/v4/accounts"
            f"/{account_id}/ai/models/search"
            f"?per_page=500"
        )
        data = _http_get(url_fallback, headers)
    if not data:
        return []
    # Python-side text-gen filter (matches model_selector.py approach)
    _TEXT_GEN_TASKS = {
        "text generation", "text-generation", "text gen",
        "conversational", "chat", "instruction", "instruct",
    }
    models: List[LiveModel] = []
    for m in data.get("result", []):
        model_id = m.get("name", "")
        if not model_id:
            continue
        # BUG-FIX-18.0: Filter text-gen models in Python (task field from API)
        task_obj  = m.get("task", {}) or {}
        task_name = (task_obj.get("name", "") or "").lower().strip()
        # Accept models with known text-gen task names OR @cf/ hosted models
        # (some models may have missing/different task labels)
        if task_name and task_name not in _TEXT_GEN_TASKS:
            continue
        props = [p.get("name", "").lower() for p in m.get("properties", [])]
        tags  = [t.lower() for t in m.get("tags", [])]
        caps  = props + tags

        param_b  = _infer_params(model_id)
        ctx_k    = CF_KNOWN_CONTEXT_K.get(model_id, 8)
        is_hosted = model_id.startswith("@cf/")

        models.append(LiveModel(
            id=model_id,
            source=(ModelSource.CLOUDFLARE_HOSTED if is_hosted
                    else ModelSource.CLOUDFLARE_PROXIED),
            provider=task_name or task_obj.get("name", "unknown"),
            param_b=param_b,
            context_k=ctx_k,
            has_reasoning=(
                "reasoning" in caps or "think" in model_id.lower()
            ),
            has_function_calling=(
                "function-calling" in caps or "tool" in caps
            ),
            has_vision=(
                "vision" in caps or "visual" in caps
            ),
            is_newest=m.get("is_featured", False),
            latency_tier=1 if "fast" in model_id else 2,
            account_id=account_id,
        ))
    logger.info(
        f"[Brain] CF fetch ({_mask(account_id, 6)}): {len(models)} models"
    )
    return models


# ──────────────────────────────────────────────────────────────
# 4. PORTKEY LIVE MODEL FETCHER (SYNC)
# ──────────────────────────────────────────────────────────────

PORTKEY_MODEL_SCORES: Dict[str, float] = {
    # OpenAI
    "gpt-5.2":                          98.0,
    "gpt-5.2-2025-12-11":               98.0,
    "gpt-4.5":                          85.0,
    "o3":                               90.0,
    "o3-pro":                           93.0,
    # Anthropic
    "claude-fable-5":                   97.0,
    "claude-opus-4.8":                  94.0,
    "claude-4-opus-20250514":           94.0,
    "claude-opus-4-0":                  88.0,
    # Google
    "gemini-3-pro-preview":             89.0,
    "gemini-3-flash-preview":           75.0,
    # DeepSeek
    "deepseek-v4-pro":                  86.0,
    # MiniMax
    "minimax-m3":                       80.0,
    # Llama via Portkey
    "meta/llama-3.1-70b-instruct":      72.0,
    "meta/llama-3.1-8b-instruct":       55.0,
    "llama-3.3-70b":                    72.0,
    # Cerebras (already integrated)
    "zai-glm-4.7":                      65.0,
    "gpt-oss-120b":                     70.0,
}


def fetch_portkey_models_sync(api_key: str) -> List[LiveModel]:
    """Fetch available models from Portkey model catalog API.
    Pure synchronous — uses urllib only.
    """
    url = "https://api.portkey.ai/v1/models"
    headers = {
        "x-portkey-api-key": api_key,
        "Content-Type": "application/json",
    }
    data = _http_get(url, headers)
    if not data:
        return []
    models: List[LiveModel] = []
    for m in data.get("data", data.get("models", [])):
        model_id = m.get("id", m.get("model", ""))
        if not model_id:
            continue
        score_base = PORTKEY_MODEL_SCORES.get(model_id, 0.0)
        if score_base == 0.0:
            out_price = float(m.get("output_price", 0) or 0)
            score_base = min(60.0 + out_price * 2, 85.0)
        ctx_raw = m.get("context_window", m.get("max_tokens", 0)) or 0
        models.append(LiveModel(
            id=model_id,
            source=ModelSource.PORTKEY,
            provider=m.get("provider", "unknown"),
            param_b=0.0,
            context_k=int(ctx_raw / 1000) if isinstance(ctx_raw, (int, float)) and ctx_raw > 0 else 0,
            has_reasoning=(
                any(k in model_id.lower() for k in ("reason", "think", "o3", "r1"))
            ),
            has_function_calling=bool(m.get("supports_function_calling", False)),
            has_vision=bool(m.get("supports_vision", False)),
            is_newest=bool(m.get("is_latest", False)),
            score=score_base,
        ))
    logger.info(f"[Brain] Portkey fetch: {len(models)} models")
    return models


# ──────────────────────────────────────────────────────────────
# 5. UNIVERSAL SCORING ENGINE
# ──────────────────────────────────────────────────────────────

def score_model(m: LiveModel, task: str = "fast") -> float:
    """
    Score a model on a 0-100 scale.
    Higher = stronger / more desirable.
    """
    # Base: parameter count (log scale)
    if m.param_b > 0:
        param_score = math.log2(m.param_b + 1) * 8.0
    else:
        param_score = 20.0

    # Context window bonus
    context_bonus = math.log2(m.context_k + 1) * 2.0 if m.context_k > 0 else 0.0

    # Capability bonuses
    cap_bonus = 0.0
    if m.has_reasoning:         cap_bonus += 15.0
    if m.has_function_calling:  cap_bonus += 8.0
    if m.has_vision:            cap_bonus += 5.0

    # Recency / featured bonus
    newest_bonus = 10.0 if m.is_newest else 0.0

    # Hosting bonus (CF-hosted = on Cloudflare GPUs = fast)
    hosted_bonus = 5.0 if m.source == ModelSource.CLOUDFLARE_HOSTED else 0.0

    # Speed penalty for "fast" task
    speed_penalty = 0.0
    if task == "fast":
        speed_penalty = m.latency_tier * 5.0
        if "fast" in m.id.lower() or "flash" in m.id.lower():
            speed_penalty -= 10.0

    # Task affinity bonuses
    task_bonus = 0.0
    if task == "reasoning" and m.has_reasoning:
        task_bonus += 10.0
    elif task == "coding" and m.has_reasoning:
        task_bonus += 5.0
    elif task == "vision" and m.has_vision:
        task_bonus += 10.0

    total = (
        param_score + context_bonus + cap_bonus
        + newest_bonus + hosted_bonus + task_bonus
        - speed_penalty
    )

    # If Portkey pre-computed a score, blend it (50/50)
    if m.score > 0.0:
        total = (total + m.score) / 2.0

    return round(max(0.0, min(100.0, total)), 2)


# ──────────────────────────────────────────────────────────────
# 6. IRAN ANTI-DPI SCORING OVERRIDE
# ──────────────────────────────────────────────────────────────

def score_model_anti_dpi(m: LiveModel, task: str = "fast") -> float:
    """
    Score a model with Iran anti-DPI considerations.
    CF-hosted models strongly preferred when DPI is active.
    """
    base_score = score_model(m, task)

    if m.source == ModelSource.CLOUDFLARE_HOSTED:
        base_score += 15.0
    elif m.source == ModelSource.CLOUDFLARE_PROXIED:
        base_score += 5.0
    else:
        base_score -= 10.0

    if m.latency_tier == 1:
        base_score += 10.0
    elif m.latency_tier == 3:
        base_score -= 8.0

    if m.context_k > 0 and m.context_k <= 8:
        base_score += 5.0
    elif m.context_k > 128:
        base_score -= 3.0

    if m.has_reasoning and task != "reasoning":
        base_score -= 5.0

    return round(max(0.0, min(100.0, base_score)), 2)


# ──────────────────────────────────────────────────────────────
# 7. BRAIN ORCHESTRATOR (100% synchronous)
# ──────────────────────────────────────────────────────────────


class DynamicModelBrain:
    """
    Fetches live model lists from all providers,
    scores them, returns the globally strongest model.

    Supports all 11 CF account slots for maximum coverage.
    100% synchronous — no asyncio/aiohttp needed.

    Usage:
        brain = DynamicModelBrain()
        brain.refresh()
        top = brain.get_top_model(task="fast", source="cf_hosted")
        print(top.id, top.score)
    """

    def __init__(self):
        self._cf_models:      List[LiveModel] = []
        self._portkey_models: List[LiveModel] = []
        self._all_models:     List[LiveModel] = []
        self._fetched_at:     float = 0.0
        self._cache_ttl:      float = 1800.0  # 30 min refresh
        self._anti_dpi_mode:  bool = False
        self._fetch_errors:   List[str] = []

    @property
    def anti_dpi_mode(self) -> bool:
        return self._anti_dpi_mode

    def enable_anti_dpi(self) -> None:
        self._anti_dpi_mode = True
        logger.info("[Brain] Iran anti-DPI mode ENABLED")

    def disable_anti_dpi(self) -> None:
        self._anti_dpi_mode = False
        logger.info("[Brain] Iran anti-DPI mode DISABLED")

    def refresh(self) -> None:
        """Fetch live model lists from all providers synchronously.
        Iterates all 11 CF account slots + all 3 Portkey keys.
        """
        self._fetch_errors = []

        # Build CF slot list from env (CF_ACCOUNT_ID_1..11)
        cf_slots = [
            (os.environ.get(f"CF_ACCOUNT_ID_{i}", "").strip(),
             os.environ.get(f"CF_API_TOKEN_{i}", "").strip())
            for i in range(1, CF_N_SLOTS + 1)
            if os.environ.get(f"CF_ACCOUNT_ID_{i}", "").strip()
            and os.environ.get(f"CF_API_TOKEN_{i}", "").strip()
        ]

        # Build Portkey key list from env
        pk_keys = [
            os.environ.get(f"PORTKEY_API_KEY_{i}", "").strip()
            for i in range(1, 4)
            if os.environ.get(f"PORTKEY_API_KEY_{i}", "").strip()
        ]

        # BUG-FIX-18.0: Fetch CF models — try ALL accounts (don't stop on 403/empty).
        # Previously used "stop after first success" but 403-accounts gave 0 models
        # and caused the loop to never break. Now we try each account and break
        # on the FIRST account that actually returns models (not just "no error").
        seen_cf_ids: set = set()
        self._cf_models = []
        for acct, tok in cf_slots:
            try:
                fetched = fetch_cf_models_sync(acct, tok)
                for m in fetched:
                    if m.id not in seen_cf_ids:
                        seen_cf_ids.add(m.id)
                        self._cf_models.append(m)
                # BUG-FIX: Only break if we actually got models — don't break on empty
                if self._cf_models:
                    logger.info(
                        f"[Brain] Got {len(self._cf_models)} models from "
                        f"account {_mask(acct, 6)} — stopping early"
                    )
                    break
                else:
                    logger.debug(
                        f"[Brain] Account {_mask(acct, 6)} returned 0 models, "
                        f"trying next account"
                    )
            except Exception as exc:
                err_msg = f"CF slot ({_mask(acct, 6)}): {exc}"
                logger.warning(f"[Brain] {err_msg}")
                self._fetch_errors.append(err_msg)

        if not self._cf_models and cf_slots:
            self._fetch_errors.append(
                "All CF slots returned 0 models"
            )
            # BUG-FIX-18.0: Fall back to offline model list when live fetch fails
            # This ensures the brain always has models to score/rank even when
            # CF API tokens lack model-listing permission.
            logger.warning(
                "[Brain] All CF accounts returned 0 models — "
                "loading offline fallback model list"
            )
            try:
                from .model_selector import _OFFLINE_MODELS  # type: ignore
                for m_dict in _OFFLINE_MODELS:
                    mid = m_dict.get("id", "")
                    if mid and mid not in seen_cf_ids:
                        seen_cf_ids.add(mid)
                        self._cf_models.append(LiveModel(
                            id=mid,
                            source=ModelSource.CLOUDFLARE_HOSTED,
                            provider="text generation",
                            param_b=float(m_dict.get("param_b", 0.0)),
                            context_k=int(m_dict.get("ctx_k", 8)),
                            is_newest="maverick" in mid or "scout" in mid,
                            latency_tier=1 if "fast" in mid else 2,
                        ))
                logger.info(
                    f"[Brain] Offline fallback loaded: {len(self._cf_models)} models"
                )
            except Exception as fb_exc:
                logger.warning(f"[Brain] Offline fallback also failed: {fb_exc}")

        # Fetch Portkey models (stop after first successful key)
        seen_pk_ids: set = set()
        self._portkey_models = []
        for key in pk_keys:
            try:
                fetched = fetch_portkey_models_sync(key)
                for m in fetched:
                    if m.id not in seen_pk_ids:
                        seen_pk_ids.add(m.id)
                        self._portkey_models.append(m)
                if self._portkey_models:
                    break
            except Exception as exc:
                err_msg = f"Portkey key ({_mask(key, 4)}): {exc}"
                logger.warning(f"[Brain] {err_msg}")
                self._fetch_errors.append(err_msg)

        self._all_models = self._cf_models + self._portkey_models
        self._fetched_at = time.time()
        logger.info(
            f"[Brain] Refreshed: {len(self._cf_models)} CF, "
            f"{len(self._portkey_models)} Portkey, "
            f"{len(self._all_models)} total"
        )

    def _ensure_fresh(self) -> None:
        """Refresh model lists if cache has expired."""
        if time.time() - self._fetched_at > self._cache_ttl:
            self.refresh()

    def get_top_models(
        self,
        task: str = "fast",
        source: Optional[str] = None,
        top_n: int = 5,
    ) -> List[LiveModel]:
        """Return top-N scored models, optionally filtered by source."""
        self._ensure_fresh()

        pool = self._all_models
        if source:
            pool = [m for m in pool if m.source.value == source]

        # BUG-2 FIX: Guard against empty pool
        if not pool:
            return []

        scorer = score_model_anti_dpi if self._anti_dpi_mode else score_model
        for m in pool:
            m.score = scorer(m, task=task)

        ranked = sorted(pool, key=lambda m: m.score, reverse=True)
        return ranked[:top_n]

    def get_top_cf_hosted_models(
        self,
        task: str = "fast",
        top_n: int = 5,
    ) -> List[LiveModel]:
        """Return top-N CF-hosted models (runs on Cloudflare GPUs)."""
        return self.get_top_models(
            task=task,
            source=ModelSource.CLOUDFLARE_HOSTED.value,
            top_n=top_n,
        )

    def get_top_portkey_model(
        self,
        task: str = "fast",
    ) -> Optional[LiveModel]:
        """Return the single strongest model available via Portkey."""
        models = self.get_top_models(
            task=task,
            source=ModelSource.PORTKEY.value,
            top_n=1,
        )
        # BUG-2 FIX: safe access — never crashes on empty list
        return models[0] if models else None

    def get_globally_strongest(
        self, task: str = "general"
    ) -> Optional[LiveModel]:
        """Return the single strongest model across ALL providers."""
        models = self.get_top_models(task=task, top_n=1)
        # BUG-2 FIX: safe access
        return models[0] if models else None

    def get_best_model_for_account(
        self,
        account_id: str,
        task: str = "fast",
    ) -> Optional[LiveModel]:
        """Return the best CF-hosted model available on a specific account."""
        self._ensure_fresh()
        pool = [
            m for m in self._cf_models
            if m.source == ModelSource.CLOUDFLARE_HOSTED
            and m.account_id == account_id
        ]
        # BUG-2 FIX: guard empty pool
        if not pool:
            return None
        scorer = score_model_anti_dpi if self._anti_dpi_mode else score_model
        for m in pool:
            m.score = scorer(m, task=task)
        ranked = sorted(pool, key=lambda m: m.score, reverse=True)
        return ranked[0] if ranked else None

    def summary(self) -> Dict[str, Any]:
        """Return a summary dict for logging / reports."""
        return {
            "cf_model_count":      len(self._cf_models),
            "portkey_model_count": len(self._portkey_models),
            "total_models":        len(self._all_models),
            "fetched_at":          self._fetched_at,
            "cache_ttl_s":         self._cache_ttl,
            "anti_dpi_mode":       self._anti_dpi_mode,
            "fetch_errors":        self._fetch_errors,
            "cf_accounts_queried": CF_N_SLOTS,
        }


# ──────────────────────────────────────────────────────────────
# 8. SINGLETON + SYNC CONVENIENCE WRAPPERS
# ──────────────────────────────────────────────────────────────

_brain: Optional[DynamicModelBrain] = None


def get_brain() -> DynamicModelBrain:
    """Get or create the singleton DynamicModelBrain instance."""
    global _brain
    if _brain is None:
        _brain = DynamicModelBrain()
    return _brain


def ranked_cf_models_live(task: str = "fast", top_n: int = 5) -> List[LiveModel]:
    """
    Synchronous wrapper — drop-in replacement for ranked_cf_models()
    in model_selector.py. Falls back to existing offline list on error.
    """
    brain = get_brain()
    try:
        brain.refresh()
        pool = [
            m for m in brain._cf_models
            if m.source == ModelSource.CLOUDFLARE_HOSTED
        ]
        if not pool:
            raise ValueError("No CF hosted models fetched")
        for m in pool:
            m.score = score_model(m, task=task)
        return sorted(pool, key=lambda m: m.score, reverse=True)[:top_n]
    except Exception as exc:
        logger.warning(f"[Brain] Live rank failed: {exc}")
        try:
            from torshield_ai_gateway.model_selector import ranked_cf_models
            return ranked_cf_models(task=task, top_n=top_n)
        except Exception:
            return []


def best_portkey_model_live(task: str = "fast") -> Optional[LiveModel]:
    """Synchronous — best Portkey model for Portkey provider."""
    brain = get_brain()
    try:
        brain.refresh()
        pool = [m for m in brain._portkey_models]
        # BUG-2 FIX: guard empty pool
        if not pool:
            return None
        for m in pool:
            m.score = score_model(m, task=task)
        return sorted(pool, key=lambda m: m.score, reverse=True)[0]
    except Exception as exc:
        logger.warning(f"[Brain] Portkey model fetch failed: {exc}")
        return None


def best_cf_model_live(task: str = "fast") -> Optional[LiveModel]:
    """Synchronous — best CF-hosted model."""
    brain = get_brain()
    try:
        brain.refresh()
        pool = [
            m for m in brain._cf_models
            if m.source == ModelSource.CLOUDFLARE_HOSTED
        ]
        # BUG-2 FIX: guard empty pool
        if not pool:
            return None
        for m in pool:
            m.score = score_model(m, task=task)
        return sorted(pool, key=lambda m: m.score, reverse=True)[0]
    except Exception as exc:
        logger.warning(f"[Brain] CF model fetch failed: {exc}")
        return None


def globally_strongest_model_live(task: str = "general") -> Optional[LiveModel]:
    """Synchronous — globally strongest model across all providers."""
    brain = get_brain()
    try:
        brain.refresh()
        pool = brain._all_models
        if not pool:
            return None
        scorer = score_model_anti_dpi if brain.anti_dpi_mode else score_model
        for m in pool:
            m.score = scorer(m, task=task)
        ranked = sorted(pool, key=lambda m: m.score, reverse=True)
        return ranked[0] if ranked else None
    except Exception as exc:
        logger.warning(f"[Brain] Global model fetch failed: {exc}")
        return None


def refresh_brain_sync() -> Dict[str, Any]:
    """Refresh the brain and return summary dict."""
    brain = get_brain()
    try:
        brain.refresh()
    except Exception as exc:
        logger.warning(f"[Brain] Refresh failed: {exc}")
    return brain.summary()


# ──────────────────────────────────────────────────────────────
# 9. IRAN ANTI-DPI / ANTI-FILTER INTEGRATION
# ──────────────────────────────────────────────────────────────

def detect_iran_dpi_active() -> bool:
    """Detect if Iran DPI is likely active based on environment signals."""
    if os.environ.get("TORSHIELD_IRAN_MODE", "").lower() in ("1", "true", "yes"):
        return True

    try:
        from torshield_ai_gateway.iran_intelligence import IranIntelligenceLayer as IranIntelligence
        intel = IranIntelligence()
        if hasattr(intel, 'is_dpi_active') and intel.is_dpi_active:
            return True
    except (ImportError, AttributeError):
        pass

    try:
        from torshield_ai_gateway.anti_censorship import get_anti_censorship_engine
        engine = get_anti_censorship_engine()
        if engine and hasattr(engine, 'censorship_level'):
            level = getattr(engine, 'censorship_level', None)
            if level and str(level) in ("severe", "high", "CRITICAL"):
                return True
    except (ImportError, AttributeError):
        pass

    return False


def activate_anti_dpi_if_needed() -> bool:
    """Check if Iran DPI is active and enable anti-DPI scoring mode."""
    brain = get_brain()
    if detect_iran_dpi_active():
        if not brain.anti_dpi_mode:
            brain.enable_anti_dpi()
            logger.info(
                "[Brain] Iran DPI detected — anti-DPI scoring mode activated. "
                "CF-hosted models prioritized, cross-border traffic penalized."
            )
        return True
    else:
        if brain.anti_dpi_mode:
            brain.disable_anti_dpi()
        return False


# ──────────────────────────────────────────────────────────────
# 10. CLI SELF-TEST
# ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import json
    logging.basicConfig(level=logging.INFO)

    brain = DynamicModelBrain()
    brain.refresh()
    print(json.dumps(brain.summary(), indent=2, default=str))

    print("\n=== TOP 5 CF-HOSTED (task=fast) ===")
    for i, m in enumerate(brain.get_top_cf_hosted_models("fast", top_n=5)):
        print(
            f"  #{i+1} {m.id}  score={m.score}  "
            f"params={m.param_b}B  ctx={m.context_k}k  "
            f"reasoning={m.has_reasoning}"
        )

    print("\n=== TOP 5 PORTKEY MODELS (task=general) ===")
    for i, m in enumerate(brain.get_top_models("general", source="portkey", top_n=5)):
        print(
            f"  #{i+1} {m.id}  score={m.score}  "
            f"provider={m.provider}"
        )

    print("\n=== GLOBALLY STRONGEST MODEL ===")
    best = brain.get_globally_strongest("general")
    if best:
        print(
            f"  {best.id}  score={best.score}  "
            f"source={best.source.value}"
        )
    else:
        print("  (no models available)")

    print("\n=== ANTI-DPI MODE TEST ===")
    brain.enable_anti_dpi()
    for i, m in enumerate(brain.get_top_cf_hosted_models("fast", top_n=5)):
        print(
            f"  #{i+1} {m.id}  score={m.score}  "
            f"params={m.param_b}B  ctx={m.context_k}k"
        )
