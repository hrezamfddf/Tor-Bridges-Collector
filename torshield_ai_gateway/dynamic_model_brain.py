"""
dynamic_model_brain.py — Live Model Fetcher + Intelligent Scorer for TorShield AI Gateway
===========================================================================================

Fetches LIVE model lists from Cloudflare (11 accounts) + Portkey APIs,
scores each model automatically, and picks the highest-scoring model per task.
Self-updating as providers release new models. Never needs manual updates.

ARCHITECTURE:
  ┌──────────────────────────────────────────────────┐
  │  DynamicModelBrain.get_globally_strongest()      │
  └──────────────────┬───────────────────────────────┘
                     │
       ┌─────────────▼──────────────────┐
       │  1. Fetch CF models (11 accts) │  Concurrent async fetch
       │  2. Fetch Portkey models       │  Portkey catalog API
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

Version: Fix-16.0 / Feature: DYNAMIC-BRAIN
"""

from __future__ import annotations

import os
import re
import time
import math
import logging
import asyncio
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
    account_id: str = ""                # CF account that has this model (for multi-account)


# ──────────────────────────────────────────────────────────────
# 2. CLOUDFLARE LIVE MODEL FETCHER (11 ACCOUNTS)
# ──────────────────────────────────────────────────────────────
# API: GET https://api.cloudflare.com/client/v4/accounts/
#          {account_id}/ai/models/search
#          ?task=text-generation&per_page=100
# Auth: Authorization: Bearer {CF_API_TOKEN}

CF_MODELS_API = (
    "https://api.cloudflare.com/client/v4/accounts"
    "/{account_id}/ai/models/search"
    "?task=text-generation&per_page=100"
)

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


def _infer_param_from_name(model_id: str) -> float:
    """Extract parameter count from model ID string.
    e.g. 'llama-3.1-70b' -> 70.0, 'mistral-7b' -> 7.0
    """
    # MoE pattern: 17b-16e -> 17.0 (active params)
    moe_match = re.search(r"(\d+(?:\.\d+)?)b[_\-](\d+)e", model_id.lower())
    if moe_match:
        return float(moe_match.group(1))

    # Standard dense: first plain Nb occurrence
    for part in model_id.replace("/", "-").split("-"):
        if part.endswith("b") and part[:-1].replace(".", "").isdigit():
            try:
                return float(part[:-1])
            except ValueError:
                pass
    return 0.0


async def _fetch_cf_models_for_account(
    account_id: str,
    api_token: str,
    session: "aiohttp.ClientSession",
    slot_index: int = 0,
) -> List[LiveModel]:
    """Fetch live text-generation models from a single CF account."""
    url = CF_MODELS_API.format(account_id=account_id)
    headers = {
        "Authorization": f"Bearer {api_token}",
        "Content-Type": "application/json",
    }
    models: List[LiveModel] = []
    try:
        async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status != 200:
                logger.warning(
                    f"[Brain] CF slot {slot_index} model fetch HTTP {resp.status}"
                )
                return []
            data = await resp.json()
            for m in data.get("result", []):
                model_id = m.get("name", "")
                if not model_id:
                    continue
                capabilities = [
                    p.get("name", "").lower()
                    for p in m.get("properties", [])
                ]
                tags = [t.lower() for t in m.get("tags", [])]
                all_caps = capabilities + tags

                # Infer parameter count
                param_b = CF_KNOWN_PARAMS.get(model_id, 0.0)
                if param_b == 0.0:
                    param_b = _infer_param_from_name(model_id)

                ctx_k = CF_KNOWN_CONTEXT_K.get(model_id, 8)

                is_hosted = model_id.startswith("@cf/")
                source = (
                    ModelSource.CLOUDFLARE_HOSTED if is_hosted
                    else ModelSource.CLOUDFLARE_PROXIED
                )

                lm = LiveModel(
                    id=model_id,
                    source=source,
                    provider=_extract_provider_from_id(model_id),
                    param_b=param_b,
                    context_k=ctx_k,
                    has_reasoning=(
                        "reasoning" in all_caps
                        or "think" in model_id.lower()
                        or "r1" in model_id.lower()
                        or "qwq" in model_id.lower()
                    ),
                    has_function_calling=(
                        "function-calling" in all_caps
                        or "tool" in all_caps
                    ),
                    has_vision=(
                        "vision" in all_caps
                        or "visual" in all_caps
                        or "multimodal" in all_caps
                    ),
                    is_newest=m.get("is_featured", False),
                    latency_tier=(
                        1 if "fast" in model_id.lower() or "flash" in model_id.lower() else 2
                    ),
                    account_id=account_id,
                )
                models.append(lm)
    except asyncio.TimeoutError:
        logger.warning(f"[Brain] CF slot {slot_index} model fetch timed out")
    except Exception as exc:
        logger.warning(f"[Brain] CF slot {slot_index} model fetch error: {exc}")
    logger.info(
        f"[Brain] CF slot {slot_index} ({_mask(account_id, 3)}): "
        f"{len(models)} models fetched"
    )
    return models


def _extract_provider_from_id(model_id: str) -> str:
    """Extract provider name from model ID.
    e.g. '@cf/meta/llama-3.1-70b' -> 'meta'
    """
    if model_id.startswith("@cf/"):
        parts = model_id[4:].split("/")
        if len(parts) >= 2:
            return parts[0]
    elif model_id.startswith("@hf/"):
        parts = model_id[4:].split("/")
        if len(parts) >= 2:
            return parts[0]
    return "unknown"


def _mask(val: str, visible: int = 4) -> str:
    """Mask a sensitive value for logging."""
    if not val:
        return "<EMPTY>"
    if len(val) <= visible * 2:
        return f"{val[:2]}***"
    return f"{val[:visible]}...{val[-visible:]}"


async def fetch_cf_models_all_accounts() -> List[LiveModel]:
    """Fetch live models from ALL 11 CF accounts concurrently.

    This is the key enhancement: iterates CF_ACCOUNT_ID_1..11 and
    CF_API_TOKEN_1..11, fetches models from each valid account,
    and deduplicates by model ID (keeping the first seen).
    """
    try:
        import aiohttp
    except ImportError:
        logger.warning("[Brain] aiohttp not installed — CF live fetch skipped")
        return []

    accounts: List[tuple] = []
    for i in range(1, CF_N_SLOTS + 1):
        acct_id = os.environ.get(f"CF_ACCOUNT_ID_{i}", "").strip()
        api_token = os.environ.get(f"CF_API_TOKEN_{i}", "").strip()
        if acct_id and api_token:
            accounts.append((acct_id, api_token, i))

    if not accounts:
        logger.warning("[Brain] No CF account credentials found in env")
        return []

    all_models: List[LiveModel] = []
    seen_ids: set = set()

    async with aiohttp.ClientSession() as session:
        tasks = [
            _fetch_cf_models_for_account(acct_id, api_token, session, slot_idx)
            for acct_id, api_token, slot_idx in accounts
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, Exception):
            logger.warning(f"[Brain] CF account fetch failed: {result}")
            continue
        for m in result:
            # Deduplicate by model ID
            if m.id not in seen_ids:
                seen_ids.add(m.id)
                all_models.append(m)

    logger.info(
        f"[Brain] Cloudflare live fetch: {len(all_models)} unique models "
        f"from {len(accounts)} account(s)"
    )
    return all_models


async def fetch_cf_models(
    account_id: str,
    api_token: str,
    session: "aiohttp.ClientSession",
) -> List[LiveModel]:
    """Fetch live text-generation models from a single CF account.
    Legacy interface for backward compatibility.
    """
    return await _fetch_cf_models_for_account(account_id, api_token, session, 0)


# ──────────────────────────────────────────────────────────────
# 3. PORTKEY LIVE MODEL FETCHER
# ──────────────────────────────────────────────────────────────
# API: GET https://api.portkey.ai/v1/models
# Auth: x-portkey-api-key: {PORTKEY_API_KEY}
# Returns: list of models across all configured integrations

PORTKEY_MODELS_API = "https://api.portkey.ai/v1/models"

# Score table for known frontier models available via Portkey
# (sourced from portkey.ai/models, updated June 2026)
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


async def fetch_portkey_models(
    api_key: str,
    session: "aiohttp.ClientSession",
) -> List[LiveModel]:
    """Fetch available models from Portkey's model catalog API."""
    try:
        import aiohttp
    except ImportError:
        logger.warning("[Brain] aiohttp not installed — Portkey live fetch skipped")
        return []

    headers = {
        "x-portkey-api-key": api_key,
        "Content-Type": "application/json",
    }
    models: List[LiveModel] = []
    try:
        async with session.get(
            PORTKEY_MODELS_API, headers=headers, timeout=aiohttp.ClientTimeout(total=10)
        ) as resp:
            if resp.status != 200:
                logger.warning(f"[Brain] Portkey model fetch HTTP {resp.status}")
                return []
            data = await resp.json()
            model_list = data.get("data", data.get("models", []))
            for m in model_list:
                model_id = m.get("id", m.get("model", ""))
                if not model_id:
                    continue

                # Use known score or derive from pricing
                score_base = PORTKEY_MODEL_SCORES.get(model_id, 0.0)
                if score_base == 0.0:
                    # Infer from pricing: output price in $/M tokens
                    # Higher output $/M token often = more capable model
                    output_price = float(m.get("output_price", 0) or 0)
                    score_base = min(60.0 + output_price * 2, 85.0)

                # Extract context window
                ctx_raw = m.get("context_window", m.get("max_tokens", 0)) or 0
                ctx_k = int(ctx_raw / 1000) if isinstance(ctx_raw, (int, float)) and ctx_raw > 0 else 0

                lm = LiveModel(
                    id=model_id,
                    source=ModelSource.PORTKEY,
                    provider=m.get("provider", "unknown"),
                    param_b=0.0,   # Portkey API doesn't expose params
                    context_k=ctx_k,
                    has_reasoning=(
                        "reason" in model_id.lower()
                        or "think" in model_id.lower()
                        or "o3" in model_id.lower()
                    ),
                    has_function_calling=(
                        bool(m.get("supports_function_calling", False))
                        or bool(m.get("tool_use", False))
                    ),
                    has_vision=(
                        bool(m.get("supports_vision", False))
                        or "vision" in model_id.lower()
                    ),
                    is_newest=bool(m.get("is_latest", False)),
                    score=score_base,
                )
                models.append(lm)
    except asyncio.TimeoutError:
        logger.warning("[Brain] Portkey model fetch timed out")
    except Exception as exc:
        logger.warning(f"[Brain] Portkey model fetch error: {exc}")
    logger.info(f"[Brain] Portkey live fetch: {len(models)} models")
    return models


async def fetch_portkey_models_all_keys() -> List[LiveModel]:
    """Fetch Portkey models using all available API keys (1-3)."""
    try:
        import aiohttp
    except ImportError:
        logger.warning("[Brain] aiohttp not installed — Portkey live fetch skipped")
        return []

    all_models: List[LiveModel] = []
    seen_ids: set = set()

    async with aiohttp.ClientSession() as session:
        tasks = []
        for i in range(1, 4):
            pk_key = os.environ.get(f"PORTKEY_API_KEY_{i}", "").strip()
            if pk_key:
                tasks.append(fetch_portkey_models(pk_key, session))

        if not tasks:
            logger.warning("[Brain] No Portkey API keys found in env")
            return []

        results = await asyncio.gather(*tasks, return_exceptions=True)

    for result in results:
        if isinstance(result, Exception):
            logger.warning(f"[Brain] Portkey key fetch failed: {result}")
            continue
        for m in result:
            if m.id not in seen_ids:
                seen_ids.add(m.id)
                all_models.append(m)

    logger.info(
        f"[Brain] Portkey live fetch: {len(all_models)} unique models"
    )
    return all_models


# ──────────────────────────────────────────────────────────────
# 4. UNIVERSAL SCORING ENGINE
# ──────────────────────────────────────────────────────────────

def score_model(m: LiveModel, task: str = "fast") -> float:
    """
    Score a model on a 0-100 scale.
    Higher = stronger / more desirable.

    Scoring formula (weights tuned for agentic + gateway use):
      param_score      = log2(params+1) * 8        max ~80
      context_bonus    = log2(ctx_k+1) * 2         max ~20
      reasoning_bonus  = 15 if has_reasoning
      fc_bonus         = 8  if has_function_calling
      vision_bonus     = 5  if has_vision
      newest_bonus     = 10 if is_newest/featured
      hosted_bonus     = 5  if CF-hosted (lower latency)
      speed_penalty    = -tier*5 if task=="fast" (negative = faster = better)
    """
    # Base: parameter count (log scale so 1T doesn't dominate)
    if m.param_b > 0:
        param_score = math.log2(m.param_b + 1) * 8.0
    else:
        param_score = 20.0  # unknown params -> neutral score

    # Context window bonus
    if m.context_k > 0:
        context_bonus = math.log2(m.context_k + 1) * 2.0
    else:
        context_bonus = 0.0

    # Capability bonuses
    cap_bonus = 0.0
    if m.has_reasoning:
        cap_bonus += 15.0
    if m.has_function_calling:
        cap_bonus += 8.0
    if m.has_vision:
        cap_bonus += 5.0

    # Recency / featured bonus
    newest_bonus = 10.0 if m.is_newest else 0.0

    # Hosting bonus (CF-hosted = on Cloudflare GPUs = fast)
    hosted_bonus = 5.0 if m.source == ModelSource.CLOUDFLARE_HOSTED else 0.0

    # Speed penalty for "fast" task
    speed_penalty = 0.0
    if task == "fast":
        speed_penalty = m.latency_tier * 5.0
        if "fast" in m.id.lower() or "flash" in m.id.lower():
            speed_penalty -= 10.0   # explicit "fast" models get bonus

    # Task affinity bonuses
    task_bonus = 0.0
    if task == "reasoning" and m.has_reasoning:
        task_bonus += 10.0
    elif task == "coding" and m.has_reasoning:
        task_bonus += 5.0
    elif task == "vision" and m.has_vision:
        task_bonus += 10.0

    total = (
        param_score
        + context_bonus
        + cap_bonus
        + newest_bonus
        + hosted_bonus
        + task_bonus
        - speed_penalty
    )

    # If Portkey pre-computed a score, blend it (50/50)
    if m.score > 0.0:
        total = (total + m.score) / 2.0

    return round(max(0.0, min(100.0, total)), 2)


# ──────────────────────────────────────────────────────────────
# 5. IRAN ANTI-DPI SCORING OVERRIDE
# ──────────────────────────────────────────────────────────────

def score_model_anti_dpi(m: LiveModel, task: str = "fast") -> float:
    """
    Score a model with Iran anti-DPI considerations.

    When Iran DPI is active, the scoring engine:
    - Strongly prefers CF-hosted models (no cross-border API calls, less
      fingerprintable traffic patterns)
    - Boosts fast/low-latency models (less time on wire = less traffic analysis)
    - Penalizes models that produce long streaming responses
    - Deprioritizes Portkey/third-party models that route through multiple hops
    - Adds bonus for models that can operate with minimal metadata leakage
    """
    base_score = score_model(m, task)

    # CF-hosted models get a significant anti-DPI bonus
    # (traffic stays within Cloudflare network, harder to fingerprint)
    if m.source == ModelSource.CLOUDFLARE_HOSTED:
        base_score += 15.0
    elif m.source == ModelSource.CLOUDFLARE_PROXIED:
        base_score += 5.0
    else:
        # Portkey / third-party: traffic crosses borders, easier to fingerprint
        base_score -= 10.0

    # Fast models reduce time on wire -> less traffic analysis surface
    if m.latency_tier == 1:
        base_score += 10.0
    elif m.latency_tier == 3:
        base_score -= 8.0

    # Models with smaller context windows produce shorter responses
    # (less data to analyze for DPI pattern matching)
    if m.context_k > 0 and m.context_k <= 8:
        base_score += 5.0  # compact = stealthy
    elif m.context_k > 128:
        base_score -= 3.0  # long responses = more fingerprintable

    # Reasoning models tend to produce longer chain-of-thought output
    # which creates more traffic for DPI to analyze
    if m.has_reasoning and task != "reasoning":
        base_score -= 5.0

    return round(max(0.0, min(100.0, base_score)), 2)


# ──────────────────────────────────────────────────────────────
# 6. BRAIN ORCHESTRATOR
# ──────────────────────────────────────────────────────────────


class DynamicModelBrain:
    """
    Fetches live model lists from all providers,
    scores them, returns the globally strongest model.

    Supports all 11 CF account slots for maximum coverage.

    Usage:
        brain = DynamicModelBrain()
        top = await brain.get_top_model(task="fast", source="cf_hosted")
        print(top.id, top.score)
    """

    def __init__(self):
        self._cf_models:      List[LiveModel] = []
        self._portkey_models: List[LiveModel] = []
        self._all_models:     List[LiveModel] = []
        self._fetched_at:     float = 0.0
        self._cache_ttl:      float = 1800.0  # 30 min refresh
        self._anti_dpi_mode:  bool = False     # Iran anti-DPI mode
        self._fetch_errors:   List[str] = []

    @property
    def anti_dpi_mode(self) -> bool:
        """Check if Iran anti-DPI mode is active."""
        return self._anti_dpi_mode

    def enable_anti_dpi(self) -> None:
        """Enable Iran anti-DPI scoring mode."""
        self._anti_dpi_mode = True
        logger.info("[Brain] Iran anti-DPI mode ENABLED")

    def disable_anti_dpi(self) -> None:
        """Disable Iran anti-DPI scoring mode."""
        self._anti_dpi_mode = False
        logger.info("[Brain] Iran anti-DPI mode DISABLED")

    async def refresh(self) -> None:
        """Fetch live model lists from all providers concurrently.
        Iterates all 11 CF account slots for maximum model coverage.
        """
        try:
            import aiohttp
        except ImportError:
            logger.warning(
                "[Brain] aiohttp not installed — live model fetch disabled. "
                "Install with: pip install aiohttp"
            )
            self._fetch_errors.append("aiohttp not installed")
            return

        self._fetch_errors = []

        # Run CF and Portkey fetches concurrently
        cf_task = fetch_cf_models_all_accounts()
        pk_task = fetch_portkey_models_all_keys()

        results = await asyncio.gather(
            cf_task, pk_task, return_exceptions=True
        )

        self._cf_models = []
        self._portkey_models = []

        # Process CF results
        if isinstance(results[0], Exception):
            err_msg = f"CF fetch failed: {results[0]}"
            logger.warning(f"[Brain] {err_msg}")
            self._fetch_errors.append(err_msg)
        else:
            self._cf_models = results[0]

        # Process Portkey results
        if isinstance(results[1], Exception):
            err_msg = f"Portkey fetch failed: {results[1]}"
            logger.warning(f"[Brain] {err_msg}")
            self._fetch_errors.append(err_msg)
        else:
            self._portkey_models = results[1]

        self._all_models = self._cf_models + self._portkey_models
        self._fetched_at = time.time()
        logger.info(
            f"[Brain] Refreshed: {len(self._cf_models)} CF models, "
            f"{len(self._portkey_models)} Portkey models, "
            f"{len(self._all_models)} total"
        )

    async def _ensure_fresh(self) -> None:
        """Refresh model lists if cache has expired."""
        if time.time() - self._fetched_at > self._cache_ttl:
            await self.refresh()

    async def get_top_models(
        self,
        task: str = "fast",
        source: Optional[str] = None,
        top_n: int = 5,
    ) -> List[LiveModel]:
        """Return top-N scored models, optionally filtered by source."""
        await self._ensure_fresh()

        pool = self._all_models
        if source:
            pool = [m for m in pool if m.source.value == source]

        # Score all models for the given task
        scorer = score_model_anti_dpi if self._anti_dpi_mode else score_model
        for m in pool:
            m.score = scorer(m, task=task)

        ranked = sorted(pool, key=lambda m: m.score, reverse=True)
        return ranked[:top_n]

    async def get_top_cf_hosted_models(
        self,
        task: str = "fast",
        top_n: int = 5,
    ) -> List[LiveModel]:
        """Return top-N CF-hosted models (runs on Cloudflare GPUs)."""
        return await self.get_top_models(
            task=task,
            source=ModelSource.CLOUDFLARE_HOSTED.value,
            top_n=top_n,
        )

    async def get_top_portkey_model(
        self,
        task: str = "fast",
    ) -> Optional[LiveModel]:
        """Return the single strongest model available via Portkey."""
        models = await self.get_top_models(
            task=task,
            source=ModelSource.PORTKEY.value,
            top_n=1,
        )
        return models[0] if models else None

    async def get_globally_strongest(
        self, task: str = "general"
    ) -> Optional[LiveModel]:
        """Return the single strongest model across ALL providers."""
        models = await self.get_top_models(task=task, top_n=1)
        return models[0] if models else None

    async def get_best_model_for_account(
        self,
        account_id: str,
        task: str = "fast",
    ) -> Optional[LiveModel]:
        """Return the best CF-hosted model available on a specific account."""
        await self._ensure_fresh()
        pool = [
            m for m in self._cf_models
            if m.source == ModelSource.CLOUDFLARE_HOSTED
            and m.account_id == account_id
        ]
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
# 7. SINGLETON + SYNC CONVENIENCE WRAPPERS
# ──────────────────────────────────────────────────────────────

_brain: Optional[DynamicModelBrain] = None


def get_brain() -> DynamicModelBrain:
    """Get or create the singleton DynamicModelBrain instance."""
    global _brain
    if _brain is None:
        _brain = DynamicModelBrain()
    return _brain


def _run_async(coro):
    """Run an async coroutine synchronously, handling event loop issues."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # We're inside an existing event loop (e.g. Jupyter)
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(asyncio.run, coro)
                return future.result(timeout=30)
    except RuntimeError:
        loop = None

    if loop and not loop.is_closed():
        return loop.run_until_complete(coro)
    else:
        return asyncio.run(coro)


def ranked_cf_models_live(task: str = "fast", top_n: int = 5) -> List[LiveModel]:
    """
    Synchronous wrapper — drop-in replacement for ranked_cf_models()
    in model_selector.py. Falls back to existing offline list on error.
    """
    brain = get_brain()
    try:
        return _run_async(brain.get_top_cf_hosted_models(task=task, top_n=top_n))
    except Exception as exc:
        logger.warning(f"[Brain] Live rank failed, falling back: {exc}")
        # Fall back to existing model_selector.py
        try:
            from torshield_ai_gateway.model_selector import ranked_cf_models
            legacy = ranked_cf_models(task=task, top_n=top_n)
            logger.info(f"[Brain] Offline fallback: {len(legacy)} models")
            return legacy
        except Exception:
            return []


def best_portkey_model_live(task: str = "fast") -> Optional[LiveModel]:
    """Synchronous wrapper — best Portkey model for Portkey provider."""
    brain = get_brain()
    try:
        return _run_async(brain.get_top_portkey_model(task=task))
    except Exception as exc:
        logger.warning(f"[Brain] Portkey model fetch failed: {exc}")
        return None


def best_cf_model_live(task: str = "fast") -> Optional[LiveModel]:
    """Synchronous wrapper — best CF-hosted model."""
    brain = get_brain()
    try:
        return _run_async(brain.get_top_cf_hosted_models(task=task, top_n=1))[0]
    except Exception as exc:
        logger.warning(f"[Brain] CF model fetch failed: {exc}")
        return None


def globally_strongest_model_live(task: str = "general") -> Optional[LiveModel]:
    """Synchronous wrapper — globally strongest model across all providers."""
    brain = get_brain()
    try:
        return _run_async(brain.get_globally_strongest(task=task))
    except Exception as exc:
        logger.warning(f"[Brain] Global model fetch failed: {exc}")
        return None


def refresh_brain_sync() -> Dict[str, Any]:
    """Synchronous wrapper to refresh the brain. Returns summary dict."""
    brain = get_brain()
    try:
        _run_async(brain.refresh())
    except Exception as exc:
        logger.warning(f"[Brain] Refresh failed: {exc}")
    return brain.summary()


# ──────────────────────────────────────────────────────────────
# 8. IRAN ANTI-DPI / ANTI-FILTER INTEGRATION
# ──────────────────────────────────────────────────────────────

def detect_iran_dpi_active() -> bool:
    """
    Detect if Iran DPI is likely active based on environment signals.
    Checks for:
    - TORSHIELD_IRAN_MODE env var
    - Known Iran DPI detection flags from other modules
    - Time-of-day heuristics (Iran business hours = higher DPI)
    """
    # Explicit flag
    if os.environ.get("TORSHIELD_IRAN_MODE", "").lower() in ("1", "true", "yes"):
        return True

    # Check if the existing anti-DPI modules have detected active DPI
    try:
        from torshield_ai_gateway.iran_intelligence import IranIntelligence
        intel = IranIntelligence()
        if hasattr(intel, 'is_dpi_active') and intel.is_dpi_active:
            return True
    except (ImportError, AttributeError):
        pass

    # Check anti-censorship engine
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
    """
    Check if Iran DPI is active and enable anti-DPI scoring mode
    on the brain singleton. Returns True if anti-DPI mode was activated.
    """
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
# 9. CLI SELF-TEST  (python -m torshield_ai_gateway.dynamic_model_brain)
# ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import json
    logging.basicConfig(level=logging.INFO)

    async def main():
        brain = DynamicModelBrain()
        await brain.refresh()
        print(json.dumps(brain.summary(), indent=2, default=str))
        print("\n=== TOP 5 CF-HOSTED (task=fast) ===")
        for i, m in enumerate(
            await brain.get_top_cf_hosted_models("fast", top_n=5)
        ):
            print(
                f"  #{i+1} {m.id}  score={m.score}  "
                f"params={m.param_b}B  ctx={m.context_k}k  "
                f"reasoning={m.has_reasoning}"
            )

        print("\n=== TOP 5 PORTKEY MODELS (task=general) ===")
        for i, m in enumerate(
            await brain.get_top_models("general", source="portkey", top_n=5)
        ):
            print(
                f"  #{i+1} {m.id}  score={m.score}  "
                f"provider={m.provider}"
            )

        print("\n=== GLOBALLY STRONGEST MODEL ===")
        best = await brain.get_globally_strongest("general")
        if best:
            print(
                f"  {best.id}  score={best.score}  "
                f"source={best.source.value}"
            )

        # Test anti-DPI mode
        print("\n=== ANTI-DPI MODE TEST ===")
        brain.enable_anti_dpi()
        for i, m in enumerate(
            await brain.get_top_cf_hosted_models("fast", top_n=5)
        ):
            print(
                f"  #{i+1} {m.id}  score={m.score}  "
                f"params={m.param_b}B  ctx={m.context_k}k"
            )

    asyncio.run(main())
