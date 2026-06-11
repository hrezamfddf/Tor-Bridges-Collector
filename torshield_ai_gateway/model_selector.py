"""
model_selector.py — Dynamic AI Model Selector v1.0
════════════════════════════════════════════════════
Automatically discovers, scores, and selects the strongest available
Cloudflare Workers AI model at runtime.

ARCHITECTURE
────────────
  ┌─────────────────────────────────────────┐
  │  CloudflareModelSelector.best_model()   │
  └───────────────┬─────────────────────────┘
                  │
        ┌─────────▼──────────┐
        │  1. Live API fetch  │  CF REST API → model list (TTL=3600s)
        │  2. Score each model│  Multi-factor capability score
        │  3. Sort & select  │  Top model wins
        │  4. Probe winner   │  Sanity ping before commit
        │  5. Cache result   │  Avoid repeated API calls
        └─────────┬──────────┘
                  │ FAIL?
        ┌─────────▼──────────┐
        │   Offline Fallback  │  Hand-curated ranked list (always works)
        └────────────────────┘

SCORING ALGORITHM (0–100 points)
─────────────────────────────────
  • Capability tier   (0–40 pts)  — known model tier lookup
  • Parameter count   (0–25 pts)  — extracted from model ID or metadata
  • Context window    (0–15 pts)  — extracted from model metadata
  • Recency bonus     (0–10 pts)  — newer models score higher
  • Task affinity     (0–10 pts)  — matches requested task category

TASK CATEGORIES
───────────────
  "general"    — balanced, best overall
  "reasoning"  — deep thinking, complex logic
  "coding"     — programming tasks
  "vision"     — multimodal / image understanding
  "fast"       — lowest latency at cost of quality
"""

from __future__ import annotations

import json
import logging
import math
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("torshield.ai.model_selector")

# ── Cache TTL ────────────────────────────────────────────────────────────────
_CACHE_TTL_SECONDS: float = 3600.0   # refresh model list every hour
_PROBE_TIMEOUT:     int   = 12       # seconds for availability probe
_FETCH_TIMEOUT:     int   = 20       # seconds for CF API call

# ── Cloudflare API ───────────────────────────────────────────────────────────
_CF_MODELS_ENDPOINT = (
    "https://api.cloudflare.com/client/v4/accounts/{account_id}"
    "/ai/models/search?per_page=500"
)
_CF_TEXT_GEN_TASK = "Text Generation"
# Acceptable task names from CF API (the API may return variations)
_ACCEPTABLE_TASKS = {
    "text generation",
    "text-generation",
    "text gen",
    "conversational",
    "chat",
    "instruction",
    "instruct",
}


# ═══════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════

@dataclass
class ModelInfo:
    """Enriched representation of a single Cloudflare Workers AI model."""
    id:           str           # e.g. "@cf/meta/llama-3.1-70b-instruct"
    name:         str           # human name
    description:  str   = ""
    task:         str   = _CF_TEXT_GEN_TASK
    created_at:   str   = ""
    param_b:      float = 0.0   # parameter count in billions (0 = unknown)
    ctx_k:        int   = 0     # context window in K tokens (0 = unknown)
    score:        float = 0.0   # composite capability score 0–100
    tier:         int   = 0     # 1=frontier, 2=strong, 3=capable, 4=light

    @property
    def short_name(self) -> str:
        return self.id.split("/")[-1]


# ═══════════════════════════════════════════════════════════════════════════
# OFFLINE KNOWLEDGE BASE
# Known Cloudflare Workers AI models with hand-curated metadata.
# This list is the authoritative fallback when the live API is unavailable.
# Updated: June 2026
# ═══════════════════════════════════════════════════════════════════════════

# fmt: off
_OFFLINE_MODELS: List[Dict] = [
    # ── Tier 1 — Frontier ─────────────────────────────────────────────────
    {"id": "@cf/meta/llama-4-scout-17b-16e-instruct",         "param_b": 109.0,  "ctx_k": 128, "tier": 1, "tags": ["multimodal", "reasoning", "coding", "general"]},
    {"id": "@cf/meta/llama-4-maverick-17b-128e-instruct-fp8", "param_b": 400.0,  "ctx_k": 128, "tier": 1, "tags": ["multimodal", "reasoning", "coding", "general"]},
    {"id": "@cf/deepseek-ai/deepseek-r1-distill-qwen-32b",    "param_b": 32.0,   "ctx_k": 64,  "tier": 1, "tags": ["reasoning", "coding", "general"]},
    {"id": "@cf/deepseek-ai/deepseek-r1-distill-llama-70b",   "param_b": 70.0,   "ctx_k": 64,  "tier": 1, "tags": ["reasoning", "coding", "general"]},
    # ── Tier 2 — Strong ───────────────────────────────────────────────────
    {"id": "@cf/meta/llama-3.3-70b-instruct-fp8-fast",        "param_b": 70.0,   "ctx_k": 128, "tier": 2, "tags": ["general", "coding", "fast"]},
    {"id": "@cf/meta/llama-3.1-70b-instruct",                 "param_b": 70.0,   "ctx_k": 128, "tier": 2, "tags": ["general", "coding"]},
    {"id": "@cf/qwen/qwq-32b",                                "param_b": 32.0,   "ctx_k": 32,  "tier": 2, "tags": ["reasoning", "coding"]},
    {"id": "@cf/mistral/mistral-large-2407",                  "param_b": 123.0,  "ctx_k": 128, "tier": 2, "tags": ["general", "coding"]},
    {"id": "@cf/google/gemma-3-27b-it",                       "param_b": 27.0,   "ctx_k": 128, "tier": 2, "tags": ["general", "reasoning"]},
    # ── Tier 2 — Vision / Multimodal ──────────────────────────────────────
    {"id": "@cf/meta/llama-3.2-11b-vision-instruct",          "param_b": 11.0,   "ctx_k": 128, "tier": 2, "tags": ["vision", "multimodal", "general"]},
    {"id": "@cf/meta/llama-3.2-90b-vision-instruct",          "param_b": 90.0,   "ctx_k": 128, "tier": 2, "tags": ["vision", "multimodal", "general"]},
    # ── Tier 3 — Capable ──────────────────────────────────────────────────
    {"id": "@cf/meta/llama-3.1-8b-instruct",                  "param_b": 8.0,    "ctx_k": 128, "tier": 3, "tags": ["general", "fast"]},
    {"id": "@cf/meta/llama-3.2-3b-instruct",                  "param_b": 3.0,    "ctx_k": 128, "tier": 3, "tags": ["fast"]},
    {"id": "@cf/mistral/mistral-7b-instruct-v0.2",            "param_b": 7.0,    "ctx_k": 32,  "tier": 3, "tags": ["general"]},
    {"id": "@cf/google/gemma-7b-it",                          "param_b": 7.0,    "ctx_k": 8,   "tier": 3, "tags": ["general"]},
    {"id": "@cf/google/gemma-3-12b-it",                       "param_b": 12.0,   "ctx_k": 128, "tier": 3, "tags": ["general"]},
    {"id": "@cf/microsoft/phi-4",                             "param_b": 14.0,   "ctx_k": 16,  "tier": 3, "tags": ["reasoning", "coding"]},
    {"id": "@cf/qwen/qwen1.5-14b-chat-awq",                   "param_b": 14.0,   "ctx_k": 32,  "tier": 3, "tags": ["general", "coding"]},
    {"id": "@cf/openchat/openchat-3.5-0106",                  "param_b": 7.0,    "ctx_k": 8,   "tier": 3, "tags": ["general"]},
    # ── Tier 4 — Light (always-available fallbacks) ───────────────────────
    {"id": "@cf/meta/llama-3.2-1b-instruct",                  "param_b": 1.0,    "ctx_k": 128, "tier": 4, "tags": ["fast"]},
    {"id": "@cf/tinyllama/tinyllama-1.1b-chat-v1.0",          "param_b": 1.1,    "ctx_k": 2,   "tier": 4, "tags": ["fast"]},
    {"id": "@cf/microsoft/phi-2",                             "param_b": 2.7,    "ctx_k": 2,   "tier": 4, "tags": ["coding"]},
]
# fmt: on

# ── Task-tag compatibility ────────────────────────────────────────────────
_TASK_TAGS: Dict[str, List[str]] = {
    "general":   ["general"],
    "reasoning": ["reasoning", "general"],
    "coding":    ["coding", "reasoning", "general"],
    "vision":    ["vision", "multimodal"],
    "fast":      ["fast", "general"],
}

# ── Tier base scores (capability component) ───────────────────────────────
_TIER_SCORE: Dict[int, float] = {1: 40.0, 2: 32.0, 3: 22.0, 4: 10.0}

# ── Parameter-count → score mapping (log-scale, capped at 25) ────────────
def _param_score(param_b: float) -> float:
    if param_b <= 0:
        return 5.0  # unknown → neutral mid-low score
    # ln(1 + param_b) normalised so 100B → ~25 pts
    return min(25.0, 25.0 * math.log1p(param_b) / math.log1p(400))


# ── Context-window → score (capped at 15) ────────────────────────────────
def _ctx_score(ctx_k: int) -> float:
    if ctx_k <= 0:
        return 3.0
    return min(15.0, 15.0 * math.log2(max(ctx_k, 1)) / math.log2(512))


# ── Recency bonus from model ID date strings or created_at ───────────────
_RECENCY_PAT = re.compile(r"(\d{4})[_\-](\d{2})")


def _recency_score(model_id: str, created_at: str = "") -> float:
    """Newer models get up to 10 pts; pre-2023 models get 0."""
    year, month = 0, 0

    # Try created_at (ISO 8601)
    if created_at:
        m = re.match(r"(\d{4})-(\d{2})", created_at)
        if m:
            year, month = int(m.group(1)), int(m.group(2))

    # Fallback: parse date from model id (e.g. "0106" → Jan 2024)
    if year == 0:
        m2 = _RECENCY_PAT.search(model_id)
        if m2:
            year = int(m2.group(1))
            month = int(m2.group(2))

    # Heuristic: models with "llama-4", "gemma-3", "phi-4" are 2025/2026
    if year == 0:
        for token, y, mo in [
            ("llama-4",  2025, 4),
            ("gemma-3",  2025, 2),
            ("phi-4",    2025, 1),
            ("qwq",      2024, 12),
            ("deepseek-r1", 2025, 1),
            ("llama-3.3", 2024, 12),
            ("llama-3.2", 2024, 9),
            ("llama-3.1", 2024, 7),
            ("llama-3",  2024, 4),
            ("mistral-7b", 2023, 12),
        ]:
            if token in model_id.lower():
                year, mo2 = y, mo
                month = mo2
                break

    if year < 2023:
        return 0.0

    # Months since Jan 2023
    months_since = (year - 2023) * 12 + month
    return min(10.0, months_since * 0.4)


# ── Task-affinity score ───────────────────────────────────────────────────
def _task_affinity(tags: List[str], task: str) -> float:
    desired = _TASK_TAGS.get(task, ["general"])
    for t in desired:
        if t in tags:
            return 10.0
    return 0.0


# ═══════════════════════════════════════════════════════════════════════════
# MODEL ENRICHMENT
# ═══════════════════════════════════════════════════════════════════════════

_PARAM_RE = re.compile(
    r"(\d+(?:\.\d+)?)\s*x\s*(\d+(?:\.\d+)?)b|"   # MoE: NxMb
    r"(\d+(?:\.\d+)?)b",                            # dense: Nb
    re.IGNORECASE,
)


def _extract_params(model_id: str, description: str = "") -> float:
    """Extract parameter count (billions) from model ID or description."""
    text = (model_id + " " + description).lower()

    # MoE pattern: 17b-16e → 17*16 experts, report active params (17B)
    m = re.search(r"(\d+(?:\.\d+)?)b[_\-](\d+)e", text)
    if m:
        return float(m.group(1))

    # Standard dense: first plain Nb occurrence
    for m2 in _PARAM_RE.finditer(text):
        if m2.group(1) and m2.group(2):   # MoE form
            return float(m2.group(1))
        if m2.group(3):                    # dense form
            return float(m2.group(3))

    return 0.0


def _extract_ctx(model_id: str, description: str = "") -> int:
    """Extract context window in K tokens."""
    text = (model_id + " " + description).lower()
    for pat, val in [
        (r"(\d+)k\s*context", None),
        (r"context[_\-](\d+)k", None),
    ]:
        m = re.search(pat, text)
        if m:
            return int(m.group(1))
    return 0


def _infer_tags(model_id: str) -> List[str]:
    tags: List[str] = []
    mid = model_id.lower()
    if any(x in mid for x in ["vision", "vl", "multimodal"]):
        tags += ["vision", "multimodal"]
    if any(x in mid for x in ["coder", "code", "starcoder", "sqlcoder"]):
        tags.append("coding")
    if any(x in mid for x in ["r1", "qwq", "think", "reason"]):
        tags.append("reasoning")
    if any(x in mid for x in ["1b", "1.1b", "2.7b", "3b"]):
        tags.append("fast")
    if not tags:
        tags.append("general")
    return tags


def _enrich_from_offline(info: ModelInfo) -> ModelInfo:
    """Fill in metadata from offline knowledge base if known."""
    for entry in _OFFLINE_MODELS:
        if entry["id"] == info.id:
            if info.param_b == 0:
                info.param_b = entry.get("param_b", 0.0)
            if info.ctx_k == 0:
                info.ctx_k = entry.get("ctx_k", 0)
            info.tier = entry.get("tier", 3)
            return info
    return info


def _compute_score(info: ModelInfo, task: str = "general") -> float:
    tier_s = _TIER_SCORE.get(info.tier, 18.0)
    param_s = _param_score(info.param_b)
    ctx_s = _ctx_score(info.ctx_k)
    rec_s = _recency_score(info.id, info.created_at)
    tag_s = _task_affinity(_infer_tags(info.id), task)
    total = tier_s + param_s + ctx_s + rec_s + tag_s
    return round(min(100.0, total), 2)


# ═══════════════════════════════════════════════════════════════════════════
# CLOUDFLARE API FETCHER
# ═══════════════════════════════════════════════════════════════════════════

# Regex to detect UUID-format model IDs (not usable in API URLs)
_UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)

# User-Agent for model selector API calls (same as providers)
_MODEL_SELECTOR_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36 "
    "TorShieldModelSelector/11.0"
)


def _is_valid_model_id(model_id: str) -> bool:
    """
    Check if a model ID is usable in Cloudflare API URLs.
    UUID-format IDs (e.g., "f9f2250b-1048-4a52-9910-d0bf976616a1")
    are returned by the CF models API but CANNOT be used in
    /ai/run/ or /workers-ai/ endpoints — they produce 400/404 errors.
    Only @cf/ prefixed IDs are valid for inference endpoints.
    """
    if not model_id:
        return False
    if model_id.startswith("@cf/"):
        return True
    # UUID format — NOT usable in inference URLs
    if _UUID_PATTERN.match(model_id):
        return False
    # Other formats (e.g., plain names) — allow tentatively
    return True


def _fetch_cf_models(account_id: str, api_token: str) -> List[ModelInfo]:
    """
    Call Cloudflare REST API to list all text-generation models.
    Returns enriched ModelInfo list or raises on network/auth failure.
    Only includes models with valid @cf/ prefixed IDs (UUID IDs are filtered
    out because they cannot be used in inference endpoints).
    """
    url = _CF_MODELS_ENDPOINT.format(account_id=account_id)
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {api_token}",
            "Content-Type":  "application/json",
            "User-Agent":    _MODEL_SELECTOR_UA,
        },
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=_FETCH_TIMEOUT) as resp:
        raw = json.loads(resp.read().decode("utf-8"))

    if not raw.get("success"):
        raise RuntimeError(f"CF API error: {raw.get('errors', raw)}")

    results = raw.get("result", [])
    models: List[ModelInfo] = []
    uuid_count = 0
    for item in results:
        task_name = ""
        task_obj = item.get("task") or {}
        if isinstance(task_obj, dict):
            task_name = task_obj.get("name", "")
        elif isinstance(task_obj, str):
            task_name = task_obj

        # Flexible task matching: accept Text Generation and related tasks
        task_lower = task_name.lower()
        task_match = (
            _CF_TEXT_GEN_TASK.lower() in task_lower
            or any(t in task_lower for t in _ACCEPTABLE_TASKS)
        )
        # Also accept models with @cf/ prefix that have no task info
        # (some models in the API have empty task fields but are still valid)
        mid_precheck = item.get("id", item.get("name", ""))
        if not task_match:
            # If the model has a @cf/ prefix and is in our offline list, include it
            if mid_precheck and mid_precheck.startswith("@cf/"):
                offline_ids = {e["id"] for e in _OFFLINE_MODELS}
                if mid_precheck in offline_ids:
                    task_match = True
            if not task_match:
                continue

        mid = item.get("id", item.get("name", ""))
        if not mid:
            continue

        # Filter out UUID-format model IDs — they cannot be used in API URLs
        if _UUID_PATTERN.match(mid) and not mid.startswith("@cf/"):
            uuid_count += 1
            continue

        desc = item.get("description", "")
        info = ModelInfo(
            id=mid,
            name=item.get("name", mid.split("/")[-1]),
            description=desc,
            task=task_name,
            created_at=item.get("created_at", ""),
            param_b=_extract_params(mid, desc),
            ctx_k=_extract_ctx(mid, desc),
            tier=3,
        )
        info = _enrich_from_offline(info)
        models.append(info)

    if uuid_count > 0:
        logger.info(
            f"[ModelSelector] Filtered out {uuid_count} UUID-format model IDs "
            f"(not usable in inference endpoints)"
        )

    return models


# ═══════════════════════════════════════════════════════════════════════════
# MODEL PROBER
# ═══════════════════════════════════════════════════════════════════════════

def _probe_model(
    model_id: str,
    account_id: str,
    api_token: str,
) -> Tuple[bool, float]:
    """
    Send a minimal inference request to verify the model is live.
    Returns (success: bool, latency_ms: float).
    """
    url = (
        f"https://api.cloudflare.com/client/v4/accounts/{account_id}"
        f"/ai/run/{model_id}"
    )
    payload = json.dumps({
        "messages": [{"role": "user", "content": "Hi"}],
        "max_tokens": 1,
        "stream": False,
    }).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Authorization": f"Bearer {api_token}",
            "Content-Type":  "application/json",
            "User-Agent":    _MODEL_SELECTOR_UA,
        },
        method="POST",
    )
    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=_PROBE_TIMEOUT) as resp:
            resp.read()
        latency_ms = (time.monotonic() - t0) * 1000.0
        return True, latency_ms
    except Exception:
        latency_ms = (time.monotonic() - t0) * 1000.0
        return False, latency_ms


# ═══════════════════════════════════════════════════════════════════════════
# SELECTOR — main class
# ═══════════════════════════════════════════════════════════════════════════

class CloudflareModelSelector:
    """
    Singleton service that discovers and ranks Cloudflare Workers AI models.

    Usage
    ─────
    selector = CloudflareModelSelector.instance()

    # Best model for the given task, using first configured CF account
    best = selector.best_model(task="reasoning")

    # Full ranked list (no probe)
    ranked = selector.ranked_models(task="coding", top_n=5)

    # Invalidate cache (force re-fetch on next call)
    selector.invalidate_cache()
    """

    _instance: Optional["CloudflareModelSelector"] = None

    def __init__(self) -> None:
        self._cache_ts:     float               = 0.0
        self._cached_models: List[ModelInfo]    = []
        self._selected:     Dict[str, str]      = {}   # task → model_id
        self._selected_ts:  Dict[str, float]    = {}

    # ── Singleton ────────────────────────────────────────────────────────

    @classmethod
    def instance(cls) -> "CloudflareModelSelector":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    # ── Credentials helpers ──────────────────────────────────────────────

    @staticmethod
    def _first_cf_creds() -> Tuple[str, str]:
        """Return (account_id, api_token) for the first configured CF slot."""
        for i in range(1, 12):
            acct = os.environ.get(f"CF_ACCOUNT_ID_{i}", "")
            tok  = os.environ.get(f"CF_API_TOKEN_{i}",   "")
            if acct and tok:
                return acct, tok
        return "", ""

    # ── Cache management ─────────────────────────────────────────────────

    def invalidate_cache(self) -> None:
        self._cache_ts = 0.0
        self._cached_models = []
        self._selected = {}
        self._selected_ts = {}
        logger.info("[ModelSelector] Cache invalidated.")

    def _cache_stale(self) -> bool:
        return (time.monotonic() - self._cache_ts) > _CACHE_TTL_SECONDS

    # ── Model discovery ──────────────────────────────────────────────────

    def _get_models(self, task: str = "general") -> List[ModelInfo]:
        """
        Return enriched, scored, sorted model list.
        Tries live CF API first; falls back to offline list.
        Results cached for TTL.
        """
        if not self._cache_stale() and self._cached_models:
            return _rescore(self._cached_models, task)

        acct_id, api_token = self._first_cf_creds()
        models: List[ModelInfo] = []

        if acct_id and api_token:
            try:
                logger.info("[ModelSelector] Fetching live CF model list…")
                models = _fetch_cf_models(acct_id, api_token)
                logger.info(
                    f"[ModelSelector] Live fetch: {len(models)} text-gen models"
                )
                # If live API returns 0 usable models (all UUIDs or wrong task name),
                # merge with offline list to ensure we always have usable models
                if not models:
                    logger.warning(
                        "[ModelSelector] Live fetch returned 0 usable models — "
                        "API may have changed. Merging offline models."
                    )
                    models = _build_offline_models()
            except Exception as exc:
                logger.warning(
                    f"[ModelSelector] Live fetch failed ({exc}); using offline list"
                )
        else:
            logger.info("[ModelSelector] No CF creds found; using offline list")

        if not models:
            models = _build_offline_models()

        # Score and sort
        for m in models:
            m.score = _compute_score(m, task)
        models.sort(key=lambda m: m.score, reverse=True)

        self._cached_models = models
        self._cache_ts = time.monotonic()
        return models

    # ── Public API ───────────────────────────────────────────────────────

    def ranked_models(
        self,
        task:   str = "general",
        top_n:  int = 10,
    ) -> List[ModelInfo]:
        """
        Return top-N models ranked for the given task.
        Does NOT probe — fast, offline-safe.
        """
        models = self._get_models(task)
        return models[:top_n]

    def best_model(
        self,
        task:   str  = "general",
        probe:  bool = True,
        top_n:  int  = 5,
    ) -> str:
        """
        Return the model ID of the best available model for the given task.

        If probe=True (default), the top candidate is pinged; if it fails,
        the next candidate is tried until one responds.

        Falls back to the first offline tier-4 model if everything fails.
        """
        # Check 1-hour selection cache per task
        sel_age = time.monotonic() - self._selected_ts.get(task, 0.0)
        if task in self._selected and sel_age < _CACHE_TTL_SECONDS:
            return self._selected[task]

        candidates = self.ranked_models(task=task, top_n=top_n)
        if not candidates:
            fallback = _OFFLINE_MODELS[0]["id"]
            logger.warning(f"[ModelSelector] No candidates; fallback → {fallback}")
            return fallback

        if not probe:
            winner = candidates[0].id
            self._selected[task] = winner
            self._selected_ts[task] = time.monotonic()
            logger.info(
                f"[ModelSelector] Selected (no-probe) [{task}]: "
                f"{winner} (score={candidates[0].score})"
            )
            return winner

        acct_id, api_token = self._first_cf_creds()
        if not (acct_id and api_token):
            # No creds → skip probing
            winner = candidates[0].id
            self._selected[task] = winner
            self._selected_ts[task] = time.monotonic()
            logger.info(
                f"[ModelSelector] Selected (no-creds) [{task}]: "
                f"{winner} (score={candidates[0].score})"
            )
            return winner

        for candidate in candidates:
            logger.debug(
                f"[ModelSelector] Probing {candidate.id} "
                f"(score={candidate.score}) …"
            )
            ok, lat = _probe_model(candidate.id, acct_id, api_token)
            if ok:
                winner = candidate.id
                self._selected[task] = winner
                self._selected_ts[task] = time.monotonic()
                logger.info(
                    f"[ModelSelector] ✓ Selected [{task}]: "
                    f"{winner} | score={candidate.score} | "
                    f"probe_latency={lat:.0f}ms"
                )
                return winner
            logger.warning(
                f"[ModelSelector] ✗ Probe failed: {candidate.id} "
                f"(latency={lat:.0f}ms)"
            )

        # All probes failed → use top candidate anyway (API may be slow)
        winner = candidates[0].id
        self._selected[task] = winner
        self._selected_ts[task] = time.monotonic()
        logger.warning(
            f"[ModelSelector] All probes failed; using best scored: {winner}"
        )
        return winner

    def status(self) -> Dict:
        """Return a human-readable status dict for logging/debugging."""
        models = self._get_models()
        return {
            "total_models":   len(models),
            "cache_age_s":    round(time.monotonic() - self._cache_ts, 1),
            "cache_ttl_s":    _CACHE_TTL_SECONDS,
            "selected":       self._selected,
            "top_10": [
                {
                    "rank":    i + 1,
                    "id":      m.id,
                    "score":   m.score,
                    "tier":    m.tier,
                    "param_b": m.param_b,
                    "ctx_k":   m.ctx_k,
                }
                for i, m in enumerate(models[:10])
            ],
        }


# ═══════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════

def _rescore(models: List[ModelInfo], task: str) -> List[ModelInfo]:
    """Re-score a cached list for a different task without re-fetching."""
    for m in models:
        m.score = _compute_score(m, task)
    models.sort(key=lambda m: m.score, reverse=True)
    return models


def _build_offline_models() -> List[ModelInfo]:
    """Construct ModelInfo objects from the offline knowledge base."""
    infos: List[ModelInfo] = []
    for entry in _OFFLINE_MODELS:
        mid = entry["id"]
        info = ModelInfo(
            id=mid,
            name=mid.split("/")[-1],
            param_b=entry.get("param_b", 0.0),
            ctx_k=entry.get("ctx_k", 0),
            tier=entry.get("tier", 3),
        )
        infos.append(info)
    return infos


# ═══════════════════════════════════════════════════════════════════════════
# MODULE-LEVEL CONVENIENCE FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════

def best_cf_model(task: str = "general", probe: bool = True) -> str:
    """
    One-liner: return the best Cloudflare model ID for the given task.

    Args:
        task:  "general" | "reasoning" | "coding" | "vision" | "fast"
        probe: Whether to ping the model before returning (default True).

    Returns:
        CF model ID string, e.g. "@cf/meta/llama-4-maverick-17b-128e-instruct-fp8"
    """
    return CloudflareModelSelector.instance().best_model(task=task, probe=probe)


def ranked_cf_models(task: str = "general", top_n: int = 10) -> List[ModelInfo]:
    """
    Return the top-N ranked models for the given task (no probing).
    """
    return CloudflareModelSelector.instance().ranked_models(task=task, top_n=top_n)


def model_selector_status() -> Dict:
    """Return full selector status dict."""
    return CloudflareModelSelector.instance().status()
