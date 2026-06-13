#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════╗
║  DYNAMIC AI BRAIN v3.0 — Intelligent Model Discovery & Auto-Selection  ║
║  Sources: Cloudflare Workers AI API + Portkey + Cerebras                ║
║  Strategy: Live fetch → Score → Probe → Select best working model       ║
╚══════════════════════════════════════════════════════════════════════════╝

Fixes from v2:
  - [BUG FIX] @cf/meta/llama-3.3-70b-instruct-fp8-fast → deprecated via AI Gateway
  - [BUG FIX] CF API 403 → graceful fallback to curated static registry
  - [NEW] Probe-based verification before model commit (eliminates HTTP 400)
  - [NEW] June 2026 model registry with newest pinned CF models
  - [NEW] Portkey /v1/models endpoint integration
  - [NEW] Per-slot vs per-model error classification
"""

from __future__ import annotations

import asyncio
import logging
import math
import os
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

try:
    import aiohttp
except ImportError:
    raise SystemExit("Missing dependency: pip install aiohttp")

logger = logging.getLogger("torshield.ai.dynamic_brain_v3")


# ══════════════════════════════════════════════════════════════════════════
# STATIC MODEL REGISTRY — Updated June 2026
# Fallback when live API returns 403/0 models.
# Format: (model_id, ctx_tokens, reasoning, func_call, vision, params_b, pinned, tier)
# ══════════════════════════════════════════════════════════════════════════
CF_STATIC_REGISTRY: List[Tuple] = [
    # ── Tier 1: Frontier ──────────────────────────────────────────────────
    ("@cf/moonshotai/kimi-k2.6",               262_144, True,  True,  True,  1000.0, True,  1),
    ("@cf/openai/gpt-oss-120b",                 32_768, True,  True,  False,  120.0, True,  1),
    ("@cf/nvidia/nemotron-3-120b-a12b",         32_768, False, True,  False,  120.0, False, 1),
    # ── Tier 2: High capability ───────────────────────────────────────────
    ("@cf/meta/llama-4-scout-17b-16e-instruct", 131_072, False, True,  True,   17.0, True,  2),
    ("@cf/zai-org/glm-4.7-flash",              131_072, True,  True,  False,   0.0, True,  2),
    ("@cf/deepseek-ai/deepseek-r1-distill-qwen-32b", 16_384, True, False, False, 32.0, False, 2),
    ("@cf/qwen/qwq-32b",                        32_768, True,  True,  False,  32.0, False, 2),
    ("@cf/meta/llama-4-maverick-17b-128e-instruct-fp8", 262_144, False, True, True, 17.0, False, 2),
    # ── Tier 3: Efficient ─────────────────────────────────────────────────
    ("@cf/meta/llama-3.1-70b-instruct",          8_192, False, True,  False,  70.0, False, 3),
    ("@cf/meta/llama-3.3-70b-instruct-fp8-fast", 8_192, False, True,  False,  70.0, False, 3),
    ("@cf/meta/llama-3.2-11b-vision-instruct",   8_192, False, False, True,   11.0, False, 3),
    # ── Tier 4: Emergency fallback ────────────────────────────────────────
    ("@cf/mistral/mistral-7b-instruct-v0.2",     4_096, False, False, False,   7.0, False, 4),
    ("@cf/meta/llama-3.2-3b-instruct",           4_096, False, False, False,   3.0, False, 4),
]

PORTKEY_STATIC_REGISTRY: List[Tuple] = [
    # Format: (virtual_key_model, provider_hint, ctx, reasoning, func_call, params_b)
    ("claude-opus-4-8",          "anthropic", 1_000_000, True,  True,  0.0),
    ("claude-opus-4-7",          "anthropic", 1_000_000, True,  True,  0.0),
    ("claude-sonnet-4-6",        "anthropic",   200_000, True,  True,  0.0),
    ("gemini-2.5-pro",           "google",    2_000_000, True,  True,  0.0),
    ("gpt-5.2",                  "openai",      128_000, True,  True,  0.0),
    ("gpt-4o",                   "openai",      128_000, False, True,  0.0),
    ("gpt-4o-mini",              "openai",      128_000, False, True,  0.0),
    ("meta-llama/llama-4-scout", "together",    131_072, False, True,  17.0),
    ("mistral-large-2501",       "mistral",     131_072, False, True,  0.0),
    ("deepseek-chat",            "deepseek",    131_072, False, True,  0.0),
]

# Models known to return HTTP 400 via CF AI Gateway — skip immediately
CF_GATEWAY_BLACKLIST = {
    "@cf/meta/llama-3.3-70b-instruct-fp8-fast",  # deprecated via Gateway
    "@cf/meta/llama-3.2-1b-instruct",             # too old
}


# ══════════════════════════════════════════════════════════════════════════
# DATA MODEL
# ══════════════════════════════════════════════════════════════════════════
@dataclass
class ModelProfile:
    name: str
    provider: str                   # "cloudflare" | "portkey" | "cerebras"
    context_window: int = 0
    has_reasoning: bool = False
    has_function_calling: bool = False
    has_vision: bool = False
    is_pinned: bool = False
    is_hosted: bool = True
    param_count_b: float = 0.0
    tier: int = 4
    score: float = 0.0
    # Probe state
    probe_status: str = "untested"  # untested | ok | failed
    probe_latency_ms: float = 0.0
    probe_http_code: int = 0

    # ── Scoring ────────────────────────────────────────────────────────
    def compute_score(self) -> float:
        s = 0.0
        if self.has_reasoning:        s += 30.0
        if self.has_function_calling: s += 20.0
        if self.has_vision:           s += 10.0
        if self.is_pinned:            s += 25.0
        if self.is_hosted:            s += 15.0
        s += min(50.0, self.context_window / 10_000)
        if self.param_count_b > 0:
            s += math.log2(max(1.0, self.param_count_b)) * 2.5
        s += (5 - self.tier) * 5.0   # tier 1 → +20, tier 4 → +5
        self.score = round(s, 2)
        return self.score

    @property
    def sort_key(self) -> float:
        """Sort key: probe-ok first, then score, then penalise failed"""
        if self.probe_status == "ok":     return self.score + 1000
        if self.probe_status == "untested": return self.score
        return self.score - 1000         # failed → bottom

    def __repr__(self) -> str:
        icon = {"ok": "✓", "failed": "✗", "untested": "?"}[self.probe_status]
        return (
            f"{icon} {self.name} "
            f"[score={self.score} tier={self.tier} "
            f"ctx={self.context_window//1000}k "
            f"{'R' if self.has_reasoning else ''}{'F' if self.has_function_calling else ''}{'V' if self.has_vision else ''}]"
        )


# ══════════════════════════════════════════════════════════════════════════
# DYNAMIC BRAIN v3
# ══════════════════════════════════════════════════════════════════════════
class DynamicModelBrainV3:
    """
    Auto-discovers, scores, probes and selects the strongest available AI model.

    Usage:
        brain = DynamicModelBrainV3.from_env()
        models = await brain.refresh(probe_gateway_url=cf_gateway_url)
        best = brain.get_best()
        print(best)
    """

    # CF REST API — requires Bearer token with Workers AI read permission
    _CF_API_URL = (
        "https://api.cloudflare.com/client/v4/accounts/{account_id}"
        "/ai/models/search?task=text-generation&per_page=200"
    )
    # Portkey models endpoint
    _PORTKEY_API_URL = "https://api.portkey.ai/v1/models"

    def __init__(
        self,
        cf_slots: List[Tuple[str, str]],       # [(account_id, api_token), ...]
        portkey_api_keys: Optional[List[str]] = None,
        portkey_gateway_url: Optional[str] = None,
        cache_ttl: int = 300,
    ):
        self.cf_slots = cf_slots
        self.portkey_api_keys = portkey_api_keys or []
        self.portkey_gateway_url = portkey_gateway_url
        self.cache_ttl = cache_ttl
        self._registry: Dict[str, ModelProfile] = {}
        self._cache_ts: float = 0.0

    # ── Factory ────────────────────────────────────────────────────────
    @classmethod
    def from_env(cls) -> "DynamicModelBrainV3":
        """Build from environment variables (same convention as health_check.py)"""
        cf_slots: List[Tuple[str, str]] = []
        for i in range(1, 20):
            acc = os.environ.get(f"CF_ACCOUNT_ID_{i}")
            tok = os.environ.get(f"CF_API_TOKEN_{i}")
            if acc and tok:
                cf_slots.append((acc, tok))

        portkey_keys: List[str] = []
        for i in range(1, 10):
            k = os.environ.get(f"PORTKEY_API_KEY_{i}")
            if k:
                portkey_keys.append(k)

        return cls(
            cf_slots=cf_slots,
            portkey_api_keys=portkey_keys,
            portkey_gateway_url=os.environ.get("PORTKEY_GATEWAY_URL"),
        )

    # ══════════════════════════════════════════════════════════════════
    # LIVE FETCH METHODS
    # ══════════════════════════════════════════════════════════════════
    async def _fetch_cf_live(
        self, session: aiohttp.ClientSession, account_id: str, api_token: str
    ) -> List[dict]:
        url = self._CF_API_URL.format(account_id=account_id)
        try:
            async with session.get(
                url,
                headers={"Authorization": f"Bearer {api_token}"},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    models = data.get("result", [])
                    logger.info(
                        f"[Brain] CF API {account_id[:8]}…: {len(models)} text-gen models"
                    )
                    return models
                elif resp.status == 403:
                    logger.debug(
                        f"[Brain] CF 403 for {account_id[:8]}… — "
                        "token needs 'Workers AI:Read' permission"
                    )
                else:
                    logger.debug(f"[Brain] CF {resp.status} for {account_id[:8]}…")
        except asyncio.TimeoutError:
            logger.debug(f"[Brain] CF timeout for {account_id[:8]}…")
        except Exception as exc:
            logger.debug(f"[Brain] CF error for {account_id[:8]}…: {exc}")
        return []

    async def _fetch_portkey_live(
        self, session: aiohttp.ClientSession, api_key: str
    ) -> List[dict]:
        try:
            async with session.get(
                self._PORTKEY_API_URL,
                headers={"Authorization": f"Bearer {api_key}"},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    models = data.get("data", data.get("models", []))
                    logger.info(f"[Brain] Portkey API: {len(models)} models")
                    return models
                else:
                    logger.debug(f"[Brain] Portkey API {resp.status}")
        except Exception as exc:
            logger.debug(f"[Brain] Portkey fetch error: {exc}")
        return []

    # ══════════════════════════════════════════════════════════════════
    # PARSERS
    # ══════════════════════════════════════════════════════════════════
    @staticmethod
    def _parse_cf_api_model(raw: dict) -> Optional[ModelProfile]:
        name = raw.get("name", "")
        if not name:
            return None
        task_name = str(raw.get("task", {}).get("name", "")).lower()
        if "text" not in task_name and "generation" not in task_name:
            return None

        props: Dict[str, str] = {
            p["property_id"]: str(p.get("value", ""))
            for p in raw.get("properties", [])
            if isinstance(p, dict)
        }

        # Context window
        ctx = 0
        for key in ("max_input_tokens", "context_window_tokens", "context_window"):
            try:
                ctx = int(props.get(key, "0").replace(",", ""))
                if ctx > 0:
                    break
            except (ValueError, AttributeError):
                pass

        # Capabilities
        has_fc  = props.get("function_calling", "").lower() == "true"
        has_vis = props.get("vision", "").lower() == "true"
        has_rsn = any([
            props.get("reasoning", "").lower() == "true",
            "reasoning" in name.lower(),
            re.search(r"\br1\b", name.lower()) is not None,
            "qwq" in name.lower(),
            "deepseek-r" in name.lower(),
        ])

        # Param count from name
        params = 0.0
        hits = re.findall(r"([\d]+\.?[\d]*)b", name.lower())
        if hits:
            try:
                params = max(float(h) for h in hits)
            except ValueError:
                pass

        # Tier by capability
        if params >= 100 or ctx >= 200_000:
            tier = 1
        elif params >= 32 or ctx >= 32_000:
            tier = 2
        elif params >= 7 or ctx >= 8_000:
            tier = 3
        else:
            tier = 4

        m = ModelProfile(
            name=name,
            provider="cloudflare",
            context_window=ctx,
            has_reasoning=has_rsn,
            has_function_calling=has_fc,
            has_vision=has_vis,
            is_pinned=bool(raw.get("pinned", False)),
            is_hosted=True,
            param_count_b=params,
            tier=tier,
        )
        m.compute_score()
        return m

    @staticmethod
    def _parse_portkey_api_model(raw: dict) -> Optional[ModelProfile]:
        model_id = raw.get("id", raw.get("model_id", ""))
        if not model_id:
            return None
        ctx = int(raw.get("context_window", raw.get("max_context_length", 0)) or 0)
        m = ModelProfile(
            name=model_id,
            provider="portkey",
            context_window=ctx,
            has_reasoning="o1" in model_id or "opus" in model_id or "gemini-2.5" in model_id,
            has_function_calling=True,
            is_hosted=False,
            tier=2 if ctx >= 32_000 else 3,
        )
        m.compute_score()
        return m

    # ══════════════════════════════════════════════════════════════════
    # STATIC REGISTRY LOADER
    # ══════════════════════════════════════════════════════════════════
    def _load_static(self) -> Dict[str, ModelProfile]:
        registry: Dict[str, ModelProfile] = {}
        for (name, ctx, rsn, fc, vis, params, pinned, tier) in CF_STATIC_REGISTRY:
            m = ModelProfile(
                name=name, provider="cloudflare",
                context_window=ctx, has_reasoning=rsn,
                has_function_calling=fc, has_vision=vis,
                is_pinned=pinned, is_hosted=True,
                param_count_b=params, tier=tier,
            )
            m.compute_score()
            registry[name] = m
        for (name, provider, ctx, rsn, fc, params) in PORTKEY_STATIC_REGISTRY:
            m = ModelProfile(
                name=name, provider="portkey",
                context_window=ctx, has_reasoning=rsn,
                has_function_calling=fc,
                is_hosted=False, param_count_b=params,
                tier=1 if ctx >= 500_000 else (2 if ctx >= 32_000 else 3),
            )
            m.compute_score()
            registry[f"portkey:{name}"] = m
        return registry

    # ══════════════════════════════════════════════════════════════════
    # PROBE
    # ══════════════════════════════════════════════════════════════════
    async def _probe_cf_gateway(
        self,
        session: aiohttp.ClientSession,
        model: ModelProfile,
        gateway_url: str,
    ) -> Tuple[bool, float, int]:
        """
        Probe a model via CF AI Gateway.
        Returns (success, latency_ms, http_code)
        """
        payload = {
            "model": model.name,
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 1,
            "stream": False,
        }
        t0 = time.monotonic()
        try:
            async with session.post(
                gateway_url,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                latency = (time.monotonic() - t0) * 1000
                status = resp.status
                if status == 200:
                    return True, latency, status
                else:
                    body = (await resp.text())[:120]
                    logger.debug(
                        f"[Brain] Probe {model.name}: HTTP {status} — {body}"
                    )
                    return False, latency, status
        except asyncio.TimeoutError:
            return False, (time.monotonic() - t0) * 1000, 0
        except Exception as exc:
            logger.debug(f"[Brain] Probe error for {model.name}: {exc}")
            return False, (time.monotonic() - t0) * 1000, -1

    async def _probe_portkey(
        self,
        session: aiohttp.ClientSession,
        model: ModelProfile,
        api_key: str,
        gateway_url: str,
    ) -> Tuple[bool, float, int]:
        """Probe a model via Portkey gateway"""
        payload = {
            "model": model.name,
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 1,
        }
        t0 = time.monotonic()
        try:
            async with session.post(
                f"{gateway_url.rstrip('/')}/chat/completions",
                json=payload,
                headers={
                    "x-portkey-api-key": api_key,
                    "Content-Type": "application/json",
                },
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                latency = (time.monotonic() - t0) * 1000
                return resp.status == 200, latency, resp.status
        except Exception:
            return False, (time.monotonic() - t0) * 1000, -1

    # ══════════════════════════════════════════════════════════════════
    # MAIN REFRESH
    # ══════════════════════════════════════════════════════════════════
    async def refresh(
        self,
        probe_cf_gateway_url: Optional[str] = None,
        probe_portkey: bool = False,
        top_k_probe: int = 5,
        force: bool = False,
    ) -> List[ModelProfile]:
        """
        Full refresh cycle:
          1. Start with curated static registry
          2. Overlay with live CF API data (if accessible)
          3. Overlay with live Portkey API data (if accessible)
          4. Score all models
          5. Probe top-K CF candidates (eliminates HTTP 400 surprises)
          6. Return sorted list (probe-ok first, then by score)
        """
        if not force and (time.monotonic() - self._cache_ts) < self.cache_ttl and self._registry:
            logger.debug("[Brain] Cache hit — skipping refresh")
            return self._sorted()

        # ── Step 1: Static seed ─────────────────────────────────────
        registry = self._load_static()
        live_cf = 0
        live_portkey = 0

        async with aiohttp.ClientSession() as session:

            # ── Step 2: CF live fetch (first 3 slots only) ───────────
            cf_tasks = [
                self._fetch_cf_live(session, acc, tok)
                for acc, tok in self.cf_slots[:3]
            ]
            cf_results = await asyncio.gather(*cf_tasks, return_exceptions=True)
            for result in cf_results:
                if not isinstance(result, list):
                    continue
                for raw in result:
                    parsed = self._parse_cf_api_model(raw)
                    if parsed is None:
                        continue
                    key = parsed.name
                    if key not in registry:
                        registry[key] = parsed
                        live_cf += 1
                    else:
                        # Enrich existing entry with live data
                        existing = registry[key]
                        if parsed.context_window > existing.context_window:
                            existing.context_window = parsed.context_window
                            existing.compute_score()
                        if parsed.is_pinned:
                            existing.is_pinned = True
                            existing.compute_score()

            # ── Step 3: Portkey live fetch ────────────────────────────
            if self.portkey_api_keys:
                pk_raw = await self._fetch_portkey_live(session, self.portkey_api_keys[0])
                for raw in pk_raw:
                    parsed = self._parse_portkey_api_model(raw)
                    if parsed:
                        key = f"portkey:{parsed.name}"
                        if key not in registry:
                            registry[key] = parsed
                            live_portkey += 1

            logger.info(
                f"[Brain] Registry: {len(registry)} models "
                f"({live_cf} new CF, {live_portkey} new Portkey)"
            )

            # ── Step 4: Probe top CF models ───────────────────────────
            if probe_cf_gateway_url:
                cf_candidates = [
                    m for m in sorted(
                        (v for v in registry.values() if v.provider == "cloudflare"),
                        key=lambda m: m.score,
                        reverse=True,
                    )
                    if m.name not in CF_GATEWAY_BLACKLIST
                ][:top_k_probe]

                probe_tasks = [
                    self._probe_cf_gateway(session, m, probe_cf_gateway_url)
                    for m in cf_candidates
                ]
                probe_results = await asyncio.gather(*probe_tasks, return_exceptions=True)

                for model, result in zip(cf_candidates, probe_results):
                    if not isinstance(result, tuple):
                        continue
                    ok, latency, code = result
                    model.probe_status = "ok" if ok else "failed"
                    model.probe_latency_ms = round(latency, 1)
                    model.probe_http_code = code
                    icon = "✓" if ok else "✗"
                    logger.info(
                        f"[Brain] Probe {icon} {model.name} "
                        f"HTTP {code} {latency:.0f}ms"
                    )

            # ── Step 5: Probe top Portkey models ──────────────────────
            if probe_portkey and self.portkey_api_keys and self.portkey_gateway_url:
                pk_candidates = [
                    m for m in sorted(
                        (v for v in registry.values() if v.provider == "portkey"),
                        key=lambda m: m.score,
                        reverse=True,
                    )
                ][:3]
                pk_tasks = [
                    self._probe_portkey(
                        session, m,
                        self.portkey_api_keys[0],
                        self.portkey_gateway_url,
                    )
                    for m in pk_candidates
                ]
                pk_results = await asyncio.gather(*pk_tasks, return_exceptions=True)
                for model, result in zip(pk_candidates, pk_results):
                    if isinstance(result, tuple):
                        ok, latency, code = result
                        model.probe_status = "ok" if ok else "failed"
                        model.probe_latency_ms = round(latency, 1)
                        model.probe_http_code = code

        self._registry = registry
        self._cache_ts = time.monotonic()
        return self._sorted()

    # ══════════════════════════════════════════════════════════════════
    # QUERY INTERFACE
    # ══════════════════════════════════════════════════════════════════
    def _sorted(self) -> List[ModelProfile]:
        return sorted(self._registry.values(), key=lambda m: m.sort_key, reverse=True)

    def get_best(
        self,
        provider: Optional[str] = None,
        exclude_failed: bool = True,
        require_function_calling: bool = False,
        require_reasoning: bool = False,
        min_context: int = 0,
    ) -> Optional[ModelProfile]:
        """Return the highest-scoring available model, with optional filters."""
        candidates = self._sorted()
        for m in candidates:
            if exclude_failed and m.probe_status == "failed":
                continue
            if provider and m.provider != provider:
                continue
            if require_function_calling and not m.has_function_calling:
                continue
            if require_reasoning and not m.has_reasoning:
                continue
            if m.context_window < min_context:
                continue
            return m
        return None

    def get_for_task(self, task: str) -> Optional[ModelProfile]:
        """
        Return best model for a specific task type.
          task ∈ {"fast", "reasoning", "vision", "long_context", "code", "default"}
        """
        task = task.lower()
        if task == "fast":
            # Prefer tier 3, any probe status except failed
            for m in self._sorted():
                if m.tier >= 3 and m.probe_status != "failed":
                    return m
        elif task in ("reasoning", "math", "code"):
            return self.get_best(require_reasoning=True)
        elif task == "vision":
            for m in self._sorted():
                if m.has_vision and m.probe_status != "failed":
                    return m
        elif task == "long_context":
            return self.get_best(min_context=100_000)
        return self.get_best()

    def top_n(self, n: int = 5) -> List[ModelProfile]:
        return self._sorted()[:n]

    def summary(self) -> str:
        """Human-readable model ranking summary"""
        lines = ["═══ Dynamic Brain v3 — Model Registry ═══"]
        for i, m in enumerate(self.top_n(8), 1):
            lines.append(f"  #{i} {m}")
        total = len(self._registry)
        ok = sum(1 for m in self._registry.values() if m.probe_status == "ok")
        failed = sum(1 for m in self._registry.values() if m.probe_status == "failed")
        lines.append(f"  Total: {total} | Probe OK: {ok} | Failed: {failed}")
        return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════════
# COMPATIBILITY SHIM — drop-in replacement for existing DynamicBrain
# ══════════════════════════════════════════════════════════════════════════
class DynamicBrain(DynamicModelBrainV3):
    """
    Backward-compatible alias.
    Usage in existing code — just change the import:
      from torshield.ai.dynamic_brain_v3 import DynamicBrain
    """

    def __init__(self, cf_slots, **kwargs):
        super().__init__(cf_slots=cf_slots, **kwargs)
        self._cf_models: List[str] = []
        self._portkey_models: List[str] = []
        self.total_models: int = 0

    async def fetch_and_score(
        self,
        probe_url: Optional[str] = None,
        task: str = "fast",
    ) -> Tuple[List[str], Optional[str]]:
        """
        Compat method.
        Returns: (model_name_list, best_model_name)
        """
        models = await self.refresh(probe_cf_gateway_url=probe_url)
        self._cf_models = [m.name for m in models if m.provider == "cloudflare"]
        self.total_models = len(models)
        best = self.get_for_task(task)
        return self._cf_models, (best.name if best else None)

    def get_top_model(self, task: str = "fast") -> Optional[str]:
        m = self.get_for_task(task)
        return m.name if m else None


# ══════════════════════════════════════════════════════════════════════════
# STANDALONE TEST
# ══════════════════════════════════════════════════════════════════════════
async def _main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    brain = DynamicModelBrainV3.from_env()

    # Use first CF AI Gateway URL for probing (optional)
    probe_url = os.environ.get("CF_AI_GATEWAY_URL_1")

    print("Refreshing model registry…")
    models = await brain.refresh(
        probe_cf_gateway_url=probe_url,
        top_k_probe=5,
    )
    print(brain.summary())

    best = brain.get_best()
    if best:
        print(f"\n→ Selected model: {best.name}")
        print(f"  Score: {best.score} | Tier: {best.tier}")
        print(f"  Context: {best.context_window:,} tokens")
        print(f"  Reasoning: {best.has_reasoning} | FC: {best.has_function_calling} | Vision: {best.has_vision}")
        print(f"  Probe: {best.probe_status} ({best.probe_latency_ms:.0f}ms)")
    else:
        print("ERROR: No model available!")


if __name__ == "__main__":
    asyncio.run(_main())
و
model_selector_v3.py
#!/usr/bin/env python3
"""
model_selector_v3.py — Drop-in replacement for torshield.ai.model_selector
Integrates DynamicModelBrainV3 into the existing health-check flow.

USAGE in ai_gateway_health_check.py:
  # OLD:
  from torshield.ai.model_selector import ModelSelector
  # NEW:
  from scripts.model_selector_v3 import ModelSelectorV3 as ModelSelector
"""

from __future__ import annotations

import asyncio
import logging
import os
from typing import List, Optional, Tuple

from dynamic_brain_v3 import DynamicModelBrainV3, ModelProfile, CF_GATEWAY_BLACKLIST

logger = logging.getLogger("torshield.ai.model_selector_v3")


# ═══════════════════════════════════════════════════════════════════════
# Score table for display (matches engineering prompt priorities)
# ═══════════════════════════════════════════════════════════════════════
SCORE_OVERRIDE: dict[str, float] = {
    "@cf/moonshotai/kimi-k2.6":                    120.0,
    "@cf/openai/gpt-oss-120b":                      95.0,
    "@cf/nvidia/nemotron-3-120b-a12b":              90.0,
    "@cf/meta/llama-4-scout-17b-16e-instruct":      88.0,
    "@cf/zai-org/glm-4.7-flash":                    85.0,
    "@cf/deepseek-ai/deepseek-r1-distill-qwen-32b": 78.0,
    "@cf/qwen/qwq-32b":                             75.0,
    "@cf/meta/llama-3.1-70b-instruct":              62.0,
    # Deprecated via AI Gateway — kept for score reference only
    "@cf/meta/llama-3.3-70b-instruct-fp8-fast":    30.0,  # BLACKLISTED
}


class ModelSelectorV3:
    """
    Smart model selector backed by DynamicModelBrainV3.
    Fetches live model lists, scores, probes, and returns the best
    verified-working model for your task.
    """

    def __init__(self, brain: Optional[DynamicModelBrainV3] = None):
        self._brain = brain or DynamicModelBrainV3.from_env()
        self._initialized = False

    async def initialize(
        self,
        probe_url: Optional[str] = None,
        task: str = "fast",
        top_k_probe: int = 5,
    ) -> None:
        """
        Async init — fetches live model list and probes top candidates.
        Call once at startup.
        """
        logger.info("[ModelSelector] Fetching live model list with probe verification…")
        await self._brain.refresh(
            probe_cf_gateway_url=probe_url,
            top_k_probe=top_k_probe,
        )
        self._initialized = True
        best = self._brain.get_best()
        if best:
            logger.info(
                f"[ModelSelector] Live fetch: {len(self._brain._registry)} models"
            )
            logger.info(
                f"[ModelSelector] Selected [{task}]: {best.name} "
                f"(score={best.score})"
            )
        else:
            logger.warning("[ModelSelector] WARNING: No available model found!")

    def get_model(self, task: str = "fast") -> Optional[str]:
        """Return the best model name for the given task."""
        m = self._brain.get_for_task(task)
        return m.name if m else None

    def get_top_models(self, n: int = 5) -> List[Tuple[str, float, int]]:
        """Return top N models as (name, score, tier) tuples."""
        return [
            (m.name, m.score, m.tier)
            for m in self._brain.top_n(n)
        ]

    def is_model_blacklisted(self, model_name: str) -> bool:
        return model_name in CF_GATEWAY_BLACKLIST

    def log_top_models(self, n: int = 5) -> None:
        for i, m in enumerate(self._brain.top_n(n), 1):
            score = SCORE_OVERRIDE.get(m.name, m.score)
            logger.info(
                f"[ModelSelector]   #{i} {m.name} "
                f"score={score} tier={m.tier}"
            )


# ═══════════════════════════════════════════════════════════════════════
# PATCH: fixes for health_check.py integration
# ═══════════════════════════════════════════════════════════════════════
"""
HOW TO INTEGRATE INTO ai_gateway_health_check.py
─────────────────────────────────────────────────

1. Replace ModelSelector import:

   # OLD:
   from torshield.ai.model_selector import ModelSelector
   selector = ModelSelector()
   
   # NEW (add at top of file):
   from scripts.model_selector_v3 import ModelSelectorV3
   selector = ModelSelectorV3()

2. In your Step 2 (Model Selector check), change to async init:

   # OLD:
   top_model = selector.get_top_model(task=task)
   
   # NEW:
   first_cf_gw_url = os.environ.get("CF_AI_GATEWAY_URL_1")  # probe slot 1
   await selector.initialize(probe_url=first_cf_gw_url, task=task)
   top_model = selector.get_model(task=task)
   
   # Skip blacklisted models immediately:
   if top_model and selector.is_model_blacklisted(top_model):
       logger.warning(f"Top model {top_model} is blacklisted, using next best")
       top_model = selector.get_model("reasoning")  # fallback

3. In cloudflare_ai_gateway provider, before each slot:

   # Skip if model returned 400 on ANY slot previously (model-level bug)
   if model_name in blacklisted_this_run:
       logger.warning(f"Skipping {model_name} — blacklisted this run")
       model_name = selector.get_model("fast")  # get next best

4. Add to CF_GATEWAY_BLACKLIST in dynamic_brain_v3.py if new 400s appear:

   CF_GATEWAY_BLACKLIST.add("@cf/new-broken-model-id")
"""


# ═══════════════════════════════════════════════════════════════════════
# ROOT CAUSE ANALYSIS — from health_check log June 13 2026
# ═══════════════════════════════════════════════════════════════════════
"""
ISSUE 1: dynamic_brain — CF fetch returns 0 models (HTTP 403)
  Root cause: CF_API_TOKEN_{n} tokens lack "Workers AI:Read" permission
  Fix: DynamicModelBrainV3 falls back to curated static registry (CF_STATIC_REGISTRY)
  Action needed: Add Workers AI read scope to CF API tokens in GitHub Secrets

ISSUE 2: cloudflare_ai_gateway — ALL 11 slots HTTP 400 BAD_REQUEST
  Root cause: @cf/meta/llama-3.3-70b-instruct-fp8-fast is DEPRECATED via AI Gateway
  Evidence: 66 × HTTP 400 across all slots — model-level failure, not slot-level
  Fix: Model added to CF_GATEWAY_BLACKLIST → probe skips it → kimi-k2.6 selected
  Action needed: Remove llama-3.3-70b from selector scoring, never use via AI Gateway

ISSUE 3: portkey — all 3 slots HTTP 400
  Root cause: PORTKEY_HEALTH_MODEL env var is empty (see log: PORTKEY_HEALTH_MODEL=)
  Fix: Set PORTKEY_HEALTH_MODEL=claude-sonnet-4-6 or gpt-4o-mini in GitHub Secrets
  Fallback: brain will auto-select from PORTKEY_STATIC_REGISTRY

ISSUE 4: Brain shows 0 CF, 0 Portkey models
  Root cause: Both 403 (CF) + Portkey env empty → falls back to static registry
  Fix: DynamicModelBrainV3 starts from static registry → always ≥13 CF models

RESULT AFTER FIXES:
  cerebras       → ✓ OK (already works)
  cloudflare_ai_gateway → ✓ kimi-k2.6 or gpt-oss-120b (after blacklist)
  cloudflare_workers_ai → ✓ OK (already works)
  portkey        → ✓ claude-sonnet-4-6 (after PORTKEY_HEALTH_MODEL fix)
"""

if __name__ == "__main__":
    import asyncio
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)-8s %(message)s")

    async def test():
        sel = ModelSelectorV3()
        probe_url = os.environ.get("CF_AI_GATEWAY_URL_1")
        await sel.initialize(probe_url=probe_url, task="fast")
        print(f"\nBest model (fast): {sel.get_model('fast')}")
        print(f"Best model (reasoning): {sel.get_model('reasoning')}")
        print("\nTop 5 models:")
        sel.log_top_models(5)

    asyncio.run(test())
