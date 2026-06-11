"""
Provider implementations v9.0: Portkey.ai, Cerebras.ai,
Cloudflare Workers AI, Cloudflare AI Gateway.

CHANGES IN v9.0:
  - Dynamic model selection via CloudflareModelSelector.
  - CF providers now call model_selector.best_model(task=...) at call-time.
  - Task routing: "reasoning" → deepseek/qwq, "coding" → deepseek/phi,
                  "vision" → llama-vision, "fast" → 8b/3b, "general" → best.
  - CF_STABLE_MODELS kept as last-resort offline fallback.
  - All other behaviour (slot rotation, circuit breaker, latency EMA)
    unchanged from v8.0.

SECURITY NOTE (preserved from v7.0):
  - NEVER inject a secret as a path component of a URL.
  - CF_AI_GATEWAY_URL_{i} must be a full absolute URL.
  - Validated at runtime: must start with 'https://'.
"""

import os
import json
import time
import logging
import urllib.request
import urllib.error
from typing import Optional, List, Dict, Any
from .rotator import AccountRotator, AccountSlot, build_rotator_from_env
from .model_selector import CloudflareModelSelector, best_cf_model

logger = logging.getLogger("torshield.ai.providers")

# Number of Cloudflare slots
CF_N_SLOTS = 11

# Guaranteed free-tier fallbacks (used only when model selector fails entirely)
CF_STABLE_MODELS = [
    "@cf/meta/llama-3.1-8b-instruct",
    "@cf/meta/llama-3.2-11b-vision-instruct",
    "@cf/mistral/mistral-7b-instruct-v0.1",
]


def _validate_url(url: str, label: str) -> str:
    if not url.startswith("https://"):
        raise ValueError(
            f"[{label}] Invalid URL '{url[:40]}': must be absolute HTTPS."
        )
    return url.rstrip("/")


class _BaseProvider:
    name: str = "base"
    MAX_RETRIES: int = 4

    def chat_complete(
        self,
        messages:    List[Dict[str, str]],
        model:       Optional[str] = None,
        max_tokens:  int = 2048,
        temperature: float = 0.2,
        timeout:     int = 60,
        task:        str = "general",
    ) -> str:
        raise NotImplementedError

    @staticmethod
    def _post_json(
        url: str, headers: dict, payload: dict, timeout: int
    ) -> tuple[dict, float]:
        t0   = time.monotonic()
        data = json.dumps(payload).encode("utf-8")
        req  = urllib.request.Request(url, data=data, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            result = json.loads(resp.read().decode("utf-8"))
        latency_ms = (time.monotonic() - t0) * 1000.0
        return result, latency_ms

    @staticmethod
    def _extract_text(response: dict) -> str:
        try:
            return response["choices"][0]["message"]["content"].strip()
        except (KeyError, IndexError):
            pass
        try:
            return response["result"]["response"].strip()
        except (KeyError, TypeError):
            pass
        return str(response)


# ── Portkey ────────────────────────────────────────────────────────────────────

class PortkeyProvider(_BaseProvider):
    name          = "portkey"
    DEFAULT_MODEL = "llama3-70b-8192"

    def __init__(self):
        self.rotator = build_rotator_from_env("PORTKEY", n_accounts=3)
        raw_url = os.environ.get("PORTKEY_GATEWAY_URL", "https://api.portkey.ai/v1")
        if not raw_url.startswith("http"):
            raw_url = "https://api.portkey.ai/v1"
        self.gateway_url = raw_url.rstrip("/")

    def chat_complete(
        self, messages, model=None, max_tokens=2048, temperature=0.2,
        timeout=60, task="general"
    ) -> str:
        model    = model or self.DEFAULT_MODEL
        slot     = self.rotator.get_primary()
        fallbacks = [slot] + self.rotator.get_fallback_chain(slot.index)

        for attempt, s in enumerate(fallbacks):
            try:
                url     = f"{self.gateway_url}/chat/completions"
                headers = {
                    "Content-Type":       "application/json",
                    "x-portkey-api-key":  s.api_key,
                    "x-portkey-provider": "openai",
                }
                payload = {
                    "model":       model,
                    "messages":    messages,
                    "max_tokens":  max_tokens,
                    "temperature": temperature,
                }
                resp, lat = self._post_json(url, headers, payload, timeout)
                self.rotator.mark_success(s, lat)
                return self._extract_text(resp)
            except urllib.error.HTTPError as e:
                logger.warning(f"[Portkey] slot {s.index} HTTP {e.code}: {e.reason}")
                self.rotator.mark_failure(s)
                if attempt == len(fallbacks) - 1:
                    raise
                time.sleep(2 ** attempt)
        return ""


# ── Cerebras ───────────────────────────────────────────────────────────────────

class CerebrasProvider(_BaseProvider):
    name          = "cerebras"
    BASE_URL      = "https://api.cerebras.ai/v1"
    DEFAULT_MODEL = "llama-3.3-70b"

    def __init__(self):
        self.rotator = build_rotator_from_env("CEREBRAS", n_accounts=3)

    def chat_complete(
        self, messages, model=None, max_tokens=2048, temperature=0.2,
        timeout=60, task="general"
    ) -> str:
        model     = model or self.DEFAULT_MODEL
        slot      = self.rotator.get_primary()
        fallbacks = [slot] + self.rotator.get_fallback_chain(slot.index)

        for attempt, s in enumerate(fallbacks):
            try:
                url     = f"{self.BASE_URL}/chat/completions"
                headers = {
                    "Content-Type":  "application/json",
                    "Authorization": f"Bearer {s.api_key}",
                }
                payload = {
                    "model":       model,
                    "messages":    messages,
                    "max_tokens":  max_tokens,
                    "temperature": temperature,
                    "stream":      False,
                }
                resp, lat = self._post_json(url, headers, payload, timeout)
                self.rotator.mark_success(s, lat)
                return self._extract_text(resp)
            except urllib.error.HTTPError as e:
                logger.warning(f"[Cerebras] slot {s.index} HTTP {e.code}: {e.reason}")
                self.rotator.mark_failure(s)
                if attempt == len(fallbacks) - 1:
                    raise
                time.sleep(2 ** attempt)
        return ""


# ── Cloudflare Workers AI (direct) ────────────────────────────────────────────

class CloudflareWorkersAIProvider(_BaseProvider):
    """
    Cloudflare Workers AI — direct API with dynamic model selection.
    Model is resolved at call-time via CloudflareModelSelector.
    """
    name = "cloudflare_workers_ai"

    def __init__(self):
        slots = []
        for i in range(1, CF_N_SLOTS + 1):
            acct_id   = os.environ.get(f"CF_ACCOUNT_ID_{i}", "")
            api_token = os.environ.get(f"CF_API_TOKEN_{i}", "")
            if acct_id and api_token:
                slots.append(
                    AccountSlot(index=i, account_id=acct_id, api_key=api_token)
                )
        if not slots:
            raise ValueError(
                "[CloudflareWorkersAI] No CF accounts configured."
            )
        self.rotator = AccountRotator("cloudflare_workers_ai", slots)
        self._selector = CloudflareModelSelector.instance()

    def _resolve_model(self, model: Optional[str], task: str) -> str:
        """Return model to use: explicit > dynamic selection > stable fallback."""
        if model:
            return model
        try:
            selected = self._selector.best_model(task=task, probe=False)
            logger.debug(f"[CF-Workers-AI] Dynamic model [{task}]: {selected}")
            return selected
        except Exception as exc:
            logger.warning(f"[CF-Workers-AI] Model selector error: {exc}; using fallback")
            return CF_STABLE_MODELS[0]

    def chat_complete(
        self, messages, model=None, max_tokens=2048, temperature=0.2,
        timeout=60, task="general"
    ) -> str:
        chosen_model = self._resolve_model(model, task)

        slot      = self.rotator.get_primary()
        fallbacks = [slot] + self.rotator.get_fallback_chain(slot.index)

        # Build fallback model chain: chosen → stable models
        models_to_try = [chosen_model] + [m for m in CF_STABLE_MODELS if m != chosen_model]

        for attempt, s in enumerate(fallbacks):
            last_err = None
            for m in models_to_try:
                try:
                    url = (
                        "https://api.cloudflare.com/client/v4/accounts/"
                        f"{s.account_id}/ai/run/{m}"
                    )
                    headers = {
                        "Content-Type":  "application/json",
                        "Authorization": f"Bearer {s.api_key}",
                    }
                    payload = {
                        "messages":    messages,
                        "max_tokens":  max_tokens,
                        "temperature": temperature,
                        "stream":      False,
                    }
                    resp, lat = self._post_json(url, headers, payload, timeout)
                    self.rotator.mark_success(s, lat)
                    return self._extract_text(resp)
                except urllib.error.HTTPError as e:
                    last_err = e
                    if e.code == 404:
                        logger.debug(f"[CF-Workers-AI] Model not found: {m}")
                        continue
                    raise
            if last_err:
                logger.warning(f"[CF-Workers-AI] slot {s.index} all models failed")
                self.rotator.mark_failure(s)
                if attempt == len(fallbacks) - 1:
                    raise last_err  # type: ignore[misc]
                time.sleep(2 ** attempt)
        return ""


# ── Cloudflare AI Gateway (proxy layer) ───────────────────────────────────────

class CloudflareAIGatewayProvider(_BaseProvider):
    """
    Cloudflare AI Gateway — proxy layer with caching and dynamic model selection.
    11 gateway slots × free quota = 11× effective throughput.
    Model resolved dynamically via CloudflareModelSelector.
    """
    name = "cloudflare_ai_gateway"

    def __init__(self):
        slots = []
        for i in range(1, CF_N_SLOTS + 1):
            acct_id     = os.environ.get(f"CF_ACCOUNT_ID_{i}", "")
            api_token   = os.environ.get(f"CF_API_TOKEN_{i}", "")
            gateway_url = os.environ.get(f"CF_AI_GATEWAY_URL_{i}", "")
            if not (acct_id and api_token and gateway_url):
                continue
            try:
                gateway_url = _validate_url(gateway_url, f"CF_AI_GATEWAY_URL_{i}")
            except ValueError as e:
                logger.error(str(e))
                continue
            slots.append(
                AccountSlot(
                    index=i,
                    account_id=acct_id,
                    api_key=api_token,
                    gateway_url=gateway_url,
                )
            )
        if not slots:
            raise ValueError(
                "[CF-AI-Gateway] No gateway slots configured."
            )
        self.rotator  = AccountRotator("cloudflare_ai_gateway", slots)
        self._selector = CloudflareModelSelector.instance()

    def _resolve_model(self, model: Optional[str], task: str) -> str:
        if model:
            return model
        try:
            selected = self._selector.best_model(task=task, probe=False)
            logger.debug(f"[CF-AI-GW] Dynamic model [{task}]: {selected}")
            return selected
        except Exception as exc:
            logger.warning(f"[CF-AI-GW] Model selector error: {exc}; using fallback")
            return CF_STABLE_MODELS[0]

    def chat_complete(
        self, messages, model=None, max_tokens=2048, temperature=0.2,
        timeout=60, task="general"
    ) -> str:
        chosen_model = self._resolve_model(model, task)

        slot      = self.rotator.get_primary()
        fallbacks = [slot] + self.rotator.get_fallback_chain(slot.index)

        models_to_try = [chosen_model] + [m for m in CF_STABLE_MODELS if m != chosen_model]

        for attempt, s in enumerate(fallbacks):
            last_err = None
            for m in models_to_try:
                try:
                    url = f"{s.gateway_url}/workers-ai/{m}"
                    headers = {
                        "Content-Type":  "application/json",
                        "Authorization": f"Bearer {s.api_key}",
                    }
                    payload = {
                        "messages":    messages,
                        "max_tokens":  max_tokens,
                        "temperature": temperature,
                    }
                    resp, lat = self._post_json(url, headers, payload, timeout)
                    self.rotator.mark_success(s, lat)
                    return self._extract_text(resp)
                except urllib.error.HTTPError as e:
                    last_err = e
                    if e.code == 404:
                        logger.debug(f"[CF-AI-GW] Model not found: {m}")
                        continue
                    logger.warning(
                        f"[CF-AI-GW] slot {s.index} "
                        f"URL={s.gateway_url[:40]}... HTTP {e.code}"
                    )
                    raise
            if last_err:
                logger.warning(f"[CF-AI-GW] slot {s.index} all models failed")
                self.rotator.mark_failure(s)
                if attempt == len(fallbacks) - 1:
                    raise last_err  # type: ignore[misc]
                time.sleep(2 ** attempt)
        return ""
