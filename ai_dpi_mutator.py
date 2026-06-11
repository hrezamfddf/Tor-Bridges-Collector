#!/usr/bin/env python3
"""
ai_dpi_mutator.py — Agentic AI DPI Self-Heal Loop (Stage 8j)

Reads data/dpi_intelligence.json produced by dpi_evasion_advanced.py.
If active blocking patterns are detected above the alert threshold, this
script autonomously mutates obfuscation parameters in the Go/Rust source
tree, triggering a recompile and committing the updated artefacts via the
GitHub API — zero human intervention required.

Detection -> Mutation -> Recompile -> Commit pipeline:
  1. Parse dpi_intelligence.json for blocking_score and active_patterns.
  2. Query eleven AI providers in priority order for consensus analysis.
  3. If consensus_score >= 0.60 or final blocking score >= ALERT_THRESHOLD,
     select mutation strategies recommended by the AI waterfall.
  4. Mutate: rotate obfs4 IAT mode, swap port lists, update JA3 seed.
  5. Run `go build` + `cargo build` to produce fresh binaries.
  6. Commit mutated source + binaries with [dpi-mutation] tag.
"""
from __future__ import annotations

import json
import logging
import os
import random
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import urllib.error
import urllib.request

log = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)-8s %(message)s",
)

ALERT_THRESHOLD  = 0.65
DPI_REPORT       = Path("data/dpi_intelligence.json")
MUTATION_LOG     = Path("data/mutation_history.json")
CONSENSUS_REPORT = Path("data/ai_consensus_report.json")

CANDIDATE_PORTS = [443, 8443, 2053, 2083, 2087, 2096, 8080, 1443]
OBFS4_IAT_MODES = [1, 2]

_DPI_REPORT_MAX_CHARS = 2000


# ── URL safety helper (BUG FIX v7.0) ──────────────────────────────────────────
# The "unknown url type: '***/openai/...'" error was caused by secrets being
# concatenated directly into URL strings.  This helper ensures every URL has
# a proper scheme before use.  Additive: does not remove or rename any
# existing function — only provides a safe accessor.
def _safe_base_url(env_var: str, default: str) -> str:
    """
    Return a full absolute URL from an env var.
    If the value doesn't start with http, fall back to default.
    Prevents 'unknown url type' errors when secrets store partial paths.
    """
    val = os.environ.get(env_var, "").strip().rstrip("/")
    if val and val.startswith("http"):
        return val
    return default.rstrip("/")


# ─────────────────────────────────────────────────────────────────────────────
# Prompt builder
# ─────────────────────────────────────────────────────────────────────────────

def _build_prompt(dpi_report: dict[str, Any]) -> str:
    report_text = json.dumps(dpi_report, ensure_ascii=False)
    if len(report_text) > _DPI_REPORT_MAX_CHARS:
        report_text = report_text[:_DPI_REPORT_MAX_CHARS] + "...[truncated]"
    return (
        "You are an expert in censorship circumvention and Tor network obfuscation, "
        "specifically for Iran's NIN (National Information Network) and SIAM DPI.\n\n"
        "Analyze the following DPI intelligence report and respond with a JSON "
        "object only. Do not include any explanation outside the JSON.\n\n"
        f"DPI Report:\n{report_text}\n\n"
        "Respond with exactly this JSON schema:\n"
        "{\n"
        '  "mutation_needed": true | false,\n'
        '  "confidence": 0.0 to 1.0,\n'
        '  "recommended_strategies": ["port_rotation"|"obfs4_iat_boost"|'
        '"ja3_randomize"|"none"],\n'
        '  "reasoning": "one sentence"\n'
        "}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# Existing helpers (unchanged)
# ─────────────────────────────────────────────────────────────────────────────

def _load_dpi_report() -> dict[str, Any]:
    if not DPI_REPORT.exists():
        log.warning("dpi_intelligence.json not found -- nothing to analyse.")
        return {}
    try:
        return json.loads(DPI_REPORT.read_text(encoding="utf-8"))
    except Exception as e:
        log.error("Cannot parse dpi_intelligence.json: %s", e)
        return {}


def _blocking_score(report: dict[str, Any]) -> float:
    for key in ("blocking_score", "iran_blocking_score", "dpi_score", "score"):
        val = report.get(key)
        if isinstance(val, (int, float)):
            return float(val)
    patterns = report.get("active_patterns", report.get("patterns", []))
    if isinstance(patterns, list) and patterns:
        return min(len(patterns) / 10.0, 1.0)
    return 0.0


def _mutate_go_ports(score: float) -> bool:
    target = Path("cmd/iran_tester/main.go")
    if not target.exists():
        return False
    src = target.read_text(encoding="utf-8")
    new_port = random.choice(CANDIDATE_PORTS)
    mutated = re.sub(
        r'var iranHighRiskPorts = map\[int\]bool\{[^}]+\}',
        f'var iranHighRiskPorts = map[int]bool{{{new_port}: true, 9001: true, 9030: true}}',
        src,
    )
    if mutated == src:
        log.info("Go port mutation: no pattern matched -- skipping.")
        return False
    target.write_text(mutated, encoding="utf-8")
    log.info("Mutated Go port list -- added port %d as preferred safe port.", new_port)
    return True


def _mutate_obfs4_iat(score: float) -> bool:
    targets = list(Path(".").rglob("*.py"))
    mutated_any = False
    iat_mode = random.choice(OBFS4_IAT_MODES)
    for path in targets:
        try:
            src = path.read_text(encoding="utf-8")
            if "iat-mode" not in src:
                continue
            new_src = re.sub(r'iat-mode=\d', f'iat-mode={iat_mode}', src)
            if new_src != src:
                path.write_text(new_src, encoding="utf-8")
                log.info("Mutated IAT mode to %d in %s", iat_mode, path)
                mutated_any = True
        except Exception:
            pass
    return mutated_any


def _rebuild_go() -> bool:
    for target, cmd_path in [("iran_tester", "./cmd/iran_tester/"),
                              ("probe_scheduler", "./cmd/probe_scheduler/")]:
        result = subprocess.run(
            ["go", "build", "-o", target, cmd_path],
            env={**os.environ, "CGO_ENABLED": "0", "GOOS": "linux"},
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode != 0:
            log.error("go build %s failed:\n%s", target, result.stderr)
            return False
        log.info("Rebuilt %s", target)
    return True


def _commit_mutation(strategy: str) -> bool:
    try:
        subprocess.run(["git", "config", "user.name", "dpi-mutator[bot]"],
                       check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email",
                        "dpi-mutator[bot]@users.noreply.github.com"],
                       check=True, capture_output=True)
        subprocess.run(["git", "add", "-A"], check=True, capture_output=True)
        diff = subprocess.run(["git", "diff", "--staged", "--quiet"],
                              capture_output=True)
        if diff.returncode == 0:
            log.info("Nothing to commit after mutation.")
            return True
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        msg = f"auto(dpi-mutation): {strategy} [{ts}] [skip ci]"
        subprocess.run(["git", "commit", "-m", msg], check=True, capture_output=True)
        subprocess.run(["git", "push"], check=True, capture_output=True)
        log.info("Mutation committed: %s", msg)
        return True
    except subprocess.CalledProcessError as e:
        log.error("Git commit failed: %s", e)
        return False


def _record_mutation(strategy: str, score: float) -> None:
    history: list[dict[str, Any]] = []
    if MUTATION_LOG.exists():
        try:
            history = json.loads(MUTATION_LOG.read_text(encoding="utf-8"))
        except Exception:
            pass
    history.append({
        "timestamp":      datetime.now(timezone.utc).isoformat(),
        "strategy":       strategy,
        "blocking_score": score,
    })
    MUTATION_LOG.write_text(
        json.dumps(history[-100:], indent=2, ensure_ascii=False), encoding="utf-8"
    )


# ─────────────────────────────────────────────────────────────────────────────
# AI provider helpers -- stdlib urllib only
# ─────────────────────────────────────────────────────────────────────────────

def _http_post(url: str, body: bytes, headers: dict[str, str]) -> bytes | None:
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read()
    except urllib.error.HTTPError as exc:
        log.warning("HTTP %d from %s: %s", exc.code, url, exc.reason)
    except urllib.error.URLError as exc:
        log.warning("URL error for %s: %s", url, exc.reason)
    except Exception as exc:
        log.warning("Request failed for %s: %s", url, exc)
    return None


def _parse_ai_json(text: str) -> dict[str, Any] | None:
    if not text:
        return None
    cleaned = re.sub(r"```(?:json)?", "", text).strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass
    m = re.search(r"\{[^{}]*\}", cleaned, re.DOTALL)
    if m:
        try:
            return json.loads(m.group())
        except json.JSONDecodeError:
            pass
    log.warning("Could not parse JSON from AI response (first 200 chars): %.200s", text)
    return None


def _call_claude_cloudflare(prompt: str) -> dict[str, Any] | None:
    """Provider 1 -- Claude Opus 4.8 via Cloudflare Workers AI."""
    cf_token      = os.environ.get("CF_API_TOKEN", "")
    cf_account_id = os.environ.get("CF_ACCOUNT_ID", "")
    if not cf_token or not cf_account_id:
        log.info("Provider 1 (Claude/CF): CF_API_TOKEN or CF_ACCOUNT_ID not set -- skip.")
        return None
    url = (
        f"https://api.cloudflare.com/client/v4/accounts/{cf_account_id}"
        "/ai/v1/messages"
    )
    payload = json.dumps({
        "model":      "anthropic/claude-opus-4.8",
        "max_tokens": 512,
        "messages":   [{"role": "user", "content": prompt}],
    }).encode()
    headers = {
        "Authorization": f"Bearer {cf_token}",
        "Content-Type":  "application/json",
    }
    raw = _http_post(url, payload, headers)
    if raw is None:
        return None
    try:
        data = json.loads(raw)
        text = data["content"][0]["text"]
        return _parse_ai_json(text)
    except Exception as exc:
        log.warning("Provider 1 (Claude/CF) response parse error: %s", exc)
        return None


def _call_gemini(prompt: str) -> dict[str, Any] | None:
    """Provider 2 -- Google Gemini 3.1 Pro."""
    api_key = os.environ.get("GEMINI_API_KEY", "")
    if not api_key:
        log.info("Provider 2 (Gemini): GEMINI_API_KEY not set -- skip.")
        return None
    url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"gemini-3.1-pro:generateContent?key={api_key}"
    )
    payload = json.dumps({
        "contents": [{"parts": [{"text": prompt}]}]
    }).encode()
    headers = {"Content-Type": "application/json"}
    raw = _http_post(url, payload, headers)
    if raw is None:
        return None
    try:
        data = json.loads(raw)
        text = data["candidates"][0]["content"]["parts"][0]["text"]
        return _parse_ai_json(text)
    except Exception as exc:
        log.warning("Provider 2 (Gemini) response parse error: %s", exc)
        return None


def _call_openai_compat(
    endpoint: str,
    api_key: str,
    model: str,
    prompt: str,
    extra_headers: dict[str, str] | None = None,
) -> dict[str, Any] | None:
    """Generic caller for all OpenAI-compatible providers (Providers 3-11)."""
    if not api_key:
        return None
    payload = json.dumps({
        "model":      model,
        "messages":   [{"role": "user", "content": prompt}],
        "max_tokens": 512,
    }).encode()
    headers: dict[str, str] = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type":  "application/json",
    }
    if extra_headers:
        headers.update(extra_headers)
    raw = _http_post(endpoint, payload, headers)
    if raw is None:
        return None
    try:
        data = json.loads(raw)
        text = data["choices"][0]["message"]["content"]
        return _parse_ai_json(text)
    except Exception as exc:
        log.warning("OpenAI-compat response parse error (%s): %s", endpoint, exc)
        return None




def _cf_gw_url(provider_slug: str, path: str) -> str:
    """Build a Cloudflare AI Gateway URL if CF_AI_GATEWAY_URL is configured.

    CF_AI_GATEWAY_URL format (set in GitHub Actions Secrets):
        https://gateway.ai.cloudflare.com/v1/{account_id}/{gateway_name}

    Supported provider slugs: groq, deepseek, mistral, huggingface, openai
    Returns direct provider URL if CF_AI_GATEWAY_URL is not set.

    BUG FIX v7.0: Uses _safe_base_url() to validate the URL scheme,
    preventing 'unknown url type' errors when the secret stores only a path.
    """
    base = _safe_base_url("CF_AI_GATEWAY_URL", "")
    if not base:
        return ""
    return f"{base}/{provider_slug}/{path}"


def _call_cerebras(prompt: str, model: str = "llama3.1-70b") -> dict[str, Any] | None:
    """Provider: Cerebras ultra-high-speed inference.

    Free tier: generous rate limits, sub-100ms TTFT on 70B models.
    Models: llama3.1-70b, llama3.1-8b, qwen-2.5-72b
    Env: CEREBRAS_API_KEY
    """
    api_key = os.environ.get("CEREBRAS_API_KEY", "")
    if not api_key:
        log.info("Cerebras (%s): CEREBRAS_API_KEY not set -- skip.", model)
        return None
    return _call_openai_compat(
        "https://api.cerebras.ai/v1/chat/completions",
        api_key, model, prompt,
    )


def _call_portkey(
    provider: str,
    model: str,
    prompt: str,
    provider_api_key: str = "",
) -> dict[str, Any] | None:
    """Route through Portkey.ai unified AI gateway.

    Portkey provides smart load-balancing, automatic retries with
    exponential back-off, rate-limit bypass via virtual key rotation,
    and a persistent fallback chain (Cerebras → Groq → OpenRouter).
    Acts as the master orchestrator for all AI provider calls.

    Architecture:
        GitHub Actions → Portkey.ai → {provider}
        If CF_AI_GATEWAY_URL is set, Portkey is additionally cached
        at Cloudflare's edge:
        GitHub Actions → CF AI Gateway → Portkey.ai → {provider}

    Env: PORTKEY_API_KEY, provider's own key, CF_AI_GATEWAY_URL (optional)
    """
    portkey_key = os.environ.get("PORTKEY_API_KEY", "")
    if not portkey_key:
        log.info("Portkey/%s: PORTKEY_API_KEY not set -- skip.", provider)
        return None

    # Optionally route through CF AI Gateway for edge caching
    # BUG FIX v7.0: Use _safe_base_url() to validate CF_AI_GATEWAY_URL scheme
    cf_gw = _safe_base_url("CF_AI_GATEWAY_URL", "")
    if cf_gw:
        # Route Portkey itself through CF AI Gateway universal endpoint
        url = f"{cf_gw}/openai/v1/chat/completions"
    else:
        # BUG FIX v7.0: Use _safe_base_url() to validate PORTKEY base URL
        portkey_base = _safe_base_url("PORTKEY_GATEWAY_URL", "https://api.portkey.ai/v1")
        url = f"{portkey_base}/chat/completions"

    payload = json.dumps({
        "model":      model,
        "messages":   [{"role": "user", "content": prompt}],
        "max_tokens": 512,
    }).encode()

    headers: dict[str, str] = {
        "Content-Type":       "application/json",
        "x-portkey-api-key":  portkey_key,
        "x-portkey-provider": provider,
    }
    if provider_api_key:
        headers["Authorization"] = f"Bearer {provider_api_key}"

    raw = _http_post(url, payload, headers)
    if raw is None:
        return None
    try:
        data = json.loads(raw)
        text = data["choices"][0]["message"]["content"]
        return _parse_ai_json(text)
    except Exception as exc:
        log.warning("Portkey/%s parse error: %s", provider, exc)
        return None

def _query_ai_providers(dpi_report: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Calls all eleven providers in priority order.
    Never raises an exception under any condition.
    Returns a list of parsed AI response dicts (may be empty).
    """
    prompt = _build_prompt(dpi_report)
    responses: list[dict[str, Any]] = []

    cf_account_id = os.environ.get("CF_ACCOUNT_ID", "_missing_account_id")

    providers: list[tuple[str, Any, tuple[Any, ...]]] = [
        # ── Tier 0: Portkey AI Gateway (master orchestrator, auto-retry) ──────
        # Portkey routes internally: Cerebras → Groq → OpenRouter on failure
        ("Provider P0a -- Portkey/Cerebras-Llama-70B",
         _call_portkey, ("cerebras", "llama3.1-70b", prompt,
                         os.environ.get("CEREBRAS_API_KEY", ""))),
        ("Provider P0b -- Portkey/Cerebras-Qwen-72B",
         _call_portkey, ("cerebras", "qwen-2.5-72b", prompt,
                         os.environ.get("CEREBRAS_API_KEY", ""))),
        ("Provider P0c -- Portkey/Groq-Llama-70B",
         _call_portkey, ("groq", "llama-3.3-70b-versatile", prompt,
                         os.environ.get("GROQ_API_KEY", ""))),
        ("Provider P0d -- Portkey/DeepSeek-R1",
         _call_portkey, ("deepseek", "deepseek-reasoner", prompt,
                         os.environ.get("DEEPSEEK_API_KEY", ""))),
        # ── Tier 1: Cerebras direct (sub-100ms inference, generous free tier) ─
        ("Provider P1a -- Cerebras/Llama-3.1-70B",
         _call_cerebras, (prompt, "llama3.1-70b")),
        ("Provider P1b -- Cerebras/Qwen-2.5-72B",
         _call_cerebras, (prompt, "qwen-2.5-72b")),
        # ── Tier 2: Primary provider pool (via CF AI Gateway edge cache) ──────
        ("Provider 1 -- Claude/CF-Workers-AI",
         _call_claude_cloudflare, (prompt,)),
        ("Provider 2 -- Gemini-3.1-Pro",
         _call_gemini, (prompt,)),
        ("Provider 3 -- DeepSeek-R1",
         _call_openai_compat, (
             _cf_gw_url("deepseek", "v1/chat/completions")
             or "https://api.deepseek.com/v1/chat/completions",
             os.environ.get("DEEPSEEK_API_KEY", ""),
             "deepseek-reasoner", prompt,
         )),
        ("Provider 4 -- DeepSeek-V3",
         _call_openai_compat, (
             _cf_gw_url("deepseek", "v1/chat/completions")
             or "https://api.deepseek.com/v1/chat/completions",
             os.environ.get("DEEPSEEK_API_KEY", ""),
             "deepseek-chat", prompt,
         )),
        ("Provider 5 -- Qwen3-Coder-480B",
         _call_openai_compat, (
             "https://api.hyperbolic.xyz/v1/chat/completions",
             os.environ.get("HYPERBOLIC_API_KEY", ""),
             "Qwen/Qwen3-Coder-480B-A35B-Instruct", prompt,
         )),
        ("Provider 6 -- Llama-3.3-70B-Hyperbolic",
         _call_openai_compat, (
             "https://api.hyperbolic.xyz/v1/chat/completions",
             os.environ.get("HYPERBOLIC_API_KEY", ""),
             "llama-3.3-70b-instruct-fp8-fast", prompt,
         )),
        ("Provider 7 -- Groq-Llama-3.3-70B",
         _call_openai_compat, (
             _cf_gw_url("groq", "openai/v1/chat/completions")
             or "https://api.groq.com/openai/v1/chat/completions",
             os.environ.get("GROQ_API_KEY", ""),
             "llama-3.3-70b-versatile", prompt,
         )),
        ("Provider 8 -- Groq-Llama-3-70B",
         _call_openai_compat, (
             _cf_gw_url("groq", "openai/v1/chat/completions")
             or "https://api.groq.com/openai/v1/chat/completions",
             os.environ.get("GROQ_API_KEY", ""),
             "llama3-70b-8192", prompt,
         )),
        ("Provider 9 -- Qwen2.5-Coder-32B-HuggingFace",
         _call_openai_compat, (
             "https://api-inference.huggingface.co/models/"
             "Qwen/Qwen2.5-Coder-32B-Instruct/v1/chat/completions",
             os.environ.get("HUGGINGFACE_API_KEY", ""),
             "Qwen/Qwen2.5-Coder-32B-Instruct", prompt,
         )),
        ("Provider 10 -- Mistral-Large-2",
         _call_openai_compat, (
             _cf_gw_url("mistral", "v1/chat/completions")
             or "https://api.mistral.ai/v1/chat/completions",
             os.environ.get("MISTRAL_API_KEY", ""),
             "mistral-large-latest", prompt,
         )),
        ("Provider 11 -- Cloudflare-Llama",
         _call_openai_compat, (
             f"https://api.cloudflare.com/client/v4/accounts/{cf_account_id}"
             "/ai/run/@cf/meta/llama-3.3-70b-instruct-fp8-fast",
             os.environ.get("CF_API_TOKEN", ""),
             "@cf/meta/llama-3.3-70b-instruct-fp8-fast", prompt,
         )),
    ]

    for name, fn, args in providers:
        try:
            log.info("Querying %s...", name)
            result = fn(*args)
            if result is not None:
                result["_provider"] = name
                responses.append(result)
                log.info(
                    "%s -> mutation_needed=%s confidence=%.2f",
                    name,
                    result.get("mutation_needed"),
                    result.get("confidence", 0.0),
                )
            else:
                log.info("%s -> no response (skipped or failed).", name)
        except Exception as exc:
            log.warning("%s raised an unexpected exception: %s -- continuing.", name, exc)

    log.info(
        "AI waterfall complete: %d/%d providers responded.",
        len(responses), len(providers),
    )
    return responses


def _compute_consensus(
    responses: list[dict[str, Any]],
) -> tuple[float, list[str]]:
    """
    Compute consensus score and strategy union from provider responses.
    Returns (consensus_score, strategies).
    Returns (0.0, []) if responses is empty or all are invalid.
    """
    if not responses:
        return 0.0, []

    mutation_responses = [
        r for r in responses
        if r.get("mutation_needed") is True
        and isinstance(r.get("confidence"), (int, float))
    ]

    if not mutation_responses:
        return 0.0, []

    consensus_score = sum(
        float(r["confidence"]) for r in mutation_responses
    ) / len(mutation_responses)

    strategies: set[str] = set()
    for r in mutation_responses:
        for s in r.get("recommended_strategies", []):
            if isinstance(s, str) and s != "none":
                strategies.add(s)

    return round(consensus_score, 4), sorted(strategies)


def _save_consensus_report(
    responses: list[dict[str, Any]],
    score: float,
    strategies: list[str],
) -> None:
    """Write data/ai_consensus_report.json with full provider breakdown."""
    Path("data").mkdir(parents=True, exist_ok=True)
    triggered = (
        score >= 0.60
        or sum(1 for r in responses if r.get("mutation_needed") is True) >= 2
    )
    report: dict[str, Any] = {
        "generated_at":        datetime.now(timezone.utc).isoformat(),
        "provider_count":      len(responses),
        "consensus_score":     score,
        "selected_strategies": strategies,
        "mutation_triggered":  triggered,
        "individual_responses": responses,
    }
    CONSENSUS_REPORT.write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    log.info(
        "AI consensus report written -> %s (score=%.4f, strategies=%s)",
        CONSENSUS_REPORT, score, strategies,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> int:
    # Step 1: Load DPI report
    report = _load_dpi_report()
    if not report:
        log.info("DPI report unavailable -- mutator is a no-op this run.")
        _save_consensus_report([], 0.0, [])
        return 0

    local_score = _blocking_score(report)
    log.info(
        "Local DPI blocking score: %.3f (alert threshold: %.2f)",
        local_score, ALERT_THRESHOLD,
    )

    # Step 2: Query eleven AI providers
    responses = _query_ai_providers(report)

    # Step 3: Compute consensus
    ai_score, ai_strategies = _compute_consensus(responses)
    log.info("AI consensus score: %.4f  strategies: %s", ai_score, ai_strategies)

    # Step 4: Determine final score
    final_score = max(local_score, ai_score)
    log.info("Final score: %.4f", final_score)

    # Step 5: Save consensus report
    _save_consensus_report(responses, ai_score, ai_strategies)

    # Step 6: Handle all-provider failure
    if not responses:
        log.warning("All eleven AI providers failed -- writing failure log.")
        history: list[dict[str, Any]] = []
        if MUTATION_LOG.exists():
            try:
                history = json.loads(MUTATION_LOG.read_text(encoding="utf-8"))
            except Exception:
                pass
        history.append({
            "timestamp":   datetime.now(timezone.utc).isoformat(),
            "event":       "ai_waterfall_failure",
            "local_score": local_score,
            "final_score": final_score,
        })
        MUTATION_LOG.write_text(
            json.dumps(history[-100:], indent=2, ensure_ascii=False), encoding="utf-8"
        )
        if final_score < ALERT_THRESHOLD:
            log.info("Local score below threshold -- no mutation required.")
            return 0

    # Step 7: Check whether mutation is warranted
    ai_triggered = (
        ai_score >= 0.60
        or sum(1 for r in responses if r.get("mutation_needed") is True) >= 2
    )
    if final_score < ALERT_THRESHOLD and not ai_triggered:
        log.info("Score below threshold and AI consensus not triggered -- no mutation.")
        return 0

    log.warning(
        "Active DPI blocking detected (final_score=%.3f, ai_score=%.3f) "
        "-- initiating mutation.",
        final_score, ai_score,
    )

    # Step 8: Run mutation strategies (AI union + local fallback)
    local_strategy_fns: dict[str, Any] = {
        "port_rotation":   _mutate_go_ports,
        "obfs4_iat_boost": _mutate_obfs4_iat,
    }
    run_strategies: set[str] = set(ai_strategies)
    if final_score >= ALERT_THRESHOLD:
        run_strategies.update({"port_rotation", "obfs4_iat_boost"})

    applied: list[str] = []
    for name, fn in local_strategy_fns.items():
        if name not in run_strategies:
            continue
        try:
            if fn(final_score):
                applied.append(name)
                log.info("Applied mutation: %s", name)
        except Exception as exc:
            log.warning("Mutation %s failed: %s", name, exc)

    if not applied:
        log.info("No mutations applied (patterns did not match source).")
        return 0

    strategy_desc = "+".join(applied)

    if _rebuild_go():
        log.info("Recompile successful after mutation.")
    else:
        log.warning("Recompile failed; committing source changes only.")

    _record_mutation(strategy_desc, final_score)
    _commit_mutation(strategy_desc)

    log.info("AI DPI mutator complete. Applied: %s", strategy_desc)
    return 0


if __name__ == "__main__":
    sys.exit(main())
