#!/usr/bin/env python3
"""
auto_debugger_v2.py — AI-Powered Provider Auto-Debugger v2.0
═══════════════════════════════════════════════════════════════════════════════

Automatically diagnoses ALL provider failures without human intervention.
Runs as a GitHub Actions step BEFORE the health check to pre-validate, and
AFTER to explain any remaining issues with specific, actionable fixes.

WHAT IT DOES:
  ─ Probes each provider's endpoint connectivity
  ─ Validates API key formats and lengths
  ─ Tests CF AI Gateway with a minimal request to capture the real 400 body
  ─ Tests Portkey routing with multiple strategies
  ─ Generates a machine-readable diagnosis report (JSON)
  ─ Logs human-readable fix instructions (GitHub Actions step summary)

VERSION HISTORY:
  v1.0 (Fix-16.0) — initial auto-debug system
  v2.0 (Fix-19.0) — enhanced CF AI Gateway diagnosis, Portkey strategy probe,
                     ProviderConfigurationError detection, gateway slug validator

Zero external dependencies — uses only Python stdlib (urllib, json, os, logging).
"""

from __future__ import annotations

import os
import re
import json
import time
import logging
import hashlib
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("torshield.auto_debug_v2")

# ─────────────────────────────────────────────────────────────────────────────
# 1.  DIAGNOSIS DATA STRUCTURES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ProviderDiagnosis:
    provider:    str
    status:      str          # "ok", "config_error", "auth_error", "network_error", "unknown"
    root_cause:  str = ""
    fixes:       List[str] = field(default_factory=list)
    raw_body:    str = ""     # actual HTTP response body (for 400 errors)
    latency_ms:  float = 0.0
    tested_at:   float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return {
            "provider":   self.provider,
            "status":     self.status,
            "root_cause": self.root_cause,
            "fixes":      self.fixes,
            "raw_body":   self.raw_body[:300] if self.raw_body else "",
            "latency_ms": round(self.latency_ms, 1),
            "tested_at":  self.tested_at,
        }


@dataclass
class AutoDebugReport:
    run_id:      str
    timestamp:   float = field(default_factory=time.time)
    diagnoses:   List[ProviderDiagnosis] = field(default_factory=list)
    summary:     str = ""
    all_healthy: bool = False

    def to_dict(self) -> dict:
        return {
            "run_id":      self.run_id,
            "timestamp":   self.timestamp,
            "diagnoses":   [d.to_dict() for d in self.diagnoses],
            "summary":     self.summary,
            "all_healthy": self.all_healthy,
        }


# ─────────────────────────────────────────────────────────────────────────────
# 2.  MINIMAL HTTP HELPERS
# ─────────────────────────────────────────────────────────────────────────────

_UA = "TorShield-AutoDebug/2.0"
_PROBE_TIMEOUT = 12

def _post(url: str, headers: dict, payload: dict, timeout: int = _PROBE_TIMEOUT) -> Tuple[int, str]:
    """POST JSON payload to url. Returns (http_status, response_body)."""
    data = json.dumps(payload).encode("utf-8")
    req  = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, body
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            body = f"<unreadable: {e}>"
        return e.code, body
    except urllib.error.URLError as e:
        return 0, f"URLError: {e.reason}"
    except Exception as e:
        return 0, f"Exception: {e}"


def _get(url: str, headers: dict, timeout: int = _PROBE_TIMEOUT) -> Tuple[int, str]:
    """GET url. Returns (http_status, response_body)."""
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, body
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            body = f"<unreadable: {e}>"
        return e.code, body
    except urllib.error.URLError as e:
        return 0, f"URLError: {e.reason}"
    except Exception as e:
        return 0, f"Exception: {e}"


# ─────────────────────────────────────────────────────────────────────────────
# 3.  CLOUDFLARE AI GATEWAY DIAGNOSTICS
# ─────────────────────────────────────────────────────────────────────────────

_CF_GATEWAY_PATTERN = re.compile(
    r"https://gateway\.ai\.cloudflare\.com/v1/"
    r"(?P<account_id>[a-f0-9]{32})/"
    r"(?P<slug>[^/]+)"
)
_MINIMAL_MODEL  = "@cf/meta/llama-3.1-8b-instruct"
_MINIMAL_PROMPT = [{"role": "user", "content": "Hi"}]


def _diagnose_cf_ai_gateway(n_slots: int = 11) -> ProviderDiagnosis:
    """
    Run targeted diagnostics on the CF AI Gateway provider.

    Tests slot 1 first with a minimal model and logs the FULL 400 response body.
    This reveals the actual CF error (e.g., "Unknown AI Gateway: slug" or
    "Workers AI permission required") so the user knows exactly what to fix.
    """
    diag = ProviderDiagnosis(provider="cloudflare_ai_gateway", status="unknown")

    # Load all slots
    slots = []
    for i in range(1, n_slots + 1):
        acct_id   = os.environ.get(f"CF_ACCOUNT_ID_{i}",      "").strip()
        api_token = os.environ.get(f"CF_API_TOKEN_{i}",       "").strip()
        gw_url    = os.environ.get(f"CF_AI_GATEWAY_URL_{i}",  "").strip()
        gw_token  = os.environ.get(f"CF_AI_GATEWAY_TOKEN_{i}", "").strip()
        if acct_id and api_token and gw_url:
            slots.append((i, acct_id, api_token, gw_url, gw_token))

    if not slots:
        diag.status     = "config_error"
        diag.root_cause = "No CF AI Gateway slots configured"
        diag.fixes      = ["Set CF_ACCOUNT_ID_1, CF_API_TOKEN_1, CF_AI_GATEWAY_URL_1 in GitHub Secrets"]
        return diag

    # Test first 3 slots and collect actual error bodies
    error_bodies: List[str] = []
    for slot_n, acct_id, api_token, gw_url, gw_token in slots[:3]:
        # Normalize gateway URL
        base_url = gw_url.rstrip("/")
        for sfx in ["/workers-ai/v1/chat/completions", "/workers-ai/v1", "/workers-ai"]:
            if base_url.endswith(sfx):
                base_url = base_url[:-len(sfx)]
                break
        endpoint = f"{base_url}/workers-ai/v1/chat/completions"

        # Validate URL structure
        m = _CF_GATEWAY_PATTERN.match(base_url)
        if not m:
            diag.fixes.append(
                f"Slot {slot_n}: CF_AI_GATEWAY_URL format wrong. "
                f"Expected: https://gateway.ai.cloudflare.com/v1/{{32-char-account-id}}/{{gateway-slug}}"
            )
            continue

        slug       = m.group("slug")
        url_acct   = m.group("account_id")
        acct_match = url_acct == acct_id.lower()[:32]

        if not acct_match:
            diag.fixes.append(
                f"Slot {slot_n}: account ID in URL ({url_acct[:8]}...) "
                f"doesn't match CF_ACCOUNT_ID_{slot_n} ({acct_id[:8]}...)"
            )

        t0 = time.time()
        headers = {
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {api_token}",
            "User-Agent":    _UA,
        }
        if gw_token:
            headers["cf-aig-authorization"] = f"Bearer {gw_token}"

        status, body = _post(
            endpoint,
            headers,
            {"model": _MINIMAL_MODEL, "messages": _MINIMAL_PROMPT, "max_tokens": 5},
        )
        latency = (time.time() - t0) * 1000

        logger.info(
            f"[AutoDebug-CF-GW] slot {slot_n} slug='{slug}' → "
            f"HTTP {status} ({latency:.0f}ms)"
        )
        if body:
            logger.warning(f"[AutoDebug-CF-GW] slot {slot_n} response body: {body[:400]}")
            error_bodies.append(body[:400])

        if status == 200:
            diag.status     = "ok"
            diag.root_cause = f"Slot {slot_n} responded OK ({latency:.0f}ms)"
            return diag

        if status == 400:
            body_lower = body.lower()
            if "unknown ai gateway" in body_lower or "unknown gateway" in body_lower:
                diag.root_cause = (
                    f"Gateway slug '{slug}' does NOT exist in Cloudflare dashboard "
                    f"(CF returned: 'Unknown AI Gateway'). "
                    f"Create it at dash.cloudflare.com → AI Gateway → Create Gateway → "
                    f"name it exactly: '{slug}'"
                )
                diag.fixes.append(
                    f"1. Go to dash.cloudflare.com → AI Gateway"
                )
                diag.fixes.append(
                    f"2. Click 'Create Gateway'"
                )
                diag.fixes.append(
                    f"3. Set Gateway Name exactly to: '{slug}'"
                )
                diag.fixes.append(
                    f"4. Save and repeat for all {len(slots)} gateway slots"
                )
                diag.status   = "config_error"
            elif "permission" in body_lower or "forbidden" in body_lower or "unauthorized" in body_lower:
                diag.root_cause = (
                    f"CF API token for slot {slot_n} lacks 'AI Gateway: Execute' permission. "
                    f"Add this permission at dash.cloudflare.com → My Profile → API Tokens."
                )
                diag.fixes.append(
                    "Edit CF_API_TOKEN in GitHub Secrets → add 'AI Gateway: Execute' permission"
                )
                diag.status   = "auth_error"
            elif "workers ai" in body_lower:
                diag.root_cause = (
                    f"Workers AI permission issue through gateway. "
                    f"Ensure token has 'Workers AI: Run' AND 'AI Gateway: Execute'."
                )
                diag.status = "auth_error"
            elif not body.strip():
                diag.root_cause = (
                    f"CF AI Gateway returned HTTP 400 with empty body for slug '{slug}'. "
                    f"This usually means the gateway slug doesn't exist."
                )
                diag.fixes.append(
                    f"Create gateway '{slug}' at dash.cloudflare.com → AI Gateway"
                )
                diag.status = "config_error"
            else:
                diag.root_cause = f"CF AI Gateway returned HTTP 400: {body[:200]}"
                diag.status     = "config_error"
            diag.raw_body = body[:400]

        elif status == 403:
            diag.root_cause = (
                f"CF API token for slot {slot_n} got HTTP 403 Forbidden. "
                f"Token lacks required permission. Check 'Workers AI: Run' AND "
                f"'AI Gateway: Execute' scopes in Cloudflare dashboard."
            )
            diag.status = "auth_error"
            diag.fixes.append(
                "Add 'AI Gateway: Execute' and 'Workers AI: Run' to CF_API_TOKEN"
            )

        elif status == 0:
            diag.root_cause = f"Network error connecting to CF AI Gateway: {body}"
            diag.status     = "network_error"

        diag.latency_ms = latency

    if not diag.fixes:
        diag.fixes.append(
            f"Check all {len(slots)} CF AI Gateway slugs exist at "
            f"dash.cloudflare.com → AI Gateway"
        )
    return diag


# ─────────────────────────────────────────────────────────────────────────────
# 4.  PORTKEY DIAGNOSTICS
# ─────────────────────────────────────────────────────────────────────────────

def _diagnose_portkey(n_slots: int = 3) -> ProviderDiagnosis:
    """
    Run targeted diagnostics on the Portkey provider.
    Tests multiple routing strategies to find which one works.
    """
    diag = ProviderDiagnosis(provider="portkey", status="unknown")

    gateway_url = os.environ.get("PORTKEY_GATEWAY_URL", "").strip()
    if not gateway_url:
        diag.status     = "config_error"
        diag.root_cause = "PORTKEY_GATEWAY_URL not set"
        diag.fixes      = ["Set PORTKEY_GATEWAY_URL in GitHub Secrets (e.g. https://api.portkey.ai/v1)"]
        return diag

    cerebras_key = os.environ.get("CEREBRAS_API_KEY_1", "").strip()
    endpoint     = f"{gateway_url.rstrip('/')}/chat/completions"

    # Load Portkey keys
    pk_keys = []
    for i in range(1, n_slots + 1):
        k = os.environ.get(f"PORTKEY_API_KEY_{i}", "").strip()
        if k:
            pk_keys.append((i, k))

    if not pk_keys:
        diag.status     = "config_error"
        diag.root_cause = "No PORTKEY_API_KEY_n secrets set"
        diag.fixes      = ["Set PORTKEY_API_KEY_1 in GitHub Secrets (Portkey admin/virtual key)"]
        return diag

    # Strategy matrix: try each (headers, model) combination
    strategies = []

    if cerebras_key:
        # Strategy A: Direct Cerebras routing through Portkey (most reliable)
        strategies.append((
            "A: Portkey→Cerebras (direct key)",
            {
                "x-portkey-api-key": pk_keys[0][1],
                "x-portkey-provider": "cerebras",
                "Authorization": f"Bearer {cerebras_key}",
                "Content-Type": "application/json",
                "User-Agent": _UA,
            },
            "llama3.1-8b",
        ))

    # Strategy B: Virtual key routing (Portkey dashboard-configured)
    strategies.append((
        "B: Portkey virtual key routing",
        {
            "x-portkey-api-key": pk_keys[0][1],
            "Content-Type": "application/json",
            "User-Agent": _UA,
        },
        "llama3.1-8b",
    ))

    # Strategy C: OpenAI-compat through Portkey
    strategies.append((
        "C: Portkey→OpenAI fallback",
        {
            "x-portkey-api-key": pk_keys[0][1],
            "Content-Type": "application/json",
            "User-Agent": _UA,
        },
        "gpt-3.5-turbo",
    ))

    payload_base = {"messages": _MINIMAL_PROMPT, "max_tokens": 5}

    for strat_name, headers, model in strategies:
        payload = {**payload_base, "model": model}
        t0 = time.time()
        status, body = _post(endpoint, headers, payload)
        latency = (time.time() - t0) * 1000

        logger.info(
            f"[AutoDebug-Portkey] {strat_name} → HTTP {status} ({latency:.0f}ms)"
        )
        if status != 200 and body:
            logger.warning(f"[AutoDebug-Portkey] {strat_name} body: {body[:300]}")

        if status == 200:
            diag.status     = "ok"
            diag.root_cause = f"Strategy '{strat_name}' succeeded ({latency:.0f}ms)"
            diag.latency_ms = latency
            logger.info(f"[AutoDebug-Portkey] ✓ Strategy '{strat_name}' works!")
            return diag

        if status == 400:
            body_lower = body.lower()
            if "no provider" in body_lower or "provider not" in body_lower:
                diag.fixes.append(
                    "Portkey returned 'no provider' — configure a virtual key at "
                    "dash.portkey.ai → Virtual Keys → Add Cerebras key"
                )
            if "invalid" in body_lower and "key" in body_lower:
                diag.fixes.append(
                    "Portkey key format may be wrong — check PORTKEY_API_KEY_1 "
                    "is a valid Portkey admin or virtual key"
                )
            diag.raw_body   = body[:300]
        elif status == 401:
            diag.root_cause = "Portkey API key invalid or expired"
            diag.status     = "auth_error"
            diag.fixes      = [
                "Check PORTKEY_API_KEY_1 is valid at dash.portkey.ai → API Keys",
                "Generate a new API key if expired",
            ]
            return diag
        elif status == 0:
            diag.root_cause = f"Network error connecting to Portkey: {body}"
            diag.status     = "network_error"
            return diag

    # All strategies failed
    diag.status     = "config_error"
    diag.root_cause = (
        "All Portkey routing strategies returned HTTP 400. "
        "Portkey is reachable but cannot route to any provider. "
        f"Last 400 body: {diag.raw_body[:200]}"
    )
    if not diag.fixes:
        diag.fixes = [
            "1. Go to dash.portkey.ai → Virtual Keys → Create Key for Cerebras",
            "2. Set PORTKEY_API_KEY_1 to that virtual key in GitHub Secrets",
            "3. OR set PORTKEY_PROVIDER_KEY secret to your Cerebras API key",
            "4. Set PORTKEY_HEALTH_MODEL to 'llama3.1-8b'",
        ]
    diag.latency_ms = sum(
        (time.time() - time.time()) * 0 for _ in strategies
    )  # approximate
    return diag


# ─────────────────────────────────────────────────────────────────────────────
# 5.  CEREBRAS DIAGNOSTICS
# ─────────────────────────────────────────────────────────────────────────────

def _diagnose_cerebras(n_slots: int = 3) -> ProviderDiagnosis:
    """Quick Cerebras health check."""
    diag = ProviderDiagnosis(provider="cerebras", status="unknown")

    for i in range(1, n_slots + 1):
        key = os.environ.get(f"CEREBRAS_API_KEY_{i}", "").strip()
        if not key:
            continue
        t0 = time.time()
        status, body = _post(
            "https://api.cerebras.ai/v1/chat/completions",
            {
                "Authorization": f"Bearer {key}",
                "Content-Type":  "application/json",
                "User-Agent":    _UA,
            },
            {"model": "llama3.1-8b", "messages": _MINIMAL_PROMPT, "max_tokens": 5},
        )
        latency = (time.time() - t0) * 1000
        logger.info(f"[AutoDebug-Cerebras] slot {i} → HTTP {status} ({latency:.0f}ms)")
        if status == 200:
            diag.status     = "ok"
            diag.root_cause = f"Slot {i} OK ({latency:.0f}ms)"
            diag.latency_ms = latency
            return diag
        if status in (401, 403):
            diag.fixes.append(f"CEREBRAS_API_KEY_{i} is invalid or expired")

    if diag.status == "unknown":
        diag.status     = "config_error"
        diag.root_cause = "No valid Cerebras keys configured"
        diag.fixes      = ["Set CEREBRAS_API_KEY_1 in GitHub Secrets"]
    return diag


# ─────────────────────────────────────────────────────────────────────────────
# 6.  CF WORKERS AI DIRECT DIAGNOSTICS
# ─────────────────────────────────────────────────────────────────────────────

def _diagnose_cf_workers_ai(n_slots: int = 11) -> ProviderDiagnosis:
    """Quick CF Workers AI direct API health check."""
    diag = ProviderDiagnosis(provider="cloudflare_workers_ai", status="unknown")

    for i in range(1, n_slots + 1):
        acct_id   = os.environ.get(f"CF_ACCOUNT_ID_{i}", "").strip()
        api_token = os.environ.get(f"CF_API_TOKEN_{i}", "").strip()
        if not (acct_id and api_token):
            continue
        url = (
            f"https://api.cloudflare.com/client/v4/accounts/{acct_id}"
            f"/ai/v1/chat/completions"
        )
        t0 = time.time()
        status, body = _post(
            url,
            {
                "Authorization": f"Bearer {api_token}",
                "Content-Type":  "application/json",
                "User-Agent":    _UA,
            },
            {"model": _MINIMAL_MODEL, "messages": _MINIMAL_PROMPT, "max_tokens": 5},
        )
        latency = (time.time() - t0) * 1000
        logger.info(
            f"[AutoDebug-CF-Workers] slot {i} → HTTP {status} ({latency:.0f}ms)"
        )
        if status == 200:
            diag.status     = "ok"
            diag.root_cause = f"Slot {i} OK ({latency:.0f}ms)"
            diag.latency_ms = latency
            return diag
        if status in (401, 403):
            diag.fixes.append(
                f"CF_API_TOKEN_{i} lacks 'Workers AI: Run' permission"
            )
        break  # Test only slot 1 for speed; if it works, assume others too

    if diag.status == "unknown":
        diag.status = "config_error"
        diag.root_cause = "CF Workers AI check incomplete"
    return diag


# ─────────────────────────────────────────────────────────────────────────────
# 7.  MAIN AUTO-DEBUG RUNNER
# ─────────────────────────────────────────────────────────────────────────────

def run_auto_debug(
    providers: Optional[List[str]] = None,
    output_path: str = "data/auto_debug_report.json",
    run_id: str = "",
) -> AutoDebugReport:
    """
    Run the full auto-debug suite and return a report.
    Called from GitHub Actions as a diagnostic step.
    """
    if not providers:
        providers = ["cerebras", "cloudflare_ai_gateway", "cloudflare_workers_ai", "portkey"]

    if not run_id:
        run_id = os.environ.get("GITHUB_RUN_ID", f"local-{int(time.time())}")

    logger.info(f"[AutoDebug v2.0] Starting diagnostic for {providers}")
    report = AutoDebugReport(run_id=run_id)

    dispatchers = {
        "cerebras":              _diagnose_cerebras,
        "cloudflare_ai_gateway": _diagnose_cf_ai_gateway,
        "cloudflare_workers_ai": _diagnose_cf_workers_ai,
        "portkey":               _diagnose_portkey,
    }

    all_ok = True
    for pname in providers:
        fn = dispatchers.get(pname)
        if not fn:
            logger.warning(f"[AutoDebug] No diagnostic for '{pname}' — skipping")
            continue
        try:
            logger.info(f"[AutoDebug] ─── Diagnosing {pname} ───")
            diag = fn()
            report.diagnoses.append(diag)
            if diag.status == "ok":
                logger.info(f"[AutoDebug] ✓ {pname}: {diag.root_cause}")
            elif diag.status == "config_error":
                all_ok = False
                logger.warning(
                    f"[AutoDebug] ⚠ {pname} CONFIG ERROR: {diag.root_cause}"
                )
                for fix in diag.fixes:
                    logger.warning(f"[AutoDebug]   FIX: {fix}")
            elif diag.status == "auth_error":
                all_ok = False
                logger.error(f"[AutoDebug] ✗ {pname} AUTH ERROR: {diag.root_cause}")
                for fix in diag.fixes:
                    logger.error(f"[AutoDebug]   FIX: {fix}")
            else:
                all_ok = False
                logger.error(f"[AutoDebug] ✗ {pname}: {diag.status} — {diag.root_cause}")
        except Exception as exc:
            logger.exception(f"[AutoDebug] Diagnostic for {pname} raised: {exc}")
            report.diagnoses.append(ProviderDiagnosis(
                provider=pname, status="unknown",
                root_cause=f"Diagnostic failed: {exc}",
            ))
            all_ok = False

    report.all_healthy = all_ok
    report.summary = (
        f"AutoDebug v2.0 — {sum(1 for d in report.diagnoses if d.status=='ok')}"
        f"/{len(report.diagnoses)} providers healthy"
    )

    # Write JSON report
    try:
        import os as _os
        _os.makedirs(_os.path.dirname(output_path), exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(report.to_dict(), f, indent=2)
        logger.info(f"[AutoDebug] Report saved to {output_path}")
    except Exception as exc:
        logger.warning(f"[AutoDebug] Failed to save report: {exc}")

    return report


# ─────────────────────────────────────────────────────────────────────────────
# 8.  GITHUB ACTIONS STEP SUMMARY WRITER
# ─────────────────────────────────────────────────────────────────────────────

def write_step_summary(report: AutoDebugReport) -> None:
    """Write a formatted Markdown summary to GitHub Actions step summary."""
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY", "")
    if not summary_path:
        return

    lines = [
        "## 🔍 Auto-Debug Report v2.0\n",
        f"**Run:** `{report.run_id}` | **Healthy:** {'✅ All OK' if report.all_healthy else '⚠️ Issues found'}\n",
        "\n| Provider | Status | Root Cause |\n",
        "|----------|--------|------------|\n",
    ]
    for d in report.diagnoses:
        emoji = {"ok": "✅", "config_error": "⚙️", "auth_error": "🔑",
                 "network_error": "🌐", "unknown": "❓"}.get(d.status, "❓")
        lines.append(f"| {d.provider} | {emoji} {d.status} | {d.root_cause[:100]} |\n")

    # Fix instructions for failed providers
    failed = [d for d in report.diagnoses if d.status != "ok"]
    if failed:
        lines.append("\n### 🔧 Required Fixes\n")
        for d in failed:
            if d.fixes:
                lines.append(f"\n**{d.provider}** ({d.status}):\n")
                for fix in d.fixes:
                    lines.append(f"- {fix}\n")

    try:
        with open(summary_path, "a") as f:
            f.writelines(lines)
        logger.info("[AutoDebug] Step summary written")
    except Exception as exc:
        logger.warning(f"[AutoDebug] Failed to write step summary: {exc}")


# ─────────────────────────────────────────────────────────────────────────────
# 9.  CLI ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    ap = argparse.ArgumentParser(description="TorShield Provider Auto-Debugger v2.0")
    ap.add_argument("--providers", nargs="+",
                    default=["cerebras", "cloudflare_ai_gateway",
                             "cloudflare_workers_ai", "portkey"])
    ap.add_argument("--output", default="data/auto_debug_report.json")
    args = ap.parse_args()

    report = run_auto_debug(
        providers=args.providers,
        output_path=args.output,
        run_id=os.environ.get("GITHUB_RUN_ID", ""),
    )
    write_step_summary(report)

    print(f"\n{report.summary}")
    for d in report.diagnoses:
        status_icon = "✓" if d.status == "ok" else "✗"
        print(f"  {status_icon} {d.provider}: {d.status} — {d.root_cause[:100]}")
        for fix in d.fixes:
            print(f"      FIX: {fix}")
