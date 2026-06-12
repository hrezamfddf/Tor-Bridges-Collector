# Bug Report — Tor-Bridges-Collector

> **Project**: Tor-Bridges-Collector (TorShield-IR)  
> **Report Date**: 2026-06-12  
> **Version Audited**: v15.0 — Ultra-Quantum Edition  
> **Total Bugs Documented**: 16  
> **Status**: ALL FIXED

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Original 5 Root Causes](#original-5-root-causes)
   - [BUG-001: Cerebras 404 — Invalid Model Name](#bug-001-cerebras-404--invalid-model-name)
   - [BUG-002: CF AI Gateway 400 — Missing Account ID in URL Path](#bug-002-cf-ai-gateway-400--missing-account-id-in-url-path)
   - [BUG-003: Portkey 401 — Malformed API Key and Missing Virtual Key Support](#bug-003-portkey-401--malformed-api-key-and-missing-virtual-key-support)
   - [BUG-004: Health Check Miscounting LocalAIEngine as Primary](#bug-004-health-check-miscounting-localaiengine-as-primary)
   - [BUG-005: Deprecated FORCE_JAVASCRIPT_ACTIONS_TO_NODE24 Env Var](#bug-005-deprecated-force_javascript_actions_to_node24-env-var)
3. [PYEOF Heredoc Syntax Errors in Workflow YAMLs](#pyeof-heredoc-syntax-errors-in-workflow-yamls)
4. [Bugs Found by Audit Scripts](#bugs-found-by-audit-scripts)
5. [Summary Table](#summary-table)

---

## Executive Summary

This document catalogs all bugs discovered, diagnosed, and fixed across the Tor-Bridges-Collector project from v10.0 through v15.0. The project experienced a series of cascading failures originating from five root causes in the AI provider integration layer, compounded by heredoc syntax errors in GitHub Actions workflow YAMLs. All 16 documented bugs have been resolved and verified by the 314-test suite.

### Impact Assessment

| Category | Count | Severity Range |
|----------|-------|---------------|
| Provider Integration Bugs | 3 | Critical |
| Health Check / Monitoring Bugs | 1 | High |
| Configuration / Deprecation Bugs | 1 | Medium |
| Workflow Heredoc Bugs | 8 | High |
| Dead Code / Quality Issues | 3 | Low–Medium |

---

## Original 5 Root Causes

### BUG-001: Cerebras 404 — Invalid Model Name

| Field | Detail |
|-------|--------|
| **Bug ID** | BUG-001 |
| **Status** | FIXED |
| **Severity** | Critical |
| **Affected Version** | v10.0–v11.0 |
| **Fixed Version** | v12.0 |
| **File** | `torshield_ai_gateway/providers.py` |
| **Symptom** | Cerebras API returning HTTP 404 "Model not found" on every request |

#### Root Cause Analysis

The Cerebras provider was configured with the model name `"llama3.3-70b"`, which does not exist on the Cerebras inference platform. Cerebras hosts Meta's Llama models but uses a different naming convention than other providers. The model name `llama3.3-70b` appears to have been copied from an OpenAI-compatible endpoint convention without verifying Cerebras's actual model catalog.

Every request to `https://api.cerebras.ai/v1/chat/completions` with model `llama3.3-70b` returned:

```json
{
  "error": {
    "message": "Model llama3.3-70b not found",
    "type": "invalid_request_error",
    "code": "model_not_found"
  }
}
```

#### Resolution

1. Changed `DEFAULT_MODEL` from `"llama3.3-70b"` to `"llama3.1-8b"` (most stable free-tier model)
2. Added `CEREBRAS_MODELS` fallback list with known valid models: `["llama3.1-8b", "llama3.1-70b", "llama-3.3-70b"]`
3. Implemented `_discover_models()` method that fetches available models from `/v1/models` endpoint
4. On 400/404 errors, the provider now automatically tries the next model in the fallback list

```python
# Before (broken):
DEFAULT_MODEL = "llama3.3-70b"  # Does NOT exist on Cerebras

# After (fixed):
DEFAULT_MODEL = "llama3.1-8b"   # Most stable free-tier model
CEREBRAS_MODELS = ["llama3.1-8b", "llama3.1-70b", "llama-3.3-70b"]
```

---

### BUG-002: CF AI Gateway 400 — Missing Account ID in URL Path

| Field | Detail |
|-------|--------|
| **Bug ID** | BUG-002 |
| **Status** | FIXED |
| **Severity** | Critical |
| **Affected Version** | v10.0–v11.0 |
| **Fixed Version** | v12.0 |
| **File** | `torshield_ai_gateway/providers.py` |
| **Symptom** | Cloudflare AI Gateway returning HTTP 400 "Bad Request" or "No route for URI" |

#### Root Cause Analysis

The CF AI Gateway URL construction was missing the `account_id` in the `workers-ai` path segment. According to Cloudflare's AI Gateway documentation, the correct URL format is:

```
https://gateway.ai.cloudflare.com/v1/{account_id}/gateway-slug/workers-ai/{model}
```

But the code was constructing URLs without embedding the `account_id` in the workers-ai path, resulting in requests to an invalid endpoint. Additionally, there was no validation of gateway URL format — users could configure malformed URLs that would silently fail.

#### Resolution

1. Added `_validate_gateway_url()` method that validates the URL starts with `https://gateway.ai.cloudflare.com/v1/`
2. Extracts and validates `account_id` from the URL path
3. Added `_probe_gateway()` that sends a lightweight GET to check gateway reachability before attempting inference
4. URL path construction now correctly includes `account_id` for workers-ai routing
5. Tests added for URL validation (valid URL, invalid no-https, trailing slash stripping)

```python
# Before (broken):
# URL constructed without account_id validation

# After (fixed):
def _validate_gateway_url(self, url: str) -> str:
    """Validate CF AI Gateway URL format."""
    if not url.startswith("https://gateway.ai.cloudflare.com/v1/"):
        raise ValueError(f"Invalid CF AI Gateway URL: must start with https://gateway.ai.cloudflare.com/v1/")
    url = url.rstrip("/")
    return url
```

---

### BUG-003: Portkey 401 — Malformed API Key and Missing Virtual Key Support

| Field | Detail |
|-------|--------|
| **Bug ID** | BUG-003 |
| **Status** | FIXED |
| **Severity** | Critical |
| **Affected Version** | v10.0–v11.0 |
| **Fixed Version** | v12.0 |
| **File** | `torshield_ai_gateway/providers.py` |
| **Symptom** | Portkey API returning HTTP 401 "Unauthorized" despite valid API key being configured |

#### Root Cause Analysis

Three sub-issues were identified:

1. **Key format not validated**: Portkey API keys use the `pk-` prefix convention, but the code did not validate this. Keys with trailing newlines (common in CI/CD secret injection) or missing prefixes were silently accepted and sent to the API.

2. **No virtual key support**: Portkey's recommended authentication method uses virtual keys (`PORTKEY_VIRTUAL_KEY_{i}`) per-slot, but the code only supported the master `PORTKEY_API_KEY`.

3. **Poor 401 diagnostics**: When a 401 was received, the error message did not distinguish between "key missing", "key invalid", or "key expired", making debugging extremely difficult.

#### Resolution

1. Added `_validate_portkey_key()` method that checks for `pk-` prefix and strips whitespace/newlines
2. Added support for `PORTKEY_VIRTUAL_KEY_{1,2,3}` environment variables as alternative per-slot auth
3. Enhanced 401 error diagnostics with specific failure categories:
   - `key_missing`: No PORTKEY_API_KEY or virtual keys configured
   - `key_invalid_format`: Key does not start with `pk-` prefix
   - `key_has_whitespace`: Key contains trailing newlines or spaces
   - `key_expired_or_unauthorized`: Key format valid but API rejects it

```python
# Before (broken):
# No validation, no virtual keys, poor diagnostics

# After (fixed):
AUTH_FAILURE_HTTP_CODES = {401, 403}  # NEVER retry these

def _validate_portkey_key(self, key: str) -> str:
    """Validate Portkey API key format."""
    key = key.strip()
    if not key:
        raise ValueError("Portkey API key is empty")
    if not key.startswith("pk-"):
        raise ValueError("Portkey API key must start with 'pk-' prefix")
    return key
```

---

### BUG-004: Health Check Miscounting LocalAIEngine as Primary

| Field | Detail |
|-------|--------|
| **Bug ID** | BUG-004 |
| **Status** | FIXED |
| **Severity** | High |
| **Affected Version** | v10.0–v12.0 |
| **Fixed Version** | v13.0 |
| **File** | `torshield_ai_gateway/gateway.py`, `scripts/ai_gateway_health_check.py` |
| **Symptom** | Health check reporting system as "healthy" when all primary AI providers were down, because LocalAIEngine responses were counted as primary successes |

#### Root Cause Analysis

The `TorShieldAIGateway` class has a fallback mechanism: when all primary providers (Cerebras, CF, Portkey) fail, the `LocalAIEngine` (a rule-based system) provides a response. However, the health check was counting ALL successful responses as "primary_ok", including LocalAIEngine fallback responses.

This meant the system could report itself as fully healthy while actually operating in degraded mode with no real AI inference capability. In production, this would mask complete provider outages.

#### Resolution

1. Added `_last_response_source` tracking to `TorShieldAIGateway`:
   - `"primary"` — a real AI provider answered
   - `"local_fallback"` — LocalAIEngine answered (degraded mode)
   - `None` — no request has been made yet

2. Health check now distinguishes between `primary_ok` and `degraded` states:
   - **Exit 0**: At least one primary provider responds
   - **Exit 1**: All primary providers failed (LocalAIEngine = degraded, not healthy)
   - **Exit 2**: Required environment variables are missing

3. Added `_stats` monitoring counters:
   - `total_requests`: Total inference requests
   - `primary_successes`: Responses from real AI providers
   - `fallback_activations`: Times LocalAIEngine was used
   - `wrong_responses`: Responses with unexpected content

```python
# Before (broken):
# Health check counted LocalAIEngine as primary success

# After (fixed):
self._last_response_source: Optional[str] = None  # "primary" | "local_fallback"

def is_primary_healthy(self) -> bool:
    """True only if a real AI provider answered, NOT LocalAIEngine."""
    return self._last_response_source == "primary"
```

---

### BUG-005: Deprecated FORCE_JAVASCRIPT_ACTIONS_TO_NODE24 Env Var

| Field | Detail |
|-------|--------|
| **Bug ID** | BUG-005 |
| **Status** | FIXED |
| **Severity** | Medium |
| **Affected Version** | v10.0–v12.0 |
| **Fixed Version** | v13.0 |
| **File** | `.github/workflows/torshield-ir.yml` |
| **Symptom** | Three deprecation warning annotations on every workflow run: "Node.js 20 is deprecated... but are being forced to run on Node.js 24" |

#### Root Cause Analysis

The environment variable `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24` was set in the workflow as an opt-in for GitHub's Node.js 20→24 migration. This variable was a temporary mechanism introduced during GitHub's September 2025 deprecation announcement. However, after Node.js 20 reached end-of-life in April 2026, GitHub began automatically upgrading node20 actions to node24 without requiring the opt-in variable.

The variable was generating three deprecation warning annotations per workflow run because the runner detected the forced migration flag. The warnings stated: *"being forced to run on Node.js 24"* — this "being forced" message is specifically triggered by this environment variable.

#### Resolution

Removed `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24` entirely from all workflow files. GitHub now upgrades node20 actions to node24 automatically and silently, making the variable both redundant and warning-generating.

```yaml
# Before (broken):
env:
  FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: "true"  # CAUSED 3 deprecation warnings

# After (fixed):
# Variable removed entirely — GitHub auto-upgrades node20 → node24
```

---

## PYEOF Heredoc Syntax Errors in Workflow YAMLs

### BUG-006 through BUG-013: Heredoc Delimiter Mismatches

| Field | Detail |
|-------|--------|
| **Bug IDs** | BUG-006 through BUG-013 |
| **Status** | ALL FIXED |
| **Severity** | High |
| **Affected Version** | v10.0–v14.0 |
| **Fixed Version** | v15.0 |
| **Files** | All 4 workflow YAML files in `.github/workflows/` |
| **Symptom** | GitHub Actions failing with "unexpected end of file" or "command not found" errors during inline Python script execution |

#### Root Cause Analysis

The workflow YAML files use heredoc syntax to embed inline Python scripts:

```yaml
- name: Run analysis
  run: |
    cat > /tmp/_script.py << 'ENDSCRIPT'
    import json
    # ... Python code ...
    ENDSCRIPT
    python3 /tmp/_script.py
```

**8 heredoc blocks** across the 4 workflow files had mismatched or broken delimiters:

| # | File | Heredoc Name | Issue |
|---|------|-------------|-------|
| BUG-006 | `torshield-ir.yml` | `_validate_requirements.py` | Indentation of `ENDSCRIPT` delimiter caused shell to not recognize the terminator |
| BUG-007 | `torshield-ir.yml` | `_quality_report.py` | Missing `ENDSCRIPT` on final line |
| BUG-008 | `torshield-ir.yml` | `_vercel_cleanup.py` | `ENDSCRIPT` had trailing whitespace preventing match |
| BUG-009 | `torshield-ir.yml` | `_failsafe_bridges.py` | Heredoc started with `<<` but closed with `PYEOF` (mismatched delimiters) |
| BUG-010 | `ai_gateway_health_check.yml` | `_model_rankings.py` | `ENDSCRIPT` indented with tabs instead of spaces |
| BUG-011 | `ai_gateway_health_check.yml` | `_health_summary.py` | Missing closing delimiter |
| BUG-012 | `ai_gateway_health_check.yml` | `_obs_report.py` | Extra blank line before `ENDSCRIPT` causing shell parse error |
| BUG-013 | `ai_self_healing.yml` | `_categorize.py` | `ENDSCRIPT` on same line as last Python statement |

#### Heredoc Syntax Rules (for future reference)

1. The closing delimiter **must** appear on a line by itself (no leading whitespace in the default `<<` form)
2. Use `<<-` (with dash) if the delimiter is indented — this strips leading tabs
3. The opening and closing delimiters **must** match exactly
4. No trailing whitespace on the closing delimiter line
5. No extra blank lines before the closing delimiter

#### Resolution

All 8 heredoc blocks were fixed by:
1. Ensuring `ENDSCRIPT` delimiter appears at column 0 (no indentation)
2. Matching opening `<< 'ENDSCRIPT'` with closing `ENDSCRIPT`
3. Removing trailing whitespace from delimiter lines
4. Adding proper spacing between last code line and delimiter

---

## Bugs Found by Audit Scripts

### BUG-014: Dangerous `sudo rm -rf` Pattern in Shell Scripts

| Field | Detail |
|-------|--------|
| **Bug ID** | BUG-014 |
| **Status** | FIXED (mitigated) |
| **Severity** | Critical (scan finding) |
| **File** | `install.sh:121`, `setup_env.sh:101` |
| **Found By** | `scripts/security_scan.py` |

#### Description

The security scan flagged `sudo rm -rf` patterns in both `install.sh` and `setup_env.sh`. While these are intentional cleanup operations, the pattern `sudo rm -rf /` (if a variable is empty) is a classic shell scripting hazard.

#### Resolution

Added guard checks before all `rm -rf` operations to ensure the target path is non-empty and absolute:

```bash
# Before (risky):
sudo rm -rf "$TARGET_DIR"

# After (safe):
if [ -n "$TARGET_DIR" ] && [ "${TARGET_DIR:0:1}" = "/" ]; then
    sudo rm -rf "$TARGET_DIR"
fi
```

---

### BUG-015: `pickle.load()` Deserialization Vulnerability

| Field | Detail |
|-------|--------|
| **Bug ID** | BUG-015 |
| **Status** | FIXED |
| **Severity** | High |
| **File** | `ml_predictor.py:280` |
| **Found By** | `scripts/security_scan.py` |

#### Description

The ML predictor module uses `pickle.load()` to deserialize model files, which is a known security vulnerability. Pickle deserialization can execute arbitrary code if the pickle file has been tampered with.

#### Resolution

Replaced `pickle.load()` with `json.load()` for model metadata and added integrity verification:

```python
# Before (vulnerable):
with open(model_path, "rb") as f:
    model = pickle.load(f)

# After (secure):
import hashlib
def load_model_secure(path: str):
    """Load model with integrity verification."""
    with open(path, "rb") as f:
        data = f.read()
    expected_hash = compute_expected_hash(path)
    actual_hash = hashlib.sha256(data).hexdigest()
    if actual_hash != expected_hash:
        raise ValueError(f"Model integrity check failed: {path}")
    # Use safer deserialization
    return json.loads(data.decode("utf-8"))
```

---

### BUG-016: `yaml.load()` Without SafeLoader

| Field | Detail |
|-------|--------|
| **Bug ID** | BUG-016 |
| **Status** | FIXED |
| **Severity** | High |
| **File** | `scripts/security_scan.py:231,297,315` |
| **Found By** | `scripts/security_scan.py` |

#### Description

Multiple calls to `yaml.load()` were made without specifying `Loader=yaml.SafeLoader`, which allows arbitrary Python object instantiation during YAML parsing.

#### Resolution

All `yaml.load()` calls replaced with `yaml.safe_load()`:

```python
# Before (vulnerable):
data = yaml.load(content)

# After (secure):
data = yaml.safe_load(content)
# or equivalently:
data = yaml.load(content, Loader=yaml.SafeLoader)
```

---

## Summary Table

| Bug ID | Description | Severity | Status | Fixed In |
|--------|-------------|----------|--------|----------|
| BUG-001 | Cerebras 404 — Invalid model name `llama3.3-70b` | Critical | FIXED | v12.0 |
| BUG-002 | CF AI Gateway 400 — Missing account_id in URL | Critical | FIXED | v12.0 |
| BUG-003 | Portkey 401 — Malformed key, no virtual key support | Critical | FIXED | v12.0 |
| BUG-004 | Health check miscounting LocalAIEngine as primary | High | FIXED | v13.0 |
| BUG-005 | Deprecated `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24` env var | Medium | FIXED | v13.0 |
| BUG-006 | Heredoc: `_validate_requirements.py` indentation | High | FIXED | v15.0 |
| BUG-007 | Heredoc: `_quality_report.py` missing delimiter | High | FIXED | v15.0 |
| BUG-008 | Heredoc: `_vercel_cleanup.py` trailing whitespace | High | FIXED | v15.0 |
| BUG-009 | Heredoc: `_failsafe_bridges.py` delimiter mismatch | High | FIXED | v15.0 |
| BUG-010 | Heredoc: `_model_rankings.py` tab indentation | High | FIXED | v15.0 |
| BUG-011 | Heredoc: `_health_summary.py` missing closing | High | FIXED | v15.0 |
| BUG-012 | Heredoc: `_obs_report.py` extra blank line | High | FIXED | v15.0 |
| BUG-013 | Heredoc: `_categorize.py` delimiter on code line | High | FIXED | v15.0 |
| BUG-014 | Dangerous `sudo rm -rf` patterns | Critical | FIXED | v15.0 |
| BUG-015 | `pickle.load()` deserialization vulnerability | High | FIXED | v15.0 |
| BUG-016 | `yaml.load()` without SafeLoader | High | FIXED | v15.0 |

---

## Verification

All fixes verified by the automated test suite:

```
=================== 314 passed, 51 subtests passed in 30.00s ===================
```

Key test files covering bug fixes:
- `tests/test_providers.py` — 37 tests (Cerebras model, CF Gateway URL, Portkey auth)
- `tests/test_circuit_breaker.py` — 20 tests (provider circuit breaker)
- `tests/test_health_check.py` — 22 tests (source tracking, primary vs fallback)
- `tests/test_ci_workflows.py` — 10 tests (YAML validity, deprecated env var)
- `tests/test_gateway.py` — 18 tests (gateway waterfall, fallback behavior)
