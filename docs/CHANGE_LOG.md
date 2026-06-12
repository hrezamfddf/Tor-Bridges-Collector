# Change Log — Tor-Bridges-Collector

> **Project**: Tor-Bridges-Collector (TorShield-IR)  
> **Repository**: github.com/hrrjruruufgbbvhrh/Tor-Bridges-Collector-Ultra  
> **Current Version**: v15.0 — Ultra-Quantum Edition  

---

## Table of Contents

1. [v15.0 — Ultra-Quantum Edition (2026-06-12)](#v150--ultra-quantum-edition-2026-06-12)
2. [v14.0 — Audit & Quality Hardening (2026-06-11)](#v140--audit--quality-hardening-2026-06-11)
3. [v13.0 — Monitoring & Observability (2026-06-10)](#v130--monitoring--observability-2026-06-10)
4. [v12.0 — Provider Fix Release (2026-06-09)](#v120--provider-fix-release-2026-06-09)
5. [v11.0 — Anti-Censorship V2 (2026-06-07)](#v110--anti-censorship-v2-2026-06-07)
6. [v10.0 — Foundation Release (2026-06-05)](#v100--foundation-release-2026-06-05)
7. [Summary of All Changes by Category](#summary-of-all-changes-by-category)

---

## v15.0 — Ultra-Quantum Edition (2026-06-12)

### Overview

Major release focused on resolving all remaining workflow heredoc syntax errors, adding comprehensive audit tooling, and expanding the test suite to 314 tests.

### Bug Fixes

| Change | Description |
|--------|-------------|
| **PYEOF Heredoc Fixes** | Fixed 8 heredoc delimiter syntax errors across all 4 workflow YAML files. Mismatched `ENDSCRIPT`/`PYEOF` delimiters, indentation issues, and missing closing delimiters caused "unexpected end of file" errors in GitHub Actions. |
| **`sudo rm -rf` Guard** | Added guard checks before all `rm -rf` operations in `install.sh` and `setup_env.sh` to prevent accidental root filesystem deletion if variables are empty. |
| **`pickle.load()` Removal** | Replaced `pickle.load()` in `ml_predictor.py` with `json.load()` plus SHA-256 integrity verification. |
| **`yaml.safe_load()` Migration** | Replaced all `yaml.load()` calls with `yaml.safe_load()` across the codebase to prevent arbitrary object instantiation. |

### New Features

| Change | Description |
|--------|-------------|
| **Audit Scripts** | Added three comprehensive audit scripts: `scripts/security_scan.py`, `scripts/validate_dependencies.py`, `scripts/audit_dead_code.py` |
| **Full Audit Runner** | Added `scripts/run_full_audit.py` that orchestrates all audit scripts in sequence |
| **Test Suite Expansion** | Expanded from ~240 tests to **314 tests** across 10 test files |
| **V3 Anti-DPI Tests** | Added 74 tests for Neural Anti-DPI V3 module (`test_neural_anti_dpi_v3.py`) |
| **E2E Tests** | Added 34 end-to-end tests (`test_e2e.py`) |
| **Integration Tests** | Added 39 integration tests (`test_integration.py`) |

### Workflow Changes

| Change | Description |
|--------|-------------|
| **Workflow Heredoc Standardization** | All 8 inline Python heredocs in workflows now use `<< 'ENDSCRIPT'` with consistent delimiter at column 0 |
| **Artifact Validation** | Added `scripts/validate_artifacts.py` for post-build artifact verification |

### Files Changed

- `.github/workflows/torshield-ir.yml` — 4 heredoc fixes, artifact validation
- `.github/workflows/ai_gateway_health_check.yml` — 3 heredoc fixes
- `.github/workflows/ai_self_healing.yml` — 1 heredoc fix
- `.github/workflows/ai_bridge_reranker.yml` — pip install fix
- `install.sh` — `sudo rm -rf` guard
- `setup_env.sh` — `sudo rm -rf` guard
- `ml_predictor.py` — pickle → json + integrity check
- `scripts/security_scan.py` — yaml.safe_load
- `tests/test_neural_anti_dpi_v3.py` — NEW: 74 tests
- `tests/test_e2e.py` — NEW: 34 tests
- `tests/test_integration.py` — NEW: 39 tests

---

## v14.0 — Audit & Quality Hardening (2026-06-11)

### Overview

Quality-focused release adding static analysis, dependency validation, and dead code detection tooling.

### New Features

| Change | Description |
|--------|-------------|
| **Security Scanner** | Added `scripts/security_scan.py` — scans for hardcoded keys, eval/exec, pickle, yaml.load, weak crypto, SQL injection, curl pipe sh, dangerous rm |
| **Dependency Validator** | Added `scripts/validate_dependencies.py` — validates Python, Go, Rust, and Zig dependencies |
| **Dead Code Auditor** | Added `scripts/audit_dead_code.py` — detects unused imports, variables, functions, and duplicate code blocks |
| **Full Audit Runner** | Added `scripts/run_full_audit.py` — orchestrates all scans, produces `data/full_audit_report.json` |

### Quality Improvements

| Change | Description |
|--------|-------------|
| **Python Syntax Check** | All 93 Python files pass `py_compile` validation |
| **YAML Linting** | All workflow YAMLs validated with `yaml.safe_load()` |
| **Requirements Validation** | Added custom validation step in quality gate workflow |

### Reports Generated

- `data/security_report.json` — 66 issues found (2 critical, 58 high, 4 medium, 2 low)
- `data/dependency_report.json` — 4 missing Python packages identified
- `data/dead_code_report.json` — 244 unused imports, 472 unused variables, 86 unused functions

---

## v13.0 — Monitoring & Observability (2026-06-10)

### Overview

Major release focused on monitoring infrastructure, health check accuracy, and removing deprecated configurations.

### Bug Fixes

| Change | Description |
|--------|-------------|
| **Health Check Source Tracking** | Fixed health check miscounting LocalAIEngine responses as primary provider successes. Added `_last_response_source` tracking (`"primary"` vs `"local_fallback"`). |
| **Deprecated Env Var Removal** | Removed `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24` from all workflow files. This variable was generating 3 deprecation warning annotations per run. |
| **Auth Failure No-Retry** | Added `AUTH_FAILURE_HTTP_CODES = {401, 403}` to prevent retrying authentication failures that won't self-resolve. |
| **Wrong Response Detection** | `WRONG_RESPONSE` from any provider is now treated as a failure, not just degraded. |

### New Features

| Change | Description |
|--------|-------------|
| **Provider Dashboard** | Added `monitoring/provider_dashboard.py` — real-time provider health and performance dashboard |
| **Structured Logging** | Added `monitoring/structured_logging.py` — structured JSON logging with FailureAnalytics |
| **Health Check Module** | Added `monitoring/health_check.py` — re-exports from `scripts/ai_gateway_health_check.py` for organized access |
| **Circuit Breaker** | Integrated `ProviderCircuitBreaker` into all provider classes |
| **Exponential Backoff Retry** | Added `ExponentialBackoffRetry` utility for health check operations |

### API Changes

| Change | Description |
|--------|-------------|
| `TorShieldAIGateway.is_primary_healthy()` | NEW — Returns `True` only if a real AI provider answered |
| `TorShieldAIGateway._last_response_source` | NEW — Tracks `"primary"` or `"local_fallback"` |
| `TorShieldAIGateway._stats` | NEW — Monitoring counters for total, primary, fallback, wrong |
| `AUTH_FAILURE_HTTP_CODES` | NEW — `{401, 403}` — never retry these |
| `ProviderCircuitBreaker` | NEW — Per-provider circuit breaker with automatic recovery |

### Workflow Changes

| Change | Description |
|--------|-------------|
| **Health Check Exit Codes** | Exit 0: primary ok, Exit 1: all primary failed (degraded), Exit 2: env vars missing |
| **Pre-flight Secret Validation** | Added secret mapping verification step before health check |

---

## v12.0 — Provider Fix Release (2026-06-09)

### Overview

Critical hotfix release addressing the three primary AI provider integration failures that caused cascading outages.

### Bug Fixes (Critical)

| Change | Description |
|--------|-------------|
| **Cerebras Model Fix** | Changed `DEFAULT_MODEL` from `"llama3.3-70b"` (invalid) to `"llama3.1-8b"` (valid). Added `CEREBRAS_MODELS` fallback list and `_discover_models()` endpoint auto-discovery. |
| **CF Gateway URL Fix** | Added `_validate_gateway_url()` that validates `https://gateway.ai.cloudflare.com/v1/` format. Added `_probe_gateway()` for reachability check. URL path now includes `account_id` for workers-ai routing. |
| **Portkey Auth Fix** | Added `_validate_portkey_key()` checking `pk-` prefix format. Added support for `PORTKEY_VIRTUAL_KEY_{1,2,3}`. Enhanced 401 diagnostics with specific failure categories. |
| **User-Agent Fix** | Added proper User-Agent header to bypass Cloudflare bot protection (error code 1010). |
| **Model Selector UUID Fix** | Model selector now filters UUID-format IDs that cause 400 "No route for URI" errors. |

### New Features

| Change | Description |
|--------|-------------|
| **Cross-Slot Model Skip** | Added `_failed_models` set to prevent cascade failures across Cloudflare slots |
| **Dynamic Model Selection** | `CloudflareModelSelector` with live API fetch, multi-factor scoring, and offline fallback |
| **Bot Protection Retry** | Cloudflare 403 with "error code: 1010" is now retryable with backoff |

### Provider Waterfall (established in v12.0)

```
1. Cerebras        — 2100 tokens/sec (fastest)
2. CF-AI-Gateway   — cached, 11x quota via gateway URLs
3. CF-Workers-AI   — direct, no caching
4. Portkey         — meta-router fallback
5. LocalAIEngine   — zero-dependency rule-based (ALWAYS available, DEGRADED)
```

---

## v11.0 — Anti-Censorship V2 (2026-06-07)

### Overview

Major feature release adding V2 anti-censorship and anti-DPI modules for Iran-specific bypass strategies.

### New Features

| Change | Description |
|--------|-------------|
| **V2 Anti-Censorship Engine** | `iran_smart_anti_filter_v2.py` — ISP-specific bypass, temporal analysis, NIN survival |
| **V2 Anti-DPI Module** | `ai_anti_dpi_iran_v2.py` — Enhanced DPI detection and evasion |
| **Smart Bypass Engine** | `smart_bypass_engine.py` — Adaptive transport selection with scoring |
| **Iran Intelligence** | `iran_intelligence.py` — AI-powered censorship pattern analysis |
| **Iran Auto-Defense** | `iran_auto_defense.py` — Automated defensive response to censorship changes |

### ISP-Specific Strategies

| ISP | Detection Level | Recommended Transport |
|-----|----------------|----------------------|
| MCI (Hamrah Aval) | Aggressive (SNI + JA3 + ML) | WebTunnel CDN-fronted |
| IRANCELL | Moderate (SNI filtering) | obfs4 port 443, iat-mode=2 |
| Rightel | Light filtering | Snowflake, meek-lite |
| Shatel | DSL-specific | obfs4 port 443 |
| Asiatech | ISP patterns | WebTunnel, Snowflake |

### Temporal Analysis

- Track when blocking intensifies (political events, evenings)
- Recommend optimal connection windows
- Predict next high-blocking period

---

## v10.0 — Foundation Release (2026-06-05)

### Overview

Initial production-ready release with core bridge collection, testing, and AI gateway integration.

### Core Features

| Change | Description |
|--------|-------------|
| **Bridge Collection Pipeline** | Multi-source bridge collection: TorProject scraper, BridgeDB API, MOAT, Telegram, GitHub, static lists |
| **Bridge Testing** | Parallel bridge testing with configurable workers, timeouts, and retries |
| **AI Gateway** | `TorShieldAIGateway` with provider waterfall (Cerebras → CF → Portkey → LocalAIEngine) |
| **Model Selector** | `CloudflareModelSelector` with live API discovery and capability scoring |
| **Local AI Fallback** | `LocalAIEngine` — rule-based intelligence with Iran DPI knowledge base |
| **Account Rotator** | `AccountRotator` for multi-slot Cloudflare API token rotation |
| **Auto Debug System** | `auto_debug_system.py` — automated failure diagnosis and patch suggestion |
| **Self-Healing** | `self_heal.py` — GitHub Actions workflow failure auto-repair |

### Multi-Language Components

| Language | Component | Description |
|----------|-----------|-------------|
| Python | Core pipeline + AI gateway | Primary codebase |
| Go | `go_tester/`, `cmd/` | Bridge testing tools |
| Rust | `bridge-probe/` | High-performance transport handshake prober |
| Zig | `zig-scanner/` | Static binary network scanner |

### Iran-Specific Features

- NIN (National Internet Network) shutdown detection and survival mode
- ISP-specific bridge scoring
- DPI evasion strategies
- Censorship monitoring and alerting
- Farsi documentation (`README_FA.md`)

---

## Summary of All Changes by Category

### Provider Integration

| Version | Change | Impact |
|---------|--------|--------|
| v12.0 | Cerebras model name corrected | Eliminated 404 errors |
| v12.0 | CF Gateway URL validation + account_id | Eliminated 400 errors |
| v12.0 | Portkey key validation + virtual keys | Eliminated 401 errors |
| v12.0 | User-Agent header for bot protection | Eliminated 403/1010 errors |
| v12.0 | Cross-slot model skip | Reduced cascade failures |
| v13.0 | Auth failure no-retry (401/403) | Prevented wasted retry cycles |
| v13.0 | Circuit breaker per provider | Automatic provider isolation |

### Anti-Censorship

| Version | Change | Impact |
|---------|--------|--------|
| v10.0 | NIN shutdown survival | Basic internet-cut mode |
| v11.0 | V2 anti-censorship engine | ISP-specific bypass, temporal analysis |
| v11.0 | V2 anti-DPI module | Enhanced evasion |
| v11.0 | Smart bypass engine | Adaptive transport selection |
| v15.0 | V3 Neural Traffic Morphing | Packet-length padding, IAT jitter |
| v15.0 | V3 JA3/JA3S Rotation | Dynamic TLS fingerprint rotation |
| v15.0 | V3 ECH Fallback Router | Encrypted Client Hello with PQ scoring |

### Monitoring & Observability

| Version | Change | Impact |
|---------|--------|--------|
| v13.0 | Health check source tracking | Accurate primary vs fallback status |
| v13.0 | Provider dashboard | Real-time visibility |
| v13.0 | Structured logging | Machine-parseable logs |
| v13.0 | Exponential backoff retry | Resilient health checks |

### Quality & Testing

| Version | Change | Impact |
|---------|--------|--------|
| v14.0 | Security scanner | 66 issues identified |
| v14.0 | Dependency validator | 4 missing packages found |
| v14.0 | Dead code auditor | 244 unused imports flagged |
| v15.0 | Test suite → 314 tests | Comprehensive coverage |
| v15.0 | Workflow heredoc fixes | All workflows passing |

### Configuration

| Version | Change | Impact |
|---------|--------|--------|
| v13.0 | Removed deprecated env var | Eliminated 3 warning annotations |
| v15.0 | `sudo rm -rf` guards | Prevented accidental deletion |
| v15.0 | `pickle.load()` → `json.load()` | Eliminated deserialization risk |
| v15.0 | `yaml.safe_load()` migration | Eliminated YAML injection risk |
