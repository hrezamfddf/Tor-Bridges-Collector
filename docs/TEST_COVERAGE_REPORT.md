# Test Coverage Report — Tor-Bridges-Collector

> **Project**: Tor-Bridges-Collector (TorShield-IR)  
> **Report Date**: 2026-06-12  
> **Test Framework**: pytest 9.0.2  
> **Total Tests**: 314  
> **Status**: ALL PASSING (314 passed, 51 subtests passed)  

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Test Suite Overview](#test-suite-overview)
3. [Unit Tests](#unit-tests)
4. [Integration Tests](#integration-tests)
5. [End-to-End Tests](#end-to-end-tests)
6. [V3 Anti-DPI Tests](#v3-anti-dpi-tests)
7. [CI Workflow Tests](#ci-workflow-tests)
8. [Coverage by Module](#coverage-by-module)
9. [Test Execution Results](#test-execution-results)
10. [Test Writing Guidelines](#test-writing-guidelines)

---

## Executive Summary

The Tor-Bridges-Collector project maintains a comprehensive test suite of **314 tests** across **10 test files**, covering all major components from individual provider classes to full end-to-end workflows. All tests pass successfully.

| Metric | Value |
|--------|-------|
| Total Tests | 314 |
| Test Files | 10 |
| Passed | 314 |
| Failed | 0 |
| Subtests Passed | 51 |
| Execution Time | 30.00s |
| Pass Rate | 100% |

---

## Test Suite Overview

| Test File | Category | Tests | Description |
|-----------|----------|-------|-------------|
| `test_providers.py` | Unit | 37 | AI provider classes (Cerebras, CF, Portkey) |
| `test_gateway.py` | Unit | 18 | Gateway waterfall and fallback behavior |
| `test_model_selector.py` | Unit | 18 | Cloudflare model discovery and scoring |
| `test_health_check.py` | Unit | 22 | Health check utilities and source tracking |
| `test_iran_modules.py` | Unit | 42 | Iran anti-censorship and anti-DPI V2 modules |
| `test_circuit_breaker.py` | Unit | 20 | Provider circuit breaker lifecycle |
| `test_ci_workflows.py` | Unit | 10 | GitHub Actions workflow YAML validation |
| `test_integration.py` | Integration | 39 | Multi-component interaction tests |
| `test_e2e.py` | E2E | 34 | Complete workflow end-to-end tests |
| `test_neural_anti_dpi_v3.py` | Unit (V3) | 74 | Neural Anti-DPI V3 subsystem tests |

### Distribution

```
Unit Tests (7 files)     ████████████████████████████████████████  167  (53.2%)
Integration Tests (1)    ██████████████████  39  (12.4%)
E2E Tests (1)           ███████████████  34  (10.8%)
V3 Anti-DPI Tests (1)   ██████████████████████████████████  74  (23.6%)
```

---

## Unit Tests

### test_providers.py — 37 Tests

Tests for the AI provider layer (`torshield_ai_gateway/providers.py`).

| Test Class | Count | Description |
|------------|-------|-------------|
| `TestCerebrasProvider` | 6 | Cerebras API key validation, model discovery, fallback list |
| `TestCFWorkersAIProvider` | 7 | Cloudflare Workers AI URL construction, token rotation, model selection |
| `TestCFAIGatewayProvider` | 3 | CF AI Gateway URL validation (valid, no-https, trailing slash) |
| `TestPortkeyProvider` | 5 | Portkey key validation (pk- prefix, empty, newline, valid, no-key) |
| `TestModelFallbackChain` | 9 | Retryable codes, auth failure codes, backoff delay, key masking, stable models |
| `TestExtractText` | 3 | Response text extraction (OpenAI format, CF format, string fallback) |
| `TestRetryMechanism` | 4 | Exponential backoff, jitter, max delay cap |

**Key test cases**:

```python
# Auth failures are NEVER retried
def test_401_not_retried_in_post_json(self):
    """401 should not be retried — auth failures won't fix themselves."""
    assert 401 in AUTH_FAILURE_HTTP_CODES
    assert 401 not in RETRYABLE_HTTP_CODES

# Portkey key validation
def test_portkey_key_validation_no_prefix(self):
    """Keys without pk- prefix should be rejected."""
    with pytest.raises(ValueError):
        validate_portkey_key("sk-invalid-key")

# CF Gateway URL validation
def test_url_validation_invalid_no_https(self):
    """Non-HTTPS URLs should be rejected."""
    with pytest.raises(ValueError):
        validate_gateway_url("http://gateway.ai.cloudflare.com/v1/abc/gw")
```

---

### test_gateway.py — 18 Tests

Tests for the `TorShieldAIGateway` class (`torshield_ai_gateway/gateway.py`).

| Test Class | Count | Description |
|------------|-------|-------------|
| `TestGatewayInit` | 4 | Provider initialization, priority order, selector creation |
| `TestProviderWaterfall` | 6 | Provider fallback chain, retry across providers |
| `TestFallbackBehavior` | 4 | LocalAIEngine fallback, degraded mode flag |
| `TestResponseSourceTracking` | 4 | Primary vs fallback source tracking |

**Key test cases**:

```python
# Gateway correctly tracks response source
def test_primary_source_tracked(self):
    """When Cerebras responds, source is 'primary'."""
    gateway = TorShieldAIGateway()
    # ... mock Cerebras response ...
    assert gateway._last_response_source == "primary"

# Fallback activates when all primary providers fail
def test_fallback_activation(self):
    """LocalAIEngine activates when all primary providers fail."""
    gateway = TorShieldAIGateway()
    # ... mock all primary failures ...
    assert gateway._last_response_source == "local_fallback"
```

---

### test_model_selector.py — 18 Tests

Tests for `CloudflareModelSelector` (`torshield_ai_gateway/model_selector.py`).

| Test Class | Count | Description |
|------------|-------|-------------|
| `TestModelScoring` | 6 | Multi-factor capability scoring algorithm |
| `TestModelSelection` | 5 | Best model selection, task affinity, fallback |
| `TestCacheBehavior` | 3 | TTL-based cache, refresh, offline fallback |
| `TestUUIDFiltering` | 4 | UUID-format model IDs filtered (prevent 400 errors) |

---

### test_health_check.py — 22 Tests

Tests for health check utilities and source tracking.

| Test Class | Count | Description |
|------------|-------|-------------|
| `TestExponentialBackoffRetry` | 5 | Retry with exponential backoff and jitter |
| `TestAuthFailureDiagnostics` | 6 | 401/403 diagnosis and categorization |
| `TestEnvVarValidator` | 5 | Environment variable mapping validation |
| `TestSourceTracking` | 6 | Primary vs fallback response tracking |

---

### test_iran_modules.py — 42 Tests

Tests for Iran-specific anti-censorship and anti-DPI modules.

| Test Class | Count | Description |
|------------|-------|-------------|
| `TestIranAntiDPIV2` | 12 | V2 anti-DPI detection and evasion |
| `TestIranSmartAntiFilterV2` | 10 | ISP-specific bypass, temporal analysis, NIN survival |
| `TestIranIntelligence` | 8 | AI-powered censorship pattern analysis |
| `TestIranAutoDefense` | 6 | Automated defensive response |
| `TestSmartBypassEngine` | 6 | Adaptive transport selection |

---

### test_circuit_breaker.py — 20 Tests

Tests for `ProviderCircuitBreaker` — per-provider circuit breaker with automatic recovery.

| Test Class | Count | Description |
|------------|-------|-------------|
| `TestProviderCircuitBreaker` | 20 | Full lifecycle: closed → open → half-open → closed |

**Key test cases**:

```python
def test_closed_allows_all_requests(self):
    """Circuit in CLOSED state allows all requests through."""

def test_exact_threshold_triggers_open(self):
    """Reaching the failure threshold transitions to OPEN."""

def test_beyond_threshold_stays_open(self):
    """Once OPEN, additional failures don't change state."""

def test_half_open_allows_probe(self):
    """HALF-OPEN allows one probe request through."""

def test_full_lifecycle(self):
    """Complete lifecycle: CLOSED → OPEN → (wait) → HALF-OPEN → CLOSED."""
```

---

### test_ci_workflows.py — 10 Tests

Tests for GitHub Actions workflow YAML validity.

| Test Class | Count | Description |
|------------|-------|-------------|
| `TestWorkflowYAMLValidity` | 7 | YAML syntax, required keys, job structure, deprecated env vars |
| `TestWorkflowScriptReferences` | 1 | Referenced Python scripts exist |
| `TestWorkflowTriggers` | 2 | Triggers present, scheduled workflows have cron |

**Key test cases**:

```python
def test_yaml_syntax_valid(self):
    """All workflow YAML files parse without errors."""

def test_no_deprecated_node24_env_var(self):
    """FORCE_JAVASCRIPT_ACTIONS_TO_NODE24 should NOT be present."""

def test_required_top_level_keys(self):
    """Each workflow has 'name' and 'on' keys."""
```

---

## Integration Tests

### test_integration.py — 39 Tests

Tests for multi-component interactions, verifying that modules work correctly together.

| Test Category | Count | Description |
|---------------|-------|-------------|
| Provider ↔ Gateway | 8 | Provider integration with gateway waterfall |
| Gateway ↔ Model Selector | 7 | Model selection affects gateway routing |
| Gateway ↔ Circuit Breaker | 6 | Circuit breaker isolates failing providers |
| Health Check ↔ Gateway | 6 | Health check correctly reports gateway status |
| Anti-DPI ↔ Gateway | 6 | Anti-DPI strategies integrate with AI gateway |
| Iran Modules ↔ Gateway | 6 | Iran-specific modules use gateway for analysis |

**Test methodology**: Integration tests use mock HTTP responses to simulate provider behavior while testing the actual interaction patterns between components.

---

## End-to-End Tests

### test_e2e.py — 34 Tests

Tests for complete workflow execution from start to finish.

| Test Category | Count | Description |
|---------------|-------|-------------|
| Full Pipeline | 8 | Complete bridge collection → testing → scoring pipeline |
| AI Gateway E2E | 8 | Full AI gateway request lifecycle |
| Health Check E2E | 6 | Complete health check with exit code verification |
| Anti-Censorship E2E | 6 | Full anti-censorship analysis workflow |
| Iran-Specific E2E | 6 | Iran-specific NIN detection and bypass workflow |

**Test methodology**: E2E tests simulate complete user workflows with mock data, verifying that all components chain together correctly and produce expected outputs.

---

## V3 Anti-DPI Tests

### test_neural_anti_dpi_v3.py — 74 Tests

The largest test file, covering the Neural Anti-DPI V3 module (`torshield_ai_gateway/neural_anti_dpi_v3.py`).

| Test Class | Count | Description |
|------------|-------|-------------|
| `TestNeuralTrafficMorphing` | 18 | Packet-length padding, IAT timing jitter, target profiles |
| `TestJA3RotationEngine` | 16 | TLS fingerprint rotation, fingerprint database, randomization |
| `TestECHFallbackRouter` | 16 | Encrypted Client Hello, PQ scoring, fallback chains |
| `TestAntiDPIV3Orchestrator` | 14 | Unified orchestrator, V2 fallback integration, status reporting |
| `TestV3StatePersistence` | 10 | State file save/load, data integrity |

**Key test cases**:

```python
# Neural traffic morphing defeats L1 CNN classifiers
def test_packet_padding_to_target_length(self):
    """Packets should be padded to match target traffic profile."""

# IAT jitter defeats L2 LSTM analyzers
def test_iat_jitter_within_bounds(self):
    """Inter-arrival timing jitter should stay within target distribution."""

# JA3 rotation cycles through fingerprints
def test_rotation_cycles_through_database(self):
    """Should cycle through Chrome, Firefox, Safari, Edge profiles."""

# ECH fallback chain
def test_ech_to_domain_fronting_fallback(self):
    """When ECH fails, should fall back to domain fronting."""

# PQ-aware bridge scoring
def test_kyber_bridge_scores_higher(self):
    """Post-quantum (Kyber/ML-KEM) bridges should score higher."""
```

---

## CI Workflow Tests

### test_ci_workflows.py — 10 Tests

| Test | Description |
|------|-------------|
| `test_workflow_files_exist` | All 4 expected workflow files exist |
| `test_yaml_syntax_valid` | All YAML files parse without errors |
| `test_required_top_level_keys` | Each workflow has `name` and `on` keys |
| `test_jobs_have_runs_on` | Every job specifies `runs-on` |
| `test_jobs_have_steps` | Every job has at least one step |
| `test_no_deprecated_node24_env_var` | `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24` not present |
| `test_no_inline_python_c_flag` | No `-c` flag inline Python in workflow steps |
| `test_referenced_python_scripts_exist` | All referenced Python scripts in workflows exist |
| `test_workflows_have_triggers` | Each workflow has at least one trigger |
| `test_scheduled_workflows_have_cron` | Scheduled workflows define cron expressions |

---

## Coverage by Module

| Module | Test File | Tests | Key Coverage Areas |
|--------|-----------|-------|--------------------|
| `torshield_ai_gateway/providers.py` | `test_providers.py` | 37 | URL validation, key validation, retry logic, auth failures |
| `torshield_ai_gateway/gateway.py` | `test_gateway.py` | 18 | Provider waterfall, fallback, source tracking |
| `torshield_ai_gateway/model_selector.py` | `test_model_selector.py` | 18 | Model scoring, selection, caching, UUID filtering |
| `torshield_ai_gateway/local_ai_engine.py` | `test_gateway.py` | (18) | Fallback activation, degraded mode |
| `torshield_ai_gateway/ai_anti_dpi_iran_v2.py` | `test_iran_modules.py` | (42) | DPI detection, evasion |
| `torshield_ai_gateway/iran_smart_anti_filter_v2.py` | `test_iran_modules.py` | (42) | ISP bypass, NIN survival |
| `torshield_ai_gateway/iran_intelligence.py` | `test_iran_modules.py` | (42) | Censorship analysis |
| `torshield_ai_gateway/iran_auto_defense.py` | `test_iran_modules.py` | (42) | Auto-defense responses |
| `torshield_ai_gateway/smart_bypass_engine.py` | `test_iran_modules.py` | (42) | Transport selection |
| `torshield_ai_gateway/neural_anti_dpi_v3.py` | `test_neural_anti_dpi_v3.py` | 74 | Traffic morphing, JA3 rotation, ECH, orchestrator |
| `monitoring/health_check.py` | `test_health_check.py` | 22 | Backoff retry, auth diagnostics, env validation |
| `ProviderCircuitBreaker` | `test_circuit_breaker.py` | 20 | Full lifecycle, custom timeout, flapping |
| `.github/workflows/*.yml` | `test_ci_workflows.py` | 10 | YAML validity, triggers, deprecated vars |
| Cross-module | `test_integration.py` | 39 | Multi-component interactions |
| Full pipeline | `test_e2e.py` | 34 | Complete workflows |

---

## Test Execution Results

```
=================== 314 passed, 51 subtests passed in 30.00s ===================
```

### Per-File Results

| Test File | Passed | Failed | Time |
|-----------|--------|--------|------|
| `test_providers.py` | 37 | 0 | ~3.2s |
| `test_gateway.py` | 18 | 0 | ~1.8s |
| `test_model_selector.py` | 18 | 0 | ~2.1s |
| `test_health_check.py` | 22 | 0 | ~2.4s |
| `test_iran_modules.py` | 42 | 0 | ~4.5s |
| `test_circuit_breaker.py` | 20 | 0 | ~1.6s |
| `test_ci_workflows.py` | 10 | 0 | ~1.2s |
| `test_integration.py` | 39 | 0 | ~5.8s |
| `test_e2e.py` | 34 | 0 | ~4.9s |
| `test_neural_anti_dpi_v3.py` | 74 | 0 | ~2.5s |

### Running the Tests

```bash
# Run all tests
python3 -m pytest tests/ -v

# Run with coverage
python3 -m pytest tests/ --cov=torshield_ai_gateway --cov-report=html

# Run a specific test file
python3 -m pytest tests/test_providers.py -v

# Run a specific test
python3 -m pytest tests/test_providers.py::TestPortkeyProvider::test_portkey_key_validation_valid -v

# Collect tests without running
python3 -m pytest tests/ --co -q
```

---

## Test Writing Guidelines

### Naming Convention

- Test files: `test_<module_name>.py`
- Test classes: `Test<ClassName>` or `Test<Feature>`
- Test methods: `test_<specific_behavior>`

### Structure

```python
class TestProviderCircuitBreaker:
    """Tests for the ProviderCircuitBreaker class."""

    def test_closed_allows_all_requests(self):
        """Circuit in CLOSED state allows all requests through."""
        cb = ProviderCircuitBreaker(failure_threshold=3, recovery_timeout=30)
        assert cb.state == "closed"
        assert cb.allow_request() is True
```

### Mocking External Dependencies

All tests that interact with external APIs use mocking:

```python
from unittest.mock import patch, MagicMock

@patch("urllib.request.urlopen")
def test_cerebras_success(self, mock_urlopen):
    """Test successful Cerebras API response."""
    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps({
        "choices": [{"message": {"content": "test response"}}]
    }).encode()
    mock_urlopen.return_value = mock_response
    # ... test logic ...
```

### What to Test

1. **Happy path**: Normal operation with valid inputs
2. **Error handling**: Invalid inputs, missing data, API errors
3. **Edge cases**: Empty strings, None values, boundary conditions
4. **Integration**: Component interactions
5. **Security**: Auth failures not retried, key validation
