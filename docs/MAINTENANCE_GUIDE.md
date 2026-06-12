# Maintenance Guide — Tor-Bridges-Collector

> **Project**: Tor-Bridges-Collector (TorShield-IR)  
> **Version**: v15.0 — Ultra-Quantum Edition  
> **Guide Date**: 2026-06-12  

---

## Table of Contents

1. [Project Structure Overview](#project-structure-overview)
2. [Module Descriptions](#module-descriptions)
3. [Adding New Providers](#adding-new-providers)
4. [Adding New Anti-Censorship Strategies](#adding-new-anti-censorship-strategies)
5. [Updating Model Catalogs](#updating-model-catalogs)
6. [Running Tests](#running-tests)
7. [Running Audits](#running-auds)
8. [Updating Dependencies](#updating-dependencies)
9. [Log Analysis](#log-analysis)
10. [Performance Monitoring](#performance-monitoring)

---

## Project Structure Overview

```
tor_project/
├── .github/workflows/        # GitHub Actions CI/CD workflows
│   ├── torshield-ir.yml          # Main pipeline (hourly)
│   ├── ai_gateway_health_check.yml  # Health check (every 6h)
│   ├── ai_self_healing.yml       # Auto-heal on failures
│   └── ai_bridge_reranker.yml    # AI bridge re-ranking
│
├── torshield_ai_gateway/     # Core AI gateway package
│   ├── __init__.py
│   ├── providers.py              # AI provider implementations
│   ├── gateway.py                # Unified gateway facade
│   ├── model_selector.py         # Dynamic model selection
│   ├── local_ai_engine.py        # Zero-dependency fallback
│   ├── rotator.py                # Multi-slot account rotation
│   ├── auto_debug.py             # Auto-debug engine
│   ├── ai_anti_dpi_iran_v2.py   # V2 Anti-DPI module
│   ├── iran_smart_anti_filter_v2.py  # V2 Anti-filter engine
│   ├── iran_intelligence.py      # AI censorship analysis
│   ├── iran_auto_defense.py      # Auto-defense system
│   ├── smart_bypass_engine.py    # Adaptive bypass engine
│   └── neural_anti_dpi_v3.py    # V3 Neural Anti-DPI
│
├── core/                     # Core pipeline modules
│   ├── __init__.py
│   ├── collector.py              # Bridge collection
│   ├── tester.py                 # Bridge testing
│   ├── scorer.py                 # Bridge scoring
│   ├── formatter.py              # Output formatting
│   ├── history.py                # History management
│   ├── notifier.py               # Notifications
│   ├── iran_detector.py          # Iran detection
│   ├── iran_dpi_shaper.py        # DPI traffic shaping
│   ├── nin_selector.py           # NIN bridge selection
│   ├── smart_iran_scorer.py      # Iran-specific scoring
│   ├── censorship_monitor.py     # Censorship monitoring
│   └── dt_utils.py               # Date/time utilities
│
├── sources/                  # Bridge collection sources
│   ├── __init__.py
│   ├── torproject.py             # bridges.torproject.org
│   ├── moat.py                   # MOAT API
│   ├── bridgedb_api.py           # BridgeDB API
│   ├── telegram_bridges.py       # Telegram channels
│   ├── github_bridges.py         # GitHub repositories
│   ├── static_bridges.py         # Static bridge lists
│   ├── direct_scraper.py         # Direct web scraping
│   └── legacy_scraper.py         # Legacy scraper
│
├── monitoring/               # Monitoring and observability
│   ├── __init__.py
│   ├── health_check.py           # Health check re-exports
│   ├── provider_dashboard.py     # Provider dashboard
│   └── structured_logging.py     # Structured JSON logging
│
├── scripts/                  # Utility scripts
│   ├── security_scan.py          # Security vulnerability scanner
│   ├── validate_dependencies.py  # Dependency validation
│   ├── audit_dead_code.py        # Dead code detection
│   ├── run_full_audit.py         # Full audit orchestrator
│   ├── ai_gateway_health_check.py # Health check utility
│   ├── ai_bridge_reranker.py     # Bridge re-ranking
│   ├── validate_artifacts.py     # Build artifact validation
│   ├── generate_architecture_docs.py
│   ├── generate_dependency_graph.py
│   ├── generate_deployment_report.py
│   └── generate_final_report.py
│
├── tests/                    # Test suite (314 tests)
│   ├── test_providers.py         # 37 tests
│   ├── test_gateway.py           # 18 tests
│   ├── test_model_selector.py    # 18 tests
│   ├── test_health_check.py      # 22 tests
│   ├── test_iran_modules.py      # 42 tests
│   ├── test_circuit_breaker.py   # 20 tests
│   ├── test_ci_workflows.py      # 10 tests
│   ├── test_integration.py       # 39 tests
│   ├── test_e2e.py               # 34 tests
│   └── test_neural_anti_dpi_v3.py # 74 tests
│
├── bridge-probe/             # Rust bridge prober
│   ├── Cargo.toml
│   └── src/ (main.rs, probe.rs, transport.rs)
│
├── go_tester/                # Go bridge tester
│   ├── go.mod
│   └── main.go
│
├── zig-scanner/              # Zig network scanner
│   ├── build.zig
│   └── src/main.zig
│
├── cmd/                      # Go command-line tools
│   ├── iran_tester/main.go
│   └── probe_scheduler/main.go
│
├── internal/                 # Go internal packages
│   ├── asn/iran_asns.go
│   ├── bridge/parser.go, tester.go
│   ├── ooni/client.go
│   ├── ipinfo/client.go
│   └── ripe/atlas.go
│
├── configs/                  # Configuration
│   └── env_template.sh
│
├── data/                     # Runtime data
├── export/                   # Exported bridge files
├── docs/                     # Documentation
├── reports/                  # Generated reports
├── packaging/                # Build packaging
│   └── build_package.sh
│
├── main.py                   # Main entry point
├── config.py                 # Configuration module
├── requirements.txt          # Python dependencies
├── go.mod                    # Go module definition
└── setup_env.sh              # Environment setup
```

---

## Module Descriptions

### AI Gateway (`torshield_ai_gateway/`)

| Module | Lines | Description |
|--------|-------|-------------|
| `providers.py` | 1264 | AI provider implementations (Cerebras, CF Workers AI, CF AI Gateway, Portkey). Includes circuit breaker, retry logic, auth validation. |
| `gateway.py` | 305 | Unified facade over all providers with waterfall fallback, source tracking, and monitoring counters. |
| `model_selector.py` | 1278 | Dynamic Cloudflare model discovery, multi-factor scoring, capability ranking, and offline fallback. |
| `local_ai_engine.py` | 781 | Zero-dependency rule-based AI fallback with Iran DPI knowledge base. Always available, always degraded. |
| `neural_anti_dpi_v3.py` | 1945 | V3 Neural Anti-DPI: traffic morphing, JA3/JA3S rotation, ECH fallback, PQ scoring. |
| `ai_anti_dpi_iran_v2.py` | ~1700 | V2 Anti-DPI: ML-based traffic analysis, DPI detection, evasion strategies. |
| `iran_smart_anti_filter_v2.py` | 1611 | V2 Anti-filter: ISP bypass, temporal analysis, NIN survival, adaptive transport. |
| `iran_intelligence.py` | ~500 | AI-powered censorship pattern analysis and prediction. |
| `iran_auto_defense.py` | ~400 | Automated defensive response to censorship changes. |
| `smart_bypass_engine.py` | ~1000 | Adaptive transport selection with scoring and effectiveness tracking. |
| `rotator.py` | ~300 | Multi-slot API token rotation for Cloudflare accounts. |
| `auto_debug.py` | ~500 | Automated failure diagnosis and patch suggestion. |

### Core Pipeline (`core/`)

| Module | Description |
|--------|-------------|
| `collector.py` | Multi-source bridge collection with deduplication |
| `tester.py` | Parallel bridge testing with configurable workers |
| `scorer.py` | Multi-factor bridge scoring |
| `smart_iran_scorer.py` | Iran-specific scoring with DPI awareness |
| `formatter.py` | Output formatting for bridge packs |
| `history.py` | Bridge history tracking and retention |
| `notifier.py` | Telegram and webhook notifications |
| `iran_detector.py` | Detect if running from Iran |
| `iran_dpi_shaper.py` | DPI traffic shaping for Iran |
| `nin_selector.py` | NIN shutdown bridge selection |
| `censorship_monitor.py` | Real-time censorship monitoring |
| `dt_utils.py` | Date/time utility functions |

---

## Adding New Providers

### Step 1: Create the Provider Class

Add a new provider class in `torshield_ai_gateway/providers.py`:

```python
class NewProvider:
    """New AI provider implementation."""
    
    PROVIDER_NAME = "new_provider"
    DEFAULT_MODEL = "default-model-name"
    MAX_NETWORK_RETRIES = 3
    
    def __init__(self, api_key: str = None, **kwargs):
        self._api_key = self._validate_key(api_key or os.environ.get("NEW_PROVIDER_API_KEY", ""))
        self._circuit_breaker = ProviderCircuitBreaker(
            failure_threshold=3,
            recovery_timeout=60
        )
    
    @staticmethod
    def _validate_key(key: str) -> str:
        """Validate API key format."""
        key = key.strip()
        if not key:
            raise ValueError("API key is required")
        return key
    
    def post_json(self, prompt: str, **kwargs) -> Optional[str]:
        """Send a prompt and return the response text."""
        if not self._circuit_breaker.allow_request():
            return None
        
        try:
            # Implement API call here
            response = self._make_api_call(prompt)
            self._circuit_breaker.record_success()
            return response
        except urllib.error.HTTPError as e:
            if e.code in AUTH_FAILURE_HTTP_CODES:
                self._circuit_breaker.record_failure()
                return None  # Never retry auth failures
            if e.code in RETRYABLE_HTTP_CODES:
                # Retry with backoff
                return self._retry_request(prompt)
            self._circuit_breaker.record_failure()
            return None
    
    def _make_api_call(self, prompt: str) -> str:
        """Make the actual API call."""
        # Implement HTTP request
        pass
    
    def _retry_request(self, prompt: str) -> Optional[str]:
        """Retry with exponential backoff."""
        for attempt in range(self.MAX_NETWORK_RETRIES):
            delay = min(
                RETRY_BASE_DELAY_SEC * (2 ** attempt) + random.uniform(0, RETRY_JITTER_SEC),
                RETRY_MAX_DELAY_SEC
            )
            time.sleep(delay)
            try:
                return self._make_api_call(prompt)
            except urllib.error.HTTPError as e:
                if e.code in AUTH_FAILURE_HTTP_CODES:
                    return None
                continue
        return None
```

### Step 2: Register with the Gateway

Add the provider to `TorShieldAIGateway` in `gateway.py`:

```python
class TorShieldAIGateway:
    PROVIDER_PRIORITY = [
        "cerebras",
        "cloudflare_ai_gateway",
        "cloudflare_workers_ai",
        "portkey",
        "new_provider",  # Add here — position determines priority
    ]
    
    def _init_providers(self):
        # ... existing providers ...
        
        # New provider
        new_key = os.environ.get("NEW_PROVIDER_API_KEY", "")
        if new_key:
            from .providers import NewProvider
            self._providers["new_provider"] = NewProvider(api_key=new_key)
```

### Step 3: Add Tests

Create tests in `tests/test_providers.py`:

```python
class TestNewProvider:
    """Tests for NewProvider."""
    
    def test_key_validation_valid(self):
        """Valid key should be accepted."""
        provider = NewProvider(api_key="valid-key")
        assert provider._api_key == "valid-key"
    
    def test_key_validation_empty(self):
        """Empty key should be rejected."""
        with pytest.raises(ValueError):
            NewProvider(api_key="")
    
    def test_circuit_breaker_integration(self):
        """Circuit breaker should track failures."""
        provider = NewProvider(api_key="test-key")
        assert provider._circuit_breaker.state == "closed"
```

### Step 4: Add Environment Variable

Add to `configs/env_template.sh`:

```bash
# ─────────────────────────────────────────────────────────────────────────────
# AI PROVIDER: New Provider
# ─────────────────────────────────────────────────────────────────────────────
NEW_PROVIDER_API_KEY=""               # [RECOMMENDED] New Provider API key
```

### Step 5: Add to Workflow Secrets

Add to all workflow files that need the provider:

```yaml
env:
  NEW_PROVIDER_API_KEY: ${{ secrets.NEW_PROVIDER_API_KEY }}
```

---

## Adding New Anti-Censorship Strategies

### Step 1: Understand the V2/V3 Architecture

The anti-censorship system is layered:

```
V3 (neural_anti_dpi_v3.py)
  ├── NeuralTrafficMorphing
  ├── JA3RotationEngine
  ├── ECHFallbackRouter
  └── AntiDPIV3Orchestrator
       │
       └── Falls back to V2 (ai_anti_dpi_iran_v2.py)
            ├── ML traffic analysis
            ├── DPI detection
            └── Evasion strategies
```

### Step 2: Add a New Strategy Module

Create a new module in `torshield_ai_gateway/`:

```python
# torshield_ai_gateway/your_new_strategy.py
"""Your New Strategy — Description

ADDITIVE ONLY — all existing features remain intact.
"""

from __future__ import annotations
import logging
from typing import Dict, Any, Optional

log = logging.getLogger("torshield.ai.your_strategy")

class YourNewStrategy:
    """New anti-censorship strategy implementation."""
    
    def __init__(self):
        self._active = True
        log.info("[YourStrategy] Initialized")
    
    def analyze(self, traffic_info: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze traffic and return evasion recommendations."""
        # Implement your strategy
        return {
            "strategy": "your_new_strategy",
            "recommendation": "...",
            "confidence": 0.85,
        }
    
    def get_status(self) -> Dict[str, Any]:
        """Return current status of the strategy."""
        return {
            "active": self._active,
            "strategy": "your_new_strategy",
        }
```

### Step 3: Integrate with the Orchestrator

Add to `AntiDPIV3Orchestrator` in `neural_anti_dpi_v3.py`:

```python
class AntiDPIV3Orchestrator:
    def __init__(self):
        # ... existing subsystems ...
        try:
            from .your_new_strategy import YourNewStrategy
            self._your_strategy = YourNewStrategy()
            self._your_strategy_available = True
        except ImportError:
            self._your_strategy = None
            self._your_strategy_available = False
    
    def analyze_and_evade(self, traffic_info):
        """Unified analysis with all subsystems."""
        result = {}
        
        # Existing subsystems
        result["traffic_morphing"] = self._traffic_morphing.analyze(traffic_info)
        result["ja3_rotation"] = self._ja3_engine.get_next_fingerprint()
        result["ech_fallback"] = self._ech_router.resolve(traffic_info)
        
        # New strategy
        if self._your_strategy_available:
            result["your_strategy"] = self._your_strategy.analyze(traffic_info)
        
        return result
```

### Step 4: Add Tests

```python
# tests/test_iran_modules.py (add to existing file)

class TestYourNewStrategy:
    """Tests for YourNewStrategy."""
    
    def test_initialization(self):
        strategy = YourNewStrategy()
        assert strategy._active is True
    
    def test_analysis_returns_valid_structure(self):
        strategy = YourNewStrategy()
        result = strategy.analyze({})
        assert "strategy" in result
        assert "recommendation" in result
        assert 0 <= result["confidence"] <= 1
```

### Step 5: Add ISP-Specific Configuration

If the strategy is ISP-specific, add it to `iran_smart_anti_filter_v2.py`:

```python
_ISP_STRATEGIES = {
    # ... existing ISPs ...
    "NEW_ISP": {
        "name": "New ISP Name",
        "detection_methods": ["..."],
        "blocks": ["..."],
        "bypasses": ["..."],
        "your_strategy_config": {
            "param1": "value1",
        }
    }
}
```

---

## Updating Model Catalogs

### Cloudflare Models

The `CloudflareModelSelector` automatically discovers models via the CF API. However, the offline fallback list (`CF_STABLE_MODELS`) should be updated periodically:

1. **Check current stable models** in `torshield_ai_gateway/providers.py`:

```python
CF_STABLE_MODELS = [
    "@cf/meta/llama-3.1-8b-instruct",
    "@cf/meta/llama-3.2-11b-vision-instruct",
    "@cf/mistral/mistral-7b-instruct-v0.1",
    "@cf/meta/llama-3.2-3b-instruct",
    "@cf/meta/llama-3.2-1b-instruct",
]
```

2. **Check Cloudflare's current model list**:
```bash
curl -s "https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/models/search" \
  -H "Authorization: Bearer {api_token}" | python3 -m json.tool | grep '"id"'
```

3. **Update the stable models list** with current free-tier models

4. **Update the model scoring tiers** in `model_selector.py`:
```python
_CAPABILITY_TIERS = {
    # Update with new model tier assignments
    "@cf/meta/llama-4-8b-instruct": "tier1",  # New model
}
```

### Cerebras Models

Update the `CEREBRAS_MODELS` fallback list in `providers.py`:

```python
CEREBRAS_MODELS = ["llama3.1-8b", "llama3.1-70b", "llama-3.3-70b"]
# Add new models as they become available
```

### Portkey Models

Update the `DEFAULT_MODEL` in the Portkey provider:

```python
# In the Portkey provider class
DEFAULT_MODEL = "meta/llama-3.1-70b-instruct"
```

---

## Running Tests

### Full Test Suite

```bash
# Run all 314 tests
python3 -m pytest tests/ -v

# With coverage report
python3 -m pytest tests/ --cov=torshield_ai_gateway --cov-report=html

# With detailed output
python3 -m pytest tests/ -v --tb=long
```

### Specific Test Categories

```bash
# Unit tests only
python3 -m pytest tests/test_providers.py tests/test_gateway.py tests/test_model_selector.py \
  tests/test_health_check.py tests/test_circuit_breaker.py -v

# Integration tests
python3 -m pytest tests/test_integration.py -v

# E2E tests
python3 -m pytest tests/test_e2e.py -v

# Iran-specific tests
python3 -m pytest tests/test_iran_modules.py tests/test_neural_anti_dpi_v3.py -v

# CI workflow validation
python3 -m pytest tests/test_ci_workflows.py -v
```

### Running Single Tests

```bash
# Specific test class
python3 -m pytest tests/test_providers.py::TestPortkeyProvider -v

# Specific test method
python3 -m pytest tests/test_providers.py::TestPortkeyProvider::test_portkey_key_validation_valid -v

# With print output
python3 -m pytest tests/test_providers.py -v -s
```

### Test Collection (dry run)

```bash
# List all tests without running
python3 -m pytest tests/ --co -q

# Count tests
python3 -m pytest tests/ --co -q | wc -l
```

---

## Running Audits

### Individual Audit Scripts

```bash
# Security scan
python3 scripts/security_scan.py --output data/security_report.json

# Dependency validation
python3 scripts/validate_dependencies.py --output data/dependency_report.json

# Dead code audit
python3 scripts/audit_dead_code.py --output data/dead_code_report.json
```

### Full Audit

```bash
# Run all audits in sequence
python3 scripts/run_full_audit.py

# Output: data/full_audit_report.json
```

### Full Audit Report

The full audit produces a comprehensive JSON report at `data/full_audit_report.json`:

```json
{
  "audit_timestamp": "2026-06-12T10:25:17+00:00",
  "elapsed_seconds": 25.02,
  "overall_status": "warning",
  "steps": {
    "syntax_check": "ok",
    "dead_code_audit": "ok",
    "security_scan": "ok",
    "dependency_validation": "warning",
    "yaml_validation": "ok",
    "test_runner": "skipped"
  },
  "summary_statistics": {
    "syntax_errors": 0,
    "dead_code": { ... },
    "security": { ... },
    "dependencies": { ... }
  }
}
```

### Verbose Output

```bash
# Security scan with verbose output
python3 scripts/security_scan.py --verbose

# Dependency validation with verbose output
python3 scripts/validate_dependencies.py --verbose
```

---

## Updating Dependencies

### Python

```bash
# Check for outdated packages
pip list --outdated

# Update a specific package
pip install --upgrade requests

# Update all packages (review changes first!)
pip list --outdated --format=freeze | cut -d= -f1 | xargs -n1 pip install -U

# Regenerate requirements.txt with current versions
pip freeze > requirements-lock.txt

# After updating, run tests
python3 -m pytest tests/ -v
```

### Go

```bash
# Update Go dependencies
cd go_tester && go get -u ./... && go mod tidy

# Update root module
go get -u ./... && go mod tidy
```

### Rust

```bash
# Update Cargo dependencies
cd bridge-probe && cargo update

# Check for outdated dependencies
cargo outdated  # Requires: cargo install cargo-outdated

# Audit for vulnerabilities
cargo audit    # Requires: cargo install cargo-audit
```

### Zig

Zig has no external dependencies — only stdlib + libc.

---

## Log Analysis

### Structured Logs

The project uses structured JSON logging via `monitoring/structured_logging.py`:

```python
from monitoring.structured_logging import get_logger

logger = get_logger("torshield.pipeline")
logger.info("bridge_collected", bridge_count=42, source="torproject")
```

Output:
```json
{
  "timestamp": "2026-06-12T10:30:00Z",
  "level": "INFO",
  "module": "torshield.pipeline",
  "event": "bridge_collected",
  "bridge_count": 42,
  "source": "torproject"
}
```

### Log Files

| File | Description |
|------|-------------|
| `data/anti_dpi_v2_state.json` | V2 Anti-DPI state |
| `data/anti_filter_state.json` | V1 Anti-filter state |
| `data/anti_filter_v2_state.json` | V2 Anti-filter state |
| `data/dpi_intelligence.json` | DPI intelligence data |
| `data/iran_auto_defense_state.json` | Auto-defense state |
| `data/security_report.json` | Security scan results |
| `data/dependency_report.json` | Dependency validation results |
| `data/dead_code_report.json` | Dead code audit results |
| `data/full_audit_report.json` | Full audit report |

### Analyzing Provider Failures

```bash
# Check recent provider failures in logs
rg "record_failure\|AUTH_FAILURE\|401\|403\|circuit_breaker.*open" logs/

# Check health check results
python3 -c "
import json
with open('data/full_audit_report.json') as f:
    report = json.load(f)
print(json.dumps(report['summary_statistics'], indent=2))
"
```

### Monitoring Circuit Breaker State

```python
from torshield_ai_gateway.providers import CerebrasProvider

provider = CerebrasProvider(api_key="your-key")
cb = provider._circuit_breaker

print(f"State: {cb.state}")
print(f"Failure count: {cb._failure_count}")
print(f"Last failure: {cb._last_failure_time}")
```

---

## Performance Monitoring

### Key Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Provider latency (Cerebras) | <2s | Time to first token |
| Provider latency (CF) | <5s | Time to first token |
| Provider latency (Portkey) | <8s | Time to first token |
| Health check duration | <30s | Full provider sweep |
| Bridge collection | <5 min | All sources |
| Test suite | <60s | 314 tests |
| Memory usage | <512 MB | Peak during collection |
| CPU usage | <50% | Average during testing |

### Gateway Statistics

```python
from torshield_ai_gateway.gateway import TorShieldAIGateway

gateway = TorShieldAIGateway()
stats = gateway._stats

print(f"Total requests: {stats['total_requests']}")
print(f"Primary successes: {stats['primary_successes']}")
print(f"Fallback activations: {stats['fallback_activations']}")
print(f"Wrong responses: {stats['wrong_responses']}")

# Degradation ratio
if stats['total_requests'] > 0:
    degradation_pct = (stats['fallback_activations'] / stats['total_requests']) * 100
    print(f"Degradation: {degradation_pct:.1f}%")
```

### Performance Benchmarking

```bash
# Run tests with timing
python3 -m pytest tests/ --durations=20

# Profile specific operations
python3 -m cProfile -s cumulative main.py --collect-only
```

### Scheduled Monitoring

The GitHub Actions workflows provide automated monitoring:

| Workflow | Schedule | Monitors |
|----------|----------|----------|
| TorShield-IR | Hourly | Full pipeline, bridge freshness |
| Health Check | Every 6h | AI provider availability |
| Self-Healing | On failure | Auto-repair failures |

### Alert Thresholds

Configure alerts when:
- Primary success rate drops below 80%
- Fallback activation rate exceeds 20%
- Circuit breaker opens on any provider
- Health check exits with code 1 (degraded)
- Security scan finds new critical issues
