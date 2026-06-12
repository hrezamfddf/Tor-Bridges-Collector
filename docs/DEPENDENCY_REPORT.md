# Dependency Report — Tor-Bridges-Collector

> **Project**: Tor-Bridges-Collector (TorShield-IR)  
> **Validation Date**: 2026-06-12  
> **Validator**: `scripts/validate_dependencies.py` v1.0  
> **Total Issues**: 4 (all Python — missing packages)  

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Python Dependencies](#python-dependencies)
3. [Go Dependencies](#go-dependencies)
4. [Rust Dependencies](#rust-dependencies)
5. [Zig Dependencies](#zig-dependencies)
6. [Version Compatibility](#version-compatibility)
7. [Missing Packages](#missing-packages)
8. [Recommendations](#recommendations)

---

## Executive Summary

Dependency validation was performed across all four languages used in the project: Python, Go, Rust, and Zig. The project has a healthy dependency posture with only **4 missing Python packages** identified (all optional or development tools). No version conflicts or incompatibilities were detected.

| Language | Packages/Modules | Issues | Status |
|----------|-----------------|--------|--------|
| Python | 18 | 4 missing | ⚠️ Warning |
| Go | 2 modules | 0 | ✅ Pass |
| Rust | 9 dependencies | 0 | ✅ Pass |
| Zig | 1 package | 0 | ✅ Pass |
| **Total** | **30** | **4** | **⚠️ Warning** |

---

## Python Dependencies

### Source: `requirements.txt`

The project specifies 18 Python packages across 7 categories:

#### Core HTTP + HTML Parsing

| Package | Import As | Required Version | Installed Version | Compatible | Issues |
|---------|-----------|-----------------|-------------------|------------|--------|
| requests | `requests` | >=2.31.0 | 2.32.5 | ✅ | — |
| beautifulsoup4 | `bs4` | >=4.12.0 | 4.14.3 | ✅ | — |
| lxml | `lxml` | >=5.0.0 | 6.0.2 | ✅ | — |

#### Async HTTP

| Package | Import As | Required Version | Installed Version | Compatible | Issues |
|---------|-----------|-----------------|-------------------|------------|--------|
| aiohttp | `aiohttp` | >=3.9.0 | 3.13.3 | ✅ | — |

#### ML Blocking Predictor

| Package | Import As | Required Version | Installed Version | Compatible | Issues |
|---------|-----------|-----------------|-------------------|------------|--------|
| scikit-learn | `sklearn` | >=1.4.0 | 1.5.2 | ✅ | — |
| numpy | `numpy` | >=1.26.0 | 2.1.3 | ✅ | — |

#### QUIC / Next-Gen Protocol Detection

| Package | Import As | Required Version | Installed Version | Compatible | Issues |
|---------|-----------|-----------------|-------------------|------------|--------|
| aioquic | `aioquic` | >=1.0.0 | — | ❌ | **NOT INSTALLED** |

#### Cryptography & Security

| Package | Import As | Required Version | Installed Version | Compatible | Issues |
|---------|-----------|-----------------|-------------------|------------|--------|
| cryptography | `cryptography` | >=42.0.0 | 44.0.3 | ✅ | — |
| pycryptodome | `Crypto` | >=3.20.0 | 3.23.0 | ✅ | — |

#### Terminal Output & YAML

| Package | Import As | Required Version | Installed Version | Compatible | Issues |
|---------|-----------|-----------------|-------------------|------------|--------|
| rich | `rich` | >=13.0.0 | 14.3.3 | ✅ | — |
| PyYAML | `yaml` | >=6.0.1 | 6.0.3 | ✅ | — |

#### Static Analysis & Testing

| Package | Import As | Required Version | Installed Version | Compatible | Issues |
|---------|-----------|-----------------|-------------------|------------|--------|
| ruff | `ruff` | >=0.4.0 | — | ❌ | **NOT INSTALLED** |
| mypy | `mypy` | >=1.9.0 | — | ❌ | **NOT INSTALLED** |
| pytest | `pytest` | >=8.0.0 | 9.0.2 | ✅ | — |
| pytest-cov | `pytest_cov` | >=5.0.0 | 7.0.0 | ✅ | — |
| pytest-asyncio | `pytest_asyncio` | >=0.23.0 | 1.3.0 | ✅ | — |

#### Advanced Features

| Package | Import As | Required Version | Installed Version | Compatible | Issues |
|---------|-----------|-----------------|-------------------|------------|--------|
| dnspython | `dns` | >=2.6.0 | 2.8.0 | ✅ | — |
| dpkt | `dpkt` | >=1.9.8 | — | ❌ | **NOT INSTALLED** |

### Summary

| Metric | Value |
|--------|-------|
| Total packages | 18 |
| Importable | 14 (77.8%) |
| Not importable | 4 (22.2%) |
| Version mismatches | 0 |
| Version conflicts | 0 |

---

## Go Dependencies

### Module 1: Root Module

| Field | Value |
|-------|-------|
| **File** | `go.mod` |
| **Module Path** | `github.com/hrrjruruufgbbvhrh/Tor-Bridges-Collector-Ultra` |
| **Go Version** | 1.22 |
| **Path Valid** | ✅ |
| **Dependencies** | 0 (stdlib only) |
| **Issues** | None |

### Module 2: Bridge Tester

| Field | Value |
|-------|-------|
| **File** | `go_tester/go.mod` |
| **Module Path** | `github.com/user/tor-bridge-tester` |
| **Go Version** | 1.21 |
| **Path Valid** | ✅ |
| **Dependencies** | 0 (stdlib only) |
| **Issues** | None |

### Go Command-Line Tools

| Tool | Location | Description |
|------|----------|-------------|
| `iran_tester` | `cmd/iran_tester/main.go` | Iran-specific bridge testing tool |
| `probe_scheduler` | `cmd/probe_scheduler/main.go` | Schedules and manages bridge probes |

### Internal Go Packages

| Package | Location | Description |
|---------|----------|-------------|
| `asn` | `internal/asn/iran_asns.go` | Iranian ASN database |
| `bridge` | `internal/bridge/parser.go`, `tester.go` | Bridge parsing and testing |
| `ooni` | `internal/ooni/client.go` | OONI measurement client |
| `ipinfo` | `internal/ipinfo/client.go` | IP information lookup |
| `ripe` | `internal/ripe/atlas.go` | RIPE Atlas measurement integration |

---

## Rust Dependencies

### Source: `bridge-probe/Cargo.toml`

| Field | Value |
|-------|-------|
| **Package** | `bridge-probe` |
| **Version** | 2.0.0 |
| **Edition** | 2021 |
| **Description** | TorShield-IR pluggable-transport handshake prober — Iran-optimised |
| **Binary** | `bridge-probe` → `src/main.rs` |

### Dependencies

| Package | Version | Features | Optional | Issues |
|---------|---------|----------|----------|--------|
| `tokio` | 1 | full, process | No | — |
| `serde` | 1 | derive | No | — |
| `serde_json` | 1 | — | No | — |
| `clap` | >=4.5.0, <4.6 | derive | No | — |
| `clap_lex` | >=0.7.0, <1.0 | — | No | — |
| `tracing` | 0.1 | — | No | — |
| `tracing-subscriber` | 0.3 | env-filter, fmt | No | — |
| `anyhow` | 1 | — | No | — |
| `regex` | 1 | — | No | — |

### clap Version Pinning Note

> **CRITICAL FIX (preserved in Cargo.toml comments)**: `clap` is pinned to the 4.5.x series because clap 4.6+ depends on `clap_lex 1.1.0`, which requires Cargo feature `edition2024` — not stabilized until Rust 1.85 (Cargo ≥1.85). GitHub Actions runner Cargo 1.78 fails with `"feature 'edition2024' is required"`. Both fixes applied: (A) pin clap to 4.5.x, (B) upgrade workflow toolchain from 1.78 to stable.

### Release Profile

```toml
[profile.release]
opt-level     = 3       # Maximum optimization
strip         = true    # Strip debug symbols
lto           = true    # Link-time optimization
codegen-units = 1       # Single codegen unit (slower build, faster binary)
panic         = "abort" # Abort on panic (smaller binary)
```

### Summary

| Metric | Value |
|--------|-------|
| Total dependencies | 9 |
| With version specified | 9 (100%) |
| Without version | 0 |
| Issues | 0 |

---

## Zig Dependencies

### Source: `zig-scanner/build.zig`

| Field | Value |
|-------|-------|
| **Package** | `zig-scanner` |
| **Build File** | `zig-scanner/build.zig` |
| **Source** | `zig-scanner/src/main.zig` |
| **Has Build Function** | ✅ |
| **Links libc** | ✅ |
| **Dependencies** | 0 (stdlib + libc only) |
| **Issues** | None |

### Build Configuration

```zig
const exe = b.addExecutable(.{
    .name       = "zig-scanner",
    .root_source_file = b.path("src/main.zig"),
    .target     = target,
    .optimize   = optimize,
});
exe.linkLibC();  // Static binary — no libc dependency at runtime
b.installArtifact(exe);
```

The Zig scanner is built as a static binary with no external dependencies, making it suitable for deployment on minimal systems.

---

## Version Compatibility

### Python

All installed packages are compatible with their specified version ranges. No conflicts detected.

| Package | Required | Installed | Status |
|---------|----------|-----------|--------|
| requests | >=2.31.0 | 2.32.5 | ✅ |
| beautifulsoup4 | >=4.12.0 | 4.14.3 | ✅ |
| lxml | >=5.0.0 | 6.0.2 | ✅ |
| aiohttp | >=3.9.0 | 3.13.3 | ✅ |
| scikit-learn | >=1.4.0 | 1.5.2 | ✅ |
| numpy | >=1.26.0 | 2.1.3 | ✅ |
| cryptography | >=42.0.0 | 44.0.3 | ✅ |
| pycryptodome | >=3.20.0 | 3.23.0 | ✅ |
| rich | >=13.0.0 | 14.3.3 | ✅ |
| PyYAML | >=6.0.1 | 6.0.3 | ✅ |
| pytest | >=8.0.0 | 9.0.2 | ✅ |
| pytest-cov | >=5.0.0 | 7.0.0 | ✅ |
| pytest-asyncio | >=0.23.0 | 1.3.0 | ✅ |
| dnspython | >=2.6.0 | 2.8.0 | ✅ |

### Go

Both Go modules are valid with no dependency conflicts. Module paths resolve correctly.

### Rust

All 9 dependencies have explicit version constraints. The `clap` pinning to 4.5.x prevents the `edition2024` feature requirement on older Cargo versions.

### Zig

No dependencies — uses stdlib + libc only.

---

## Missing Packages

### 1. `aioquic` — QUIC Protocol Library

| Field | Value |
|-------|-------|
| **Package** | `aioquic` |
| **Import** | `aioquic` |
| **Required** | >=1.0.0 |
| **Category** | QUIC / Next-Gen Protocol Detection |
| **Impact** | Medium — QUIC/Hysteria2 protocol probing unavailable |
| **Install Command** | `pip install aioquic` |

**Description**: Used for QUIC protocol probing and next-generation transport detection. Without this package, the system cannot directly probe QUIC-based bridges or Hysteria2 transports. The functionality is gracefully degraded — other probing methods remain available.

**Why Not Installed**: `aioquic` has complex build dependencies (requires `libssl-dev` and a C compiler for its TLS implementation). It may not build in all environments.

### 2. `ruff` — Fast Python Linter

| Field | Value |
|-------|-------|
| **Package** | `ruff` |
| **Import** | `ruff` |
| **Required** | >=0.4.0 |
| **Category** | Static Analysis / CI Quality Gates |
| **Impact** | Low — linting unavailable locally, but runs in CI |
| **Install Command** | `pip install ruff` |

**Description**: Fast Python linter used in CI quality gates. Not required for runtime — only for development and CI.

### 3. `mypy` — Static Type Checker

| Field | Value |
|-------|-------|
| **Package** | `mypy` |
| **Import** | `mypy` |
| **Required** | >=1.9.0 |
| **Category** | Static Analysis / CI Quality Gates |
| **Impact** | Low — type checking unavailable locally, but runs in CI |
| **Install Command** | `pip install mypy` |

**Description**: Static type checker for Python. Not required for runtime — only for development and CI.

### 4. `dpkt` — Packet Parsing Library

| Field | Value |
|-------|-------|
| **Package** | `dpkt` |
| **Import** | `dpkt` |
| **Required** | >=1.9.8 |
| **Category** | Advanced Features / JA3 Fingerprinting |
| **Impact** | Low — raw packet inspection unavailable |
| **Install Command** | `pip install dpkt` |

**Description**: Used for raw packet inspection and JA3 fingerprinting in the anti-DPI modules. Without this package, JA3 fingerprint computation from raw packet captures is unavailable. The anti-DPI system has fallback methods that don't require dpkt.

---

## Recommendations

### Immediate

1. **Install missing packages in development environment**:
   ```bash
   pip install aioquic dpkt ruff mypy
   ```

2. **For CI environments**, ensure all packages are installed:
   ```bash
   pip install -r requirements.txt
   ```
   The CI workflow already includes this step.

### Short-Term

3. **Separate dev dependencies**: Consider splitting `requirements.txt` into:
   - `requirements.txt` — runtime dependencies only
   - `requirements-dev.txt` — development tools (ruff, mypy, pytest, pytest-cov, pytest-asyncio)

4. **Pin exact versions for reproducibility**: Use `pip freeze > requirements-lock.txt` to create a lock file with exact versions for CI.

5. **Add `pip-audit` or `safety`** to CI pipeline for vulnerability scanning of dependencies.

### Long-Term

6. **Set up Dependabot** or Renovate for automated dependency updates.
7. **Consider `aioquic` build automation** — pre-build wheels for common platforms.
8. **Upgrade Go modules** to use Go 1.22 consistently (go_tester uses 1.21).
9. **Monitor Rust clap version** — once Cargo 1.85+ is widespread, unpin clap from 4.5.x.
10. **Add `requirements-lock.txt`** to the repository for deterministic builds.
