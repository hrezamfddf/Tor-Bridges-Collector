# Deployment Guide — Tor-Bridges-Collector

> **Project**: Tor-Bridges-Collector (TorShield-IR)  
> **Version**: v15.0 — Ultra-Quantum Edition  
> **Guide Date**: 2026-06-12  

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start](#quick-start)
3. [Environment Variable Configuration](#environment-variable-configuration)
4. [Provider Setup](#provider-setup)
5. [GitHub Actions Secrets Configuration](#github-actions-secrets-configuration)
6. [Docker Deployment](#docker-deployment)
7. [Monitoring Setup](#monitoring-setup)
8. [Iran-Specific Configuration](#iran-specific-configuration)
9. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| **Python** | 3.11+ | 3.12 |
| **Go** | 1.21+ | 1.22 |
| **Rust** | stable (1.78+) | latest stable |
| **Zig** | 0.11+ | 0.13+ |
| **RAM** | 2 GB | 4 GB |
| **Disk** | 1 GB | 5 GB |
| **Network** | Internet access | Low-latency to Cloudflare/Cerebras |

### Operating System

- **Primary**: Ubuntu 22.04+ (or any Debian-based Linux)
- **Secondary**: macOS 13+, Windows WSL2
- **CI**: `ubuntu-latest` (GitHub Actions)

### Required Tools

```bash
# Python
python3 --version    # 3.11+ required
pip3 --version

# Go
go version           # 1.21+ required

# Rust
rustc --version      # stable channel
cargo --version

# Zig
zig version          # 0.11+ required

# Git
git --version        # 2.30+
```

---

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/hrrjruruufgbbvhrh/Tor-Bridges-Collector-Ultra.git
cd Tor-Bridges-Collector-Ultra
```

### 2. Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure Environment

```bash
cp configs/env_template.sh .env
# Edit .env with your API keys (see Environment Variable Configuration below)
source .env
```

### 4. Run the Pipeline

```bash
# Full pipeline
python3 main.py

# Just bridge collection
python3 main.py --collect-only

# With AI analysis
python3 main.py --with-ai-analysis

# Iran-specific mode
python3 main.py --iran-mode
```

### 5. Run Tests

```bash
# Full test suite
python3 -m pytest tests/ -v

# Quick smoke test
python3 -m pytest tests/test_providers.py tests/test_gateway.py -v
```

---

## Environment Variable Configuration

All configuration is managed through environment variables. Copy the template and fill in your values:

```bash
cp configs/env_template.sh .env
source .env
```

### AI Provider Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `CEREBRAS_API_KEY` | Recommended | — | Cerebras API key |
| `CF_ACCOUNT_ID` | Recommended | — | Cloudflare account ID |
| `CF_API_TOKEN_1` through `CF_API_TOKEN_11` | Recommended | — | Cloudflare API tokens (1–11 slots) |
| `CF_AI_GATEWAY_URL_1` through `CF_AI_GATEWAY_URL_11` | Recommended | — | CF AI Gateway URLs (1–11 slots) |
| `PORTKEY_API_KEY` | Recommended | — | Portkey API key (pk- prefix) |
| `PORTKEY_GATEWAY_URL` | Optional | `https://api.portkey.ai/v1` | Portkey gateway URL |
| `PORTKEY_VIRTUAL_KEY_1` through `PORTKEY_VIRTUAL_KEY_3` | Optional | — | Portkey virtual keys |
| `GROQ_API_KEY` | Optional | — | Groq API key (self-heal) |

### Network Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MAX_WORKERS` | Optional | `150` | Maximum concurrent workers |
| `CONNECTION_TIMEOUT` | Optional | `8` | Connection timeout (seconds) |
| `SSL_TIMEOUT` | Optional | `6` | SSL handshake timeout (seconds) |
| `MAX_RETRIES` | Optional | `2` | Maximum retry attempts |
| `MAX_TEST_PER_TYPE` | Optional | `1000` | Max bridges to test per transport type |

### Time Windows

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `RECENT_HOURS` | Optional | `72` | Hours to consider bridges "recent" |
| `HISTORY_RETENTION_DAYS` | Optional | `45` | Days to retain bridge history |

### File Paths

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `BRIDGE_DIR` | Optional | `bridge` | Directory for bridge data |
| `EXPORT_DIR` | Optional | `export` | Directory for exported files |

### Collection Sources

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `USE_TORPROJECT_SCRAPER` | Optional | `true` | Enable bridges.torproject.org scraper |
| `USE_MOAT_API` | Optional | `true` | Enable MOAT API collector |
| `USE_BRIDGEDB_API` | Optional | `true` | Enable BridgeDB API collector |
| `USE_TELEGRAM_SOURCES` | Optional | `false` | Enable Telegram bridge channels |
| `USE_STATIC_BRIDGES` | Optional | `true` | Enable static bridge list |

### Proxy Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `HTTP_PROXY` | Optional | — | HTTP proxy URL (e.g., `socks5://127.0.0.1:1080`) |
| `HTTPS_PROXY` | Optional | — | HTTPS proxy URL |

### Notifications

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `TELEGRAM_BOT_TOKEN` | Optional | — | Telegram bot token |
| `TELEGRAM_CHAT_ID` | Optional | — | Telegram chat/channel ID |
| `TELEGRAM_UPLOAD` | Optional | `false` | Enable ZIP upload to Telegram |

---

## Provider Setup

### Cerebras.ai

1. **Get API Key**: Visit [https://cloud.cerebras.ai/](https://cloud.cerebras.ai/) and create an account
2. **Generate Key**: Navigate to API Keys section and create a new key
3. **Configure**:
   ```bash
   export CEREBRAS_API_KEY="csk-your-key-here"
   ```
4. **Verify**: The provider uses `llama3.1-8b` as the default model (fastest free-tier)
5. **Fallback models**: If the default model is unavailable, the provider automatically tries `llama3.1-70b` and `llama-3.3-70b`

**Performance**: Cerebras achieves ~2100 tokens/sec, making it the primary (fastest) provider.

### Cloudflare Workers AI + AI Gateway

1. **Get Account ID**: Found in Cloudflare Dashboard → Workers & Pages → Overview
2. **Create API Token**: Cloudflare Dashboard → My Profile → API Tokens → Create Token
   - Template: "Edit Cloudflare Workers"
   - Permissions: Workers Scripts:Edit, Workers AI:Edit
3. **Create AI Gateway**: Cloudflare Dashboard → AI → AI Gateway → Create
4. **Get Gateway URL**: Format is `https://gateway.ai.cloudflare.com/v1/{account_id}/{gateway-slug}`
5. **Configure**:
   ```bash
   export CF_ACCOUNT_ID="your-account-id"
   export CF_API_TOKEN_1="your-api-token-1"
   export CF_API_TOKEN_2="your-api-token-2"
   export CF_AI_GATEWAY_URL_1="https://gateway.ai.cloudflare.com/v1/{account_id}/gateway-slug"
   ```

**Multi-slot rotation**: Configure up to 11 API token / gateway URL pairs for quota multiplication.

### Portkey.ai

1. **Get API Key**: Visit [https://app.portkey.ai/](https://app.portkey.ai/) and create an account
2. **Generate Key**: Navigate to API Keys and create a new key (must start with `pk-`)
3. **Configure**:
   ```bash
   export PORTKEY_API_KEY="pk-your-key-here"
   export PORTKEY_GATEWAY_URL="https://api.portkey.ai/v1"  # default
   ```
4. **Alternative: Virtual Keys** (recommended for multi-tenant):
   ```bash
   export PORTKEY_VIRTUAL_KEY_1="pk-virtual-key-1"
   export PORTKEY_VIRTUAL_KEY_2="pk-virtual-key-2"
   ```

**Key format**: Portkey keys MUST start with `pk-` prefix. The validator will reject keys without it.

---

## GitHub Actions Secrets Configuration

### Required Secrets

Configure these in your GitHub repository: **Settings → Secrets and variables → Actions → New repository secret**

| Secret Name | Required | Description |
|-------------|----------|-------------|
| `CEREBRAS_API_KEY_1` | Yes | Cerebras API key slot 1 |
| `CEREBRAS_API_KEY_2` | Recommended | Cerebras API key slot 2 |
| `CEREBRAS_API_KEY_3` | Recommended | Cerebras API key slot 3 |
| `PORTKEY_API_KEY_1` | Yes | Portkey API key slot 1 |
| `PORTKEY_API_KEY_2` | Optional | Portkey API key slot 2 |
| `PORTKEY_API_KEY_3` | Optional | Portkey API key slot 3 |
| `PORTKEY_GATEWAY_URL` | Yes | Portkey gateway URL |
| `CF_ACCOUNT_ID_1` | Yes | Cloudflare account ID |
| `CF_API_TOKEN_1` | Yes | Cloudflare API token slot 1 |
| `CF_AI_GATEWAY_URL_1` | Yes | CF AI Gateway URL slot 1 |
| `CF_ACCOUNT_ID_2` | Optional | Cloudflare account ID slot 2 |
| `CF_API_TOKEN_2` | Optional | Cloudflare API token slot 2 |
| `CF_AI_GATEWAY_URL_2` | Optional | CF AI Gateway URL slot 2 |
| `GH_PAT_AUTOFIX` | Recommended | GitHub PAT for auto-fix commits |
| `GH_REPO_OWNER` | Recommended | Repository owner |
| `GH_REPO_NAME` | Recommended | Repository name |
| `GITHUB_TOKEN` | Auto | Automatic in GitHub Actions |

### Workflow Trigger Configuration

```yaml
# Hourly bridge collection
on:
  schedule:
    - cron: '0 * * * *'        # Every hour
  workflow_dispatch:             # Manual trigger

# Health check every 6 hours
on:
  schedule:
    - cron: '0 */6 * * *'      # Every 6 hours
  workflow_dispatch:
```

### Configuring Secrets

1. Navigate to your repository on GitHub
2. Go to **Settings → Secrets and variables → Actions**
3. Click **New repository secret**
4. Enter the secret name exactly as shown in the table above
5. Paste the secret value
6. Click **Add secret**

**Important**: Secret names must match exactly. The workflow YAML maps secrets to environment variables:

```yaml
env:
  CEREBRAS_API_KEY_1: ${{ secrets.CEREBRAS_API_KEY_1 }}
```

---

## Docker Deployment

### Dockerfile (Create if needed)

```dockerfile
FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    golang-go \
    curl \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /app

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . .

# Build binaries
RUN cd bridge-probe && cargo build --release && cd ..
RUN cd go_tester && go build -o /app/bin/go_tester . && cd ..

# Default command
CMD ["python3", "main.py"]
```

### Docker Compose

```yaml
version: '3.8'

services:
  torshield:
    build: .
    environment:
      - CEREBRAS_API_KEY=${CEREBRAS_API_KEY}
      - CF_ACCOUNT_ID=${CF_ACCOUNT_ID}
      - CF_API_TOKEN_1=${CF_API_TOKEN_1}
      - CF_AI_GATEWAY_URL_1=${CF_AI_GATEWAY_URL_1}
      - PORTKEY_API_KEY=${PORTKEY_API_KEY}
      - PORTKEY_GATEWAY_URL=${PORTKEY_GATEWAY_URL}
    volumes:
      - ./bridge:/app/bridge
      - ./export:/app/export
      - ./data:/app/data
    restart: unless-stopped

  health-monitor:
    build: .
    command: python3 scripts/ai_gateway_health_check.py --loop --interval 300
    environment:
      - CEREBRAS_API_KEY=${CEREBRAS_API_KEY}
      - CF_ACCOUNT_ID=${CF_ACCOUNT_ID}
      - CF_API_TOKEN_1=${CF_API_TOKEN_1}
      - PORTKEY_API_KEY=${PORTKEY_API_KEY}
    depends_on:
      - torshield
    restart: unless-stopped
```

### Running with Docker

```bash
# Build
docker compose build

# Run
docker compose up -d

# Check logs
docker compose logs -f torshield

# Run health check
docker compose up health-monitor
```

---

## Monitoring Setup

### Health Check Script

The project includes a comprehensive health check utility:

```bash
# One-time health check
python3 scripts/ai_gateway_health_check.py

# With custom task category
python3 scripts/ai_gateway_health_check.py --task reasoning

# With custom retry count
python3 scripts/ai_gateway_health_check.py --max-retries 2

# Loop mode (every 5 minutes)
python3 scripts/ai_gateway_health_check.py --loop --interval 300
```

### Health Check Exit Codes

| Code | Meaning | Action |
|------|---------|--------|
| 0 | At least one primary provider healthy | None — all good |
| 1 | All primary providers failed (degraded) | Check API keys, network |
| 2 | Required environment variables missing | Configure secrets |

### Monitoring Components

| Component | Location | Description |
|-----------|----------|-------------|
| Provider Dashboard | `monitoring/provider_dashboard.py` | Real-time provider health |
| Structured Logging | `monitoring/structured_logging.py` | JSON-formatted logs |
| Health Check | `monitoring/health_check.py` | Re-exported from scripts |
| Failure Analytics | `monitoring/structured_logging.py` | Failure categorization |

### Setting Up Alerts

1. **Telegram Alerts** (built-in):
   ```bash
   export TELEGRAM_BOT_TOKEN="your-bot-token"
   export TELEGRAM_CHAT_ID="your-chat-id"
   export TELEGRAM_UPLOAD="true"
   ```

2. **GitHub Actions Notifications**: Enable email notifications in repository settings

3. **Custom Webhooks**: Modify `core/notifier.py` to add custom webhook endpoints

---

## Iran-Specific Configuration

### NIN (National Internet Network) Mode

Enable NIN mode when Iran's domestic internet is isolated from the global internet:

```bash
export NIN_MODE="true"
```

In NIN mode:
- Only CDN-fronted bridges are used
- Snowflake and WebTunnel are prioritized
- Direct obfs4 bridges are deprioritized
- Bridge scoring weights shift toward NIN-survivable transports

### Deep Testing Mode

Test ALL bridges (slower but more thorough):

```bash
export DEEP_TEST="true"
```

### ISP-Specific Bypass

The V2 anti-censorship engine automatically detects your ISP and applies appropriate bypass strategies:

| ISP | Strategy |
|-----|----------|
| MCI (Hamrah Aval) | WebTunnel CDN-fronted, iat-mode=2 |
| IRANCELL | obfs4 port 443, Snowflake |
| Rightel | Snowflake, meek-lite |
| Shatel | obfs4 port 443 |
| Asiatech | WebTunnel, Snowflake |

### Transport Priority Chain

Default (non-NIN):
```
Snowflake → WebTunnel → obfs4-443 → meek → vanilla
```

NIN mode:
```
WebTunnel CDN → Snowflake AMP → meek-azure → obfs4-443
```

### V3 Anti-DPI Features

Enable V3 Neural Anti-DPI for maximum evasion:

```python
from torshield_ai_gateway.neural_anti_dpi_v3 import AntiDPIV3Orchestrator

v3 = AntiDPIV3Orchestrator()
result = v3.analyze_and_evade(traffic_info)
```

V3 features:
- Neural traffic morphing (packet-length padding, IAT jitter)
- JA3/JA3S fingerprint rotation (Chrome, Firefox, Safari, Edge profiles)
- ECH (Encrypted Client Hello) fallback routing
- Post-quantum bridge scoring (Kyber/ML-KEM awareness)

---

## Troubleshooting

### Common Issues

#### Issue: Cerebras returns 404 "Model not found"

**Cause**: Invalid model name in configuration  
**Fix**: The default model is now `llama3.1-8b`. If you've overridden `CEREBRAS_DEFAULT_MODEL`, ensure it's a valid Cerebras model name.

```bash
# Verify valid models
python3 -c "
from torshield_ai_gateway.providers import CerebrasProvider
p = CerebrasProvider()
print('Available models:', p.CEREBRAS_MODELS)
"
```

#### Issue: CF AI Gateway returns 400

**Cause**: Gateway URL missing account_id or malformed  
**Fix**: Ensure URL format is `https://gateway.ai.cloudflare.com/v1/{account_id}/{gateway-slug}`

```bash
# Validate your gateway URL
python3 -c "
from torshield_ai_gateway.providers import CFAIGatewayProvider
# This will validate the URL format
provider = CFAIGatewayProvider(url='your-url-here')
"
```

#### Issue: Portkey returns 401

**Cause**: API key format invalid or missing  
**Fix**: Ensure key starts with `pk-` prefix and has no trailing whitespace

```bash
# Check key format
echo -n "$PORTKEY_API_KEY" | head -c 3
# Should output: pk-

# Check for trailing whitespace
echo -n "$PORTKEY_API_KEY" | wc -c
# Compare with expected length
```

#### Issue: Health check reports degraded but providers should work

**Cause**: Environment variables not mapped in workflow  
**Fix**: Verify secrets are mapped to env vars in the workflow step:

```yaml
env:
  CEREBRAS_API_KEY_1: ${{ secrets.CEREBRAS_API_KEY_1 }}
```

#### Issue: Workflow fails with "ModuleNotFoundError"

**Cause**: Missing `pip install -r requirements.txt` step  
**Fix**: All workflows now include the install step. If you're seeing this, you may be running an older workflow version.

#### Issue: All tests pass locally but fail in CI

**Cause**: Missing secrets or environment-specific configuration  
**Fix**: Check GitHub Actions secrets configuration. The pre-flight validation step will report missing secrets.

#### Issue: `aioquic` fails to install

**Cause**: Missing system dependencies for building aioquic  
**Fix**:
```bash
# Ubuntu/Debian
sudo apt-get install -y libssl-dev build-essential

# Then retry
pip install aioquic
```

#### Issue: Rust build fails with "feature `edition2024` is required"

**Cause**: Older Cargo version (<1.85) and clap 4.6+ dependency  
**Fix**: The Cargo.toml pins clap to 4.5.x. Ensure you're using the pinned version:
```bash
cd bridge-probe && cargo update && cargo build --release
```

### Getting Help

1. Check the health check diagnostics: `python3 scripts/ai_gateway_health_check.py`
2. Run the full audit: `python3 scripts/run_full_audit.py`
3. Check structured logs in `data/` directory
4. Review workflow run logs in GitHub Actions
