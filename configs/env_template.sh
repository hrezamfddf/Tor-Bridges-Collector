#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# TorShield-IR Environment Variables Template
# ══════════════════════════════════════════════════════════════════════════════
#
# Copy this file to .env and fill in your values:
#   cp configs/env_template.sh .env
#   source .env
#
# All values are optional unless marked [REQUIRED].
# Values can also be set as GitHub Actions Secrets.
#
# ══════════════════════════════════════════════════════════════════════════════

# ─────────────────────────────────────────────────────────────────────────────
# AI PROVIDER: Cerebras.ai
# ─────────────────────────────────────────────────────────────────────────────
# Fast inference provider (2100 tokens/sec). Primary provider in the waterfall.
# Get your key at: https://cloud.cerebras.ai/
CEREBRAS_API_KEY=""                    # [RECOMMENDED] Cerebras API key

# ─────────────────────────────────────────────────────────────────────────────
# AI PROVIDER: Cloudflare Workers AI + AI Gateway
# ─────────────────────────────────────────────────────────────────────────────
# Cloudflare provides multiple slots for redundancy and quota multiplication.
# CF_ACCOUNT_ID is shared across all slots.
CF_ACCOUNT_ID=""                       # [RECOMMENDED] Cloudflare account ID

# API tokens for each Cloudflare slot (1-11)
# At least CF_API_TOKEN_1 should be set for Workers AI access.
CF_API_TOKEN_1=""                      # [RECOMMENDED] Cloudflare API token slot 1
CF_API_TOKEN_2=""                      # Cloudflare API token slot 2
CF_API_TOKEN_3=""                      # Cloudflare API token slot 3
CF_API_TOKEN_4=""                      # Cloudflare API token slot 4
CF_API_TOKEN_5=""                      # Cloudflare API token slot 5
CF_API_TOKEN_6=""                      # Cloudflare API token slot 6
CF_API_TOKEN_7=""                      # Cloudflare API token slot 7
CF_API_TOKEN_8=""                      # Cloudflare API token slot 8
CF_API_TOKEN_9=""                      # Cloudflare API token slot 9
CF_API_TOKEN_10=""                     # Cloudflare API token slot 10
CF_API_TOKEN_11=""                     # Cloudflare API token slot 11

# CF AI Gateway URLs — full absolute URLs for cached inference
# Must start with https://gateway.ai.cloudflare.com/v1/{account_id}/
# Up to 11 gateway URLs for slot rotation
CF_AI_GATEWAY_URL_1=""                 # [RECOMMENDED] CF AI Gateway URL slot 1
CF_AI_GATEWAY_URL_2=""                 # CF AI Gateway URL slot 2
CF_AI_GATEWAY_URL_3=""                 # CF AI Gateway URL slot 3
CF_AI_GATEWAY_URL_4=""                 # CF AI Gateway URL slot 4
CF_AI_GATEWAY_URL_5=""                 # CF AI Gateway URL slot 5
CF_AI_GATEWAY_URL_6=""                 # CF AI Gateway URL slot 6
CF_AI_GATEWAY_URL_7=""                 # CF AI Gateway URL slot 7
CF_AI_GATEWAY_URL_8=""                 # CF AI Gateway URL slot 8
CF_AI_GATEWAY_URL_9=""                 # CF AI Gateway URL slot 9
CF_AI_GATEWAY_URL_10=""                # CF AI Gateway URL slot 10
CF_AI_GATEWAY_URL_11=""                # CF AI Gateway URL slot 11

# ─────────────────────────────────────────────────────────────────────────────
# AI PROVIDER: Portkey.ai
# ─────────────────────────────────────────────────────────────────────────────
# Meta-router provider — routes to multiple backends.
# Get your key at: https://app.portkey.ai/
PORTKEY_API_KEY=""                     # [RECOMMENDED] Portkey API key (pk- prefix)
PORTKEY_GATEWAY_URL="https://api.portkey.ai/v1"  # Portkey gateway URL

# Alternative: per-slot Portkey virtual keys
PORTKEY_VIRTUAL_KEY_1=""               # Portkey virtual key slot 1
PORTKEY_VIRTUAL_KEY_2=""               # Portkey virtual key slot 2
PORTKEY_VIRTUAL_KEY_3=""               # Portkey virtual key slot 3

# ─────────────────────────────────────────────────────────────────────────────
# AI PROVIDER: Groq (used by self_heal.py)
# ─────────────────────────────────────────────────────────────────────────────
# Used as a fallback AI provider in the self-healing system.
GROQ_API_KEY=""                        # Groq API key for self-heal

# ─────────────────────────────────────────────────────────────────────────────
# GITHUB ACTIONS / SELF-HEAL
# ─────────────────────────────────────────────────────────────────────────────
# Required for autonomous self-healing (committing patches back to repo)
GITHUB_TOKEN=""                        # GitHub personal access token
GITHUB_REPOSITORY=""                   # Repository in owner/repo format
GITHUB_SHA=""                          # Current commit SHA (set by GitHub Actions)
GH_PAT_AUTOFIX=""                      # [SELF-HEAL] GitHub PAT for auto-fix commits
GH_REPO_OWNER=""                       # [SELF-HEAL] Repository owner
GH_REPO_NAME=""                        # [SELF-HEAL] Repository name

# ─────────────────────────────────────────────────────────────────────────────
# NETWORK / TESTING CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
# Bridge collection and testing parameters
MAX_WORKERS="150"                      # Maximum concurrent workers
CONNECTION_TIMEOUT="8"                 # Connection timeout in seconds
SSL_TIMEOUT="6"                        # SSL handshake timeout in seconds
MAX_RETRIES="2"                        # Maximum retry attempts
MAX_TEST_PER_TYPE="1000"               # Maximum bridges to test per transport type

# ─────────────────────────────────────────────────────────────────────────────
# TIME WINDOWS
# ─────────────────────────────────────────────────────────────────────────────
RECENT_HOURS="72"                      # Hours to consider bridges "recent"
HISTORY_RETENTION_DAYS="45"            # Days to retain bridge history

# ─────────────────────────────────────────────────────────────────────────────
# FILE PATHS
# ─────────────────────────────────────────────────────────────────────────────
BRIDGE_DIR="bridge"                    # Directory for bridge data
EXPORT_DIR="export"                    # Directory for exported bridge files

# ─────────────────────────────────────────────────────────────────────────────
# REPOSITORY URL
# ─────────────────────────────────────────────────────────────────────────────
# Used to fetch static bridge lists from GitHub
REPO_URL="https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/refs/heads/main"

# ─────────────────────────────────────────────────────────────────────────────
# TELEGRAM NOTIFICATIONS
# ─────────────────────────────────────────────────────────────────────────────
# Optional: send bridge updates to a Telegram channel
TELEGRAM_BOT_TOKEN=""                  # Telegram bot token
TELEGRAM_CHAT_ID=""                    # Telegram chat/channel ID
TELEGRAM_UPLOAD="false"                # Enable ZIP upload to Telegram

# ─────────────────────────────────────────────────────────────────────────────
# PROXY CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
# Optional: use a proxy for all HTTP requests
HTTP_PROXY=""                          # HTTP proxy URL (e.g., socks5://127.0.0.1:1080)
HTTPS_PROXY=""                         # HTTPS proxy URL

# ─────────────────────────────────────────────────────────────────────────────
# COLLECTION SOURCES (toggle on/off)
# ─────────────────────────────────────────────────────────────────────────────
USE_TORPROJECT_SCRAPER="true"          # Enable bridges.torproject.org scraper
USE_MOAT_API="true"                    # Enable MOAT API bridge collector
USE_BRIDGEDB_API="true"               # Enable BridgeDB API collector
USE_TELEGRAM_SOURCES="false"           # Enable Telegram bridge channels
USE_STATIC_BRIDGES="true"             # Enable static bridge list

# ─────────────────────────────────────────────────────────────────────────────
# IRAN-SPECIFIC CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
# NIN mode: rescore bridges for internet-cut scenario
NIN_MODE="false"                       # Enable NIN (internet cut) scoring mode

# Deep testing: test ALL bridges (slower but more thorough)
DEEP_TEST="false"                      # Enable deep testing mode

# ─────────────────────────────────────────────────────────────────────────────
# GITHUB ACTIONS DETECTION
# ─────────────────────────────────────────────────────────────────────────────
# Automatically set by GitHub Actions; do not configure manually
# GITHUB_ACTIONS="true"                # Set automatically in CI environment

echo "✓ TorShield-IR environment template loaded."
echo "  Configure the [RECOMMENDED] variables above before running the pipeline."
