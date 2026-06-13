"""
config.py — Central configuration for TorShield-IR Tor Bridges Collector v3.
All values are overridable via environment variables.

v3 CHANGES:
  - Added full Cloudflare Workers AI slot configuration (1-11)
  - Added CF_ACCOUNT_ID_1-11, CF_API_TOKEN_1-11, CF_AI_GATEWAY_URL_1-11
  - Added Cerebras, Portkey, Groq AI provider configs
  - Added GitHub self-heal configuration
  - Added USE_GITHUB_SOURCES toggle
  - Added anti-DPI and anti-filter mode toggles
  - All existing settings preserved — NOTHING removed
"""

import os

# ─────────────────────────────────────────────────────────────────────────────
# Network / Testing
# ─────────────────────────────────────────────────────────────────────────────
MAX_WORKERS:        int   = int(os.getenv("MAX_WORKERS",        "150"))
CONNECTION_TIMEOUT: float = float(os.getenv("CONNECTION_TIMEOUT", "8"))
SSL_TIMEOUT:        float = float(os.getenv("SSL_TIMEOUT",       "6"))
MAX_RETRIES:        int   = int(os.getenv("MAX_RETRIES",         "2"))
MAX_TEST_PER_TYPE:  int   = int(os.getenv("MAX_TEST_PER_TYPE",  "1000"))

# ─────────────────────────────────────────────────────────────────────────────
# Time Windows
# ─────────────────────────────────────────────────────────────────────────────
RECENT_HOURS:             int = int(os.getenv("RECENT_HOURS",             "72"))
HISTORY_RETENTION_DAYS:   int = int(os.getenv("HISTORY_RETENTION_DAYS",   "45"))

# ─────────────────────────────────────────────────────────────────────────────
# File Paths
# ─────────────────────────────────────────────────────────────────────────────
BRIDGE_DIR:    str = os.getenv("BRIDGE_DIR",  "bridge")
EXPORT_DIR:    str = os.getenv("EXPORT_DIR",  "export")
HISTORY_FILE:  str = os.path.join(BRIDGE_DIR, "bridge_history.json")
SCORES_FILE:   str = os.path.join(BRIDGE_DIR, "bridge_scores.json")

# ─────────────────────────────────────────────────────────────────────────────
# Repository (update to your fork URL)
# ─────────────────────────────────────────────────────────────────────────────
REPO_URL: str = os.getenv(
    "REPO_URL",
    "https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/refs/heads/main"
)

# ─────────────────────────────────────────────────────────────────────────────
# GitHub Actions
# ─────────────────────────────────────────────────────────────────────────────
IS_GITHUB: bool = os.getenv("GITHUB_ACTIONS") == "true"

# ─────────────────────────────────────────────────────────────────────────────
# Cloudflare Workers AI — 11 Slots (CF_ACCOUNT_ID_1-11, CF_API_TOKEN_1-11,
#                                  CF_AI_GATEWAY_URL_1-11)
# ─────────────────────────────────────────────────────────────────────────────
CF_N_SLOTS: int = int(os.getenv("CF_N_SLOTS", "11"))

CF_ACCOUNT_IDS: list = [
    os.getenv(f"CF_ACCOUNT_ID_{i}", "").strip() for i in range(1, CF_N_SLOTS + 1)
]
CF_API_TOKENS: list = [
    os.getenv(f"CF_API_TOKEN_{i}", "").strip() for i in range(1, CF_N_SLOTS + 1)
]
CF_AI_GATEWAY_URLS: list = [
    os.getenv(f"CF_AI_GATEWAY_URL_{i}", "").strip() for i in range(1, CF_N_SLOTS + 1)
]

# Convenience: list of (account_id, api_token, gateway_url) for valid slots
CF_VALID_SLOTS: list = [
    (acc, tok, gw)
    for acc, tok, gw in zip(CF_ACCOUNT_IDS, CF_API_TOKENS, CF_AI_GATEWAY_URLS)
    if acc and tok
]

# ─────────────────────────────────────────────────────────────────────────────
# AI Provider: Cerebras.ai
# ─────────────────────────────────────────────────────────────────────────────
CEREBRAS_API_KEY: str = os.getenv("CEREBRAS_API_KEY", "")

# ─────────────────────────────────────────────────────────────────────────────
# AI Provider: Portkey.ai
# ─────────────────────────────────────────────────────────────────────────────
PORTKEY_API_KEY:      str  = os.getenv("PORTKEY_API_KEY", "")
PORTKEY_GATEWAY_URL:  str  = os.getenv("PORTKEY_GATEWAY_URL", "https://api.portkey.ai/v1")
PORTKEY_VIRTUAL_KEYS: list = [
    os.getenv(f"PORTKEY_VIRTUAL_KEY_{i}", "") for i in range(1, 4)
]

# ─────────────────────────────────────────────────────────────────────────────
# AI Provider: Groq
# ─────────────────────────────────────────────────────────────────────────────
GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")

# ─────────────────────────────────────────────────────────────────────────────
# GitHub Self-Heal
# ─────────────────────────────────────────────────────────────────────────────
GITHUB_TOKEN:      str = os.getenv("GITHUB_TOKEN", "")
GITHUB_REPOSITORY: str = os.getenv("GITHUB_REPOSITORY", "")
GITHUB_SHA:        str = os.getenv("GITHUB_SHA", "")
GH_PAT_AUTOFIX:    str = os.getenv("GH_PAT_AUTOFIX", "")
GH_REPO_OWNER:     str = os.getenv("GH_REPO_OWNER", "")
GH_REPO_NAME:      str = os.getenv("GH_REPO_NAME", "")

# ─────────────────────────────────────────────────────────────────────────────
# Telegram
# ─────────────────────────────────────────────────────────────────────────────
TELEGRAM_BOT_TOKEN: str  = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID:   str  = os.getenv("TELEGRAM_CHAT_ID",   "")
TELEGRAM_UPLOAD:    bool = os.getenv("TELEGRAM_UPLOAD", "false").lower() == "true"

# ─────────────────────────────────────────────────────────────────────────────
# Proxy (optional, e.g. "socks5://127.0.0.1:1080")
# ─────────────────────────────────────────────────────────────────────────────
HTTP_PROXY:  str = os.getenv("HTTP_PROXY",  "")
HTTPS_PROXY: str = os.getenv("HTTPS_PROXY", "")

# ─────────────────────────────────────────────────────────────────────────────
# Collection Sources (toggle on/off)
# ─────────────────────────────────────────────────────────────────────────────
USE_TORPROJECT_SCRAPER: bool = os.getenv("USE_TORPROJECT_SCRAPER", "true").lower()  == "true"
USE_MOAT_API:           bool = os.getenv("USE_MOAT_API",           "true").lower()  == "true"
USE_BRIDGEDB_API:       bool = os.getenv("USE_BRIDGEDB_API",       "true").lower()  == "true"
USE_TELEGRAM_SOURCES:   bool = os.getenv("USE_TELEGRAM_SOURCES",   "false").lower() == "true"
USE_STATIC_BRIDGES:     bool = os.getenv("USE_STATIC_BRIDGES",     "true").lower()  == "true"
USE_GITHUB_SOURCES:     bool = os.getenv("USE_GITHUB_SOURCES",     "true").lower()  == "true"

# ─────────────────────────────────────────────────────────────────────────────
# Deep Testing (tests ALL bridges, slower)
# ─────────────────────────────────────────────────────────────────────────────
DEEP_TEST: bool = os.getenv("DEEP_TEST", "false").lower() == "true"

# ─────────────────────────────────────────────────────────────────────────────
# Iran-specific
# ─────────────────────────────────────────────────────────────────────────────
# Ports that Iran's DPI typically allows (HTTPS, HTTP, Cloudflare ports)
IRAN_PREFERRED_PORTS: list = [443, 80, 8080, 8443, 2083, 2087, 2096]

# CDN domains accessible during NIN (internet cut) scenarios
IRAN_CDN_FRONTS: list = [
    "fastly.net",
    "cdn.arvancloud.com",
    "arvancloud.ir",
    "cloudfront.net",
    "azureedge.net",
    "ajax.aspnetcdn.com",
    "googlevideo.com",
    "gstatic.com",
]

# NIN mode: rescore bridges for internet-cut scenario
NIN_MODE: bool = os.getenv("NIN_MODE", "false").lower() == "true"

# ─────────────────────────────────────────────────────────────────────────────
# Anti-DPI / Anti-Filter (Iran AI-Powered)
# ─────────────────────────────────────────────────────────────────────────────
ANTI_DPI_MODE:     bool = os.getenv("ANTI_DPI_MODE",     "false").lower() == "true"
ANTI_FILTER_MODE:  bool = os.getenv("ANTI_FILTER_MODE",  "false").lower() == "true"
TORSHIELD_IRAN_MODE: bool = os.getenv("TORSHIELD_IRAN_MODE", "false").lower() == "true"

# Auto-debug: run comprehensive auto-debug diagnosis on startup
AUTO_DEBUG_MODE: bool = os.getenv("AUTO_DEBUG_MODE", "false").lower() == "true"

# ─────────────────────────────────────────────────────────────────────────────
# v4 NEW: uTLS Evasion, Elite Registry, Circuit Breaker, Telemetry
# ALL EXISTING SETTINGS PRESERVED — NOTHING REMOVED
# ─────────────────────────────────────────────────────────────────────────────

# uTLS Evasion Layer: Dynamic TLS fingerprinting and SNI masking for Iran DPI
UTLS_EVASION_MODE:    bool = os.getenv("UTLS_EVASION_MODE",    "true").lower()  == "true"
UTLS_PROFILE_ROTATION: int  = int(os.getenv("UTLS_PROFILE_ROTATION", "30"))  # seconds between profile rotations

# Elite Registry: Dynamic model discovery and fitness scoring
ELITE_REGISTRY_ENABLED:     bool = os.getenv("ELITE_REGISTRY_ENABLED",     "true").lower() == "true"
ELITE_REGISTRY_REFRESH_HRS: int  = int(os.getenv("ELITE_REGISTRY_REFRESH_HRS", "6"))  # hours between API refreshes

# Circuit Breaker 11-Slot: Zero-error fallback across all CF slots
CIRCUIT_BREAKER_ENABLED:       bool  = os.getenv("CIRCUIT_BREAKER_ENABLED",       "true").lower() == "true"
CIRCUIT_BREAKER_MAX_FAILURES:  int   = int(os.getenv("CIRCUIT_BREAKER_MAX_FAILURES",  "3"))
CIRCUIT_BREAKER_RESET_SECS:    float = float(os.getenv("CIRCUIT_BREAKER_RESET_SECS",   "300"))
SESSION_BLACKLIST_DURATION_SECS: float = float(os.getenv("SESSION_BLACKLIST_DURATION_SECS", "3600"))

# Telemetry Watcher: Centralized monitoring and self-heal tracking
TELEMETRY_ENABLED:           bool = os.getenv("TELEMETRY_ENABLED",           "true").lower() == "true"
TELEMETRY_AUTO_DEBUG_THRESHOLD: int = int(os.getenv("TELEMETRY_AUTO_DEBUG_THRESHOLD", "2"))
TELEMETRY_LOG_MAX_MB:        int  = int(os.getenv("TELEMETRY_LOG_MAX_MB",    "10"))

# IRST High-Censorship Hours (for time-based predictive routing)
IRST_HIGH_CENSORSHIP_START: int = int(os.getenv("IRST_HIGH_CENSORSHIP_START", "18"))
IRST_HIGH_CENSORSHIP_END:   int = int(os.getenv("IRST_HIGH_CENSORSHIP_END",   "1"))
IRST_ULTRA_STEALTH_START:   int = int(os.getenv("IRST_ULTRA_STEALTH_START",   "20"))
IRST_ULTRA_STEALTH_END:     int = int(os.getenv("IRST_ULTRA_STEALTH_END",     "23"))
