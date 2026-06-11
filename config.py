"""
config.py — Central configuration for TorShield-IR Tor Bridges Collector v2.
All values are overridable via environment variables.
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
