"""
sources/github_bridges.py — GitHub-hosted public bridge lists collector.

Fetches bridge lists from publicly accessible GitHub repositories and
raw content URLs. This source works reliably from GitHub Actions because
api.github.com and raw.githubusercontent.com are always accessible from
GitHub-hosted runners.

Uses only UNAUTHENTICATED requests (no API key required).
Rate limit: 60 requests/hour unauthenticated (well within our needs).
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import List, Tuple

import requests

log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Known public bridge list sources
# ─────────────────────────────────────────────────────────────────────────────

# Raw GitHub URLs of publicly known bridge list repositories
_GITHUB_RAW_SOURCES = [
    # Tor Project's own bridge metadata (public)
    "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/main/obfs4",
    "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/main/webtunnel",
    "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/main/snowflake",
    "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/main/vanilla",
    "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/main/meek_lite",
    "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/main/obfs4_ipv6",
    "https://raw.githubusercontent.com/scriptzteam/Tor-Bridges-Collector/main/webtunnel_ipv6",
    # Additional public Tor bridge repositories
    "https://raw.githubusercontent.com/mjavid/tor-bridges/main/bridges.txt",
    "https://raw.githubusercontent.com/Ookla/tor-bridges/main/obfs4.txt",
]

# Regex to detect valid bridge lines
_BRIDGE_LINE_RE = re.compile(
    r'(obfs4|webtunnel|snowflake|meek_lite|vanilla|Bridge)\s+'
    r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\[[0-9a-fA-F:]+\]|[a-zA-Z0-9._-]+)'
    r'[:\s]',
    re.IGNORECASE,
)

_TRANSPORT_RE = re.compile(
    r'^(obfs4|webtunnel|snowflake|meek_lite|meek-lite|vanilla)\s',
    re.IGNORECASE,
)


def _detect_transport(line: str) -> str:
    line_lower = line.lower().strip()
    if "snowflake" in line_lower:
        return "snowflake"
    if "webtunnel" in line_lower or "url=https" in line_lower:
        return "webtunnel"
    if "obfs4" in line_lower:
        return "obfs4"
    if "meek" in line_lower:
        return "meek_lite"
    if _BRIDGE_LINE_RE.search(line):
        return "vanilla"
    return "unknown"


def _is_valid_bridge_line(line: str) -> bool:
    """Return True if the line looks like a Tor bridge line."""
    line = line.strip()
    if not line or line.startswith("#") or len(line) < 20:
        return False
    if not _BRIDGE_LINE_RE.search(line):
        return False
    # Must have at minimum an IP:port or a URL
    has_ip = bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+', line))
    has_url = "url=https" in line.lower()
    has_ipv6 = bool(re.search(r'\[[0-9a-fA-F:]+\]:\d+', line))
    return has_ip or has_url or has_ipv6


def _fetch_url(url: str) -> List[str]:
    """Fetch raw text from a URL and return valid bridge lines."""
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Accept": "text/plain,text/html,*/*",
    }
    try:
        r = requests.get(url, headers=headers, timeout=20)
        if r.status_code != 200:
            log.debug(f"GitHub source {url}: HTTP {r.status_code}")
            return []
        lines = []
        for raw_line in r.text.splitlines():
            line = raw_line.strip()
            # Strip "Bridge " prefix
            if line.startswith("Bridge "):
                line = line[7:]
            if _is_valid_bridge_line(line):
                lines.append(line)
        if lines:
            log.info(f"GitHub source {url.split('/')[-1]}: {len(lines)} bridges")
        return lines
    except Exception as e:
        log.debug(f"GitHub source {url}: {e}")
        return []


async def fetch_all() -> List[Tuple[str, str, str]]:
    """
    Fetch bridges from GitHub-hosted public bridge lists.
    Returns list of (bridge_line, transport, ip_version).
    """
    loop = asyncio.get_event_loop()
    results: List[Tuple[str, str, str]] = []
    seen: set = set()

    async def _run(url: str):
        lines = await loop.run_in_executor(None, _fetch_url, url)
        for line in lines:
            if line not in seen:
                seen.add(line)
                transport = _detect_transport(line)
                if transport == "unknown":
                    continue
                ip_ver = "ipv6" if ("[" in line and ":" in line) else "ipv4"
                results.append((line, transport, ip_ver))

    tasks = [_run(url) for url in _GITHUB_RAW_SOURCES]
    await asyncio.gather(*tasks, return_exceptions=True)

    log.info(f"GitHub sources total: {len(results)} unique bridge lines collected.")
    return results
