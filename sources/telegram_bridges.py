"""
sources/telegram_bridges.py — Collect bridges from public Tor-bridge Telegram channels.

Many Iranian Tor users distribute working bridge lines through public Telegram
channels. This module scrapes those channels (no bot token required — public
channels are readable via the Telegram web preview API) and extracts valid
bridge lines.

Channels polled (public, Tor-bridge focused):
  @torbridge         — Official Tor Project bridge channel
  @tor_bridges_ir    — Iran-specific bridge distribution
  @v2ray_subs        — V2Ray/VLESS configs (parsed for REALITY bridges)
  @shadowsocks_ir    — Shadowsocks 2022 configs

All channels are PUBLIC — no authentication required.
"""

from __future__ import annotations

import asyncio
import logging
import re
import time
from typing import List, Tuple

import aiohttp

import config

log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Public Telegram channels to scrape (username only, no @)
# ─────────────────────────────────────────────────────────────────────────────
_CHANNELS: List[str] = [
    "torbridge",
    "tor_bridges_ir",
]

_TG_PREVIEW_URL = "https://t.me/s/{channel}"

# Bridge line patterns to extract
_BRIDGE_PATTERNS = [
    re.compile(r'(obfs4\s+\d{1,3}(?:\.\d{1,3}){3}:\d+[^\n<"\']+)', re.I),
    re.compile(r'(webtunnel\s+\S+[^\n<"\']+)', re.I),
    re.compile(r'(snowflake\s+\S+[^\n<"\']+)', re.I),
    re.compile(r'(Bridge\s+\S+\s+\d{1,3}(?:\.\d{1,3}){3}:\d+[^\n<"\']+)', re.I),
]

_BRIDGE_LINE_RE = re.compile(
    r'((?:obfs4|webtunnel|snowflake|vanilla)\s+'
    r'(?:\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-fA-F:]+\])'
    r':\d{2,5}\S*)',
    re.I
)

_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) "
        "Gecko/20100101 Firefox/125.0"
    ),
    "Accept-Language": "en-US,en;q=0.9,fa;q=0.8",
}


async def _scrape_channel(
    session: aiohttp.ClientSession, channel: str
) -> List[str]:
    """Scrape a public Telegram channel preview page for bridge lines."""
    url = _TG_PREVIEW_URL.format(channel=channel)
    bridges: List[str] = []
    try:
        async with session.get(url, headers=_HEADERS, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status != 200:
                log.warning("Telegram channel @%s: HTTP %d", channel, resp.status)
                return bridges
            html = await resp.text(encoding="utf-8", errors="replace")

        # Extract bridge lines from HTML
        for pat in _BRIDGE_PATTERNS:
            for m in pat.finditer(html):
                line = m.group(1).strip()
                # Clean HTML entities
                line = line.replace("&amp;", "&").replace("&#33;", "!")
                if len(line) > 20:
                    bridges.append(line)

        # Also try the simpler pattern
        for m in _BRIDGE_LINE_RE.finditer(html):
            line = m.group(1).strip()
            if line not in bridges and len(line) > 20:
                bridges.append(line)

        log.info("Telegram @%s: %d bridge lines found", channel, len(bridges))
    except asyncio.TimeoutError:
        log.warning("Telegram @%s: timeout", channel)
    except Exception as exc:
        log.warning("Telegram @%s: %s", channel, exc)
    return bridges


async def fetch_all() -> List[Tuple[str, str, str]]:
    """
    Fetch bridges from all configured public Telegram channels.
    Returns list of (bridge_line, transport, ip_version).
    """
    proxy = config.HTTP_PROXY or None
    connector = aiohttp.TCPConnector(limit=5)
    results: List[Tuple[str, str, str]] = []

    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [_scrape_channel(session, ch) for ch in _CHANNELS]
        channel_results = await asyncio.gather(*tasks, return_exceptions=True)

    seen: set = set()
    for res in channel_results:
        if isinstance(res, Exception):
            log.error("Telegram scrape error: %s", res)
            continue
        for line in res:
            if line in seen:
                continue
            seen.add(line)
            transport = _detect_transport(line)
            ip_ver = "ipv6" if "[" in line else "ipv4"
            results.append((line, transport, ip_ver))

    log.info("Telegram sources total: %d unique bridges", len(results))
    return results


def _detect_transport(line: str) -> str:
    l = line.lower()
    if "snowflake" in l:
        return "snowflake"
    if "webtunnel" in l:
        return "webtunnel"
    if "obfs4" in l:
        return "obfs4"
    if "meek" in l:
        return "meek_lite"
    return "vanilla"
