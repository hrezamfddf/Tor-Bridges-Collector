"""
sources/torproject.py — Async scraper for bridges.torproject.org.

Fetches all transport types (obfs4, webtunnel, vanilla) in both IPv4 and IPv6
using rotating User-Agents and randomised request delays to avoid rate-limiting.
"""

from __future__ import annotations

import asyncio
import logging
import random
import re
import time
from typing import List, Tuple

import requests
from bs4 import BeautifulSoup

import config
from core.tester import detect_transport

log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Targets
# ─────────────────────────────────────────────────────────────────────────────

TARGETS: List[Tuple[str, str, str, str]] = [
    # (url, filename_hint, transport, ip_version)
    ("https://bridges.torproject.org/bridges?transport=obfs4",                 "obfs4.txt",          "obfs4",     "ipv4"),
    ("https://bridges.torproject.org/bridges?transport=obfs4&ipv6=yes",        "obfs4_ipv6.txt",     "obfs4",     "ipv6"),
    ("https://bridges.torproject.org/bridges?transport=webtunnel",             "webtunnel.txt",      "webtunnel", "ipv4"),
    ("https://bridges.torproject.org/bridges?transport=webtunnel&ipv6=yes",    "webtunnel_ipv6.txt", "webtunnel", "ipv6"),
    ("https://bridges.torproject.org/bridges?transport=vanilla",               "vanilla.txt",        "vanilla",   "ipv4"),
    ("https://bridges.torproject.org/bridges?transport=vanilla&ipv6=yes",      "vanilla_ipv6.txt",   "vanilla",   "ipv6"),
]

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
]

_BRIDGE_LINE_RE = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3}:\d+|\[[0-9a-fA-F:]+\]:\d+|https?://\S+)')


def _is_valid_line(line: str) -> bool:
    if not line or len(line) < 10:
        return False
    if "No bridges available" in line or line.startswith("#"):
        return False
    return bool(_BRIDGE_LINE_RE.search(line))


def _parse_html(html: str) -> List[str]:
    soup = BeautifulSoup(html, "html.parser")
    div = soup.find("div", id="bridgelines")
    if not div:
        # Fallback: try <pre> or <code> blocks
        for tag in soup.find_all(["pre", "code"]):
            text = tag.get_text()
            if _BRIDGE_LINE_RE.search(text):
                return [l.strip() for l in text.split("\n") if _is_valid_line(l.strip())]
        return []
    raw = div.get_text()
    return [l.strip() for l in raw.split("\n") if _is_valid_line(l.strip())]


def _fetch_one(url: str, transport: str) -> List[str]:
    """Synchronous fetch of a single bridge page."""
    headers = {
        "User-Agent": random.choice(_USER_AGENTS),
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Referer": "https://bridges.torproject.org/",
    }
    proxies = {}
    if config.HTTPS_PROXY:
        proxies = {"https": config.HTTPS_PROXY, "http": config.HTTP_PROXY or config.HTTPS_PROXY}

    try:
        r = requests.get(url, headers=headers, timeout=30, proxies=proxies or None)
        r.raise_for_status()
        lines = _parse_html(r.text)
        if lines:
            log.info(f"  torproject.org [{transport}]: {len(lines)} bridges")
        else:
            log.warning(f"  torproject.org [{transport}]: 0 bridges (may be rate-limited)")
        return lines
    except Exception as e:
        log.warning(f"  torproject.org fetch error [{transport}]: {e}")
        return []


async def fetch_all() -> List[Tuple[str, str, str]]:
    """
    Fetch bridges from all targets asynchronously (one thread per target).
    Returns list of (bridge_line, transport, ip_version).
    """
    loop = asyncio.get_event_loop()
    results: List[Tuple[str, str, str]] = []

    async def _async_fetch(url: str, transport: str, ip_ver: str):
        # Small random delay to be polite and avoid CAPTCHA triggers
        await asyncio.sleep(random.uniform(0.3, 1.5))
        lines = await loop.run_in_executor(None, _fetch_one, url, transport)
        for line in lines:
            results.append((line, transport, ip_ver))

    tasks = [_async_fetch(url, t, ip) for url, _, t, ip in TARGETS]
    await asyncio.gather(*tasks)
    log.info(f"torproject.org total: {len(results)} bridge lines collected.")
    return results
