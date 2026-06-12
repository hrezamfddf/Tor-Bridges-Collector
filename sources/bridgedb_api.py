"""
sources/bridgedb_api.py — BridgeDB HTTPS API + MOAT distributor interface.

Provides two collection pathways:

  1. BridgeDB HTTPS endpoint  — direct HTTPS to bridges.torproject.org/moat/
  2. Domain-fronted MOAT      — same API proxied via Fastly CDN edge,
                                 accessible inside Iran even during soft cuts.

The domain-fronting technique works because Fastly has Iranian PoPs that Iran
cannot block without collateral damage to its own banking infrastructure.
The Host header directs the request to bridges.torproject.org while the TCP
connection goes to Fastly's edge IP.

References:
  https://spec.torproject.org/bridges-spec
  https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import random
import string
import time
from typing import Any, Dict, List, Optional, Tuple

import aiohttp

import config

log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# MOAT / BridgeDB endpoints
# ─────────────────────────────────────────────────────────────────────────────

_MOAT_BASE      = "https://bridges.torproject.org/moat"
_BRIDGEDB_BASE  = "https://bridges.torproject.org/bridges"

# Fastly CDN edge IP — Fastly has PoPs inside Iran.
# This IP serves bridges.torproject.org via domain fronting.
_FASTLY_EDGE    = "https://cdn.fastly.com"  # used as base URL

_MOAT_FETCH_URL = f"{_MOAT_BASE}/fetch"
_CAPTCHA_SOLVE  = f"{_MOAT_BASE}/check"

_TRANSPORT_TYPES = ["obfs4", "webtunnel", "snowflake"]

_HEADERS_DIRECT = {
    "Content-Type":  "application/vnd.api+json",
    "Accept":        "application/vnd.api+json",
    "User-Agent":    "Tor Browser/13.0 (Windows NT 10.0; Win64; x64)",
}

# Domain-fronted headers — Host points to Tor Project, IP is Fastly edge
_HEADERS_FRONTED = {
    **_HEADERS_DIRECT,
    "Host": "bridges.torproject.org",
}


async def _moat_request(
    session: aiohttp.ClientSession,
    transport: str,
    fronted: bool = False,
) -> List[str]:
    """
    Request bridges via MOAT API for a specific transport.
    Returns a list of raw bridge lines.
    """
    payload = {
        "data": [{
            "type":      "client-transports",
            "version":   "0.1.0",
            "transports": [transport],
        }]
    }

    base_url  = _FASTLY_EDGE if fronted else _MOAT_BASE
    headers   = _HEADERS_FRONTED if fronted else _HEADERS_DIRECT
    fetch_url = f"{base_url}/moat/fetch" if fronted else _MOAT_FETCH_URL

    try:
        async with session.post(
            fetch_url,
            json=payload,
            headers=headers,
            timeout=aiohttp.ClientTimeout(total=20),
            ssl=True,
        ) as resp:
            if resp.status != 200:
                log.debug("MOAT %s %s: HTTP %d", transport,
                         "fronted" if fronted else "direct", resp.status)
                return []

            data = await resp.json(content_type=None)

        # Parse MOAT response — handle both list and dict formats
        bridges: List[str] = []
        data_list = data.get("data", [])
        if not isinstance(data_list, list):
            data_list = [data_list] if data_list else []
        for item in data_list:
            if not isinstance(item, dict):
                continue
            bridge_val = item.get("bridges", [])
            # bridges can be a list of strings OR a dict like {"obfs4": [...]}
            if isinstance(bridge_val, list):
                for bridge in bridge_val:
                    if isinstance(bridge, str) and len(bridge) > 10:
                        bridges.append(bridge)
            elif isinstance(bridge_val, dict):
                for transport_key, bridge_list in bridge_val.items():
                    if isinstance(bridge_list, list):
                        for bridge in bridge_list:
                            if isinstance(bridge, str) and len(bridge) > 10:
                                bridges.append(bridge)
        # Also check top-level "bridges" key
        if not bridges:
            top_bridges = data.get("bridges", {})
            if isinstance(top_bridges, dict):
                for transport_key, bridge_list in top_bridges.items():
                    if isinstance(bridge_list, list):
                        for bridge in bridge_list:
                            if isinstance(bridge, str) and len(bridge) > 10:
                                bridges.append(bridge)

        if bridges:
            log.info("MOAT %s (%s): %d bridges",
                     transport, "fronted" if fronted else "direct", len(bridges))
        return bridges

    except asyncio.TimeoutError:
        log.debug("MOAT %s: timeout", transport)
        return []
    except Exception as exc:
        log.debug("MOAT %s: %s", transport, exc)
        return []


async def fetch_all() -> List[Tuple[str, str, str]]:
    """
    Fetch bridges via BridgeDB API (direct + domain-fronted).
    Returns list of (bridge_line, transport, ip_version).
    """
    results: List[Tuple[str, str, str]] = []
    seen: set = set()

    connector = aiohttp.TCPConnector(limit=10, ssl=True)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []
        for transport in _TRANSPORT_TYPES:
            tasks.append(_moat_request(session, transport, fronted=False))
            tasks.append(_moat_request(session, transport, fronted=True))

        all_results = await asyncio.gather(*tasks, return_exceptions=True)

    transport_cycle = _TRANSPORT_TYPES * 2  # interleaved direct + fronted
    for i, res in enumerate(all_results):
        if isinstance(res, Exception):
            log.warning("BridgeDB fetch error: %s", res)
            continue
        transport = transport_cycle[i % len(transport_cycle)]
        for line in res:
            if line in seen:
                continue
            seen.add(line)
            ip_ver = "ipv6" if "[" in line else "ipv4"
            results.append((line, transport, ip_ver))

    log.info("BridgeDB API total: %d unique bridges", len(results))
    return results
