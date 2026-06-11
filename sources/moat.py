"""
sources/moat.py — Tor Project MOAT Circumvention API client.

CRITICAL BUG FIXED:
  data.get("data", {}).get("bridges", {}) raised AttributeError when
  data["data"] is a LIST (newer MOAT API format). Now handles all formats.

The MOAT API provides built-in bridges WITHOUT requiring a CAPTCHA,
making it the most reliable programmatic source for bridge collection.
"""

from __future__ import annotations

import asyncio
import logging
import random
from typing import Any, Dict, List, Tuple

import requests

import config

log = logging.getLogger(__name__)

MOAT_BASE = "https://bridges.torproject.org/moat"

_MOAT_HEADERS = {
    "Content-Type": "application/vnd.api+json",
    "Accept":       "application/vnd.api+json",
    "User-Agent":   "Tor Browser/13.5 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0",
    "Origin":       "https://bridges.torproject.org",
    "Referer":      "https://bridges.torproject.org/",
}

_TRANSPORT_MAP = {
    "obfs4":      "obfs4",
    "webTunnel":  "webtunnel",
    "webtunnel":  "webtunnel",
    "WebTunnel":  "webtunnel",
    "snowflake":  "snowflake",
    "meek_lite":  "meek_lite",
    "meek-lite":  "meek_lite",
}


def _guess_transport(s: str) -> str:
    s = s.lower()
    if "snowflake" in s:
        return "snowflake"
    if "webtunnel" in s or "url=https" in s:
        return "webtunnel"
    if "obfs4" in s:
        return "obfs4"
    if "meek" in s:
        return "meek_lite"
    return "unknown"


def _extract_bridges_from_dict(bridges_section: Dict[str, Any]) -> List[Tuple[str, str]]:
    """Parse a bridges dict like {"obfs4": [...], "webTunnel": [...]}."""
    results = []
    if not isinstance(bridges_section, dict):
        return results
    for key, bridge_list in bridges_section.items():
        transport = _TRANSPORT_MAP.get(key, _guess_transport(str(key)))
        if isinstance(bridge_list, list):
            for line in bridge_list:
                if isinstance(line, str) and len(line.strip()) > 10:
                    results.append((line.strip(), transport))
        elif isinstance(bridge_list, str) and len(bridge_list.strip()) > 10:
            results.append((bridge_list.strip(), transport))
    return results


def _parse_response(data: dict) -> List[Tuple[str, str]]:
    """
    Parse MOAT API response into (bridge_line, transport) pairs.

    Handles ALL known MOAT API response formats:
      Format 1: {"bridges": {"obfs4": [...], "webTunnel": [...], ...}}
      Format 2: {"data": [{"bridges": {"obfs4": [...], ...}}]}   ← list!
      Format 3: {"data": {"bridges": {...}}}
      Format 4: {"settings": [{"bridges": {"type":"obfs4","bridge_strings":[...]}}]}
    """
    results: List[Tuple[str, str]] = []

    # ── Format 1: top-level "bridges" dict ────────────────────────────────
    if "bridges" in data and isinstance(data["bridges"], dict):
        results.extend(_extract_bridges_from_dict(data["bridges"]))
        if results:
            log.debug(f"MOAT parse: Format 1, {len(results)} bridges")
            return results

    # ── Format 2 / 3: "data" key (list or dict) ──────────────────────────
    data_val = data.get("data")
    if data_val is not None:
        # Normalise list → first element
        if isinstance(data_val, list):
            if data_val and isinstance(data_val[0], dict):
                data_val = data_val[0]
            else:
                data_val = {}
        if isinstance(data_val, dict):
            bridges_section = data_val.get("bridges", {})
            if bridges_section:
                results.extend(_extract_bridges_from_dict(bridges_section))
                if results:
                    log.debug(f"MOAT parse: Format 2/3, {len(results)} bridges")
                    return results

    # ── Format 4: "settings" list ─────────────────────────────────────────
    for item in data.get("settings", []):
        if not isinstance(item, dict):
            continue
        bridge_obj = item.get("bridges", {})
        if isinstance(bridge_obj, dict):
            transport_key = bridge_obj.get("type", "")
            transport = _TRANSPORT_MAP.get(transport_key, _guess_transport(transport_key))
            for line in bridge_obj.get("bridge_strings", []):
                if isinstance(line, str) and len(line.strip()) > 10:
                    results.append((line.strip(), transport))
        elif isinstance(bridge_obj, list):
            for line in bridge_obj:
                if isinstance(line, str) and len(line.strip()) > 10:
                    results.append((line.strip(), _guess_transport(line)))

    if results:
        log.debug(f"MOAT parse: Format 4, {len(results)} bridges")
        return results

    # ── Fallback: scan entire response for string lists ───────────────────
    for val in data.values():
        if isinstance(val, list):
            for item in val:
                if isinstance(item, str) and len(item.strip()) > 20:
                    t = _guess_transport(item)
                    if t != "unknown":
                        results.append((item.strip(), t))

    if results:
        log.debug(f"MOAT parse: Fallback scan, {len(results)} bridges")
    return results


def _post_moat(endpoint: str, payload: dict, timeout: int = 30) -> List[Tuple[str, str]]:
    """POST to a MOAT endpoint, return parsed (bridge_line, transport) pairs."""
    proxies = {}
    if getattr(config, "HTTPS_PROXY", None):
        proxies = {"https": config.HTTPS_PROXY,
                   "http": getattr(config, "HTTP_PROXY", None) or config.HTTPS_PROXY}
    try:
        r = requests.post(
            endpoint,
            json=payload,
            headers=_MOAT_HEADERS,
            timeout=timeout,
            proxies=proxies or None,
        )
        if r.status_code == 200:
            try:
                data = r.json()
            except Exception:
                log.warning(f"MOAT {endpoint}: non-JSON response")
                return []
            result = _parse_response(data)
            log.info(f"MOAT {endpoint}: {len(result)} bridges")
            return result
        else:
            log.warning(f"MOAT {endpoint} → HTTP {r.status_code}: {r.text[:200]}")
            return []
    except Exception as e:
        log.warning(f"MOAT {endpoint} error: {e}")
        return []


def _fetch_builtin(country: str = "ir") -> List[Tuple[str, str]]:
    """Fetch built-in circumvention bridges (no CAPTCHA required)."""
    url = f"{MOAT_BASE}/circumvention/builtin"
    payload: dict = {
        "version": "0.1.0",
        "transports": ["obfs4", "webTunnel", "snowflake"],
    }
    if country:
        payload["country"] = country
    return _post_moat(url, payload)


def _fetch_settings(country: str = "ir") -> List[Tuple[str, str]]:
    """Query MOAT settings endpoint for country-recommended bridges."""
    url = f"{MOAT_BASE}/circumvention/settings"
    payload = {
        "version":    "0.1.0",
        "transports": ["obfs4", "webTunnel", "snowflake"],
        "country":    country,
    }
    return _post_moat(url, payload)


def _fetch_map(country: str = "ir") -> List[Tuple[str, str]]:
    """Fetch bridges from the newer /circumvention/map endpoint."""
    url = f"{MOAT_BASE}/circumvention/map"
    payload = {
        "version": "0.1.0",
        "country": country,
    }
    return _post_moat(url, payload)


async def fetch_all() -> List[Tuple[str, str, str]]:
    """
    Fetch bridges from ALL MOAT endpoints.
    Returns list of (bridge_line, transport, ip_version).
    """
    loop = asyncio.get_event_loop()
    results: List[Tuple[str, str, str]] = []
    seen: set = set()

    async def _run(fn, *args):
        await asyncio.sleep(random.uniform(0.05, 0.3))
        pairs = await loop.run_in_executor(None, fn, *args)
        for line, transport in pairs:
            if line not in seen:
                seen.add(line)
                ip_ver = "ipv6" if ("[" in line and ":" in line) else "ipv4"
                results.append((line, transport, ip_ver))

    await asyncio.gather(
        _run(_fetch_builtin, "ir"),
        _run(_fetch_settings, "ir"),
        _run(_fetch_map, "ir"),
        _run(_fetch_builtin, ""),        # global fallback
    )

    log.info(f"MOAT API total: {len(results)} unique bridge lines collected.")
    return results
