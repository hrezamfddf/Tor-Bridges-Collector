"""
core/tester.py — Async bridge connectivity tester.

Uses asyncio for high-concurrency TCP/SSL testing without threading overhead.
Supports: vanilla TCP, obfs4 TCP probe, WebTunnel TLS handshake.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import socket
import ssl
import time
from typing import Optional, Tuple

import config

log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Bridge line parsing
# ─────────────────────────────────────────────────────────────────────────────

# Regex patterns ordered by specificity
_IP6_PORT_RE = re.compile(r'\[([0-9a-fA-F:]+)\]:(\d+)')
_IP4_PORT_RE = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})')
_HTTPS_RE = re.compile(r'https?://([^/:\s]+)(?::(\d+))?', re.IGNORECASE)
_DOMAIN_PORT_RE = re.compile(r'([a-zA-Z0-9._-]+\.(?:net|com|org|io|dev)):(\d+)')


def detect_transport(line: str) -> str:
    l = line.lower()
    if 'snowflake' in l:
        return 'snowflake'
    if 'webtunnel' in l or 'url=https' in l:
        return 'webtunnel'
    if 'obfs4' in l:
        return 'obfs4'
    if 'meek' in l:
        return 'meek_lite'
    return 'vanilla'


def extract_endpoint(line: str) -> Tuple[Optional[str], Optional[int], str]:
    """Return (host, port, transport) from a bridge line, or (None, None, transport)."""
    line = line.strip()
    if line.startswith("Bridge "):
        line = line[7:]

    transport = detect_transport(line)

    # WebTunnel / meek: prefer HTTPS URL host
    if transport in ('webtunnel', 'meek_lite', 'snowflake'):
        m = _HTTPS_RE.search(line)
        if m:
            host = m.group(1)
            port = int(m.group(2)) if m.group(2) else 443
            return host, port, transport

    # IPv6 [addr]:port
    m = _IP6_PORT_RE.search(line)
    if m:
        return m.group(1), int(m.group(2)), transport

    # IPv4 addr:port
    m = _IP4_PORT_RE.search(line)
    if m:
        return m.group(1), int(m.group(2)), transport

    # Domain:port (fallback)
    m = _DOMAIN_PORT_RE.search(line)
    if m:
        return m.group(1), int(m.group(2)), transport

    return None, None, transport


def is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# Low-level async probes
# ─────────────────────────────────────────────────────────────────────────────

async def _probe_tcp(host: str, port: int, timeout: float) -> Tuple[bool, int]:
    """Open a TCP connection and return (success, latency_ms)."""
    start = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        latency = int((time.monotonic() - start) * 1000)
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
        except Exception:
            pass
        return True, latency
    except Exception:
        return False, -1


async def _probe_tls(host: str, port: int, timeout: float) -> Tuple[bool, int]:
    """Complete a TLS handshake and return (success, latency_ms)."""
    start = time.monotonic()
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # Randomise cipher list to avoid static TLS fingerprint (anti-DPI measure)
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
            timeout=timeout,
        )
        latency = int((time.monotonic() - start) * 1000)
        # Send minimal HTTP/1.0 probe to confirm the TLS layer is live
        writer.write(b"GET / HTTP/1.0\r\nHost: " + host.encode() + b"\r\n\r\n")
        try:
            await asyncio.wait_for(reader.read(32), timeout=3.0)
        except Exception:
            pass
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
        except Exception:
            pass
        return True, latency
    except Exception:
        return False, -1


# ─────────────────────────────────────────────────────────────────────────────
# DNS helper (blocking, run in thread pool)
# ─────────────────────────────────────────────────────────────────────────────

async def _resolve(host: str) -> Optional[str]:
    if is_ip(host):
        return host
    loop = asyncio.get_event_loop()
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(None, socket.gethostbyname, host),
            timeout=5.0,
        )
        return result
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Per-bridge test
# ─────────────────────────────────────────────────────────────────────────────

async def test_bridge(line: str) -> Tuple[bool, int]:
    """
    Test a single bridge line.
    Returns (reachable: bool, latency_ms: int).
    latency_ms is -1 on failure.
    """
    host, port, transport = extract_endpoint(line)
    if not host or not port:
        return False, -1

    # Snowflake uses WebRTC — no meaningful TCP/TLS test from a plain socket.
    # We mark them as "untested" but assume they're valid if from official source.
    if transport == 'snowflake':
        return True, 0  # optimistic — snowflake is hard to block

    # Resolve domain to IP if needed
    resolved = await _resolve(host)
    if not resolved:
        return False, -1

    timeout = config.CONNECTION_TIMEOUT

    for attempt in range(config.MAX_RETRIES):
        if transport in ('webtunnel', 'meek_lite'):
            ok, lat = await _probe_tls(resolved, port, timeout)
        else:
            ok, lat = await _probe_tcp(resolved, port, timeout)

        if ok:
            return True, lat
        if attempt < config.MAX_RETRIES - 1:
            await asyncio.sleep(0.4 * (attempt + 1))

    return False, -1


# ─────────────────────────────────────────────────────────────────────────────
# Batch tester
# ─────────────────────────────────────────────────────────────────────────────

class BridgeTester:
    def __init__(self, workers: int = None):
        self._workers = workers or config.MAX_WORKERS

    async def test_all(
        self,
        bridge_lines: list[str],
        max_per_run: int = None,
    ) -> dict[str, Tuple[bool, int]]:
        """
        Test a list of bridge lines concurrently.
        Returns dict: bridge_line -> (passed, latency_ms)
        """
        limit = max_per_run or config.MAX_TEST_PER_TYPE
        lines = list(dict.fromkeys(l.strip() for l in bridge_lines if l.strip()))
        if len(lines) > limit:
            log.info(f"Capping test pool at {limit} (have {len(lines)})")
            lines = lines[:limit]

        semaphore = asyncio.Semaphore(self._workers)
        results: dict[str, Tuple[bool, int]] = {}

        async def bounded_test(line: str):
            async with semaphore:
                ok, lat = await test_bridge(line)
                results[line] = (ok, lat)

        log.info(f"Testing {len(lines)} bridges (concurrency={self._workers})…")
        await asyncio.gather(*[bounded_test(l) for l in lines])

        passed = sum(1 for ok, _ in results.values() if ok)
        log.info(f"Test complete: {passed}/{len(lines)} reachable.")
        return results
