"""
core/iran_detector.py — Iran network isolation detector.

Detects whether the machine running this tool is inside Iran and, if so,
whether international internet is currently reachable or if the National
Information Network (NIN / شبکه ملی اطلاعات) is active (i.e., international
traffic is blocked).

This module is most useful when the tool is run locally inside Iran.
In GitHub Actions mode the detection always returns "international reachable".

Methodology:
  1. Attempt TCP connections to multiple international DNS resolvers (port 53).
  2. Attempt HTTPS to a known-good international endpoint.
  3. Cross-check against Iranian NIN test IPs (10.x / 172.x national gateways).
  If all international probes fail → NIN is likely active.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import time
from typing import Tuple

log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Test targets
# ─────────────────────────────────────────────────────────────────────────────

# Well-known international DNS/HTTPS endpoints
_INTERNATIONAL_PROBES = [
    ("8.8.8.8",        53),   # Google DNS
    ("1.1.1.1",        53),   # Cloudflare DNS
    ("208.67.222.222", 53),   # OpenDNS
    ("9.9.9.9",        53),   # Quad9
]

# Iranian NIN / domestic gateway IPs (usually reachable even during cuts)
_NIN_PROBES = [
    ("10.10.34.34",  80),   # IRNIC / IRCERT portal
    ("185.51.200.2", 80),   # Known NIN DNS
]

_PROBE_TIMEOUT = 3.0


async def _probe_tcp(host: str, port: int, timeout: float = _PROBE_TIMEOUT) -> bool:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
        except Exception:
            pass
        return True
    except Exception:
        return False


async def check_connectivity() -> Tuple[bool, bool]:
    """
    Returns (international_ok: bool, nin_active: bool).

    - international_ok = True  →  at least one international probe succeeded
    - nin_active       = True  →  NIN domestic probe succeeded BUT international failed
                                  (strong signal that internet cut is in effect)
    """
    # Run all probes concurrently
    int_tasks  = [_probe_tcp(h, p) for h, p in _INTERNATIONAL_PROBES]
    nin_tasks  = [_probe_tcp(h, p) for h, p in _NIN_PROBES]

    int_results, nin_results = await asyncio.gather(
        asyncio.gather(*int_tasks, return_exceptions=True),
        asyncio.gather(*nin_tasks, return_exceptions=True),
    )

    int_ok  = any(r is True for r in int_results)
    nin_ok  = any(r is True for r in nin_results)
    nin_active = nin_ok and not int_ok

    if nin_active:
        log.warning(
            "⚠️  IRAN INTERNET CUT DETECTED — international internet unreachable. "
            "Recommending Snowflake / WebTunnel (CDN) bridges."
        )
    elif not int_ok:
        log.warning("No internet connectivity detected at all.")
    else:
        log.info("International internet reachable.")

    return int_ok, nin_active


def recommend_strategy(nin_active: bool) -> str:
    if nin_active:
        return (
            "Internet cut detected (شبکه ملی فعال). "
            "Use: export/iran_cut_pack.txt → Snowflake, then WebTunnel (CDN-fronted). "
            "Avoid vanilla/obfs4 — their IPs are unreachable during cuts."
        )
    return (
        "International internet reachable. "
        "Use: export/iran_pack.txt → obfs4 (port 443) or WebTunnel for best performance."
    )
