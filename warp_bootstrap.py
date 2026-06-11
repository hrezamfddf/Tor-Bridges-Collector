#!/usr/bin/env python3
"""
warp_bootstrap.py — FEATURE 10: Cloudflare WARP Bootstrap Transport.

In Iran, Cloudflare WARP (WireGuard over UDP/2408 or the fallback TCP/443 MASQUE
path) provides a low-latency, DPI-resistant tunnel that Iran has never fully
blocked due to the massive collateral damage it would cause (banking, e-commerce,
CDN-served government sites all depend on Cloudflare infrastructure).

This module detects whether WARP is reachable from the current network and,
if so, recommends it as a *first hop* before connecting to Tor:

  User  ──WARP──►  Cloudflare Edge  ──Tor──►  Tor network  ──►  Internet

This "Tor over WARP" pattern has two advantages over direct Tor access:
  1. The DPI box sees only WARP/WireGuard traffic — no Tor fingerprint.
  2. The Tor bridge IP is hidden inside WARP; Iran cannot enumerate and block it.

Outputs:
  data/warp_status.json        — WARP reachability result
  export/warp_bridges.txt      — Recommended bridges for Tor-over-WARP use

Usage:
  python warp_bootstrap.py
  from warp_bootstrap import WARPProber
  prober = WARPProber()
  status = prober.probe()
"""

from __future__ import annotations

import asyncio
import json
import logging
import socket
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

DATA_DIR   = Path("data")
EXPORT_DIR = Path("export")
DATA_DIR.mkdir(parents=True, exist_ok=True)
EXPORT_DIR.mkdir(parents=True, exist_ok=True)

WARP_STATUS_PATH   = DATA_DIR / "warp_status.json"
WARP_BRIDGES_PATH  = EXPORT_DIR / "warp_bridges.txt"

# ─────────────────────────────────────────────────────────────────────────────
# WARP endpoint catalogue
# Cloudflare publishes these in their WARP client app and open-source code.
# ─────────────────────────────────────────────────────────────────────────────

_WARP_UDP_ENDPOINTS: List[Tuple[str, int]] = [
    ("162.159.192.1", 2408),
    ("162.159.192.9", 2408),
    ("162.159.193.1", 2408),
    ("162.159.195.1", 2408),
    ("188.114.96.1",  2408),
    ("188.114.97.1",  2408),
]

# Fallback: WARP over MASQUE (HTTP/3 CONNECT) — TCP/443 to Cloudflare
_WARP_TCP_FALLBACK: List[Tuple[str, int]] = [
    ("162.159.192.1", 443),
    ("162.159.193.1", 443),
]

# Cloudflare anycast ranges that Iran cannot block without CDN collateral damage
_CF_ANYCAST_RANGES = ["162.159.0.0/16", "188.114.96.0/22", "1.1.1.0/24"]

_PROBE_TIMEOUT = 4.0


@dataclass
class WARPProbeResult:
    udp_reachable:     bool  = False
    tcp_fallback_ok:   bool  = False
    latency_ms:        float = 0.0
    best_endpoint:     str   = ""
    nin_survivable:    bool  = False
    recommendation:    str   = ""
    note:              str   = ""


async def _probe_tcp(host: str, port: int, timeout: float = _PROBE_TIMEOUT) -> Tuple[bool, float]:
    """Returns (reachable, latency_ms)."""
    t0 = time.monotonic()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        latency = (time.monotonic() - t0) * 1000
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
        except Exception:
            pass
        return True, round(latency, 1)
    except Exception:
        return False, 0.0


async def _probe_udp(host: str, port: int, timeout: float = _PROBE_TIMEOUT) -> Tuple[bool, float]:
    """
    UDP reachability check: send a minimal WireGuard Initiation packet.
    A WARP endpoint that receives it will respond with a WireGuard Handshake Response.
    We do not complete the WireGuard handshake (we lack keys) — we only check
    whether the network path is open by timing whether we get *any* UDP response.
    """
    import asyncio

    class UDPProbeProtocol(asyncio.DatagramProtocol):
        def __init__(self) -> None:
            self.received = asyncio.Event()
            self.t0 = time.monotonic()
            self.latency: float = 0.0

        def datagram_received(self, data: bytes, addr: Any) -> None:
            if not self.received.is_set():
                self.latency = (time.monotonic() - self.t0) * 1000
                self.received.set()

        def error_received(self, exc: Exception) -> None:
            self.received.set()

        def connection_lost(self, exc: Optional[Exception]) -> None:
            self.received.set()

    loop = asyncio.get_event_loop()
    proto_holder: List[UDPProbeProtocol] = []

    try:
        # Build a minimal WireGuard Handshake Initiation message (148 bytes)
        # Message type 1 (0x01), reserved (3 bytes), sender index (4 bytes),
        # then 140 zero bytes. A real WARP server won't complete the handshake
        # (keys are wrong) but will typically send back a message-type-4 cookie
        # reply, confirming the UDP path is open.
        wg_initiation = bytes([0x01, 0x00, 0x00, 0x00]) + bytes(144)

        transport, protocol = await loop.create_datagram_endpoint(
            lambda: (
                lambda p=(None,): (
                    proto_holder.append(UDPProbeProtocol()),
                    proto_holder[-1]
                )[-1]
            )(),
            remote_addr=(host, port),
        )
        t0 = time.monotonic()
        transport.sendto(wg_initiation)
        try:
            await asyncio.wait_for(proto_holder[-1].received.wait(), timeout=timeout)
            latency = proto_holder[-1].latency or (time.monotonic() - t0) * 1000
            return True, round(latency, 1)
        except asyncio.TimeoutError:
            return False, 0.0
        finally:
            transport.close()
    except Exception:
        # UDP probe failed at OS level (ICMP port unreachable counts as reachable path info)
        return False, 0.0


class WARPProber:
    """
    Probes Cloudflare WARP endpoints to determine if WARP is usable as a
    Tor bootstrap transport from the current network.
    """

    def probe(self) -> WARPProbeResult:
        return asyncio.run(self._async_probe())

    async def _async_probe(self) -> WARPProbeResult:
        result = WARPProbeResult()

        # ── TCP fallback (port 443) — most reliable indicator ────────────────
        tcp_tasks = [_probe_tcp(h, p) for h, p in _WARP_TCP_FALLBACK]
        tcp_results = await asyncio.gather(*tcp_tasks)

        for (ok, lat), (host, port) in zip(tcp_results, _WARP_TCP_FALLBACK):
            if ok:
                result.tcp_fallback_ok = True
                if result.latency_ms == 0.0 or lat < result.latency_ms:
                    result.latency_ms   = lat
                    result.best_endpoint = f"{host}:{port}"

        # ── Build recommendation ─────────────────────────────────────────────
        if result.udp_reachable or result.tcp_fallback_ok:
            result.nin_survivable = True   # Cloudflare cannot be blocked in NIN mode
            result.recommendation = (
                "WARP REACHABLE ✓\n"
                "Recommended strategy for Iran: enable Cloudflare WARP first, then\n"
                "connect Tor Browser. This hides Tor bridge traffic inside WARP's\n"
                "WireGuard/MASQUE envelope — DPI sees only Cloudflare traffic.\n"
                f"Best endpoint: {result.best_endpoint} (latency {result.latency_ms:.0f} ms)"
            )
            result.note = (
                "WARP is free (cloudflare.com/products/zero-trust/warp). "
                "Install the 1.1.1.1 app (Android/iOS) or WARP client (Windows/Linux/macOS). "
                "In the app: set 'Connection mode' to 'WARP' or 'WARP via WireGuard'. "
                "Then open Tor Browser — all Tor traffic is tunnelled inside WARP."
            )
        else:
            result.nin_survivable = False
            result.recommendation = (
                "WARP NOT REACHABLE — WARP endpoints blocked on this network.\n"
                "Fallback: use Snowflake bridges from export/iran_cut_pack.txt."
            )

        return result


def run() -> Dict[str, Any]:
    prober = WARPProber()
    log.info("Probing Cloudflare WARP reachability…")
    result = prober.probe()

    report: Dict[str, Any] = {
        "generated_at":     datetime.now(timezone.utc).isoformat(),
        "warp_available":   result.udp_reachable or result.tcp_fallback_ok,
        "udp_reachable":    result.udp_reachable,
        "tcp_fallback_ok":  result.tcp_fallback_ok,
        "latency_ms":       result.latency_ms,
        "best_endpoint":    result.best_endpoint,
        "nin_survivable":   result.nin_survivable,
        "recommendation":   result.recommendation,
        "note":             result.note,
        "warp_install_url": "https://1.1.1.1",
    }

    WARP_STATUS_PATH.write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    log.info("WARP status: available=%s, latency=%.0f ms → %s",
             report["warp_available"], result.latency_ms, WARP_STATUS_PATH)

    # Write bridge recommendation file
    if result.udp_reachable or result.tcp_fallback_ok:
        warp_bridges_text = (
            "# WARP Bootstrap — Recommended Tor Bridges for Tor-over-WARP\n"
            "# Enable Cloudflare WARP first (1.1.1.1 app), then use these bridges.\n"
            "# WebTunnel (CDN-fronted) bridges work best inside WARP:\n"
            "# See export/iran_pack.txt for the full list, sorted by Iran score.\n"
            "#\n"
            "# Strategy: WARP (WireGuard/UDP) → Tor Browser → Tor bridge\n"
            "# DPI sees: Cloudflare WireGuard traffic (not Tor)\n"
        )
        WARP_BRIDGES_PATH.write_text(warp_bridges_text, encoding="utf-8")

    return report


if __name__ == "__main__":
    run()
