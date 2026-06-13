#!/usr/bin/env python3
"""
sources/direct_scraper.py — Direct scraper for bridges.torproject.org.

Adapted from the legacy standalone main.py and integrated into the TorShield-IR
pipeline as a supplementary bridge source.  It scrapes the official Tor Project
bridge distribution website, performs connectivity testing, and seeds the
bridge history with fresh bridges.

Run standalone (seeds bridge/ directory directly):
    python sources/direct_scraper.py

Used by the GitHub Actions workflow as "Stage 0" before the main scraper.py
pipeline, so freshly scraped bridges are already in history before OONI testing.
"""

from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import logging
import os
import re
import socket
import ssl
import time
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

TARGETS: List[Dict[str, str]] = [
    {"url": "https://bridges.torproject.org/bridges?transport=obfs4",              "file": "obfs4.txt",          "type": "obfs4",     "ip": "IPv4"},
    {"url": "https://bridges.torproject.org/bridges?transport=webtunnel",          "file": "webtunnel.txt",      "type": "webtunnel", "ip": "IPv4"},
    {"url": "https://bridges.torproject.org/bridges?transport=vanilla",            "file": "vanilla.txt",        "type": "vanilla",   "ip": "IPv4"},
    {"url": "https://bridges.torproject.org/bridges?transport=obfs4&ipv6=yes",     "file": "obfs4_ipv6.txt",     "type": "obfs4",     "ip": "IPv6"},
    {"url": "https://bridges.torproject.org/bridges?transport=webtunnel&ipv6=yes", "file": "webtunnel_ipv6.txt", "type": "webtunnel", "ip": "IPv6"},
    {"url": "https://bridges.torproject.org/bridges?transport=vanilla&ipv6=yes",   "file": "vanilla_ipv6.txt",   "type": "vanilla",   "ip": "IPv6"},
]

RECENT_HOURS           = int(os.getenv("RECENT_HOURS", "72"))
HISTORY_RETENTION_DAYS = 30
MAX_WORKERS            = 50
CONNECTION_TIMEOUT     = 8
MAX_RETRIES            = 2
SSL_TIMEOUT            = 5
MAX_TEST_PER_TYPE      = 500

BRIDGE_DIR   = Path(os.getenv("BRIDGE_DIR", "bridge"))
HISTORY_FILE = BRIDGE_DIR / "bridge_history.json"

BRIDGE_DIR.mkdir(parents=True, exist_ok=True)

_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

# ─────────────────────────────────────────────────────────────────────────────
# Validation helpers
# ─────────────────────────────────────────────────────────────────────────────

_BRIDGE_RE = re.compile(r'\d+\.\d+\.\d+\.\d+|\[.*\]|https?://')


def is_valid_bridge_line(line: str) -> bool:
    if "No bridges available" in line:
        return False
    if line.startswith("#"):
        return False
    if len(line) < 10:
        return False
    return bool(_BRIDGE_RE.search(line))


# ─────────────────────────────────────────────────────────────────────────────
# Vanilla format normalisation
# ─────────────────────────────────────────────────────────────────────────────

def normalize_vanilla_for_history(line: str) -> str:
    """Store vanilla bridges with 'Bridge ' prefix for dedup consistency."""
    if not line.startswith("Bridge "):
        return "Bridge " + line
    return line


def convert_vanilla_for_saving(line: str) -> str:
    """Strip 'Bridge ' prefix when writing vanilla bridges to .txt files."""
    if line.startswith("Bridge "):
        return line[7:]
    return line


# ─────────────────────────────────────────────────────────────────────────────
# History management
# ─────────────────────────────────────────────────────────────────────────────

def load_history() -> Dict[str, Any]:
    """
    Load bridge history.

    Supports both formats:
    - New dict format:  { "<key>": {"raw": ..., "transport": ..., ...} }
    - Legacy string:    { "<key>": "<iso-timestamp>" }
    """
    if HISTORY_FILE.exists() and HISTORY_FILE.stat().st_size > 2:
        try:
            raw: dict = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
            normalised: Dict[str, Any] = {}
            for k, v in raw.items():
                if isinstance(v, str):
                    # Legacy format — v is an ISO timestamp
                    normalised[k] = v
                elif isinstance(v, dict):
                    normalised[k] = v
            return normalised
        except Exception as exc:
            log.warning(f"History load error: {exc}. Starting fresh.")
    return {}


def save_history(history: Dict[str, Any]) -> None:
    HISTORY_FILE.write_text(
        json.dumps(history, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def cleanup_history(history: Dict[str, Any]) -> Dict[str, Any]:
    """Remove entries older than HISTORY_RETENTION_DAYS."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=HISTORY_RETENTION_DAYS)
    to_delete: List[str] = []
    for k, v in history.items():
        try:
            if isinstance(v, str):
                ts_str = v
            elif isinstance(v, dict):
                ts_str = v.get("last_seen") or v.get("first_seen", "2000-01-01")
            else:
                to_delete.append(k)
                continue
            first = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            # Make naive for comparison
            if first.tzinfo is not None:
                first = first.replace(tzinfo=None)
            if first < cutoff:
                to_delete.append(k)
        except Exception:
            pass
    for k in to_delete:
        del history[k]
    if to_delete:
        log.info(f"Cleaned up {len(to_delete)} stale history entries.")
    return history


def update_history_entry(history: Dict[str, Any], key: str, transport: str, raw: str) -> None:
    """Upsert a bridge entry in the history dict."""
    now = datetime.now(tz=timezone.utc).isoformat()
    if key not in history:
        history[key] = {
            "raw":         raw.strip(),
            "transport":   transport,
            "ip_version":  "ipv6" if "[" in raw else "ipv4",
            "first_seen":  now,
            "last_seen":   now,
            "tcp_reachable": None,
        }
    else:
        existing = history[key]
        if isinstance(existing, str):
            # Upgrade legacy string entry to dict format
            history[key] = {
                "raw":         raw.strip(),
                "transport":   transport,
                "ip_version":  "ipv6" if "[" in raw else "ipv4",
                "first_seen":  existing,
                "last_seen":   now,
                "tcp_reachable": None,
            }
        elif isinstance(existing, dict):
            existing["last_seen"] = now
            existing["raw"] = raw.strip()


# ─────────────────────────────────────────────────────────────────────────────
# TCP / TLS connectivity tests
# ─────────────────────────────────────────────────────────────────────────────

_IPV4_PORT_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})")
_URL_RE       = re.compile(r"(https?://[^\s]+)")


def _test_tcp(host: str, port: int, timeout: float = CONNECTION_TIMEOUT) -> bool:
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        return True
    except OSError:
        return False


def _test_tls(host: str, port: int, timeout: float = SSL_TIMEOUT) -> bool:
    """TLS handshake check for WebTunnel / meek bridges."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls_sock:
                tls_sock.do_handshake()
        return True
    except Exception:
        return False


def test_bridge_reachable(bridge_line: str, transport_type: str) -> bool:
    """
    Test whether a bridge is TCP/TLS reachable.

    - vanilla / obfs4: raw TCP connect to IP:port
    - webtunnel / meek: TLS handshake to the CDN host
    - snowflake: always True (WebRTC — cannot be tested from a simple TCP probe)
    """
    if transport_type in ("snowflake", "meek_lite"):
        return True

    if transport_type in ("webtunnel",):
        # WebTunnel uses a URL; test TLS reachability of the CDN endpoint
        m = _URL_RE.search(bridge_line)
        if m:
            try:
                parsed = urlparse(m.group(1))
                host = parsed.hostname or ""
                port = parsed.port or 443
                if host:
                    return _test_tls(host, port)
            except Exception:
                pass
        return False

    # Default: IPv4 TCP
    m = _IPV4_PORT_RE.search(bridge_line)
    if not m:
        return False
    try:
        host, port = m.group(1), int(m.group(2))
        # Quick sanity — skip obviously private / RFC-1918 addresses
        try:
            if ipaddress.ip_address(host).is_private:
                return False
        except ValueError:
            return False
        return _test_tcp(host, port)
    except Exception:
        return False


def batch_test_bridges(bridges: List[str], transport_type: str) -> List[str]:
    """Parallel connectivity test; returns list of reachable bridge lines."""
    subset = bridges[:MAX_TEST_PER_TYPE]
    passed: List[str] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        future_map = {
            ex.submit(test_bridge_reachable, b, transport_type): b
            for b in subset
        }
        for future in concurrent.futures.as_completed(future_map):
            bridge = future_map[future]
            try:
                if future.result():
                    passed.append(bridge)
            except Exception:
                pass

    return passed


# ─────────────────────────────────────────────────────────────────────────────
# Scraping
# ─────────────────────────────────────────────────────────────────────────────

def _make_session() -> requests.Session:
    session = requests.Session()
    session.headers.update({"User-Agent": _USER_AGENT})
    return session


def fetch_bridges_for_target(
    session: requests.Session,
    url: str,
    transport_type: str,
) -> List[str]:
    """Fetch and parse bridge lines from a single bridges.torproject.org URL."""
    for attempt in range(MAX_RETRIES + 1):
        try:
            response = session.get(url, timeout=30)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, "html.parser")
                bridge_div = soup.find("div", id="bridgelines")
                if bridge_div:
                    raw_text = bridge_div.get_text()
                else:
                    # Fallback: look for <pre> or <code> blocks
                    for tag in soup.find_all(["pre", "code"]):
                        if _BRIDGE_RE.search(tag.get_text()):
                            raw_text = tag.get_text()
                            break
                    else:
                        raw_text = ""
                lines = [l.strip() for l in raw_text.split("\n") if l.strip()]
                valid = [l for l in lines if is_valid_bridge_line(l)]
                log.info(f"  [{transport_type}] {url}: {len(valid)} bridges fetched")
                return valid
            else:
                log.warning(f"  [{transport_type}] HTTP {response.status_code} for {url}")
        except Exception as exc:
            log.warning(f"  [{transport_type}] attempt {attempt+1}: {exc}")
            if attempt < MAX_RETRIES:
                time.sleep(2 ** attempt)
    return []


# ─────────────────────────────────────────────────────────────────────────────
# Entry point (standalone + pipeline)
# ─────────────────────────────────────────────────────────────────────────────

def run(bridge_dir: Optional[Path] = None) -> Dict[str, int]:
    """
    Main scraping routine.

    Returns stats dict: filename → bridge count.
    Can be called programmatically from scraper.py or run standalone.
    """
    global BRIDGE_DIR, HISTORY_FILE
    if bridge_dir is not None:
        BRIDGE_DIR   = bridge_dir
        HISTORY_FILE = BRIDGE_DIR / "bridge_history.json"
        BRIDGE_DIR.mkdir(parents=True, exist_ok=True)

    log.info("═══ Direct Scraper — bridges.torproject.org ═════════════════")

    session = _make_session()
    history = load_history()
    history = cleanup_history(history)

    recent_cutoff = datetime.now(timezone.utc) - timedelta(hours=RECENT_HOURS)
    stats: Dict[str, int] = {}

    for target in TARGETS:
        url            = target["url"]
        filename       = target["file"]
        transport_type = target["type"]
        ip_version     = target["ip"]

        bridge_path  = BRIDGE_DIR / filename
        recent_fname = filename.replace(".txt", f"_{RECENT_HOURS}h.txt")
        recent_path  = BRIDGE_DIR / recent_fname
        tested_fname = filename.replace(".txt", "_tested.txt")
        tested_path  = BRIDGE_DIR / tested_fname

        # Load existing bridges from disk
        existing: Set[str] = set()
        if bridge_path.exists():
            for line in bridge_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if is_valid_bridge_line(line):
                    existing.add(line)

        # Fetch fresh bridges
        fetched: Set[str] = set(fetch_bridges_for_target(session, url, transport_type))

        # Update history with freshly seen bridges
        for line in fetched:
            key = normalize_vanilla_for_history(line) if transport_type == "vanilla" else line
            update_history_entry(history, key, transport_type, line)

        all_bridges = existing | fetched

        # --- Write full archive file ---
        if transport_type == "vanilla":
            sorted_save = [convert_vanilla_for_saving(b) for b in sorted(all_bridges)]
        else:
            sorted_save = sorted(all_bridges)
        bridge_path.write_text("\n".join(sorted_save) + "\n", encoding="utf-8")

        # --- Write recent (72h) file ---
        recent_bridges: List[str] = []
        for bridge in all_bridges:
            key = normalize_vanilla_for_history(bridge) if transport_type == "vanilla" else bridge
            entry = history.get(key)
            if entry is None:
                continue
            try:
                if isinstance(entry, str):
                    ts_str = entry
                elif isinstance(entry, dict):
                    ts_str = entry.get("first_seen", "2000-01-01")
                else:
                    continue
                first = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                if first.tzinfo is not None:
                    first = first.replace(tzinfo=None)
                if first > recent_cutoff:
                    recent_bridges.append(bridge)
            except Exception:
                pass

        if transport_type == "vanilla":
            recent_save = [convert_vanilla_for_saving(b) for b in sorted(recent_bridges)]
        else:
            recent_save = sorted(recent_bridges)
        recent_path.write_text("\n".join(recent_save) + "\n" if recent_save else "", encoding="utf-8")

        # --- TCP/TLS connectivity test ---
        tested_bridges = batch_test_bridges(list(all_bridges), transport_type)
        if transport_type == "vanilla":
            tested_save = [convert_vanilla_for_saving(b) for b in sorted(tested_bridges)]
        else:
            tested_save = sorted(tested_bridges)
        tested_path.write_text("\n".join(tested_save) + "\n" if tested_save else "", encoding="utf-8")

        log.info(
            f"  {filename}: total={len(all_bridges)}, recent={len(recent_bridges)}, "
            f"tested={len(tested_bridges)}"
        )

        stats[filename]       = len(all_bridges)
        stats[recent_fname]   = len(recent_bridges)
        stats[tested_fname]   = len(tested_bridges)

        time.sleep(0.5)  # polite delay between requests

    save_history(history)
    log.info(f"History saved: {len(history)} total entries")
    log.info("═══ Direct Scraper done ═════════════════════════════════════")
    return stats


if __name__ == "__main__":
    run()
