#!/usr/bin/env python3
"""
sources/legacy_scraper.py — Integrated legacy scraper from upstream main.py.

Merges the Delta-Kronecker/Tor-Bridges-Collector scraping logic into the
TorShield-IR pipeline.  Provides:
  - Direct scraping from bridges.torproject.org (all transports, IPv4+IPv6)
  - Parallel TCP/TLS connectivity testing
  - Bridge history with 30-day retention
  - Zip export for Telegram upload
  - README.md stats update

This module is compatible with the project's existing bridge_history.json
format and writes directly to the bridge/ directory used by the pipeline.
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
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

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
SSL_TIMEOUT            = 5
MAX_RETRIES            = 2
MAX_TEST_PER_TYPE      = 500

BRIDGE_DIR   = Path(os.getenv("BRIDGE_DIR", "bridge"))
HISTORY_FILE = BRIDGE_DIR / "bridge_history.json"
BRIDGE_DIR.mkdir(parents=True, exist_ok=True)

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID", "")
TELEGRAM_UPLOAD    = os.getenv("TELEGRAM_UPLOAD", "false").lower() == "true"
IS_GITHUB          = os.getenv("GITHUB_ACTIONS") == "true"
REPO_URL           = os.getenv("REPO_URL", "https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/refs/heads/main")

_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)
_BRIDGE_RE = re.compile(r'\d+\.\d+\.\d+\.\d+|\[.*\]|https?://')
_IPV4_RE   = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})')
_URL_RE    = re.compile(r'(https?://\S+)')

# ─────────────────────────────────────────────────────────────────────────────
# Bridge line validation and normalisation
# ─────────────────────────────────────────────────────────────────────────────

def is_valid(line: str) -> bool:
    return (
        bool(line)
        and "No bridges available" not in line
        and not line.startswith("#")
        and len(line) >= 10
        and bool(_BRIDGE_RE.search(line))
    )


def _vanilla_key(line: str) -> str:
    """Vanilla bridges are keyed with 'Bridge ' prefix for history dedup."""
    return line if line.startswith("Bridge ") else "Bridge " + line


def _vanilla_save(line: str) -> str:
    return line[7:] if line.startswith("Bridge ") else line

# ─────────────────────────────────────────────────────────────────────────────
# History management (compatible with project format)
# ─────────────────────────────────────────────────────────────────────────────

def load_history() -> Dict[str, Any]:
    if HISTORY_FILE.exists() and HISTORY_FILE.stat().st_size > 2:
        try:
            return json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
        except Exception as exc:
            log.warning(f"History load error: {exc}")
    return {}


def save_history(history: Dict[str, Any]) -> None:
    HISTORY_FILE.write_text(
        json.dumps(history, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def cleanup_history(history: Dict[str, Any]) -> Dict[str, Any]:
    cutoff = datetime.now(timezone.utc) - timedelta(days=HISTORY_RETENTION_DAYS)
    stale = []
    for k, v in history.items():
        try:
            ts = v if isinstance(v, str) else v.get("first_seen", "2000-01-01")
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00")).replace(tzinfo=None)
            if dt < cutoff:
                stale.append(k)
        except Exception:
            pass
    for k in stale:
        del history[k]
    return history


def upsert_history(history: Dict[str, Any], key: str, transport: str, raw: str) -> None:
    now = datetime.now(tz=timezone.utc).isoformat()
    if key not in history:
        history[key] = {
            "raw": raw.strip(),
            "transport": transport,
            "ip_version": "ipv6" if "[" in raw else "ipv4",
            "first_seen": now,
            "last_seen": now,
            "tcp_reachable": None,
        }
    else:
        entry = history[key]
        if isinstance(entry, str):
            history[key] = {
                "raw": raw.strip(), "transport": transport,
                "ip_version": "ipv6" if "[" in raw else "ipv4",
                "first_seen": entry, "last_seen": now, "tcp_reachable": None,
            }
        elif isinstance(entry, dict):
            entry["last_seen"] = now
            entry["raw"] = raw.strip()

# ─────────────────────────────────────────────────────────────────────────────
# Connectivity testing
# ─────────────────────────────────────────────────────────────────────────────

def _tcp(host: str, port: int) -> bool:
    try:
        s = socket.create_connection((host, port), timeout=CONNECTION_TIMEOUT)
        s.close()
        return True
    except OSError:
        return False


def _tls(host: str, port: int) -> bool:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=SSL_TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as ts:
                ts.do_handshake()
        return True
    except Exception:
        return False


def test_bridge(line: str, transport: str) -> bool:
    if transport in ("snowflake", "meek_lite"):
        return True
    if transport == "webtunnel":
        m = _URL_RE.search(line)
        if m:
            try:
                p = urlparse(m.group(1))
                return _tls(p.hostname or "", p.port or 443)
            except Exception:
                return False
        return False
    m = _IPV4_RE.search(line)
    if not m:
        return False
    try:
        host, port = m.group(1), int(m.group(2))
        if ipaddress.ip_address(host).is_private:
            return False
        return _tcp(host, port)
    except Exception:
        return False


def batch_test(bridges: List[str], transport: str) -> List[str]:
    subset = bridges[:MAX_TEST_PER_TYPE]
    passed: List[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        fut_map = {ex.submit(test_bridge, b, transport): b for b in subset}
        for fut in concurrent.futures.as_completed(fut_map):
            try:
                if fut.result():
                    passed.append(fut_map[fut])
            except Exception:
                pass
    return passed

# ─────────────────────────────────────────────────────────────────────────────
# Scraping
# ─────────────────────────────────────────────────────────────────────────────

def _session() -> requests.Session:
    s = requests.Session()
    s.headers["User-Agent"] = _USER_AGENT
    return s


def _fetch(session: requests.Session, url: str, transport: str) -> List[str]:
    for attempt in range(MAX_RETRIES + 1):
        try:
            r = session.get(url, timeout=30)
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "html.parser")
                div  = soup.find("div", id="bridgelines")
                text = div.get_text() if div else r.text
                lines = [l.strip() for l in text.split("\n") if l.strip()]
                valid = [l for l in lines if is_valid(l)]
                log.info(f"  [{transport}] {url}: {len(valid)} bridges")
                return valid
            log.warning(f"  [{transport}] HTTP {r.status_code}")
        except Exception as exc:
            log.warning(f"  [{transport}] attempt {attempt+1}: {exc}")
            if attempt < MAX_RETRIES:
                time.sleep(2 ** attempt)
    return []

# ─────────────────────────────────────────────────────────────────────────────
# README update
# ─────────────────────────────────────────────────────────────────────────────

def _update_readme(stats: Dict[str, int]) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    content = f"""# Tor Bridges Collector & Archive

Auto-updated every hour. Last update: **{ts}**

## Bridge Lists

### ✅ Tested & Active (Recommended)
| Transport | File | Count |
|:----------|:-----|------:|
| obfs4 | [obfs4_tested.txt]({REPO_URL}/bridge/obfs4_tested.txt) | **{stats.get('obfs4_tested.txt', 0)}** |
| WebTunnel | [webtunnel_tested.txt]({REPO_URL}/bridge/webtunnel_tested.txt) | **{stats.get('webtunnel_tested.txt', 0)}** |
| Vanilla | [vanilla_tested.txt]({REPO_URL}/bridge/vanilla_tested.txt) | **{stats.get('vanilla_tested.txt', 0)}** |

### 🕐 Fresh (Last 72 Hours)
| Transport | IPv4 | Count | IPv6 | Count |
|:----------|:-----|------:|:-----|------:|
| obfs4 | [obfs4_72h.txt]({REPO_URL}/bridge/obfs4_72h.txt) | **{stats.get('obfs4_72h.txt', 0)}** | [obfs4_ipv6_72h.txt]({REPO_URL}/bridge/obfs4_ipv6_72h.txt) | **{stats.get('obfs4_ipv6_72h.txt', 0)}** |
| WebTunnel | [webtunnel_72h.txt]({REPO_URL}/bridge/webtunnel_72h.txt) | **{stats.get('webtunnel_72h.txt', 0)}** | [webtunnel_ipv6_72h.txt]({REPO_URL}/bridge/webtunnel_ipv6_72h.txt) | **{stats.get('webtunnel_ipv6_72h.txt', 0)}** |
| Vanilla | [vanilla_72h.txt]({REPO_URL}/bridge/vanilla_72h.txt) | **{stats.get('vanilla_72h.txt', 0)}** | [vanilla_ipv6_72h.txt]({REPO_URL}/bridge/vanilla_ipv6_72h.txt) | **{stats.get('vanilla_ipv6_72h.txt', 0)}** |

### 🗂 Full Archive
| Transport | IPv4 | Count | IPv6 | Count |
|:----------|:-----|------:|:-----|------:|
| obfs4 | [obfs4.txt]({REPO_URL}/bridge/obfs4.txt) | **{stats.get('obfs4.txt', 0)}** | [obfs4_ipv6.txt]({REPO_URL}/bridge/obfs4_ipv6.txt) | **{stats.get('obfs4_ipv6.txt', 0)}** |
| WebTunnel | [webtunnel.txt]({REPO_URL}/bridge/webtunnel.txt) | **{stats.get('webtunnel.txt', 0)}** | [webtunnel_ipv6.txt]({REPO_URL}/bridge/webtunnel_ipv6.txt) | **{stats.get('webtunnel_ipv6.txt', 0)}** |
| Vanilla | [vanilla.txt]({REPO_URL}/bridge/vanilla.txt) | **{stats.get('vanilla.txt', 0)}** | [vanilla_ipv6.txt]({REPO_URL}/bridge/vanilla_ipv6.txt) | **{stats.get('vanilla_ipv6.txt', 0)}** |

> ⭐ Star this repo to support the project!
"""
    Path("README.md").write_text(content, encoding="utf-8")
    log.info("README.md updated.")

# ─────────────────────────────────────────────────────────────────────────────
# Telegram upload
# ─────────────────────────────────────────────────────────────────────────────

def _make_zip(stats: Dict[str, int]) -> Optional[Path]:
    zip_path = BRIDGE_DIR / "tor_bridges.zip"
    try:
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in BRIDGE_DIR.glob("*.txt"):
                category = (
                    "Tested" if "_tested" in f.name
                    else f"Recent_{RECENT_HOURS}h" if f"_{RECENT_HOURS}h" in f.name
                    else "Full_Archive"
                )
                zf.write(f, f"Tor_Bridges/{category}/{f.name}")
        log.info(f"ZIP created: {zip_path}")
        return zip_path
    except Exception as exc:
        log.error(f"ZIP error: {exc}")
        return None


def _telegram(zip_path: Path, stats: Dict[str, int]) -> None:
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        log.info("Telegram: credentials not set, skipping.")
        return
    total = sum(stats.get(f"{t}.txt", 0) for t in ("obfs4", "webtunnel", "vanilla"))
    caption = (
        f"*Tor Bridges Update*\n\n"
        f"*Tested:* obfs4={stats.get('obfs4_tested.txt',0)} | "
        f"WebTunnel={stats.get('webtunnel_tested.txt',0)} | "
        f"Vanilla={stats.get('vanilla_tested.txt',0)}\n"
        f"*Total unique:* {total}"
    )
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendDocument"
    try:
        with open(zip_path, "rb") as f:
            r = requests.post(url, data={
                "chat_id": TELEGRAM_CHAT_ID,
                "caption": caption,
                "parse_mode": "Markdown",
            }, files={"document": f}, timeout=60)
        if r.status_code == 200:
            log.info("Telegram upload OK.")
        else:
            log.warning(f"Telegram upload failed: {r.status_code}")
    except Exception as exc:
        log.error(f"Telegram error: {exc}")

# ─────────────────────────────────────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────────────────────────────────────

def run() -> Dict[str, int]:
    log.info("══ Legacy scraper (bridges.torproject.org) ═══════════════════")
    session = _session()
    history = load_history()
    history = cleanup_history(history)
    cutoff  = datetime.now(timezone.utc) - timedelta(hours=RECENT_HOURS)
    stats: Dict[str, int] = {}

    for target in TARGETS:
        url       = target["url"]
        filename  = target["file"]
        transport = target["type"]

        bridge_path  = BRIDGE_DIR / filename
        recent_fname = filename.replace(".txt", f"_{RECENT_HOURS}h.txt")
        recent_path  = BRIDGE_DIR / recent_fname
        tested_fname = filename.replace(".txt", "_tested.txt")
        tested_path  = BRIDGE_DIR / tested_fname

        # Load existing + fetch fresh
        existing: Set[str] = set()
        if bridge_path.exists():
            for line in bridge_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if is_valid(line):
                    existing.add(line)

        fetched: Set[str] = set(_fetch(session, url, transport))
        for line in fetched:
            key = _vanilla_key(line) if transport == "vanilla" else line
            upsert_history(history, key, transport, line)

        all_bridges = existing | fetched

        # Write full archive
        if transport == "vanilla":
            sorted_save = [_vanilla_save(b) for b in sorted(all_bridges)]
        else:
            sorted_save = sorted(all_bridges)
        bridge_path.write_text("\n".join(sorted_save) + "\n", encoding="utf-8")

        # Write recent file
        recent: List[str] = []
        for b in all_bridges:
            key   = _vanilla_key(b) if transport == "vanilla" else b
            entry = history.get(key)
            if not entry:
                continue
            try:
                ts_str = entry if isinstance(entry, str) else entry.get("first_seen", "2000-01-01")
                dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00")).replace(tzinfo=None)
                if dt > cutoff:
                    recent.append(b)
            except Exception:
                pass
        recent_save = (
            [_vanilla_save(b) for b in sorted(recent)] if transport == "vanilla"
            else sorted(recent)
        )
        recent_path.write_text(
            "\n".join(recent_save) + "\n" if recent_save else "",
            encoding="utf-8",
        )

        # Test connectivity
        tested = batch_test(list(all_bridges), transport)
        tested_save = (
            [_vanilla_save(b) for b in sorted(tested)] if transport == "vanilla"
            else sorted(tested)
        )
        tested_path.write_text(
            "\n".join(tested_save) + "\n" if tested_save else "",
            encoding="utf-8",
        )

        log.info(f"  {filename}: total={len(all_bridges)} recent={len(recent)} tested={len(tested)}")
        stats[filename]       = len(all_bridges)
        stats[recent_fname]   = len(recent)
        stats[tested_fname]   = len(tested)
        time.sleep(0.5)

    save_history(history)

    # README + Telegram
    _update_readme(stats)
    current_hour = datetime.now(timezone.utc).hour
    should_upload = (IS_GITHUB and TELEGRAM_UPLOAD) or (IS_GITHUB and current_hour == 0)
    if should_upload:
        zip_path = _make_zip(stats)
        if zip_path:
            _telegram(zip_path, stats)

    log.info("══ Legacy scraper done ═══════════════════════════════════════")
    return stats


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)-8s %(message)s")
    run()
