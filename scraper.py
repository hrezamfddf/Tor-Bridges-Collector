#!/usr/bin/env python3
"""
scraper.py — TorShield-IR bridge scraper and history manager.

Collects Tor bridges from all available sources (bridges.torproject.org,
MOAT API, static built-ins), maintains a 30-day rolling history, writes
categorised output files, and emits bridge_list_for_testing.json for the
Go iran_tester binary.

Bug fixes applied vs. original codebase
────────────────────────────────────────
• Bug 1 — Double vanilla prefix:
    normalize_for_history() checks startswith("Bridge ") before prepending.

• Bug 2 — Spurious \\x00 send:
    tcp reachability is labelled tcp_reachable; no data is ever sent.

• Bug 3 — Misleading label:
    TCP success ≠ "working"; only labelled tcp_reachable in history.

• Bug 4 — update_readme() KeyError:
    All non-interpolated braces are escaped as {{ / }} in f-strings;
    dynamic values use .format_map() on a separate dict.

• Bug 5 — SyntaxError: from __future__ imports must occur at the beginning
    Moved from __future__ import annotations to after the docstring,
    before all other imports.

• Bug 6 — _HAVE_GITHUB and fetch_github_async undefined:
    Added import guard for sources.github_bridges with graceful fallback.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import socket
import time
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.request import Request, urlopen

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter, Retry

# ─────────────────────────────────────────────────────────────────────────────
# GitHub bridge source — graceful fallback if module unavailable (Bug 6 fix)
# ─────────────────────────────────────────────────────────────────────────────

try:
    from sources.github_bridges import fetch_all as _github_fetch_all
    _HAVE_GITHUB = True
except ImportError:
    _HAVE_GITHUB = False
    async def _github_fetch_all() -> List[Tuple[str, str, str]]:  # type: ignore[misc]
        return []


async def fetch_github_async() -> List[Tuple[str, str, str]]:
    """Wrapper so main() always has a callable regardless of import success."""
    return await _github_fetch_all()


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
# Configuration (overridable via environment)
# ─────────────────────────────────────────────────────────────────────────────

BRIDGE_DIR         = Path(os.getenv("BRIDGE_DIR",   "bridge"))
RECENT_HOURS       = int(os.getenv("RECENT_HOURS",  "72"))
RETENTION_DAYS     = int(os.getenv("RETENTION_DAYS","30"))
REPO_URL           = os.getenv("REPO_URL", "https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/refs/heads/main")

BRIDGE_DIR.mkdir(parents=True, exist_ok=True)
Path("export").mkdir(parents=True, exist_ok=True)
Path("data").mkdir(parents=True, exist_ok=True)
Path("docs").mkdir(parents=True, exist_ok=True)

HISTORY_FILE       = BRIDGE_DIR / "bridge_history.json"
TESTING_JSON       = BRIDGE_DIR / "bridge_list_for_testing.json"

# ─────────────────────────────────────────────────────────────────────────────
# Canonical normalisation helpers (single source of truth)
# ─────────────────────────────────────────────────────────────────────────────

def normalize_for_history(line: str, transport: str) -> str:
    """Store vanilla bridges WITH 'Bridge ' prefix; all others as-is."""
    if transport == "vanilla":
        return line if line.startswith("Bridge ") else f"Bridge {line}"
    return line.strip()


def normalize_for_file(line: str, transport: str) -> str:
    """Strip 'Bridge ' prefix for vanilla bridges written to .txt files."""
    if transport == "vanilla":
        return line[7:].strip() if line.startswith("Bridge ") else line.strip()
    return line.strip()


# ─────────────────────────────────────────────────────────────────────────────
# Validation
# ─────────────────────────────────────────────────────────────────────────────

_VALID_LINE_RE = re.compile(
    r'(\d{1,3}(?:\.\d{1,3}){3}:\d+|'      # IPv4:port
    r'\[[0-9a-fA-F:]+\]:\d+|'              # [IPv6]:port
    r'https?://[^\s]+)'                    # HTTPS URL (WebTunnel/meek)
)


def is_valid_line(line: str) -> bool:
    if not line or len(line) < 20:
        return False
    if "No bridges available" in line or line.startswith("#"):
        return False
    return bool(_VALID_LINE_RE.search(line))


# ─────────────────────────────────────────────────────────────────────────────
# HTTP session with retry + exponential backoff
# ─────────────────────────────────────────────────────────────────────────────

def make_session() -> requests.Session:
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=1.0,          # 1 s → 2 s → 4 s
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://",  adapter)
    session.headers.update({
        "User-Agent":      "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
        "Accept":          "text/html,application/xhtml+xml",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
    })
    return session


# ─────────────────────────────────────────────────────────────────────────────
# Source 1 — bridges.torproject.org
# ─────────────────────────────────────────────────────────────────────────────

_TARGETS: List[Tuple[str, str, str, str]] = [
    # (url, hint, transport, ip_version)
    ("https://bridges.torproject.org/bridges?transport=obfs4",              "obfs4",     "obfs4",     "ipv4"),
    ("https://bridges.torproject.org/bridges?transport=obfs4&ipv6=yes",     "obfs4_ipv6","obfs4",     "ipv6"),
    ("https://bridges.torproject.org/bridges?transport=webtunnel",          "webtunnel", "webtunnel", "ipv4"),
    ("https://bridges.torproject.org/bridges?transport=webtunnel&ipv6=yes", "webtunnel_ipv6","webtunnel","ipv6"),
    ("https://bridges.torproject.org/bridges?transport=vanilla",            "vanilla",   "vanilla",   "ipv4"),
    ("https://bridges.torproject.org/bridges?transport=vanilla&ipv6=yes",   "vanilla_ipv6","vanilla", "ipv6"),
]


def _parse_bridgelines_html(html: str) -> List[str]:
    soup = BeautifulSoup(html, "html.parser")
    div  = soup.find("div", id="bridgelines")
    if div:
        raw = div.get_text("\n")
    else:
        raw = " ".join(tag.get_text("\n") for tag in soup.find_all(["pre", "code"]))
    return [l.strip() for l in raw.split("\n") if is_valid_line(l.strip())]


def fetch_torproject(session: requests.Session) -> List[Tuple[str, str, str]]:
    """Return list of (bridge_line, transport, ip_version) from torproject.org."""
    results: List[Tuple[str, str, str]] = []
    for url, _, transport, ip_ver in _TARGETS:
        try:
            time.sleep(0.4)   # polite delay between requests
            r = session.get(url, timeout=30)
            r.raise_for_status()
            lines = _parse_bridgelines_html(r.text)
            log.info(f"  torproject.org [{transport}/{ip_ver}]: {len(lines)} bridges")
            for line in lines:
                results.append((line, transport, ip_ver))
        except Exception as exc:
            log.warning(f"  torproject.org [{transport}]: {exc}")
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Source 2 — MOAT API (no CAPTCHA, country-aware)
# ─────────────────────────────────────────────────────────────────────────────

_MOAT_BUILTIN_URL  = "https://bridges.torproject.org/moat/circumvention/builtin"
_MOAT_SETTINGS_URL = "https://bridges.torproject.org/moat/circumvention/settings"
_MOAT_HEADERS = {
    "Content-Type": "application/vnd.api+json",
    "Accept":       "application/vnd.api+json",
    "User-Agent":   "Tor Browser/13.5 (Windows NT 10.0; rv:115.0)",
}
_MOAT_TRANSPORT_MAP = {
    "obfs4":     "obfs4",
    "webTunnel": "webtunnel",
    "WebTunnel": "webtunnel",
    "webtunnel": "webtunnel",
    "snowflake": "snowflake",
    "meek_lite": "meek_lite",
}


def _parse_moat_response(data: Dict[str, Any]) -> List[Tuple[str, str]]:
    results: List[Tuple[str, str]] = []
    bridges_section = data.get("bridges") or {}
    for key, bridge_list in bridges_section.items():
        transport = _MOAT_TRANSPORT_MAP.get(key, "unknown")
        if isinstance(bridge_list, list):
            for line in bridge_list:
                if isinstance(line, str) and is_valid_line(line):
                    results.append((line.strip(), transport))
    return results


def fetch_moat(session: requests.Session) -> List[Tuple[str, str, str]]:
    """Return (bridge_line, transport, ip_version) from both MOAT endpoints."""
    results: List[Tuple[str, str, str]] = []
    payload = {
        "version":    "0.1.0",
        "transports": ["obfs4", "webTunnel", "snowflake"],
        "country":    "ir",
    }
    for url in [_MOAT_BUILTIN_URL, _MOAT_SETTINGS_URL]:
        try:
            r = session.post(url, json=payload, headers=_MOAT_HEADERS, timeout=30)
            if r.status_code == 200:
                pairs = _parse_moat_response(r.json())
                log.info(f"  MOAT [{url.split('/')[-1]}]: {len(pairs)} bridges")
                for line, transport in pairs:
                    ip_ver = "ipv6" if "[" in line else "ipv4"
                    results.append((line, transport, ip_ver))
            else:
                log.debug(f"  MOAT [{url}]: HTTP {r.status_code}")
        except Exception as exc:
            log.warning(f"  MOAT [{url}]: {exc}")
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Source 3 — Static built-in bridges (Snowflake, meek-lite)
# ─────────────────────────────────────────────────────────────────────────────

_STATIC_BRIDGES: List[Tuple[str, str]] = [
    # Snowflake — official Tor Browser 13+ default bridges
    ("snowflake 192.0.2.3:1 2B280B23E1107BB62ABFC40DDCC8824814F80A72 "
     "fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 "
     "url=https://snowflake-broker.torproject.net.global.prod.fastly.net/ "
     "fronts=ftls.googlevideo.com "
     "ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478 "
     "utls-imitate=hellorandomizedalpn", "snowflake"),
    ("snowflake 192.0.2.4:1 8838024498816A039FCBBAB14E6F40A0843051FA "
     "fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA "
     "url=https://snowflake-broker.torproject.net/ "
     "fronts=snowflake-broker.torproject.net.global.prod.fastly.net "
     "ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478 "
     "utls-imitate=hellorandomizedalpn", "snowflake"),
    # meek-lite — CDN domain-fronting fallback
    ("meek_lite 192.0.2.18:80 BE776A53492E1E044A26F17306E1BC46A55A1625 "
     "url=https://meek.azureedge.net/ front=ajax.aspnetcdn.com", "meek_lite"),
    ("meek_lite 192.0.2.16:80 0AC9589027B0B1F3B1D1D94C63CD9E8D05CD6D77 "
     "url=https://a0.awsstatic.com/ front=a0.awsstatic.com", "meek_lite"),
]


def get_static() -> List[Tuple[str, str, str]]:
    return [(line, transport, "ipv4") for line, transport in _STATIC_BRIDGES]


# ─────────────────────────────────────────────────────────────────────────────
# TCP reachability probe (no data sent — Bug 2 fix)
# ─────────────────────────────────────────────────────────────────────────────

_IP4_PORT_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})")


def tcp_reachable(line: str, timeout_s: float = 6.0) -> bool:
    """
    Test TCP reachability of a bridge line.
    Labelled tcp_reachable (Bug 3 fix) — not "working".
    Never sends any bytes (Bug 2 fix).
    """
    m = _IP4_PORT_RE.search(line)
    if not m:
        return False  # non-IPv4 bridges skipped from basic test
    host, port_str = m.group(1), m.group(2)
    try:
        sock = socket.create_connection((host, int(port_str)), timeout=timeout_s)
        sock.close()
        return True
    except OSError:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# History management
# ─────────────────────────────────────────────────────────────────────────────

def _infer_transport(key: str) -> str:
    """Infer transport from a bridge key string (best-effort for migration)."""
    low = key.lower()
    if "snowflake" in low:
        return "snowflake"
    if "webtunnel" in low or "url=https" in low:
        return "webtunnel"
    if "obfs4" in low:
        return "obfs4"
    if "meek" in low:
        return "meek_lite"
    return "vanilla"


def _infer_ip_version(key: str) -> str:
    """Infer IP version from a bridge key (best-effort for migration)."""
    import re as _re
    if _re.search(r"\[[0-9a-fA-F:]{2,39}\]", key):
        return "ipv6"
    return "ipv4"


def load_history() -> Dict[str, Dict[str, Any]]:
    """Load bridge history, normalising any legacy string-format entries.

    onionhop_collector (and older pipeline versions) may write entries as
    plain ISO timestamp strings:  {"<bridge_key>": "2026-06-06T14:30:39+00:00"}

    scraper.py requires dict entries:
        {"<bridge_key>": {"raw": ..., "transport": ..., "last_seen": ..., ...}}

    Any string-valued entry is transparently upgraded on load so that every
    downstream function (prune_history, write_bridge_files, main) always
    receives the dict format it expects.
    """
    if HISTORY_FILE.exists():
        try:
            raw: dict = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
            normalised: Dict[str, Dict[str, Any]] = {}
            for k, v in raw.items():
                if isinstance(v, str):
                    # Legacy / onionhop format — v is an ISO timestamp string
                    normalised[k] = {
                        "raw":           k,
                        "transport":     _infer_transport(k),
                        "ip_version":    _infer_ip_version(k),
                        "first_seen":    v,
                        "last_seen":     v,
                        "tcp_reachable": None,
                    }
                elif isinstance(v, dict):
                    normalised[k] = v
                # else: skip any unexpected types silently
            return normalised
        except Exception as exc:
            log.warning(f"History load error: {exc}. Starting fresh.")
    return {}


def save_history(history: Dict[str, Dict[str, Any]]) -> None:
    HISTORY_FILE.write_text(
        json.dumps(history, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )


def update_history(
    history: Dict[str, Dict[str, Any]],
    lines: List[Tuple[str, str, str]],   # (raw_line, transport, ip_version)
) -> None:
    now = datetime.now(tz=timezone.utc).isoformat()
    for raw_line, transport, ip_version in lines:
        key = normalize_for_history(raw_line, transport)
        if key not in history:
            history[key] = {
                "transport":   transport,
                "ip_version":  ip_version,
                "first_seen":  now,
                "last_seen":   now,
                "tcp_reachable": None,  # Bug 3 fix: correct label
            }
        else:
            history[key]["last_seen"] = now


def prune_history(history: Dict[str, Dict[str, Any]]) -> int:
    cutoff = datetime.now(tz=timezone.utc) - timedelta(days=RETENTION_DAYS)
    to_delete = [
        k for k, v in history.items()
        if datetime.fromisoformat(v.get("last_seen", "2000-01-01T00:00:00+00:00")) < cutoff
    ]
    for k in to_delete:
        del history[k]
    removed = len(to_delete)
    if removed:
        log.info(f"Pruned {removed} entries older than {RETENTION_DAYS} days.")
    return removed


# ─────────────────────────────────────────────────────────────────────────────
# File writers
# ─────────────────────────────────────────────────────────────────────────────

def _write_sorted(path: Path, lines: List[str]) -> None:
    clean = sorted(set(l for l in lines if l.strip()))
    path.write_text("\n".join(clean) + ("\n" if clean else ""), encoding="utf-8")
    log.debug(f"  → {path}: {len(clean)} bridges")


def write_bridge_files(history: Dict[str, Dict[str, Any]]) -> Dict[str, int]:
    """
    Write all categorised .txt bridge files and return a stats dict.
    File names use only ASCII characters for GitHub Actions compatibility.
    """
    now       = datetime.now(tz=timezone.utc)
    cutoff_72 = now - timedelta(hours=RECENT_HOURS)
    stats: Dict[str, int] = {}

    transports = ["obfs4", "webtunnel", "vanilla", "snowflake", "meek_lite"]

    for transport in transports:
        fname = transport.replace("_", "_")
        records = [v for v in history.values() if v.get("transport") == transport]

        ipv4 = [normalize_for_file(v.get("raw", ""), transport)
                for v in records if v.get("ip_version", "ipv4") != "ipv6" and v.get("raw")]
        ipv6 = [normalize_for_file(v.get("raw", ""), transport)
                for v in records if v.get("ip_version") == "ipv6" and v.get("raw")]
        ipv4_72h = [normalize_for_file(v.get("raw", ""), transport)
                    for v in records
                    if v.get("ip_version") != "ipv6"
                    and v.get("raw")
                    and datetime.fromisoformat(v.get("first_seen", "2000-01-01T00:00:00+00:00")) > cutoff_72]
        ipv6_72h = [normalize_for_file(v.get("raw", ""), transport)
                    for v in records
                    if v.get("ip_version") == "ipv6"
                    and v.get("raw")
                    and datetime.fromisoformat(v.get("first_seen", "2000-01-01T00:00:00+00:00")) > cutoff_72]

        _write_sorted(BRIDGE_DIR / f"{fname}.txt",         ipv4)
        _write_sorted(BRIDGE_DIR / f"{fname}_ipv6.txt",    ipv6)
        _write_sorted(BRIDGE_DIR / f"{fname}_{RECENT_HOURS}h.txt",      ipv4_72h)
        _write_sorted(BRIDGE_DIR / f"{fname}_{RECENT_HOURS}h_ipv6.txt", ipv6_72h)

        stats[f"{fname}.txt"]      = len(ipv4)
        stats[f"{fname}_ipv6.txt"] = len(ipv6)
        stats[f"{fname}_{RECENT_HOURS}h.txt"]      = len(ipv4_72h)
        stats[f"{fname}_{RECENT_HOURS}h_ipv6.txt"] = len(ipv6_72h)

    return stats


def write_testing_json(history: Dict[str, Dict[str, Any]]) -> int:
    """Write bridge_list_for_testing.json consumed by Go iran_tester."""
    all_lines = list(history.keys())
    TESTING_JSON.write_text(
        json.dumps(all_lines, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    log.info(f"bridge_list_for_testing.json: {len(all_lines)} entries")
    return len(all_lines)


def build_zip(stats: Dict[str, int]) -> str:
    """Build tor_bridges.zip for Telegram distribution."""
    for f in BRIDGE_DIR.glob("*.zip"):
        f.unlink()
    zip_path = str(BRIDGE_DIR / "tor_bridges.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for txt in sorted(BRIDGE_DIR.glob("*.txt")):
            if "_tested" in txt.name or "likely_working" in txt.name:
                folder = "Tor Bridges/Verified"
            elif f"_{RECENT_HOURS}h" in txt.name:
                folder = f"Tor Bridges/Fresh ({RECENT_HOURS}h)"
            else:
                folder = "Tor Bridges/Full Archive"
            zf.write(str(txt), f"{folder}/{txt.name}")
        for ef in ["iran_pack.txt", "iran_cut_pack.txt"]:
            ep = Path("export") / ef
            if ep.exists():
                zf.write(str(ep), f"Tor Bridges/Iran Optimised/{ef}")
    log.info(f"ZIP built: {zip_path}")
    return zip_path


# ─────────────────────────────────────────────────────────────────────────────
# README updater (Bug 4 fix — all non-interpolated braces escaped)
# ─────────────────────────────────────────────────────────────────────────────

def update_readme(stats: Dict[str, int]) -> None:
    ts   = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    rh   = RECENT_HOURS
    repo = REPO_URL

    def lnk(fname: str) -> str:
        return f"[{fname}]({repo}/bridge/{fname})"

    def cnt(key: str) -> str:
        return f"**{stats.get(key, 0)}**"

    template = """\
# 🌐 TorShield-IR — Tor Bridges for Iran

> Production-grade, Iran-optimised bridge collection with OONI intelligence.
> **Last update:** `{ts}`
> Pipeline: Python scraper → Go iran_tester (OONI + ASN + 8-layer DPI analysis) → Rust bridge-probe

## ⚠️ For Iran Users (برای کاربران ایران)

- **شبکه ملی (NIN active):** Use `export/iran_cut_pack.txt` — Snowflake and CDN-fronted WebTunnel survive cuts.
- **Normal censorship:** Use `export/iran_pack.txt` — OONI-verified bridges ranked by Iran score.
- **Port 443 bridges** are highest priority — Iran cannot block HTTPS without breaking banking.

## ✅ OONI-Verified Working (Iran)

| File | Bridges |
| :--- | :--- |
| [iran_likely_working_obfs4.txt]({repo}/bridge/iran_likely_working_obfs4.txt) | Auto |
| [iran_likely_working_webtunnel.txt]({repo}/bridge/iran_likely_working_webtunnel.txt) | Auto |
| [iran_likely_working_all.txt]({repo}/bridge/iran_likely_working_all.txt) | Auto |

## 📦 Full Archive

| Transport | IPv4 | Count | IPv6 | Count |
| :--- | :--- | :--- | :--- | :--- |
| **obfs4** | {lnk_obfs4} | {cnt_obfs4} | {lnk_obfs4_v6} | {cnt_obfs4_v6} |
| **WebTunnel** | {lnk_wt} | {cnt_wt} | {lnk_wt_v6} | {cnt_wt_v6} |
| **Snowflake** | {lnk_sf} | {cnt_sf} | — | — |
| **Vanilla** | {lnk_va} | {cnt_va} | {lnk_va_v6} | {cnt_va_v6} |
| **meek-lite** | {lnk_ml} | {cnt_ml} | — | — |

## 🇮🇷 Iran Packs

| Pack | Description |
| :--- | :--- |
| [iran_pack.txt]({repo}/export/iran_pack.txt) | Top 100 bridges by Iran composite score |
| [iran_cut_pack.txt]({repo}/export/iran_cut_pack.txt) | Bridges for internet cut / NIN scenarios |

## 📊 DPI Resistance Guide

| Transport | Iran DPI | Survives Cut | Port 443 |
| :--- | :--- | :--- | :--- |
| Snowflake | ⭐⭐⭐⭐⭐ | ✅ | N/A |
| WebTunnel | ⭐⭐⭐⭐⭐ | ✅ (CDN) | ✅ |
| obfs4 | ⭐⭐⭐⭐ | ❌ | ✅ |
| meek-lite | ⭐⭐⭐⭐ | ✅ (Azure) | ✅ |
| Vanilla | ⭐ | ❌ | ⚠️ |
"""

    values = {
        "ts":        ts,
        "repo":      repo,
        "lnk_obfs4":    lnk("obfs4.txt"),
        "cnt_obfs4":    cnt("obfs4.txt"),
        "lnk_obfs4_v6": lnk("obfs4_ipv6.txt"),
        "cnt_obfs4_v6": cnt("obfs4_ipv6.txt"),
        "lnk_wt":    lnk("webtunnel.txt"),
        "cnt_wt":    cnt("webtunnel.txt"),
        "lnk_wt_v6": lnk("webtunnel_ipv6.txt"),
        "cnt_wt_v6": cnt("webtunnel_ipv6.txt"),
        "lnk_sf":    lnk("snowflake.txt"),
        "cnt_sf":    cnt("snowflake.txt"),
        "lnk_va":    lnk("vanilla.txt"),
        "cnt_va":    cnt("vanilla.txt"),
        "lnk_va_v6": lnk("vanilla_ipv6.txt"),
        "cnt_va_v6": cnt("vanilla_ipv6.txt"),
        "lnk_ml":    lnk("meek_lite.txt"),
        "cnt_ml":    cnt("meek_lite.txt"),
    }

    Path("README.md").write_text(template.format_map(values), encoding="utf-8")
    log.info("README.md updated.")


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    log.info("═══ TorShield-IR Scraper ════════════════════════════════════")
    session = make_session()
    history = load_history()

    # Collect from all sources
    log.info("── Source 1: bridges.torproject.org")
    tp_bridges = fetch_torproject(session)

    log.info("── Source 2: MOAT API (Iran country code)")
    moat_bridges = fetch_moat(session)

    log.info("── Source 3: Static built-in bridges")
    static_bridges = get_static()

    log.info("── Source 4: GitHub public bridge repositories")
    github_bridges: List[Tuple[str, str, str]] = []
    if _HAVE_GITHUB:
        try:
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None
            if loop and loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor(1) as ex:
                    fut = ex.submit(asyncio.run, fetch_github_async())
                    github_bridges = fut.result(timeout=30)
            else:
                github_bridges = asyncio.run(fetch_github_async())
            log.info(f"GitHub bridges: {len(github_bridges)} collected")
        except Exception as e:
            log.warning(f"GitHub bridges failed: {e}")
    else:
        log.info("GitHub bridge source not available (sources.github_bridges missing)")

    # Merge all sources into history
    all_raw = tp_bridges + moat_bridges + static_bridges + github_bridges
    log.info(f"Total collected: {len(all_raw)} bridge lines (before dedup)")

    # Attach raw text back to records before update
    for raw_line, transport, ip_version in all_raw:
        key = normalize_for_history(raw_line, transport)
        now = datetime.now(tz=timezone.utc).isoformat()
        if key not in history:
            history[key] = {
                "raw":         raw_line.strip(),
                "transport":   transport,
                "ip_version":  ip_version,
                "first_seen":  now,
                "last_seen":   now,
                "tcp_reachable": None,
            }
        else:
            # Guard: if the entry is not a dict (e.g. legacy string format
            # that escaped normalisation), promote it safely.
            if not isinstance(history[key], dict):
                history[key] = {
                    "raw":           raw_line.strip(),
                    "transport":     transport,
                    "ip_version":    ip_version,
                    "first_seen":    now,
                    "last_seen":     now,
                    "tcp_reachable": None,
                }
            else:
                history[key]["last_seen"] = now
                history[key]["raw"]       = raw_line.strip()

    prune_history(history)
    save_history(history)
    log.info(f"History saved: {len(history)} total bridges")

    # Write output files
    stats = write_bridge_files(history)
    testing_count = write_testing_json(history)
    zip_path = build_zip(stats)
    update_readme(stats)

    # Write a minimal latest-results.json so the artifact upload finds it
    latest = {
        "timestamp": datetime.now(tz=timezone.utc).isoformat(),
        "total_bridges": len(history),
        "by_transport": {
            t: stats.get(f"{t}.txt", 0)
            for t in ["obfs4", "webtunnel", "snowflake", "vanilla", "meek_lite"]
        },
    }
    Path("data/latest-results.json").write_text(
        json.dumps(latest, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    log.info(f"bridge_list_for_testing.json → {testing_count} entries (for Go tester)")
    log.info(f"ZIP → {zip_path}")
    log.info("═══ Scraper done ════════════════════════════════════════════")


if __name__ == "__main__":
    main()
