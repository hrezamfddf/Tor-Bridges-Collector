#!/usr/bin/env python3
"""
onionhop_collector.py — OnionHop multi-source bridge collector (Iran-aware)
============================================================================
Derived from OnionHop Bridges Collector by center2055 (AGPL-3.0).
Integrated into TorShield-IR as an additional collection stage that runs
BEFORE scraper.py to seed the archive with additional fresh bridges.

History format: dicts identical to scraper.py's format so the two modules
share bridge_history.json without any type conflict:
  {
    "<bridge_key>": {
      "raw":           "<bridge line>",
      "transport":     "obfs4|webtunnel|snowflake|meek_lite|conjure|vanilla",
      "ip_version":    "ipv4|ipv6",
      "first_seen":    "<ISO timestamp>",
      "last_seen":     "<ISO timestamp>",
      "tcp_reachable": true|false|null
    },
    ...
  }

Sources:
  1. Official Tor BridgeDB (obfs4, webtunnel, vanilla — IPv4 + IPv6)
  2. Delta-Kronecker/Tor-Bridges-Collector community seed lists
  3. Fixed fronted bridge defaults (snowflake, meek-azure, conjure)
     → Critical for Iran's شبکه ملی (NIN) internet-cut scenario.

Iran-specific notes:
  - Fronted transports (snowflake, meek-azure, conjure) route through CDN77
    and Azure CDN and work even when the international internet is restricted.
  - Iranian ASN bridges are excluded during Go iran_tester's ASN check stage;
    this collector focuses on breadth and freshness.
"""
from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import re
import socket
import ssl
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict

import requests
from bs4 import BeautifulSoup

# ── Configuration ─────────────────────────────────────────────────────────────

BRIDGE_DIR = Path("bridge")
HISTORY_FILE = BRIDGE_DIR / "bridge_history.json"

RECENT_HOURS = 72
HISTORY_RETENTION_DAYS = 30
MAX_TEST_PER_LIST = 600
MAX_WORKERS = 50
CONNECT_TIMEOUT = 8

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)

POOLED_TRANSPORTS = ["obfs4", "webtunnel", "vanilla"]
IP_VARIANTS = [("", False), ("_ipv6", True)]

DELTA_RAW_BASE = (
    "https://raw.githubusercontent.com/Delta-Kronecker"
    "/Tor-Bridges-Collector/main/bridge"
)

# Fixed default lines for fronted transports (Tor Browser defaults).
# RFC 5737 placeholder IPs (192.0.2.x) — connectivity goes through CDN/broker.
# These work inside Iran even when the international internet is partially cut
# because snowflake uses WebRTC through CDN77, meek-azure through Azure CDN,
# and conjure through Refraction Networking.
FRONTED_BRIDGES: dict[str, list[str]] = {
    "snowflake": [
        (
            "snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 "
            "fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 "
            "url=https://1098762253.rsc.cdn77.org/ "
            "fronts=www.cdn77.com,www.phpmyadmin.net "
            "ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,"
            "stun:stun.bluesip.net:3478,stun:stun.dus.net:3478,"
            "stun:stun.epygi.com:3478 utls-imitate=hellorandomizedalpn"
        ),
        (
            "snowflake 192.0.2.4:80 8838024498816A039FCBBAB14E6F40A0843051FA "
            "fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA "
            "url=https://1098762253.rsc.cdn77.org/ "
            "fronts=www.cdn77.com,www.phpmyadmin.net "
            "ice=stun:stun.l.google.com:19302,stun:stun.antisip.com:3478,"
            "stun:stun.bluesip.net:3478,stun:stun.dus.net:3478,"
            "stun:stun.epygi.com:3478 utls-imitate=hellorandomizedalpn"
        ),
    ],
    "meek-azure": [
        (
            "meek_lite 192.0.2.20:80 97700DFE9F483596DDA6264C4D7DF7641E1E39CE "
            "url=https://meek.azureedge.net/ front=ajax.aspnetcdn.com"
        ),
    ],
    "conjure": [
        (
            "conjure 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 "
            "url=https://registration.refraction.network/api "
            "fronts=cdn.sstatic.net,assets.cloud.censys.io transport=min"
        ),
    ],
}

FRONTED_TOKENS = {"snowflake", "meek", "meek_lite", "meek-azure", "conjure"}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _log(msg: str) -> None:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    print(f"[onionhop] [{stamp}] {msg}", flush=True)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _is_valid(line: str) -> bool:
    if not line or line.startswith("#"):
        return False
    if "No bridges available" in line or len(line) < 10:
        return False
    return bool(re.search(r"\d+\.\d+\.\d+\.\d+|\[[0-9A-Fa-f:]+\]|https?://", line))


def _strip_prefix(line: str) -> str:
    return line[7:].strip() if line.startswith("Bridge ") else line.strip()


def _transport_token(line: str) -> str:
    stripped = _strip_prefix(line).strip()
    return stripped.split(None, 1)[0].lower() if stripped else ""


def _detect_transport(line: str) -> str:
    low = line.lower()
    if "snowflake" in low:
        return "snowflake"
    if "webtunnel" in low or "url=https" in low:
        return "webtunnel"
    if "obfs4" in low:
        return "obfs4"
    if "meek" in low:
        return "meek_lite"
    if "conjure" in low:
        return "conjure"
    return "vanilla"


def _detect_ip_version(line: str) -> str:
    if re.search(r"\[[0-9a-fA-F:]{2,39}\]", line):
        return "ipv6"
    return "ipv4"


def _is_fronted(line: str) -> bool:
    return _transport_token(line) in FRONTED_TOKENS


def _extract_front_host(line: str) -> str | None:
    m = re.search(r"(?:^|\s)url=(\S+)", line, re.IGNORECASE)
    if m:
        hm = re.search(r"https?://([^/:\s]+)", m.group(1))
        if hm:
            return hm.group(1)
    m = re.search(r"(?:^|\s)fronts=(\S+)", line, re.IGNORECASE)
    if m:
        first = m.group(1).split(",")[0].strip()
        if first:
            return first
    m = re.search(r"(?:^|\s)front=(\S+)", line, re.IGNORECASE)
    if m and m.group(1).strip():
        return m.group(1).strip()
    return None


def _extract_endpoint(line: str) -> tuple[str | None, int | None, str]:
    text = line.strip()
    transport = _detect_transport(text)
    for pattern, https_default in [
        (r"https?://\[([0-9A-Fa-f:]+)\](?::(\d+))?", True),
        (r"https?://([^/:]+)(?::(\d+))?", True),
        (r"\[([0-9A-Fa-f:]+)\]:(\d+)", False),
        (r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)", False),
    ]:
        m = re.search(pattern, text)
        if m:
            host = m.group(1)
            port_str = m.group(2)
            port = int(port_str) if port_str else 443
            return host, port, transport
    return None, None, transport


def _parse_iso_safe(stamp: str | None) -> datetime | None:
    """Parse an ISO timestamp string, returning None on any error."""
    if not stamp or not isinstance(stamp, str):
        return None
    try:
        return datetime.fromisoformat(stamp)
    except (ValueError, TypeError):
        return None


def _entry_last_seen(entry: Any) -> datetime | None:
    """Extract last_seen datetime from a history entry (dict or legacy string)."""
    if isinstance(entry, dict):
        return _parse_iso_safe(entry.get("last_seen"))
    if isinstance(entry, str):
        return _parse_iso_safe(entry)
    return None


# ── Connectivity tests ────────────────────────────────────────────────────────

def _test_tcp(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT):
            return True
    except OSError:
        return False


def _test_tls(host: str, port: int) -> bool:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as raw:
            try:
                ipaddress.ip_address(host)
                sni: str | None = None
            except ValueError:
                sni = host
            with ctx.wrap_socket(raw, server_hostname=sni):
                return True
    except (OSError, ssl.SSLError):
        return False


def _is_reachable(bridge_line: str) -> bool:
    if _is_fronted(bridge_line):
        front = _extract_front_host(bridge_line)
        return _test_tls(front, 443) if front else False
    host, port, transport = _extract_endpoint(bridge_line)
    if not host or not port:
        return False
    try:
        ipaddress.ip_address(host)
        h = host
    except ValueError:
        try:
            h = socket.gethostbyname(host)
        except OSError:
            return False
    return _test_tls(h, port) if transport == "webtunnel" else _test_tcp(h, port)


def _test_many(bridges: list[str]) -> list[str]:
    candidates = bridges[:MAX_TEST_PER_LIST]
    if len(bridges) > MAX_TEST_PER_LIST:
        _log(f"  (capped connectivity test at {MAX_TEST_PER_LIST}/{len(bridges)})")
    if not candidates:
        return []
    working: list[str] = []
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=min(MAX_WORKERS, len(candidates))
    ) as pool:
        fut_map = {pool.submit(_is_reachable, b): b for b in candidates}
        for fut in concurrent.futures.as_completed(fut_map):
            try:
                if fut.result():
                    working.append(fut_map[fut])
            except Exception:  # noqa: BLE001
                pass
    return working


# ── Fetchers ──────────────────────────────────────────────────────────────────

def _fetch_bridgedb(session: requests.Session, transport: str, ipv6: bool) -> set[str]:
    url = f"https://bridges.torproject.org/bridges?transport={transport}"
    if ipv6:
        url += "&ipv6=yes"
    out: set[str] = set()
    try:
        resp = session.get(url, timeout=30)
        if resp.status_code != 200:
            _log(f"  BridgeDB {transport} ipv6={ipv6}: HTTP {resp.status_code}")
            return out
        soup = BeautifulSoup(resp.text, "html.parser")
        div = soup.find("div", id="bridgelines")
        if not div:
            _log(f"  BridgeDB {transport} ipv6={ipv6}: no bridgelines (likely CAPTCHA)")
            return out
        for line in (ln.strip() for ln in div.get_text().split("\n")):
            if _is_valid(line):
                out.add(_strip_prefix(line))
    except requests.RequestException as exc:
        _log(f"  BridgeDB {transport} ipv6={ipv6} error: {exc}")
    return out


def _fetch_delta(session: requests.Session, transport: str, ipv6: bool) -> set[str]:
    suffix = "_ipv6" if ipv6 else ""
    out: set[str] = set()
    for variant in (f"{transport}{suffix}.txt", f"{transport}{suffix}_72h.txt"):
        try:
            resp = session.get(f"{DELTA_RAW_BASE}/{variant}", timeout=30)
            if resp.status_code != 200:
                continue
            for line in (ln.strip() for ln in resp.text.split("\n")):
                if _is_valid(line):
                    out.add(_strip_prefix(line))
        except requests.RequestException:
            pass
    return out


# ── Persistence ───────────────────────────────────────────────────────────────

def _read_existing(path: Path) -> set[str]:
    if not path.exists():
        return set()
    return {
        _strip_prefix(ln.strip())
        for ln in path.read_text(encoding="utf-8").splitlines()
        if _is_valid(ln.strip())
    }


def _write_lines(path: Path, lines: set[str] | list[str]) -> None:
    path.write_text("\n".join(sorted(lines)) + "\n", encoding="utf-8")


def _load_history() -> Dict[str, Any]:
    """Load history file, normalising any legacy string-format entries to dicts.

    Handles three formats:
      1. Correct dict format  (written by scraper.py or this module)
      2. Legacy string format  {"<key>": "<ISO timestamp>"}  (old onionhop format)
      3. Absent file           → returns empty dict
    """
    if HISTORY_FILE.exists():
        try:
            raw: dict = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
            normalised: Dict[str, Any] = {}
            for k, v in raw.items():
                if isinstance(v, str):
                    # Promote legacy string entry to canonical dict
                    normalised[k] = {
                        "raw":           k,
                        "transport":     _detect_transport(k),
                        "ip_version":    _detect_ip_version(k),
                        "first_seen":    v,
                        "last_seen":     v,
                        "tcp_reachable": None,
                    }
                elif isinstance(v, dict):
                    normalised[k] = v
                # Skip malformed entries
            return normalised
        except (OSError, ValueError) as exc:
            _log(f"History load error: {exc}")
    return {}


def _save_history(history: Dict[str, Any]) -> None:
    HISTORY_FILE.write_text(
        json.dumps(history, indent=2, sort_keys=True, ensure_ascii=False),
        encoding="utf-8",
    )


def _cleanup_history(history: Dict[str, Any]) -> Dict[str, Any]:
    """Remove entries older than HISTORY_RETENTION_DAYS."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=HISTORY_RETENTION_DAYS)
    return {
        k: v for k, v in history.items()
        if (ts := _entry_last_seen(v)) is not None and ts > cutoff
    }


def _record_bridge(
    history: Dict[str, Any],
    bridge: str,
    transport: str,
    ip_version: str,
) -> None:
    """Insert or update a history entry using the canonical dict format."""
    now = _now_iso()
    if bridge not in history or not isinstance(history[bridge], dict):
        history[bridge] = {
            "raw":           bridge,
            "transport":     transport,
            "ip_version":    ip_version,
            "first_seen":    now,
            "last_seen":     now,
            "tcp_reachable": None,
        }
    else:
        history[bridge]["last_seen"] = now
        # Preserve first_seen; update raw in case it got reformatted upstream
        history[bridge].setdefault("raw", bridge)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    BRIDGE_DIR.mkdir(exist_ok=True)
    Path("data").mkdir(exist_ok=True)

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    history = _cleanup_history(_load_history())
    recent_cutoff = datetime.now(timezone.utc) - timedelta(hours=RECENT_HOURS)
    stats: dict[str, int] = {}

    _log("Starting OnionHop multi-source bridge collection…")

    # ── Pooled transports (obfs4, webtunnel, vanilla) ──────────────────────
    for transport in POOLED_TRANSPORTS:
        for suffix, ipv6 in IP_VARIANTS:
            ip_version = "ipv6" if ipv6 else "ipv4"
            base_path   = BRIDGE_DIR / f"{transport}{suffix}.txt"
            recent_path = BRIDGE_DIR / f"{transport}{suffix}_72h.txt"
            tested_path = BRIDGE_DIR / f"{transport}{suffix}_tested.txt"

            existing = _read_existing(base_path)
            fetched  = _fetch_bridgedb(session, transport, ipv6)
            seeded   = _fetch_delta(session, transport, ipv6)
            archive  = existing | fetched | seeded

            for bridge in (fetched | seeded):
                _record_bridge(history, bridge, transport, ip_version)

            _write_lines(base_path, archive)

            recent = [
                b for b in archive
                if (ts := _entry_last_seen(history.get(b))) and ts > recent_cutoff
            ]
            _write_lines(recent_path, set(recent))

            tested = _test_many(sorted(archive))
            _write_lines(tested_path, set(tested))

            stats[base_path.name]   = len(archive)
            stats[recent_path.name] = len(recent)
            stats[tested_path.name] = len(tested)
            _log(
                f"{transport} ipv6={ipv6}: "
                f"archive={len(archive)} fresh72h={len(recent)} tested={len(tested)}"
            )

    # ── Fronted transports (snowflake, meek-azure, conjure) ────────────────
    # Critical for Iran's شبکه ملی (NIN) internet-cut scenario where direct
    # Tor access is blocked but CDN / broker traffic still passes.
    for transport, default_lines in FRONTED_BRIDGES.items():
        base_path   = BRIDGE_DIR / f"{transport}.txt"
        recent_path = BRIDGE_DIR / f"{transport}_72h.txt"
        tested_path = BRIDGE_DIR / f"{transport}_tested.txt"

        existing = _read_existing(base_path)
        seeded   = {ln.strip() for ln in default_lines if _is_valid(ln)}
        archive  = existing | seeded

        for bridge in seeded:
            _record_bridge(history, bridge, transport, "ipv4")

        _write_lines(base_path, archive)

        recent = [
            b for b in archive
            if (ts := _entry_last_seen(history.get(b))) and ts > recent_cutoff
        ]
        _write_lines(recent_path, set(recent))

        tested = _test_many(sorted(archive))
        _write_lines(tested_path, set(tested))

        stats[base_path.name]   = len(archive)
        stats[recent_path.name] = len(recent)
        stats[tested_path.name] = len(tested)
        _log(
            f"{transport} (fronted/NIN): "
            f"archive={len(archive)} fresh72h={len(recent)} tested={len(tested)}"
        )

    _save_history(history)
    _log(
        "Collection complete. "
        + " | ".join(f"{k}:{v}" for k, v in sorted(stats.items()) if "_tested" in k)
    )


if __name__ == "__main__":
    main()
