"""
core/formatter.py — Multi-format bridge file exporter.

Generates the following outputs from the history database:

  bridge/
    <transport>.txt              All-time archive per transport (IPv4)
    <transport>_ipv6.txt         All-time archive per transport (IPv6)
    <transport>_72h.txt          Last 72-hour window (IPv4)
    <transport>_72h_ipv6.txt     Last 72-hour window (IPv6)
    <transport>_tested.txt       Connectivity-verified (IPv4)
    <transport>_ipv6_tested.txt  Connectivity-verified (IPv6)
    snowflake.txt                Snowflake bridges
    meek_lite.txt                meek-lite bridges
    bridge_scores.json           Full scores database
    tor_bridges.zip              ZIP archive for Telegram distribution

  export/
    iran_pack.txt                Top-N highest-scored bridges for Iran
    iran_cut_pack.txt            Best bridges for NIN internet-cut scenarios
    bridges_api.json             Machine-readable JSON API
"""

from __future__ import annotations

import json
import logging
import os
import zipfile
from datetime import timedelta
from typing import Any, Dict, List

import config
from core.dt_utils import parse_dt, utc_now, utc_now_iso
from core.history import HistoryManager
from core.scorer import IranScorer
from core.tester import detect_transport, extract_endpoint

log = logging.getLogger(__name__)

TRANSPORT_FILENAMES = {
    "obfs4":     "obfs4",
    "webtunnel": "webtunnel",
    "vanilla":   "vanilla",
    "snowflake": "snowflake",
    "meek_lite": "meek_lite",
}


def _save_line(raw: str, transport: str) -> str:
    """Return the canonical bridge line to write to file."""
    line = raw.strip()
    if line.startswith("Bridge "):
        line = line[7:]
    return line


def _is_ipv6(record: Dict[str, Any]) -> bool:
    raw = record.get("raw", "")
    host, _, _ = extract_endpoint(raw)
    if host and ":" in host:
        return True
    return False


def _write(path: str, lines: List[str]) -> None:
    """Write bridge lines to file. Never overwrites non-empty file with empty content."""
    clean = sorted(set(l.strip() for l in lines if l and l.strip()))
    if not clean:
        # GUARD: never replace an existing non-empty file with empty content
        if os.path.exists(path) and os.path.getsize(path) > 0:
            log.debug(f"  → {path}: preserving {os.path.getsize(path)}B existing content (export empty)")
            return
    os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for line in clean:
            f.write(line + "\n")
    log.debug(f"  → {path}: {len(clean)} bridges written")


class BridgeFormatter:
    def __init__(self):
        self._scorer = IranScorer()
        self._bd = config.BRIDGE_DIR
        self._ed = config.EXPORT_DIR

    def _export_standard_files(self, history: HistoryManager) -> Dict[str, int]:
        """Generate the classic per-transport .txt files (archive + 72h + tested)."""
        db = history.get_all()
        # FIX: use utc_now() (UTC-aware) so comparison with parse_dt() never raises TypeError
        cutoff = utc_now() - timedelta(hours=config.RECENT_HOURS)
        stats: Dict[str, int] = {}

        for transport, fname in TRANSPORT_FILENAMES.items():
            records = [v for v in db.values() if v.get("transport") == transport]

            ipv4 = [_save_line(r.get("raw", ""), transport) for r in records if not _is_ipv6(r) and r.get("raw")]
            ipv6 = [_save_line(r.get("raw", ""), transport) for r in records if _is_ipv6(r) and r.get("raw")]

            # FIX: parse_dt() always returns UTC-aware datetime — safe to compare with cutoff
            ipv4_72h = [
                _save_line(r.get("raw", ""), transport) for r in records
                if not _is_ipv6(r) and r.get("raw")
                and parse_dt(r.get("first_seen", "2000-01-01")) > cutoff
            ]
            ipv6_72h = [
                _save_line(r.get("raw", ""), transport) for r in records
                if _is_ipv6(r) and r.get("raw")
                and parse_dt(r.get("first_seen", "2000-01-01")) > cutoff
            ]
            ipv4_tested = [_save_line(r.get("raw", ""), transport) for r in records
                           if not _is_ipv6(r) and r.get("raw") and r.get("test_pass") is True]
            ipv6_tested = [_save_line(r.get("raw", ""), transport) for r in records
                           if _is_ipv6(r) and r.get("raw") and r.get("test_pass") is True]

            _write(os.path.join(self._bd, f"{fname}.txt"),                             ipv4)
            _write(os.path.join(self._bd, f"{fname}_ipv6.txt"),                        ipv6)
            _write(os.path.join(self._bd, f"{fname}_{config.RECENT_HOURS}h.txt"),      ipv4_72h)
            _write(os.path.join(self._bd, f"{fname}_{config.RECENT_HOURS}h_ipv6.txt"), ipv6_72h)
            _write(os.path.join(self._bd, f"{fname}_tested.txt"),                      ipv4_tested)
            _write(os.path.join(self._bd, f"{fname}_ipv6_tested.txt"),                 ipv6_tested)

            stats[f"{fname}.txt"]                             = len(ipv4)
            stats[f"{fname}_ipv6.txt"]                        = len(ipv6)
            stats[f"{fname}_{config.RECENT_HOURS}h.txt"]      = len(ipv4_72h)
            stats[f"{fname}_{config.RECENT_HOURS}h_ipv6.txt"] = len(ipv6_72h)
            stats[f"{fname}_tested.txt"]                      = len(ipv4_tested)
            stats[f"{fname}_ipv6_tested.txt"]                 = len(ipv6_tested)

        return stats

    def _export_iran_packs(self, history: HistoryManager) -> None:
        """Generate Iran-optimised export files."""
        db = history.get_all()
        os.makedirs(self._ed, exist_ok=True)

        # Top-100 bridges by Iran score
        top   = self._scorer.top_for_iran(db, n=100)
        lines = [_save_line(r.get("raw", ""), r.get("transport", "")) for r in top if r.get("raw")]
        with open(os.path.join(self._ed, "iran_pack.txt"), "w", encoding="utf-8") as f:
            f.write("# Tor Bridge Iran Pack — sorted by Iran effectiveness score\n")
            f.write(f"# Generated: {utc_now().strftime('%Y-%m-%d %H:%M UTC')}\n")
            f.write("# Usage: paste lines below into Tor Browser → Settings → Connection → Bridges\n\n")
            for line in lines:
                if line:
                    f.write(line + "\n")
        log.info(f"iran_pack.txt: {len(lines)} bridges")

        # Internet-cut survival pack (snowflake + webtunnel CDN)
        cut_pack  = self._scorer.iran_cut_pack(db)
        cut_lines = [_save_line(r.get("raw", ""), r.get("transport", "")) for r in cut_pack if r.get("raw")]
        with open(os.path.join(self._ed, "iran_cut_pack.txt"), "w", encoding="utf-8") as f:
            f.write("# Bridges for Iranian Internet Cut (شبکه ملی)\n")
            f.write("# These bridges are most likely to work when international internet is blocked.\n")
            f.write("# Priority: Snowflake > WebTunnel (CDN) > obfs4 port 443\n\n")
            for line in cut_lines:
                if line:
                    f.write(line + "\n")
        log.info(f"iran_cut_pack.txt: {len(cut_lines)} bridges")

    def _export_json_api(self, history: HistoryManager) -> None:
        """Generate machine-readable JSON API file."""
        db = history.get_all()
        by_transport: Dict[str, list] = {}
        for v in db.values():
            t = v.get("transport", "unknown")
            entry = {
                "line":       _save_line(v.get("raw", ""), t),
                "score":      v.get("score", 0),
                "tested":     v.get("test_pass"),
                "first_seen": v.get("first_seen"),
                "last_seen":  v.get("last_seen"),
                "latency_ms": v.get("latency_ms"),
            }
            by_transport.setdefault(t, []).append(entry)

        for t in by_transport:
            by_transport[t].sort(key=lambda x: x["score"], reverse=True)

        api = {
            "schema":  "1.0",
            "updated": utc_now_iso(),   # ← UTC-aware ISO string
            "bridges": by_transport,
        }
        path = os.path.join(self._ed, "bridges_api.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(api, f, indent=2, ensure_ascii=False)
        log.info(f"bridges_api.json: {sum(len(v) for v in by_transport.values())} entries")

    def _save_scores_db(self, history: HistoryManager) -> None:
        db     = history.get_all()
        scores = {k: {"score": v.get("score", 0), "transport": v.get("transport")}
                  for k, v in db.items()}
        path = os.path.join(self._bd, "bridge_scores.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(scores, f, indent=2)

    def _build_zip(self, stats: Dict[str, int]) -> str:
        """Build a ZIP archive organised by category for Telegram distribution."""
        for f in os.listdir(self._bd):
            if f.endswith(".zip"):
                os.remove(os.path.join(self._bd, f))

        zip_path = os.path.join(self._bd, "tor_bridges.zip")
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            root = "Tor Bridges"
            for f in os.listdir(self._bd):
                if not f.endswith(".txt"):
                    continue
                fpath = os.path.join(self._bd, f)
                if "_tested" in f:
                    folder = f"{root}/Tested (Verified)"
                elif f"_{config.RECENT_HOURS}h" in f:
                    folder = f"{root}/Fresh (Last 72h)"
                else:
                    folder = f"{root}/Full Archive"
                zf.write(fpath, os.path.join(folder, f))

            for ef in ["iran_pack.txt", "iran_cut_pack.txt"]:
                ep = os.path.join(self._ed, ef)
                if os.path.exists(ep):
                    zf.write(ep, os.path.join(f"{root}/Iran Optimized", ef))

        log.info(f"ZIP archive built: {zip_path}")
        return zip_path

    def export_all(self, history: HistoryManager) -> Dict[str, Any]:
        """Run the full export pipeline. Returns stats dict for README/Telegram."""
        log.info("Exporting bridge files…")
        stats = self._export_standard_files(history)
        self._export_iran_packs(history)
        self._export_json_api(history)
        self._save_scores_db(history)
        zip_path      = self._build_zip(stats)
        stats["__zip_path__"] = zip_path
        return stats

    def update_readme(self, stats: Dict[str, Any]) -> None:
        ts   = utc_now().strftime("%Y-%m-%d %H:%M UTC")
        rh   = config.RECENT_HOURS
        repo = config.REPO_URL

        def _link(f):
            return f"[{f}]({repo}/bridge/{f})"

        def _cnt(key):
            return f"**{stats.get(key, 0)}**"

        content = f"""# 🌐 Tor Bridges Ultra Collector

> Auto-collected, tested, and Iran-scored Tor bridges.  
> GitHub Actions runs every hour — fresh bridges always available.  
> **Last update:** `{ts}`

## ⚠️ Notes for Iran Users

- **Internet cut (شبکه ملی):** Use `export/iran_cut_pack.txt` — contains Snowflake and WebTunnel bridges that survive NIN.
- **Normal censorship:** Use `export/iran_pack.txt` — top-ranked obfs4/WebTunnel bridges for Iran's DPI.
- **Port 443 bridges** are prioritised — Iran almost never blocks HTTPS.
- **IPv4 is more stable** than IPv6 inside Iran.

## ✅ Tested & Active (Recommended)

| Transport | IPv4 Tested | Count |
| :--- | :--- | :--- |
| **obfs4** | {_link("obfs4_tested.txt")} | {_cnt("obfs4_tested.txt")} |
| **WebTunnel** | {_link("webtunnel_tested.txt")} | {_cnt("webtunnel_tested.txt")} |
| **Snowflake** | {_link("snowflake_tested.txt")} | {_cnt("snowflake_tested.txt")} |
| **Vanilla** | {_link("vanilla_tested.txt")} | {_cnt("vanilla_tested.txt")} |
| **meek-lite** | {_link("meek_lite_tested.txt")} | {_cnt("meek_lite_tested.txt")} |

## 🕐 Fresh Bridges (Last {rh}h)

| Transport | IPv4 | Count | IPv6 | Count |
| :--- | :--- | :--- | :--- | :--- |
| **obfs4** | {_link(f"obfs4_{rh}h.txt")} | {_cnt(f"obfs4_{rh}h.txt")} | {_link(f"obfs4_{rh}h_ipv6.txt")} | {_cnt(f"obfs4_{rh}h_ipv6.txt")} |
| **WebTunnel** | {_link(f"webtunnel_{rh}h.txt")} | {_cnt(f"webtunnel_{rh}h.txt")} | {_link(f"webtunnel_{rh}h_ipv6.txt")} | {_cnt(f"webtunnel_{rh}h_ipv6.txt")} |
| **Vanilla** | {_link(f"vanilla_{rh}h.txt")} | {_cnt(f"vanilla_{rh}h.txt")} | {_link(f"vanilla_{rh}h_ipv6.txt")} | {_cnt(f"vanilla_{rh}h_ipv6.txt")} |

## 📦 Full Archive

| Transport | IPv4 | Count | IPv6 | Count |
| :--- | :--- | :--- | :--- | :--- |
| **obfs4** | {_link("obfs4.txt")} | {_cnt("obfs4.txt")} | {_link("obfs4_ipv6.txt")} | {_cnt("obfs4_ipv6.txt")} |
| **WebTunnel** | {_link("webtunnel.txt")} | {_cnt("webtunnel.txt")} | {_link("webtunnel_ipv6.txt")} | {_cnt("webtunnel_ipv6.txt")} |
| **Snowflake** | {_link("snowflake.txt")} | {_cnt("snowflake.txt")} | — | — |
| **Vanilla** | {_link("vanilla.txt")} | {_cnt("vanilla.txt")} | {_link("vanilla_ipv6.txt")} | {_cnt("vanilla_ipv6.txt")} |
| **meek-lite** | {_link("meek_lite.txt")} | {_cnt("meek_lite.txt")} | — | — |

## 🇮🇷 Iran Optimised Packs

| Pack | Description |
| :--- | :--- |
| [iran_pack.txt]({repo}/export/iran_pack.txt) | Top 100 bridges ranked by Iran effectiveness score |
| [iran_cut_pack.txt]({repo}/export/iran_cut_pack.txt) | Bridges for internet cut / شبکه ملی scenarios |
| [bridges_api.json]({repo}/export/bridges_api.json) | Machine-readable JSON API |

## 📡 Transport Guide for Iran

| Transport | Anti-DPI | Works during cut | Speed | Recommended |
| :--- | :--- | :--- | :--- | :--- |
| Snowflake | ⭐⭐⭐⭐⭐ | ✅ | Medium | **Yes** |
| WebTunnel | ⭐⭐⭐⭐⭐ | ✅ (CDN) | Fast | **Yes** |
| obfs4 | ⭐⭐⭐⭐ | ❌ | Fast | **Yes** |
| meek-lite | ⭐⭐⭐⭐ | ✅ (Azure) | Slow | Fallback |
| Vanilla | ⭐ | ❌ | Fast | No |

## Disclaimer

For educational and archival purposes. Use bridges responsibly.
"""
        with open("README.md", "w", encoding="utf-8") as f:
            f.write(content)
        log.info("README.md updated.")
