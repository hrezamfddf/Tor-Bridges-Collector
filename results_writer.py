#!/usr/bin/env python3
"""
results_writer.py — TorShield-IR bridge results writer.

Reads bridge/iran_results.json (written by the Go iran_tester) and produces
categorised, lexicographically sorted, deduplicated bridge text files:

  bridge/iran_likely_working_obfs4.txt
  bridge/iran_likely_working_webtunnel.txt
  bridge/iran_likely_working_vanilla.txt
  bridge/iran_likely_working_snowflake.txt
  bridge/iran_likely_working_all.txt
  bridge/iran_blocked.txt
  bridge/tested_global_obfs4.txt
  bridge/tested_global_webtunnel.txt
  bridge/tested_global_vanilla.txt

Classification strategy (two-tier):
  Tier 1 — OONI-verified working (iran_likely_working status from Go tester)
  Tier 2 — TCP-reachable with no OONI data (iran_unknown + tcp_reachable=true)
    → included as fallback so obfs4/webtunnel files are never left empty when
      OONI has not yet measured a bridge from Iranian probes.

WebTunnel bridges are domain-fronted (HTTPS URL, not IP:port); OONI cannot
easily match them by IP, so they almost always land in iran_unknown.  The
Tier-2 fallback ensures these still appear in iran_likely_working_webtunnel.txt.

Updates README.md with live statistics.
Optionally uploads a ZIP of iran_likely_working_all.txt to Telegram.
"""

from __future__ import annotations

import io
import json
import logging
import os
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

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

BRIDGE_DIR         = Path(os.getenv("BRIDGE_DIR", "bridge"))
IRAN_RESULTS_PATH  = BRIDGE_DIR / "iran_results.json"
REPO_URL           = os.getenv("REPO_URL", "https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/refs/heads/main")

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_CHAT_ID   = os.getenv("TELEGRAM_CHAT_ID", "")
TELEGRAM_UPLOAD    = os.getenv("TELEGRAM_UPLOAD", "false").lower() == "true"

BRIDGE_DIR.mkdir(parents=True, exist_ok=True)

# Iran status labels — Tier 1: OONI-verified
_WORKING_STATUSES = {"iran_likely_working"}
# Iran status labels — Tier 2: TCP-reachable but no OONI data
# These are included as fallback when Tier 1 is empty for a given transport.
_UNKNOWN_REACHABLE = {"iran_unknown"}
# Definitively blocked — excluded from working files
_BLOCKED_STATUSES  = {"iran_likely_blocked", "iran_frequently_blocked"}


# ─────────────────────────────────────────────────────────────────────────────
# Data loading
# ─────────────────────────────────────────────────────────────────────────────

def load_iran_results() -> Dict[str, Any]:
    if not IRAN_RESULTS_PATH.exists():
        log.error(f"iran_results.json not found at {IRAN_RESULTS_PATH}.")
        sys.exit(1)
    return json.loads(IRAN_RESULTS_PATH.read_text(encoding="utf-8"))


# ─────────────────────────────────────────────────────────────────────────────
# File writing helpers
# ─────────────────────────────────────────────────────────────────────────────

def _write_sorted_file(path: Path, lines: List[str]) -> int:
    """Write lines sorted lexicographically, deduplicated, no blank lines."""
    clean = sorted(set(l.strip() for l in lines if l.strip()))
    path.write_text("\n".join(clean) + ("\n" if clean else ""), encoding="utf-8")
    return len(clean)


def _assert_integrity(path: Path) -> None:
    """
    Post-write assertion: verify the file is sorted, deduplicated, no blanks.
    Exits with code 1 if the assertion fails (mandatory quality gate).
    """
    text = path.read_text(encoding="utf-8")
    lines = [l for l in text.splitlines() if l.strip()]
    if lines != sorted(set(lines)):
        log.error(f"INTEGRITY ASSERTION FAILED: {path} is not sorted/deduplicated.")
        sys.exit(1)
    log.debug(f"Integrity OK: {path} ({len(lines)} lines, sorted, no dupes).")


# ─────────────────────────────────────────────────────────────────────────────
# Main file generation
# ─────────────────────────────────────────────────────────────────────────────

def write_result_files(bridges: List[Dict[str, Any]]) -> Dict[str, int]:
    """
    Categorise bridges and write all output files.

    Two-tier classification for iran_likely_working_* files:
      Tier 1: OONI-confirmed iran_likely_working  (highest confidence)
      Tier 2: TCP-reachable iran_unknown bridges  (fallback when Tier 1 is empty)

    Tier 2 is critical for obfs4 and webtunnel:
    - obfs4: new/uncommon bridges may not appear in OONI measurement history.
    - webtunnel: domain-fronted (HTTPS URL), OONI queries by IP and cannot
      easily match them, so nearly all WebTunnel bridges land in iran_unknown.

    Returns a stats dict: filename → count.
    """
    stats: Dict[str, int] = {}

    # Categorise into Tier-1, Tier-2, blocked, and global buckets
    t1_by_transport: Dict[str, List[str]] = {
        "obfs4": [], "webtunnel": [], "vanilla": [],
        "snowflake": [], "meek_lite": [],
    }
    t2_by_transport: Dict[str, List[str]] = {
        "obfs4": [], "webtunnel": [], "vanilla": [],
        "snowflake": [], "meek_lite": [],
    }
    blocked_lines: List[str] = []
    global_by_transport: Dict[str, List[str]] = {
        "obfs4": [], "webtunnel": [], "vanilla": [],
    }

    for b in bridges:
        line      = b.get("line", "").strip()
        transport = b.get("transport", "unknown")
        status    = b.get("iran_status", "")
        tcp_ok    = b.get("tcp_reachable", False)

        if not line:
            continue

        # --- Tier 1: OONI-confirmed working ---
        if status in _WORKING_STATUSES:
            bucket = t1_by_transport.get(transport)
            if bucket is not None:
                bucket.append(line)

        # --- Tier 2: TCP-reachable but OONI has no data ---
        # WebTunnel: always include if TCP/TLS reachable (OONI cannot classify by domain)
        # obfs4/others: include when TCP is reachable and OONI has no measurement
        if status in _UNKNOWN_REACHABLE and (tcp_ok or transport in ("snowflake", "webtunnel")):
            bucket2 = t2_by_transport.get(transport)
            if bucket2 is not None:
                bucket2.append(line)

        # --- Blocked ---
        if status in _BLOCKED_STATUSES:
            blocked_lines.append(line)

        # --- Global: TCP-reachable regardless of Iran classification ---
        if (tcp_ok or transport == "snowflake") and transport in global_by_transport:
            global_by_transport[transport].append(line)

    # --- Iran-likely-working files (Tier 1 + Tier 2 fallback) ---------------
    all_working: List[str] = []

    for transport, t1_lines in t1_by_transport.items():
        t2_lines = t2_by_transport.get(transport, [])

        if t1_lines:
            # Tier 1 available — use it exclusively (highest confidence)
            combined = t1_lines
            log.info(f"  {transport}: {len(t1_lines)} OONI-verified bridges (Tier 1)")
        elif t2_lines:
            # Tier 1 empty — fall back to TCP-reachable unclassified bridges
            combined = t2_lines
            log.info(
                f"  {transport}: {len(t2_lines)} TCP-reachable bridges (Tier 2 fallback, "
                f"no OONI data — typical for {transport})"
            )
        else:
            combined = []
            log.info(f"  {transport}: 0 bridges (neither OONI-verified nor TCP-reachable)")

        if not combined:
            continue

        p = BRIDGE_DIR / f"iran_likely_working_{transport}.txt"
        stats[p.name] = _write_sorted_file(p, combined)
        all_working.extend(combined)
        log.info(f"  → wrote {stats[p.name]} to {p.name}")

    all_path = BRIDGE_DIR / "iran_likely_working_all.txt"
    stats[all_path.name] = _write_sorted_file(all_path, all_working)
    log.info(f"  iran_likely_working_all.txt: {stats[all_path.name]}")
    _assert_integrity(all_path)   # mandatory post-write assertion

    # --- Blocked file -------------------------------------------------------
    blocked_path = BRIDGE_DIR / "iran_blocked.txt"
    stats[blocked_path.name] = _write_sorted_file(blocked_path, blocked_lines)
    log.info(f"  iran_blocked.txt: {stats[blocked_path.name]}")

    # --- Global tested files ------------------------------------------------
    for transport, lines in global_by_transport.items():
        p = BRIDGE_DIR / f"tested_global_{transport}.txt"
        stats[p.name] = _write_sorted_file(p, lines)
        log.info(f"  {p.name}: {stats[p.name]}")

    return stats


# ─────────────────────────────────────────────────────────────────────────────
# README update
# ─────────────────────────────────────────────────────────────────────────────

def update_readme(iran_data: Dict[str, Any], stats: Dict[str, int]) -> None:
    ts      = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    summary = iran_data.get("summary", {})
    repo    = REPO_URL

    def lnk(fname: str) -> str:
        return f"[{fname}]({repo}/bridge/{fname})"

    def cnt(key: str) -> str:
        return f"`{stats.get(key, 0)}`"

    # All literal braces in this template are doubled to prevent f-string
    # interpolation — only named placeholders are substituted.
    template = """\
# 🛡️ TorShield-IR — Tor Bridge Intelligence for Iran

> Polyglot (Python · Go · Rust) bridge collector with 8-layer Iran DPI analysis.  
> OONI-verified · ASN-filtered · Composite-scored · Auto-updated hourly.  
> **Last update:** `{ts}`

---

## 🚨 Quick Start for Iran

**If international internet is cut (شبکه ملی فعال):**
```
Use: bridge/iran_likely_working_snowflake.txt
     bridge/iran_likely_working_webtunnel.txt
```

**Normal censorship (فیلترینگ معمول):**
```
Use: bridge/iran_likely_working_all.txt   ← OONI-verified / TCP-tested working
     bridge/iran_likely_working_obfs4.txt ← obfs4 on port 443
```

---

## ✅ OONI-Verified / TCP-Tested Working Bridges (Iran)

| File | Bridges |
| :--- | :---: |
| {lnk_wk_all} | {cnt_wk_all} |
| {lnk_wk_obfs4} | {cnt_wk_obfs4} |
| {lnk_wk_wt} | {cnt_wk_wt} |
| {lnk_wk_sf} | {cnt_wk_sf} |

> Note: Files include OONI-confirmed bridges (Tier 1) and TCP-reachable
> bridges with no OONI data (Tier 2 fallback). WebTunnel bridges are nearly
> always Tier 2 because OONI measures by IP but WebTunnel uses HTTPS domains.

## 🌐 Globally Tested (TCP-reachable, Iran status varies)

| File | Bridges |
| :--- | :---: |
| {lnk_gl_obfs4} | {cnt_gl_obfs4} |
| {lnk_gl_wt} | {cnt_gl_wt} |
| {lnk_gl_va} | {cnt_gl_va} |

---

## 📊 Pipeline Summary

| Metric | Value |
| :--- | :--- |
| Total tested | `{total}` |
| Globally reachable | `{global_r}` |
| Iran likely working | `{iran_ok}` |
| Iran likely blocked | `{iran_bl}` |
| Iran ASN-blocked | `{iran_asn}` |

---

## 🔬 8-Layer Classification

1. **TCP reachability** — from GitHub Actions runner
2. **ASN filter** — exclude Iranian ISP ASNs (honeypot/false-positive guard)
3. **TLS fingerprint risk** — JA3 hash vs. known Iran DPI blocklist
4. **Port risk** — flag ports 9001/9030/9050
5. **OONI recent** — 7-day anomaly history from Iranian probes
6. **OONI temporal** — 90-day recurrence rate (> 2/month → `frequently_blocked`)
7. **CDN front validation** — WebTunnel front-domain ASN check
8. **RIPE Atlas** — optional one-off TCP measurement from IR probes

---

*Report: [docs/iran-bridge-status.md]({repo}/docs/iran-bridge-status.md)*
"""

    values = {
        "ts":         ts,
        "repo":       repo,
        "lnk_wk_all":   lnk("iran_likely_working_all.txt"),
        "cnt_wk_all":   cnt("iran_likely_working_all.txt"),
        "lnk_wk_obfs4": lnk("iran_likely_working_obfs4.txt"),
        "cnt_wk_obfs4": cnt("iran_likely_working_obfs4.txt"),
        "lnk_wk_wt":    lnk("iran_likely_working_webtunnel.txt"),
        "cnt_wk_wt":    cnt("iran_likely_working_webtunnel.txt"),
        "lnk_wk_sf":    lnk("iran_likely_working_snowflake.txt"),
        "cnt_wk_sf":    cnt("iran_likely_working_snowflake.txt"),
        "lnk_gl_obfs4": lnk("tested_global_obfs4.txt"),
        "cnt_gl_obfs4": cnt("tested_global_obfs4.txt"),
        "lnk_gl_wt":    lnk("tested_global_webtunnel.txt"),
        "cnt_gl_wt":    cnt("tested_global_webtunnel.txt"),
        "lnk_gl_va":    lnk("tested_global_vanilla.txt"),
        "cnt_gl_va":    cnt("tested_global_vanilla.txt"),
        "total":      summary.get("total_tested", 0),
        "global_r":   summary.get("global_reachable", 0),
        "iran_ok":    summary.get("iran_likely_working", 0),
        "iran_bl":    summary.get("iran_likely_blocked", 0),
        "iran_asn":   summary.get("iran_asn_blocked", 0),
    }

    Path("README.md").write_text(template.format_map(values), encoding="utf-8")
    log.info("README.md updated.")


# ─────────────────────────────────────────────────────────────────────────────
# Telegram delivery
# ─────────────────────────────────────────────────────────────────────────────

def _build_zip_bytes(path: Path) -> Optional[bytes]:
    """Compress a single file into a ZIP in memory and return the bytes."""
    if not path.exists():
        return None
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(str(path), path.name)
    return buf.getvalue()


def telegram_upload(stats: Dict[str, int], summary: Dict[str, Any]) -> None:
    if not (TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID):
        log.info("Telegram credentials not configured — skipping upload.")
        return

    ts   = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    wk   = stats.get("iran_likely_working_all.txt", 0)
    tot  = summary.get("total_tested", 0)
    ok   = summary.get("iran_likely_working", 0)

    caption = (
        f"*🛡️ TorShield-IR — Bridge Update*\n"
        f"_Updated: {ts}_\n\n"
        f"*✅ OONI/TCP-Verified (Iran):* `{ok}` bridges\n"
        f"*📦 in zip:* `{wk}` bridge lines\n"
        f"*🔬 Total tested:* `{tot}`\n\n"
        f"*Transport priority for Iran:*\n"
        f"Snowflake → WebTunnel → obfs4 (443) → meek-lite\n\n"
        f"_Paste lines from the ZIP into Tor Browser → Settings → Connection → Bridges_"
    )

    zip_bytes = _build_zip_bytes(BRIDGE_DIR / "iran_likely_working_all.txt")
    if not zip_bytes:
        log.warning("iran_likely_working_all.txt not found — sending text only.")
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage",
            json={"chat_id": TELEGRAM_CHAT_ID, "text": caption, "parse_mode": "Markdown"},
            timeout=30,
        )
        return

    r = requests.post(
        f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendDocument",
        data={
            "chat_id":    TELEGRAM_CHAT_ID,
            "caption":    caption[:1024],
            "parse_mode": "Markdown",
        },
        files={"document": ("iran_working_bridges.zip", zip_bytes, "application/zip")},
        timeout=120,
    )
    if r.status_code == 200:
        log.info("Telegram upload: success.")
    else:
        log.warning(f"Telegram upload HTTP {r.status_code}: {r.text[:200]}")


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    log.info("═══ Results Writer ══════════════════════════════════════════")

    iran_data = load_iran_results()
    bridges   = iran_data.get("bridges", [])
    summary   = iran_data.get("summary", {})

    log.info(f"Loaded {len(bridges)} bridges from iran_results.json.")

    stats = write_result_files(bridges)
    update_readme(iran_data, stats)

    if TELEGRAM_UPLOAD:
        telegram_upload(stats, summary)
    else:
        log.info("TELEGRAM_UPLOAD=false — skipping Telegram notification.")

    log.info("═══ Results Writer done ═════════════════════════════════════")


if __name__ == "__main__":
    main()
