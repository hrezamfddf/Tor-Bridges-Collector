#!/usr/bin/env python3
"""
iran_anti_siam.py — Iran SIAM/NGFW Anti-AI DPI Full Analysis Pipeline

Runs the 8-layer Iran SIAM evasion scoring engine against all known bridges
and produces ranked output files for users inside Iran.

Inputs  (in order of preference):
  bridge/bridge_list_for_testing.json  (all collected bridges)
  bridge/iran_results.json             (Go tester output with OONI data)
  bridge/*.txt                         (flat bridge files as fallback)

Outputs:
  data/iran_siam_report.json           Full per-bridge SIAM analysis
  export/iran_phantom_bridges.txt      PHANTOM tier: fully undetectable
  export/iran_stealth_bridges.txt      STEALTH tier: strong evasion
  docs/iran-siam-analysis.md           Human-readable Farsi/English report

GitHub Actions stage: Stage 8r
"""

from __future__ import annotations

import json
import logging
import os
import statistics
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)-8s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────────────
# Input loaders
# ─────────────────────────────────────────────────────────────────────────────

def _load_bridges_json(path: Path) -> list[str]:
    """Load bridge lines from a JSON array file."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return [str(b) for b in data if b]
        if isinstance(data, dict):
            # iran_results.json format: {"bridges": [{...}, ...]}
            bridges = data.get("bridges", [])
            return [b.get("line", "") for b in bridges if b.get("line")]
    except Exception as exc:
        log.warning("Failed to load %s: %s", path, exc)
    return []


def _load_bridges_txt(bridge_dir: Path) -> list[str]:
    """Fallback: load from .txt bridge files."""
    lines: list[str] = []
    for txt in bridge_dir.glob("*.txt"):
        if txt.name.startswith("iran_blocked"):
            continue
        try:
            for line in txt.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    lines.append(line)
        except Exception:
            pass
    return list(dict.fromkeys(lines))  # dedup, preserve order


def _load_ja3_map() -> dict[str, str]:
    """Load JA3 hash map if available from ja3_intelligence.py output."""
    ja3_path = Path("data/ja3_rotation_report.md")
    # Also try the JSON report
    j_path = Path("data/ja3_rotation_plan.json")
    if j_path.exists():
        try:
            data = json.loads(j_path.read_text(encoding="utf-8"))
            if isinstance(data, dict) and "bridge_ja3_map" in data:
                return data["bridge_ja3_map"]
        except Exception:
            pass
    return {}


def load_bridges() -> list[str]:
    """Load bridge lines from best available source."""
    bridge_dir = Path("bridge")

    # Prefer bridge_list_for_testing.json (all collected bridges)
    test_json = bridge_dir / "bridge_list_for_testing.json"
    if test_json.exists():
        lines = _load_bridges_json(test_json)
        if lines:
            log.info("Loaded %d bridges from bridge_list_for_testing.json", len(lines))
            return lines

    # Fall back to iran_results.json (already filtered by Go tester)
    iran_json = bridge_dir / "iran_results.json"
    if iran_json.exists():
        lines = _load_bridges_json(iran_json)
        if lines:
            log.info("Loaded %d bridges from iran_results.json", len(lines))
            return lines

    # Last resort: .txt files
    lines = _load_bridges_txt(bridge_dir)
    if lines:
        log.info("Loaded %d bridges from .txt files (fallback)", len(lines))
        return lines

    log.warning("No bridge sources found — nothing to analyze")
    return []


# ─────────────────────────────────────────────────────────────────────────────
# Markdown report generator
# ─────────────────────────────────────────────────────────────────────────────

def _build_md_report(
    results: list,
    tier_counts: dict[str, int],
    transport_counts: dict[str, int],
    ts: str,
) -> str:
    """Build a Farsi/English SIAM analysis markdown report."""
    total = len(results)
    phantom_n  = tier_counts.get("PHANTOM",  0)
    stealth_n  = tier_counts.get("STEALTH",  0)
    covert_n   = tier_counts.get("COVERT",   0)
    exposed_n  = tier_counts.get("EXPOSED",  0)
    detected_n = tier_counts.get("DETECTED", 0)

    scores = [r.iran_siam_score for r in results]
    mean_s = statistics.mean(scores) if scores else 0.0
    best_s = max(scores) if scores else 0.0

    lines = [
        "# 🛡️ گزارش تحلیل SIAM ایران / Iran SIAM DPI Analysis",
        "",
        f"> آخرین بروزرسانی: `{ts}`  ",
        f"> کل پل‌های تحلیل‌شده: **{total}**  ",
        f"> میانگین امتیاز دور زدن: **{mean_s:.1%}**  ",
        f"> بهترین امتیاز: **{best_s:.1%}**",
        "",
        "---",
        "",
        "## 📊 خلاصه لایه‌بندی SIAM / SIAM Bypass Tier Summary",
        "",
        "| سطح / Tier | تعداد / Count | توضیح / Description |",
        "| :--- | :---: | :--- |",
        f"| 👻 PHANTOM  | {phantom_n}  | کاملاً ناشناس — سیستم SIAM هیچ سیگنالی دریافت نمی‌کند |",
        f"| 🕶️ STEALTH  | {stealth_n}  | قوی — از ۶-۷ لایه از ۸ لایه عبور می‌کند |",
        f"| 🥷 COVERT   | {covert_n}   | متوسط — از ۴-۵ لایه عبور می‌کند |",
        f"| ⚠️ EXPOSED  | {exposed_n}  | ضعیف — اکثر لایه‌های SIAM تشخیص می‌دهند |",
        f"| 🚫 DETECTED | {detected_n} | بلاک می‌شود — SIAM تشخیص کامل می‌دهد |",
        "",
        "---",
        "",
        "## 🔬 ۸ لایه سیستم SIAM ایران / 8 Layers of Iran SIAM DPI",
        "",
        "| لایه | نام | توضیح |",
        "| :--- | :--- | :--- |",
        "| L1 | Packet Length Fingerprinting | CNN تحلیل هیستوگرام اندازه بسته‌ها |",
        "| L2 | IAT Timing Analysis | LSTM تحلیل فواصل زمانی بین بسته‌ها |",
        "| L3 | Flow Feature Extraction | NetFlow + گشتاورهای آماری |",
        "| L4 | JA3/JA3S Fingerprint | پایگاه داده ۵۰k اثر انگشت TLS |",
        "| L5 | Certificate + SNI | تطبیق گواهی و SNI با پایگاه داده رله Tor |",
        "| L6 | ALPN Anomaly | تشخیص ALPN نامعمول روی پورت ۴۴۳ |",
        "| L7 | Temporal Analysis | تشخیص ضربان ۱ ثانیه‌ای Tor vanilla |",
        "| L8 | AS Relationship Graph | ارتباط ASN رله با شبکه‌های CDN |",
        "",
        "---",
        "",
        "## 🚀 راهنمای انتخاب پل / Bridge Selection Guide",
        "",
        "```",
        "شبکه ملی فعال (NIN / قطع اینترنت بین‌المللی):",
        "  → export/iran_phantom_bridges.txt  (Snowflake + WebTunnel CDN)",
        "",
        "فیلترینگ معمولی SIAM:",
        "  → export/iran_stealth_bridges.txt  (obfs4 IAT-2 + meek-lite)",
        "",
        "هر شرایطی / Any condition:",
        "  → bridge/iran_likely_working_all.txt",
        "```",
        "",
        "---",
        "",
        "## 📈 توزیع transport / Transport Distribution",
        "",
        "| Transport | تعداد |",
        "| :--- | :---: |",
    ]

    for t, c in sorted(transport_counts.items(), key=lambda x: -x[1]):
        lines.append(f"| {t} | {c} |")

    lines += [
        "",
        "---",
        "",
        "*تولید شده توسط iran_anti_siam.py — TorShield-IR*",
    ]
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────────────────
# Main pipeline
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    from core.iran_dpi_shaper import score_all, get_phantom_stealth, BypassTier

    log.info("═══ Iran SIAM Anti-AI DPI Analysis ══════════════════════════")

    # Ensure output dirs
    Path("data").mkdir(exist_ok=True)
    Path("export").mkdir(exist_ok=True)
    Path("docs").mkdir(exist_ok=True)

    bridge_lines = load_bridges()
    if not bridge_lines:
        log.warning("No bridges to score — writing empty outputs and exiting.")
        Path("data/iran_siam_report.json").write_text(
            json.dumps({"scored": 0, "results": []}, indent=2), encoding="utf-8"
        )
        return

    ja3_map = _load_ja3_map()
    log.info("Scoring %d bridges against Iran SIAM 8-layer DPI…", len(bridge_lines))

    results = score_all(bridge_lines, ja3_map=ja3_map)
    log.info("SIAM scoring complete: %d results", len(results))

    # Count tiers and transports
    tier_counts: dict[str, int] = {}
    transport_counts: dict[str, int] = {}
    for r in results:
        tier_counts[r.bypass_tier] = tier_counts.get(r.bypass_tier, 0) + 1
        transport_counts[r.transport] = transport_counts.get(r.transport, 0) + 1

    # Log summary
    for tier in [BypassTier.PHANTOM, BypassTier.STEALTH, BypassTier.COVERT,
                 BypassTier.EXPOSED, BypassTier.DETECTED]:
        log.info("  %-9s : %d", tier, tier_counts.get(tier, 0))

    # Write full JSON report
    ts = datetime.now(tz=timezone.utc).isoformat()
    report: dict[str, Any] = {
        "generated_at": ts,
        "total_scored": len(results),
        "tier_summary": tier_counts,
        "transport_summary": transport_counts,
        "results": [r.to_dict() for r in results],
    }
    out_json = Path("data/iran_siam_report.json")
    out_json.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    log.info("Report → %s", out_json)

    # Write PHANTOM export
    phantom_lines = [
        r.bridge_line for r in results
        if r.bypass_tier == BypassTier.PHANTOM
    ]
    if phantom_lines:
        p_path = Path("export/iran_phantom_bridges.txt")
        p_path.write_text("\n".join(phantom_lines) + "\n", encoding="utf-8")
        log.info("%d PHANTOM bridges → %s", len(phantom_lines), p_path)

    # Write STEALTH export
    stealth_lines = [
        r.bridge_line for r in results
        if r.bypass_tier == BypassTier.STEALTH
    ]
    if stealth_lines:
        s_path = Path("export/iran_stealth_bridges.txt")
        s_path.write_text("\n".join(stealth_lines) + "\n", encoding="utf-8")
        log.info("%d STEALTH bridges → %s", len(stealth_lines), s_path)

    # Write combined best (PHANTOM + STEALTH)
    best_lines = phantom_lines + stealth_lines
    if best_lines:
        b_path = Path("export/iran_siam_best_bridges.txt")
        b_path.write_text("\n".join(best_lines) + "\n", encoding="utf-8")
        log.info("%d best bridges (PHANTOM+STEALTH) → %s", len(best_lines), b_path)

    # Write markdown report
    ts_human = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    md = _build_md_report(results, tier_counts, transport_counts, ts_human)
    md_path = Path("docs/iran-siam-analysis.md")
    md_path.write_text(md, encoding="utf-8")
    log.info("Markdown report → %s", md_path)

    log.info("═══ Iran SIAM Analysis done ══════════════════════════════════")


if __name__ == "__main__":
    main()
