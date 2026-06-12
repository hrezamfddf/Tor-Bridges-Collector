"""
core/censorship_monitor.py — Iran Censorship Level Monitor
═══════════════════════════════════════════════════════════
Real-time detection of Iran's current censorship intensity on a 5-level scale.

LEVEL DEFINITIONS
─────────────────
  Level 1 – Minimal      DNS-level blocking only (HTTP sites, basic)
  Level 2 – Standard     SNI inspection + social media blocked
  Level 3 – Elevated     VPN / direct Tor blocked; obfs4 partially ok
  Level 4 – DPI Active   AI/ML traffic analysis; obfs4 degraded
  Level 5 – NIN/Shutdown International cut; only CDN-fronted tunnels survive

DETECTION METHOD
────────────────
  Concurrent async probes to category-specific endpoints:
    • Category A  — basic international DNS (fails at L5)
    • Category B  — HTTPS to CDN endpoints (fails at L5 partial)
    • Category C  — obfs4-pattern traffic probe (fails at L4)
    • Category D  — Tor directory authority probes (fail at L3+)
    • Category E  — NIN domestic endpoints (only reachable at L5)
    • Category F  — OONI HTTPS measurement targets

  Result matrix → censorship level via decision tree.

OUTPUTS
───────
  CensorshipState dataclass  (level, confidence, isp_tier, recommendations)
  data/censorship_state.json  (written on each run for downstream consumers)
"""

from __future__ import annotations

import asyncio
import json
import logging
import socket
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

log = logging.getLogger(__name__)

DATA_DIR = Path("data")
DATA_DIR.mkdir(parents=True, exist_ok=True)
STATE_FILE = DATA_DIR / "censorship_state.json"

# ── Probe categories ─────────────────────────────────────────────────────────

# Category A: basic international DNS — fail means full cut (L5)
_CAT_A: List[Tuple[str, int]] = [
    ("1.1.1.1",        53),
    ("8.8.8.8",        53),
    ("208.67.222.222", 53),
    ("9.9.9.9",        53),
]

# Category B: international HTTPS CDN — partial failure suggests L4
_CAT_B: List[Tuple[str, int]] = [
    ("104.16.132.229", 443),   # Cloudflare CDN
    ("151.101.1.140",  443),   # Fastly
    ("99.86.0.1",      443),   # Amazon CloudFront
    ("142.250.74.110", 443),   # Google GCP
]

# Category C: Tor directory authorities — fail at L3+
_CAT_C: List[Tuple[str, int]] = [
    ("128.31.0.39",   9101),   # moria1
    ("86.59.21.38",   443),    # tor26
    ("194.109.206.212", 443),  # dizum
    ("131.188.40.189", 443),   # gabelmoo
]

# Category D: known obfs4 bridge IPs on common ports — fail at L4
_CAT_D: List[Tuple[str, int]] = [
    ("38.229.1.78",  443),
    ("192.95.36.142", 443),
    ("85.31.186.98",  443),
]

# Category E: Iran domestic / NIN endpoints — only reachable during cuts
_CAT_E: List[Tuple[str, int]] = [
    ("10.10.34.34",    80),    # IRCERT portal
    ("185.51.200.2",   80),    # NIN DNS
    ("5.200.203.1",    80),    # IRNIC
]

# Category F: OONI measurement targets
_CAT_F: List[Tuple[str, int]] = [
    ("93.184.216.34",  443),   # example.com (OONI probe)
    ("204.79.197.200", 443),   # Bing
    ("31.13.65.36",    443),   # Facebook CDN
]

_PROBE_TIMEOUT = 3.0
_FAST_TIMEOUT  = 2.0

# ── ISP tier detection ────────────────────────────────────────────────────────
# Iran has multiple ISPs with different blocking aggressiveness.
# We can partially infer ISP from route latency to domestic endpoints.

ISP_TIERS: Dict[str, Dict] = {
    "mci":       {"name": "MCI / همراه اول",   "dpi_level": 4, "nin_cuts": True},
    "irancell":  {"name": "IranCell / ایرانسل", "dpi_level": 3, "nin_cuts": True},
    "rightel":   {"name": "Rightel / رایتل",    "dpi_level": 3, "nin_cuts": True},
    "shatel":    {"name": "Shatel / شاتل",      "dpi_level": 2, "nin_cuts": False},
    "asiatech":  {"name": "Asiatech / آسیاتک",  "dpi_level": 2, "nin_cuts": False},
    "unknown":   {"name": "Unknown ISP",         "dpi_level": 3, "nin_cuts": True},
}

# ── Bridge recommendations per level ─────────────────────────────────────────

LEVEL_RECOMMENDATIONS: Dict[int, Dict] = {
    1: {
        "label":       "Minimal Filtering",
        "description": "Only basic DNS/HTTP blocking. Direct Tor may work.",
        "best_transports": ["vanilla", "obfs4", "webtunnel"],
        "avoid":           [],
        "pack_file":       "export/iran_pack.txt",
        "urgency":         "low",
    },
    2: {
        "label":       "Standard SNI Filtering",
        "description": "Social media and news blocked via SNI. Use obfs4.",
        "best_transports": ["obfs4", "webtunnel", "snowflake"],
        "avoid":           ["vanilla"],
        "pack_file":       "export/iran_pack.txt",
        "urgency":         "medium",
    },
    3: {
        "label":       "Elevated — Tor Blocked",
        "description": "Direct Tor and most VPNs blocked. Need PT.",
        "best_transports": ["obfs4", "webtunnel", "meek_lite"],
        "avoid":           ["vanilla", "direct"],
        "pack_file":       "export/iran_pack.txt",
        "urgency":         "medium",
    },
    4: {
        "label":       "DPI Active — AI Analysis",
        "description": "ML-based traffic analysis. Only high-entropy transports.",
        "best_transports": ["snowflake", "webtunnel", "meek_lite"],
        "avoid":           ["vanilla", "obfs4-port-not-443"],
        "pack_file":       "export/iran_nin_pack.txt",
        "urgency":         "high",
    },
    5: {
        "label":       "NIN Active — Internet Cut",
        "description": "شبکه ملی فعال. International cut. CDN-fronted only.",
        "best_transports": ["snowflake", "webtunnel-cdn"],
        "avoid":           ["vanilla", "obfs4", "meek_lite-non-cdn"],
        "pack_file":       "export/iran_nin_pack.txt",
        "urgency":         "critical",
    },
}


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class ProbeResult:
    category:    str
    target:      str
    port:        int
    reachable:   bool
    latency_ms:  float


@dataclass
class CensorshipState:
    level:            int              = 3      # 1–5
    confidence:       float            = 0.5    # 0–1
    international_ok: bool             = True
    nin_active:       bool             = False
    tor_direct_ok:    bool             = False
    isp_tier:         str              = "unknown"
    detected_at:      str              = ""
    probe_summary:    Dict             = field(default_factory=dict)
    recommendations:  Dict             = field(default_factory=dict)
    best_pack:        str              = "export/iran_pack.txt"

    def to_dict(self) -> Dict:
        return asdict(self)

    def log_summary(self) -> None:
        log.info(
            f"[CensorshipMonitor] Level {self.level} — "
            f"{LEVEL_RECOMMENDATIONS[self.level]['label']} "
            f"(confidence={self.confidence:.0%})"
        )
        recs = LEVEL_RECOMMENDATIONS[self.level]
        log.info(
            f"  → Best transports: {recs['best_transports']} | "
            f"Pack: {recs['pack_file']} | Urgency: {recs['urgency']}"
        )


# ── Async probing ─────────────────────────────────────────────────────────────

async def _probe_tcp(host: str, port: int, timeout: float = _PROBE_TIMEOUT) -> Tuple[bool, float]:
    t0 = asyncio.get_event_loop().time()
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
        except Exception:
            pass
        return True, (asyncio.get_event_loop().time() - t0) * 1000
    except Exception:
        return False, (asyncio.get_event_loop().time() - t0) * 1000


async def _probe_category(
    category: str,
    targets:  List[Tuple[str, int]],
    timeout:  float = _PROBE_TIMEOUT,
) -> Tuple[int, int, List[ProbeResult]]:
    """Probe a category. Returns (reachable_count, total, results)."""
    tasks = [_probe_tcp(h, p, timeout) for h, p in targets]
    outcomes = await asyncio.gather(*tasks)
    results = [
        ProbeResult(category, h, p, ok, lat)
        for (h, p), (ok, lat) in zip(targets, outcomes)
    ]
    ok_count = sum(1 for r in results if r.reachable)
    return ok_count, len(results), results


# ── Decision tree ─────────────────────────────────────────────────────────────

def _decide_level(
    a_ok: int, a_tot: int,
    b_ok: int, b_tot: int,
    c_ok: int, c_tot: int,
    d_ok: int, d_tot: int,
    e_ok: int, e_tot: int,
    f_ok: int, f_tot: int,
) -> Tuple[int, float]:
    """
    Decision tree mapping probe results → censorship level + confidence.

    Rules (evaluated top-to-bottom, first match wins):
      A fraction = basic international reachability
      C fraction = Tor DA reachability
      D fraction = obfs4 port reachability
      E fraction = NIN domestic reachability (only meaningful when A fails)
    """
    a_frac = a_ok / max(a_tot, 1)
    b_frac = b_ok / max(b_tot, 1)
    c_frac = c_ok / max(c_tot, 1)
    d_frac = d_ok / max(d_tot, 1)
    e_frac = e_ok / max(e_tot, 1)

    # Level 5: NIN active — A completely fails, E partially works
    if a_frac <= 0.0 and e_frac >= 0.3:
        conf = 0.50 + e_frac * 0.3 + (1 - b_frac) * 0.2
        return 5, min(1.0, conf)

    # Level 5 fallback: both A and B completely fail
    if a_frac <= 0.0 and b_frac <= 0.0:
        return 5, 0.75

    # Level 4: A/B partially works but C and D completely fail
    if a_frac >= 0.25 and c_frac <= 0.0 and d_frac <= 0.0:
        conf = 0.55 + (1 - c_frac) * 0.2 + (1 - d_frac) * 0.15
        return 4, min(1.0, conf)

    # Level 4 strong signal: A works but both C and D fail
    if a_frac >= 0.5 and c_frac == 0 and d_frac <= 0.25:
        return 4, 0.80

    # Level 3: A/B works but Tor DAs (C) are blocked
    if a_frac >= 0.5 and c_frac <= 0.25:
        conf = 0.50 + (1 - c_frac) * 0.25 + a_frac * 0.15
        return 3, min(1.0, conf)

    # Level 2: A/B/C work but some filtering visible (F partial failures)
    if a_frac >= 0.75 and c_frac >= 0.25:
        f_frac = f_ok / max(f_tot, 1)
        if f_frac <= 0.5:
            return 2, 0.65
        if f_frac <= 0.75:
            return 2, 0.55

    # Level 1: Everything works normally
    if a_frac >= 0.75 and b_frac >= 0.5 and c_frac >= 0.5:
        return 1, 0.80

    # Default: standard filtering
    return 3, 0.45


# ── Main entry point ──────────────────────────────────────────────────────────

async def measure_censorship_level(
    write_state: bool = True,
) -> CensorshipState:
    """
    Run all probe categories concurrently and return a CensorshipState.

    Args:
        write_state: If True, write result to data/censorship_state.json.

    Returns:
        CensorshipState with level 1–5, confidence, and recommendations.
    """
    log.info("[CensorshipMonitor] Starting probe run …")

    # Run all categories in parallel
    (
        (a_ok, a_tot, a_res),
        (b_ok, b_tot, b_res),
        (c_ok, c_tot, c_res),
        (d_ok, d_tot, d_res),
        (e_ok, e_tot, e_res),
        (f_ok, f_tot, f_res),
    ) = await asyncio.gather(
        _probe_category("dns_intl",    _CAT_A, _FAST_TIMEOUT),
        _probe_category("cdn_https",   _CAT_B, _PROBE_TIMEOUT),
        _probe_category("tor_da",      _CAT_C, _PROBE_TIMEOUT),
        _probe_category("obfs4_port",  _CAT_D, _PROBE_TIMEOUT),
        _probe_category("nin_domestic",_CAT_E, _PROBE_TIMEOUT),
        _probe_category("ooni_https",  _CAT_F, _PROBE_TIMEOUT),
    )

    level, confidence = _decide_level(
        a_ok, a_tot, b_ok, b_tot,
        c_ok, c_tot, d_ok, d_tot,
        e_ok, e_tot, f_ok, f_tot,
    )

    recs   = LEVEL_RECOMMENDATIONS[level]
    state  = CensorshipState(
        level            = level,
        confidence       = round(confidence, 3),
        international_ok = a_ok > 0,
        nin_active       = (level == 5),
        tor_direct_ok    = (c_ok > 0),
        isp_tier         = "unknown",
        detected_at      = datetime.now(tz=timezone.utc).isoformat(),
        probe_summary    = {
            "dns_intl":     f"{a_ok}/{a_tot}",
            "cdn_https":    f"{b_ok}/{b_tot}",
            "tor_da":       f"{c_ok}/{c_tot}",
            "obfs4_port":   f"{d_ok}/{d_tot}",
            "nin_domestic": f"{e_ok}/{e_tot}",
            "ooni_https":   f"{f_ok}/{f_tot}",
        },
        recommendations  = recs,
        best_pack        = recs["pack_file"],
    )

    state.log_summary()

    if write_state:
        STATE_FILE.write_text(
            json.dumps(state.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        log.info(f"[CensorshipMonitor] State saved → {STATE_FILE}")

    return state


def get_last_state() -> Optional[CensorshipState]:
    """Load the last saved state from disk (without network probes)."""
    if not STATE_FILE.exists():
        return None
    try:
        d = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        return CensorshipState(**d)
    except Exception as exc:
        log.warning(f"[CensorshipMonitor] Cannot load state: {exc}")
        return None


def run_sync(write_state: bool = True) -> CensorshipState:
    """Synchronous wrapper for measure_censorship_level()."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # Already inside an event loop (e.g., Jupyter) — use new loop
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(1) as ex:
                fut = ex.submit(asyncio.run, measure_censorship_level(write_state))
                return fut.result()
        return loop.run_until_complete(measure_censorship_level(write_state))
    except RuntimeError:
        return asyncio.run(measure_censorship_level(write_state))


# ── Recommendation helper ─────────────────────────────────────────────────────

def best_transports_for_level(level: int) -> List[str]:
    return LEVEL_RECOMMENDATIONS.get(level, LEVEL_RECOMMENDATIONS[3])["best_transports"]


def should_use_nin_pack(level: int) -> bool:
    return level >= 4


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)-8s %(message)s",
    )
    state = run_sync()
    print(json.dumps(state.to_dict(), indent=2, ensure_ascii=False))
    sys.exit(0 if state.level <= 4 else 1)
