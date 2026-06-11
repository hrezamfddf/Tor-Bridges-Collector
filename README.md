# TorShield-IR — Tor Bridges Intelligence System (نسل جدید)

[![TorShield-IR Bridge Intelligence](https://github.com/hrrjruruufgbbvhrh/Tor-Bridges-Collector-vip/actions/workflows/torshield-ir.yml/badge.svg)](https://github.com/hrrjruruufgbbvhrh/Tor-Bridges-Collector-vip/actions/workflows/torshield-ir.yml)

An automated, Iran-optimised Tor bridge collection, testing, and intelligence system that runs every hour on GitHub Actions. Zero manual steps required.

---

## نصب و راه‌اندازی — Quick Start

```bash
git clone https://github.com/hrrjruruufgbbvhrh/Tor-Bridges-Collector-vip.git
cd Tor-Bridges-Collector-vip

# Install Python dependencies
pip install -r requirements.txt

# Run the full pipeline locally
python main.py

# Detect local NIN (شبکه ملی) status
python main.py --detect-iran
```

**Go binaries (build locally):**
```bash
CGO_ENABLED=0 go build -o iran_tester     ./cmd/iran_tester/
CGO_ENABLED=0 go build -o probe_scheduler ./cmd/probe_scheduler/
```

**Rust bridge-probe:**
```bash
cd bridge-probe && cargo build --release
```

---

## پیش‌نیازها — Prerequisites

| Component | Version  | Purpose                                |
|-----------|----------|----------------------------------------|
| Go        | ≥ 1.22   | iran_tester, probe_scheduler           |
| Rust      | stable   | bridge-probe (PT handshake probing)    |
| Python    | ≥ 3.11   | Core pipeline, ML predictor, scrapers  |

```bash
# Python deps
pip install -r requirements.txt

# Go deps (none external — pure stdlib)
go mod tidy

# Rust deps
cd bridge-probe && cargo fetch
```

---

## معماری — Architecture

The pipeline runs as a 10-stage GitHub Actions workflow every hour:

```
Stage 1  scraper.py            — Collect bridges (MOAT API, BridgeDB, Telegram, static)
Stage 2  iran_tester (Go)      — 8-layer TCP/ASN/JA3/Port/OONI/Temporal/CDN/RIPE analysis
Stage 3  probe_scheduler (Go)  — RIPE Atlas measurement orchestration
Stage 4  bridge-probe (Rust)   — Pluggable-transport handshake probing
Stage 5  ooni_correlator.py    — OONI measurement correlation + anomaly detection
Stage 6  main.py               — Scoring + export (all formats)
Stage 7  ml_predictor.py       — AI RandomForest blocking predictor
Stage 8  adaptive_transport.py — Dynamic transport weight engine
Stage 8b dpi_evasion_advanced.py — DPI intelligence report
Stage 8c next_gen_transports.py  — Hysteria2 / REALITY / VLESS / SS-2022 detection
Stage 8d core/nin_selector.py    — شبکه ملی internet-cut bridge pack
Stage 8e quantum_safe.py         — ECH + post-quantum key exchange scoring  ← NEW
Stage 8f warp_bootstrap.py       — Cloudflare WARP bootstrap detection       ← NEW
Stage 9  results_writer.py    — Write categorised files + Telegram upload
Stage 10 git push             — Commit results to repository
```

---

## ویژگی‌ها — Advanced Features

### FEATURE 1 — AI ML Blocking Predictor
`ml_predictor.py` trains a RandomForest classifier on OONI data from Iranian probes to predict within-24h blocking probability. Score adjustment: `adjusted_score = composite × (1 − 0.25 × block_prob)`.

### FEATURE 2 — JA3/JA3S TLS Fingerprint Evasion
`ja3_intelligence.py` maintains a database of TLS ClientHello fingerprints confirmed as Tor-identifiable by Iran's SIAM. Bridges matching these hashes receive a 0–15 point penalty.

### FEATURE 3 — Iranian ASN Hard Exclusion + Honeypot Detection
`internal/asn/iran_asns.go` contains all Iranian ISP ASNs. Bridges resolving to these ASNs are classified `iran_asn_blocked`. Honeypot ASNs (TCI, ITC, TIC, MCI — all documented for TLS interception) trigger immediate exclusion.

### FEATURE 4 — Adaptive Transport Weight Engine
`adaptive_transport.py` dynamically recalculates transport scores each hour based on observed OONI success rates, so scoring adapts automatically as Iran shifts blocking strategy.

### FEATURE 5 — Temporal Quarantine (Rolling Z-Score)
`quarantine_manager.py` detects sudden blocking spikes using a 7-day rolling z-score (threshold 2σ). Flagged bridges enter quarantine until 3 consecutive clean days are observed.

### FEATURE 6 — NIN Internet-Cut Pack (شبکه ملی)
`core/nin_selector.py` builds `export/iran_cut_pack.txt` — bridges that survive a full national internet cut. Only Snowflake, WebTunnel (CDN-fronted), and meek-lite qualify.

### FEATURE 7 — Advanced Anti-DPI Intelligence
`dpi_evasion_advanced.py` classifies each transport into a DPI resistance tier (Maximum → Low) using data from OONI, Censored Planet, and Citizen Lab.

| Transport  | DPI Tier    | Iran Block Rate | Survives NIN |
|------------|-------------|-----------------|--------------|
| Snowflake  | Maximum     | ~2%             | ✓            |
| WebTunnel  | Very High   | ~5%             | ✓ (CDN)      |
| obfs4      | High        | ~15%            | ✗            |
| meek-lite  | High        | ~10%            | ✓ (Azure)    |
| Vanilla    | Low         | ~95%            | ✗            |

### FEATURE 8 — Next-Gen Protocol Detection
`next_gen_transports.py` detects Hysteria2, REALITY, VLESS+XTLS, and Shadowsocks 2022 — protocols not in Tor Browser but used as Tor front-ends in Iran.

### FEATURE 9 — ECH + Post-Quantum Scoring *(NEW)*
`quantum_safe.py` awards structural anti-DPI bonuses:
- **ECH (Encrypted Client Hello)** +0.12: hides the SNI from Iran's DPI, making CDN-fronting interference impossible without blocking all of Cloudflare/Fastly.
- **Post-quantum key exchange** (ML-KEM-768 / X25519Kyber768) +0.08: produces a ClientHello byte sequence not in SIAM's JA3 training data.
- Maximum combined bonus: **+0.20** to composite score.

### FEATURE 10 — Cloudflare WARP Bootstrap *(NEW)*
`warp_bootstrap.py` probes whether Cloudflare WARP (WireGuard/UDP 2408) is reachable. If it is, it recommends the **Tor-over-WARP** pattern:

```
User ──WARP (WireGuard)──► Cloudflare Edge ──Tor──► Tor bridge ──► Internet
```

Iran's DPI sees only Cloudflare WireGuard traffic — the Tor fingerprint is completely hidden. WARP has never been fully blocked in Iran due to CDN collateral damage. Install: [1.1.1.1 app](https://1.1.1.1).

---

## فایل‌های خروجی — Output Files

| File                              | Description                                    |
|-----------------------------------|------------------------------------------------|
| `export/iran_pack.txt`            | Top-scored bridges for Iran                    |
| `export/iran_cut_pack.txt`        | Bridges for NIN internet-cut mode              |
| `export/warp_bridges.txt`         | Tor-over-WARP recommended bridges              |
| `bridge/iran_results.json`        | Full 8-layer classification report             |
| `data/quantum_safe_report.json`   | ECH + PQ bridge scoring report                 |
| `data/warp_status.json`           | WARP reachability status                       |
| `data/dpi_intelligence.json`      | DPI resistance intelligence report             |
| `data/next_gen_bridges.json`      | Hysteria2/REALITY/VLESS/SS-2022 bridges        |
| `data/best_transports.json`       | Current transport rankings                     |
| `data/blocking_model.pkl`         | Serialised AI blocking predictor               |

---

## اختیاری — Optional Secrets (GitHub Repository Secrets)

| Secret                | Purpose                                          |
|-----------------------|--------------------------------------------------|
| `TELEGRAM_BOT_TOKEN`  | Upload bridge packs to a Telegram channel        |
| `TELEGRAM_CHAT_ID`    | Target Telegram channel ID                       |
| `RIPE_ATLAS_API_KEY`  | Enable RIPE Atlas measurements from Iranian probes |

Without these secrets the system runs in OONI-only mode — fully functional.

---

## در زمان قطع اینترنت — During Internet Cuts (شبکه ملی فعال)

1. **Check WARP first**: open the 1.1.1.1 app → enable WARP.
2. **Then open Tor Browser**: use bridges from `export/iran_cut_pack.txt`.
3. **Priority order**: Snowflake → WebTunnel (CDN) → meek-lite (Azure).
4. Avoid obfs4 and vanilla bridges during a cut — their IPs are unreachable.

