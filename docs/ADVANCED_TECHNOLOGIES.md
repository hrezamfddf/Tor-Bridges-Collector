# Advanced Technologies Guide — TorShield-IR

## Bugs Fixed in This Release

| File | Error | Fix |
|------|-------|-----|
| `cmd/probe_scheduler/main.go:115` | `req declared and not used` | Removed duplicate request creation; uses `strings.NewReader` directly |
| `cmd/iran_tester/main.go:23` | `"fmt" imported and not used` | Removed unused `"fmt"` import |
| `bridge-probe/Cargo.toml` | `edition2024` requires Cargo ≥ 1.80 | Pinned `clap` to `"4.5"` which uses edition 2021 |

---

## New Features Added

### FEATURE 6 — NIN Bridge Selector (`core/nin_selector.py`)

When Iran activates the National Information Network (شبکه ملی / NIN) and cuts
international internet connectivity, most bridges become unreachable. This module:

- Identifies bridges that survive an internet cut via CDN routing
- Exports `export/iran_cut_pack.txt` — a dedicated pack for this scenario
- Exposes `rescore_for_nin()` for the scoring engine
- Priority order: Snowflake → WebTunnel (CDN-fronted) → meek-lite (Azure)

### FEATURE 7 — DPI Intelligence (`dpi_evasion_advanced.py`)

Provides per-transport DPI resistance scoring based on published OONI data,
Censored Planet measurements, and Tor Project pluggable transport research:

- `dpi_score(record)` — composite DPI resistance score [0.0, 1.0]
- `dpi_resistance_tier(transport)` — `maximum | very_high | high | medium | low`
- `update_dpi_report(records)` — generates `data/dpi_intelligence.json`

### FEATURE 8 — Next-Generation Protocol Detection (`next_gen_transports.py`)

Detects and scores bridge lines using protocols not yet in Tor Browser but
with superior DPI resistance for Iran:

| Protocol | DPI Tier | Mechanism |
|----------|----------|-----------|
| REALITY | Maximum | TLS server mimicry — indistinguishable from real HTTPS |
| Hysteria2 | Maximum | QUIC/UDP MASQ — identical to HTTPS/3 |
| VLESS+XTLS | Maximum | TLS passthrough, Chrome fingerprint |
| TUIC v5 | Maximum | QUIC-based, 0-RTT |
| Shadowsocks 2022 | Very High | AEAD-2022 with replay protection |

---

## Technologies Recommended for Next Generation

The following are technologies that most existing Tor bridge projects do not have
but which would add significant value for Iran:

### 1. Hysteria2 (QUIC/UDP)
Hysteria2 routes traffic over QUIC (HTTP/3), making it identical to Chrome's
browser traffic. Iran cannot block QUIC wholesale without breaking all HTTPS/3
which would catastrophically impact domestic banking and cloud services.

**Integration:** Parse `hysteria2://` URIs, probe via UDP QUIC handshake,
score and export separately. Can serve as a Tor front-end.

### 2. REALITY Protocol (TLS Mimicry)
REALITY (part of XTLS/Xray) makes the server present a valid TLS handshake
for a real target domain. DPI sees what appears to be legitimate HTTPS traffic
to, e.g., `www.microsoft.com`. No statistical signatures detectable.

**Integration:** Detect `security=reality` or `xtls-rprx-reality` in bridge lines.
Score with a maximum DPI resistance bonus.

### 3. VLESS + XTLS Vision
Sends inner TLS records inside outer TLS at the record layer, presenting a
Chrome-compatible TLS 1.3 fingerprint at the outer layer.

### 4. Zig Language (Low-Level Network Probing)
Zig would allow packet-level QUIC handshake probing and precise timing
measurement without the overhead of Go or Rust async runtimes. Particularly
useful for detecting Hysteria2 bridges.

### 5. WebAssembly (WASM) Front-end
A WASM-compiled bridge tester deployable in a browser — no installation required,
harder to block than a native binary.

### 6. Post-Quantum TLS (X25519Kyber768)
Bridges using the hybrid X25519/Kyber768 key exchange are future-proof against
quantum attacks on session keys. Detection: TLS ClientHello with `0x6399` group.

---

## Installation Requirements

```bash
# Python
pip install -r requirements.txt   # includes aioquic, cryptography

# Go 1.22+
CGO_ENABLED=0 go build -o iran_tester ./cmd/iran_tester/
CGO_ENABLED=0 go build -o probe_scheduler ./cmd/probe_scheduler/

# Rust (Cargo 1.78+ for clap 4.5, no edition2024 required)
cd bridge-probe && cargo build --release

# Optional: obfs4proxy for PT handshake probing
sudo apt install obfs4proxy
```

## Pipeline Order (Updated)

```
python scraper.py
./iran_tester --input bridge/bridge_list_for_testing.json --output bridge/iran_results.json
./probe_scheduler --bridges data/iran_bridges.json
cat bridge/bridge_list_for_testing.json | ./bridge-probe/target/release/bridge-probe > data/pt_results.json
python ooni_correlator.py
python dpi_evasion_advanced.py              # NEW: DPI intelligence report
python next_gen_transports.py               # NEW: Scan for Hysteria2/REALITY
python -m core.nin_selector                 # NEW: Build internet-cut pack
python main.py --mode score --mode export
python ml_predictor.py --train --apply
python adaptive_transport.py
python results_writer.py
```
