#!/usr/bin/env bash
# generate_quantum_project.sh
# TorShield-IR v6.0 — Automated Project Assembly Script
# Assembles the complete Tor-Bridges-Collector-Ultra-Vip-v2-quantum project
# from source and produces a verified tar.gz archive.
#
# Usage:  bash generate_quantum_project.sh
# Prereq: Run from the Tor-Bridges-Collector-Ultra-Vip-v2 project root
#         (the directory that contains ai_dpi_mutator.py, go.mod, etc.)
#
# Output: ../Tor-Bridges-Collector-Ultra-Vip-v2-quantum.tar.gz
#         SHA-256 checksum printed to stdout.

set -euo pipefail

# ── Config ───────────────────────────────────────────────────────────────────
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST_NAME="Tor-Bridges-Collector-Ultra-Vip-v2-quantum"
PARENT_DIR="$(dirname "$SRC_DIR")"
DEST_DIR="$PARENT_DIR/$DEST_NAME"
ARCHIVE="$PARENT_DIR/${DEST_NAME}.tar.gz"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

info "TorShield-IR v6.0 — Quantum Project Assembler"
info "Source : $SRC_DIR"
info "Target : $DEST_DIR"
info "Archive: $ARCHIVE"
echo ""

# ── Step 1: Clean target directory ───────────────────────────────────────────
if [[ -d "$DEST_DIR" ]]; then
  warn "Target directory exists — removing: $DEST_DIR"
  rm -rf "$DEST_DIR"
fi

# ── Step 2: Create directory structure ───────────────────────────────────────
info "Creating directory structure…"
mkdir -p \
  "$DEST_DIR/cmd/iran_tester" \
  "$DEST_DIR/cmd/probe_scheduler" \
  "$DEST_DIR/bridge-probe/src" \
  "$DEST_DIR/scripts" \
  "$DEST_DIR/sources" \
  "$DEST_DIR/quantum-core" \
  "$DEST_DIR/.github/workflows" \
  "$DEST_DIR/export" \
  "$DEST_DIR/data" \
  "$DEST_DIR/docs" \
  "$DEST_DIR/core" \
  "$DEST_DIR/internal/asn" \
  "$DEST_DIR/internal/ooni" \
  "$DEST_DIR/internal/ipinfo" \
  "$DEST_DIR/internal/ripe" \
  "$DEST_DIR/internal/bridge" \
  "$DEST_DIR/bridge"

# ── Step 3: Copy all source files ────────────────────────────────────────────
info "Copying source files…"

# Python scripts (root level)
PYTHON_SCRIPTS=(
  "ai_dpi_mutator.py"
  "adaptive_transport.py"
  "anti_ai_dpi.py"
  "config.py"
  "dpi_evasion_advanced.py"
  "ebpf_blueprint.py"
  "ech_fingerprint_evasion.py"
  "iran_nin_bypass.py"
  "ja3_intelligence.py"
  "main.py"
  "ml_predictor.py"
  "next_gen_transports.py"
  "nin_advanced_bypass.py"
  "nin_cut_tester.py"
  "nin_internet_cut_classifier.py"
  "onionhop_collector.py"
  "ooni_correlator.py"
  "quantum_safe.py"
  "quarantine_manager.py"
  "results_writer.py"
  "scraper.py"
  "warp_bootstrap.py"
  "ztunnel_ct_monitor.py"
  "generate_quantum_project.sh"
)

for f in "${PYTHON_SCRIPTS[@]}"; do
  if [[ -f "$SRC_DIR/$f" ]]; then
    cp "$SRC_DIR/$f" "$DEST_DIR/$f"
    info "  Copied: $f"
  else
    warn "  Missing: $f (will create stub)"
    echo "#!/usr/bin/env python3
# $f — stub (not yet implemented)
import sys
print('$f: not implemented in this build')
sys.exit(0)" > "$DEST_DIR/$f"
  fi
done

# Go source files
for go_file in "go.mod" "go.sum"; do
  [[ -f "$SRC_DIR/$go_file" ]] && cp "$SRC_DIR/$go_file" "$DEST_DIR/$go_file" \
    && info "  Copied: $go_file"
done
[[ -d "$SRC_DIR/cmd" ]] && cp -r "$SRC_DIR/cmd/"* "$DEST_DIR/cmd/" \
  && info "  Copied: cmd/"
[[ -d "$SRC_DIR/internal" ]] && cp -r "$SRC_DIR/internal/"* "$DEST_DIR/internal/" \
  && info "  Copied: internal/"

# Rust source
[[ -d "$SRC_DIR/bridge-probe" ]] && cp -r "$SRC_DIR/bridge-probe/"* "$DEST_DIR/bridge-probe/" \
  && info "  Copied: bridge-probe/"

# Sources directory (Python bridge scrapers)
[[ -d "$SRC_DIR/sources" ]] && cp -r "$SRC_DIR/sources/"* "$DEST_DIR/sources/" \
  && info "  Copied: sources/"

# Core directory
[[ -d "$SRC_DIR/core" ]] && cp -r "$SRC_DIR/core/"* "$DEST_DIR/core/" \
  && info "  Copied: core/"

# GitHub Actions workflow
cp "$SRC_DIR/.github/workflows/torshield-ir.yml" \
   "$DEST_DIR/.github/workflows/torshield-ir.yml" \
  && info "  Copied: .github/workflows/torshield-ir.yml"

# Docs
[[ -d "$SRC_DIR/docs" ]] && cp -r "$SRC_DIR/docs/"* "$DEST_DIR/docs/" 2>/dev/null || true
info "  Copied: docs/"

# Config files
for f in "requirements.txt" "setup_env.sh" "README.md" "README_FA.md" "install.sh"; do
  [[ -f "$SRC_DIR/$f" ]] && cp "$SRC_DIR/$f" "$DEST_DIR/$f" \
    && info "  Copied: $f"
done

# Data directory stubs (gitkeep)
touch "$DEST_DIR/export/.gitkeep"
touch "$DEST_DIR/data/.gitkeep"
touch "$DEST_DIR/bridge/.gitkeep"
[[ -f "$SRC_DIR/data/iran_bridges.json" ]] && \
  cp "$SRC_DIR/data/iran_bridges.json" "$DEST_DIR/data/"

# ── Step 4: Generate the Architectural Blueprint ──────────────────────────────
info "Generating architectural blueprint…"
cat > "$DEST_DIR/docs/ARCHITECTURE.md" << 'ARCHEOF'
# TorShield-IR v6.0 — Architectural Blueprint

## Three-Layer Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│  LAYER A: Collection & Intelligence (Stages 0–5)                    │
├─────────────────────────────────────────────────────────────────────┤
│  Stage 0   direct_scraper.py → bridges.torproject.org seed         │
│  Stage 0b  onionhop_collector.py → OnionHop bridge list            │
│  Stage 0c  legacy_scraper.py → Telegram ZIP + README               │
│  Stage 1   scraper.py → ALL sources (BridgeDB, GitHub, Telegram)   │
│  Stage 2   iran_tester (Go) → TCP/ASN/OONI/CDN analysis            │
│  Stage 3   probe_scheduler (Go) → RIPE Atlas + MOAT merge          │
│  Stage 4   bridge-probe (Rust) → PT handshake verification          │
│  Stage 5   ooni_correlator.py → OONI Iran data correlation          │
└─────────────────────────────────────────────────────────────────────┘
                              ↓ bridge data
┌─────────────────────────────────────────────────────────────────────┐
│  LAYER B: Scoring & Mutation (Stages 6–8p)                          │
├─────────────────────────────────────────────────────────────────────┤
│  Stage 6a  main.py --mode score   → composite bridge scores        │
│  Stage 6b  main.py --mode export  → ranked export files            │
│  Stage 7   ml_predictor.py        → ML blocking prediction          │
│  Stage 8   adaptive_transport.py  → transport weight engine         │
│  Stage 8b  dpi_evasion_advanced.py → dpi_intelligence.json         │
│  Stage 8c  next_gen_transports.py → VLESS/Reality/Hysteria2 scan   │
│  Stage 8d  core.nin_selector      → NIN cut bridge pack             │
│  Stage 8d2 iran_nin_bypass.py     → ECH/CDN survivability          │
│  Stage 8e  quantum_safe.py        → ECH + PQ scoring                │
│  Stage 8f  warp_bootstrap.py      → WARP bootstrap check            │
│  Stage 8g  ech_fingerprint_evasion.py → ECH evasion scoring        │
│  Stage 8h  nin_advanced_bypass.py → NIN advanced analysis          │
│  Stage 8i  anti_ai_dpi.py        → Anti-AI DPI scoring             │
│            ┌──────────────────────────────────────────────────┐     │
│  Stage 8j  │ ai_dpi_mutator.py — 14-Provider AI Waterfall    │     │
│            │                                                   │     │
│            │  data/dpi_intelligence.json                       │     │
│            │         ↓                                         │     │
│            │  _query_ai_providers()                            │     │
│            │    P0a: Vercel GW → Claude                        │     │
│            │    P0b: Vercel GW → Groq                          │     │
│            │    P0c: Vercel GW → DeepSeek                      │     │
│            │    P1:  Claude Opus 4.8 / Cloudflare              │     │
│            │    P2:  Gemini 3.1 Pro                            │     │
│            │    P3:  DeepSeek-R1                               │     │
│            │    P4:  DeepSeek-V3                               │     │
│            │    P5:  Qwen3-Coder-480B                          │     │
│            │    P6:  Llama-3.3-70B (Hyperbolic)               │     │
│            │    P7:  Groq Llama-3.3-70B                        │     │
│            │    P8:  Groq Llama-3-70B                          │     │
│            │    P9:  Qwen2.5-Coder-32B (HuggingFace)          │     │
│            │    P10: Mistral Large 2                           │     │
│            │    P11: Cloudflare Llama                          │     │
│            │         ↓                                         │     │
│            │  _compute_consensus()                             │     │
│            │    score ≥ 0.60 OR ≥2 providers → MUTATE         │     │
│            │         ↓                                         │     │
│            │  _mutate_go_ports() + _mutate_obfs4_iat()        │     │
│            │  _rebuild_go() → _commit_mutation()              │     │
│            │  → data/ai_consensus_report.json                  │     │
│            └──────────────────────────────────────────────────┘     │
│                              ↓                                       │
│  Stage 8k  nin_cut_tester.py      → NIN-cut survivability scores   │
│  Stage 8l  xtls_reality_wrapper.py → VLESS+Reality configs         │
│  Stage 8m  ebpf_blueprint.py      → eBPF/XDP deployment docs       │
│  Stage 8n  ja3_intelligence.py --rotate → JA3 rotation plan        │
│  Stage 8o  ztunnel_ct_monitor.py  → CT MITM detection              │
│  Stage 8p  nin_internet_cut_classifier.py → GREEN/YELLOW/RED       │
└─────────────────────────────────────────────────────────────────────┘
                              ↓ scored + annotated bridges
┌─────────────────────────────────────────────────────────────────────┐
│  LAYER C: Export, Notification & Commit (Stages 9–11)               │
├─────────────────────────────────────────────────────────────────────┤
│  Stage 9   results_writer.py → Telegram notification + export files│
│  Stage 10  Bridge count summary (Bash)                              │
│  Stage 11  git commit + push (signed [skip ci])                     │
│  ──────    actions/upload-artifact@v4 → bridge-intelligence-report │
└─────────────────────────────────────────────────────────────────────┘
```

## Key Data Flows

### DPI Intelligence → AI Waterfall → Mutation

```
dpi_evasion_advanced.py
        │
        ▼
data/dpi_intelligence.json
        │
        ▼
ai_dpi_mutator.py (Stage 8j)
        │
        ├─→ Vercel AI Gateway (P0a/b/c — NIN-resilient path)
        │         │
        ├─→ 11 direct AI providers (P1–P11)
        │         │
        └─→ consensus_score ≥ 0.60?
                  │
                  ├── YES → _mutate_go_ports() + _mutate_obfs4_iat()
                  │          → go build iran_tester probe_scheduler
                  │          → git commit [dpi-mutation] [skip ci]
                  │
                  └── NO  → data/ai_consensus_report.json (no mutation)
```

### NIN Survivability Pipeline

```
Stage 8d: core.nin_selector
        │
        ▼
export/nin_cut_bridges.txt
        │
        ├─→ Stage 8k: nin_cut_tester.py
        │       TCP probe (no DNS) + ASN scoring
        │       → data/nin_cut_report.json
        │       → export/nin_cut_survivable.txt
        │
        ├─→ Stage 8p: nin_internet_cut_classifier.py
        │       GREEN/YELLOW/RED CDN-tier classification
        │       → bridge/iran_likely_working_nin.txt
        │
        └─→ Stage 8o: ztunnel_ct_monitor.py
                CT log scan for Iranian MITM CAs
                → export/ct_clean_bridges.txt
```

### Portkey + Cerebras + Cloudflare AI Gateway — NIN Resilience

```
ai_dpi_mutator.py
        │
        ├── PORTKEY_API_KEY set?
        │         │
        │         ├── YES → api.portkey.ai (master router)
        │         │         ├── Cerebras (Llama-3.1-70B / Qwen-2.5-72B)
        │         │         ├── Groq (Llama-3.3-70B fallback)
        │         │         └── DeepSeek-R1 (deep reasoning fallback)
        │         │
        │         └── NO  → fall through to direct provider calls
        │
        ├── CEREBRAS_API_KEY set?
        │         ├── YES → api.cerebras.ai (sub-100ms, free tier)
        │         └── NO  → skip Cerebras tier
        │
        ├── CF_AI_GATEWAY_URL set?
        │         ├── YES → Cloudflare edge cache wraps Groq/DeepSeek/Mistral
        │         └── NO  → direct provider endpoints
        │
        └── Direct provider fallback pool (11 providers)
```

## Secrets Required

| Secret                | Stage | Purpose                                |
|-----------------------|-------|----------------------------------------|
| `CF_API_TOKEN`        | 8j    | Cloudflare Workers AI (Claude + Llama) |
| `CF_ACCOUNT_ID`       | 8j    | Cloudflare account identifier          |
| `CF_AI_GATEWAY_URL`   | 8j    | Cloudflare AI Gateway edge cache URL   |
| `PORTKEY_API_KEY`     | 8j    | Portkey.ai master AI gateway router    |
| `CEREBRAS_API_KEY`    | 8j    | Cerebras hyper-speed inference engine  |
| `GEMINI_API_KEY`      | 8j    | Google Gemini 3.1 Pro                  |
| `DEEPSEEK_API_KEY`    | 8j    | DeepSeek R1 + V3                       |
| `HYPERBOLIC_API_KEY`  | 8j    | Qwen3-Coder + Llama via Hyperbolic     |
| `GROQ_API_KEY`        | 8j    | Groq Llama-3.3-70B + 70B              |
| `MISTRAL_API_KEY`     | 8j    | Mistral Large 2                        |
| `HUGGINGFACE_API_KEY` | 8j    | Qwen2.5-Coder-32B (HuggingFace)        |
| `TELEGRAM_BOT_TOKEN`  | 9     | Telegram notifications                 |
| `TELEGRAM_CHAT_ID`    | 9     | Telegram channel/group                 |
| `RIPE_ATLAS_API_KEY`  | 3     | RIPE Atlas measurements                |

## Iran-Specific Technology Stack

| Technology           | Purpose                                    | DPI Risk Score |
|----------------------|--------------------------------------------|----------------|
| WebTunnel/CDN SNI    | Mimics browser HTTPS to Iranian CDN        | 0.05           |
| XTLS-Reality/VLESS   | Borrows TLS cert of Aparat/Digikala        | 0.10           |
| obfs4 iat-mode=2     | Randomises inter-arrival timing            | 0.25           |
| Snowflake/WebRTC     | Classified as video-call by SIAM           | 0.15           |
| QUIC/HTTP3 CDN       | Mimics Aparat video streaming              | 0.12           |
| ML-KEM hybrid        | Post-quantum, new JA3 signature            | 0.08           |
| ECH (TLS 1.3)        | Hides SNI from SIAM DPI                    | 0.03           |

Lower score = harder for SIAM to detect and block.
ARCHEOF

info "Architectural blueprint written."

# ── Step 5: Set permissions ───────────────────────────────────────────────────
info "Setting file permissions…"
find "$DEST_DIR" -name "*.py"  -exec chmod +x {} \;
find "$DEST_DIR" -name "*.sh"  -exec chmod +x {} \;
chmod +x "$DEST_DIR/setup_env.sh" 2>/dev/null || true
chmod +x "$DEST_DIR/generate_quantum_project.sh" 2>/dev/null || true

# ── Step 6: Create archive ────────────────────────────────────────────────────
info "Creating archive: $ARCHIVE"
if [[ -f "$ARCHIVE" ]]; then
  warn "Archive already exists — removing."
  rm -f "$ARCHIVE"
fi
cd "$PARENT_DIR"
tar -czf "$ARCHIVE" "$DEST_NAME"
info "Archive created: $ARCHIVE"

# ── Step 7: SHA-256 checksum ──────────────────────────────────────────────────
info "Computing SHA-256 checksum…"
if command -v sha256sum &>/dev/null; then
  SHA256=$(sha256sum "$ARCHIVE" | awk '{print $1}')
elif command -v shasum &>/dev/null; then
  SHA256=$(shasum -a 256 "$ARCHIVE" | awk '{print $1}')
else
  warn "sha256sum / shasum not found — skipping checksum"
  SHA256="(unavailable)"
fi

ARCHIVE_SIZE=$(du -sh "$ARCHIVE" | cut -f1)

echo ""
echo "══════════════════════════════════════════════════════════════════"
echo "  TorShield-IR v6.0 — Assembly Complete"
echo "══════════════════════════════════════════════════════════════════"
echo "  Archive : $ARCHIVE"
echo "  Size    : $ARCHIVE_SIZE"
echo "  SHA-256 : $SHA256"
echo "══════════════════════════════════════════════════════════════════"
echo ""
echo "Installation:"
echo "  tar -xzf $(basename "$ARCHIVE")"
echo "  cd $DEST_NAME"
echo "  bash setup_env.sh"
echo ""
echo "GitHub Actions:"
echo "  Push to repository → pipeline triggers automatically (cron + dispatch)"
echo ""
exit 0
