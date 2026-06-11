#!/usr/bin/env bash
# install.sh — TorShield-IR automated installer v3
#
# Installs all dependencies for the Tor Bridges Collector pipeline:
#   • Python 3.10+ with virtualenv
#   • Rust (stable ≥1.85, needed for edition2024 in clap's dependency tree)
#   • Go 1.22+
#   • obfs4proxy / lyrebird (Tor pluggable transport binaries)
#
# Usage:
#   bash install.sh              # full install
#   bash install.sh --no-rust    # skip Rust build
#   bash install.sh --no-go      # skip Go build
#   bash install.sh --no-venv    # skip Python venv
#   bash install.sh --dev        # include dev/test deps

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log_ok()   { echo -e "${GREEN}[✓]${NC} $*"; }
log_info() { echo -e "${CYAN}[i]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $*"; }
log_err()  { echo -e "${RED}[✗]${NC} $*"; exit 1; }

NO_GO=false; NO_RUST=false; NO_VENV=false; DEV=false
for arg in "$@"; do
  case "$arg" in
    --no-go)   NO_GO=true   ;;
    --no-rust) NO_RUST=true ;;
    --no-venv) NO_VENV=true ;;
    --dev)     DEV=true     ;;
  esac
done

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║      TorShield-IR — Tor Bridges Collector v2 Installer      ║${NC}"
echo -e "${BOLD}║              Iran-Optimised Bridge Intelligence              ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

OS="$(uname -s)"

# ── 1. Python ────────────────────────────────────────────────────────────────
log_info "Checking Python 3.10+…"
if ! command -v python3 &>/dev/null; then
  log_err "Python 3 not found. Install: apt install python3 python3-pip python3-venv"
fi
PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$(echo "$PY_VER" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VER" | cut -d. -f2)
if [[ "$PY_MAJOR" -lt 3 || ("$PY_MAJOR" -eq 3 && "$PY_MINOR" -lt 10) ]]; then
  log_err "Python 3.10+ required. Found $PY_VER."
fi
log_ok "Python $PY_VER"

# ── 2. Python virtualenv ─────────────────────────────────────────────────────
if [[ "$NO_VENV" == "false" ]]; then
  log_info "Creating Python virtual environment (.venv)…"
  python3 -m venv .venv
  # shellcheck source=/dev/null
  source .venv/bin/activate
  log_ok "Virtual environment active: .venv"
fi

# ── 3. Python dependencies ───────────────────────────────────────────────────
log_info "Installing Python dependencies…"
python3 -m pip install --upgrade pip --quiet
python3 -m pip install -r requirements.txt --quiet
if [[ "$DEV" == "true" ]]; then
  python3 -m pip install pytest pytest-cov pytest-asyncio ruff mypy --quiet
  log_ok "Dev dependencies installed."
fi
log_ok "Python dependencies installed."

# ── 4. Rust ──────────────────────────────────────────────────────────────────
if [[ "$NO_RUST" == "false" ]]; then
  log_info "Checking Rust (stable ≥1.85 required for edition2024)…"

  NEED_RUST=false
  if ! command -v cargo &>/dev/null; then
    NEED_RUST=true
  else
    RUST_VER=$(rustc --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    RUST_MINOR=$(echo "$RUST_VER" | cut -d. -f2)
    if [[ "$RUST_MINOR" -lt 85 ]]; then
      log_warn "Rust $RUST_VER found — need ≥1.85 (edition2024 support). Upgrading…"
      NEED_RUST=true
    else
      log_ok "Rust $RUST_VER (compatible)"
    fi
  fi

  if [[ "$NEED_RUST" == "true" ]]; then
    log_info "Installing Rust via rustup…"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- \
      -y --default-toolchain stable --profile minimal
    # shellcheck source=/dev/null
    source "$HOME/.cargo/env"
    rustup update stable
    log_ok "Rust $(rustc --version) installed."
  fi

  log_info "Building bridge-probe (release)…"
  cd bridge-probe
  cargo build --release
  cd ..
  log_ok "bridge-probe binary: bridge-probe/target/release/bridge-probe"
fi

# ── 5. Go ────────────────────────────────────────────────────────────────────
if [[ "$NO_GO" == "false" ]]; then
  log_info "Checking Go 1.22+…"
  if ! command -v go &>/dev/null; then
    log_warn "Go not found. Installing Go 1.22…"
    if [[ "$OS" == "Linux" ]]; then
      GO_URL="https://go.dev/dl/go1.22.4.linux-amd64.tar.gz"
      curl -fsSL "$GO_URL" -o /tmp/go.tar.gz
      sudo rm -rf /usr/local/go
      sudo tar -C /usr/local -xzf /tmp/go.tar.gz
      export PATH="/usr/local/go/bin:$PATH"
      echo 'export PATH="/usr/local/go/bin:$PATH"' >> "$HOME/.bashrc"
    else
      log_err "Please install Go 1.22+ manually from https://go.dev/dl/"
    fi
  fi
  GO_VER=$(go version | grep -oE 'go[0-9]+\.[0-9]+' | head -1 | tr -d go)
  log_ok "Go $GO_VER"

  log_info "Building Go binaries…"
  CGO_ENABLED=0 GOOS=linux go build -o iran_tester    ./cmd/iran_tester/
  CGO_ENABLED=0 GOOS=linux go build -o probe_scheduler ./cmd/probe_scheduler/
  chmod +x iran_tester probe_scheduler
  log_ok "Go binaries: iran_tester, probe_scheduler"
fi

# ── 6. obfs4proxy / lyrebird ─────────────────────────────────────────────────
log_info "Checking pluggable transport binaries (obfs4proxy / lyrebird)…"
PT_OK=false
if command -v lyrebird &>/dev/null; then
  log_ok "lyrebird found: $(which lyrebird)"
  PT_OK=true
elif command -v obfs4proxy &>/dev/null; then
  log_ok "obfs4proxy found: $(which obfs4proxy)"
  PT_OK=true
fi

if [[ "$PT_OK" == "false" ]]; then
  log_warn "Neither lyrebird nor obfs4proxy found."
  if command -v apt-get &>/dev/null; then
    log_info "Installing obfs4proxy via apt…"
    sudo apt-get install -y obfs4proxy 2>/dev/null || true
    if command -v obfs4proxy &>/dev/null; then
      log_ok "obfs4proxy installed via apt."
      PT_OK=true
    fi
  fi
  if [[ "$PT_OK" == "false" ]] && command -v go &>/dev/null; then
    log_info "Building lyrebird from source (requires Go)…"
    go install gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/cmd/lyrebird@latest 2>/dev/null || true
    if command -v lyrebird &>/dev/null; then
      log_ok "lyrebird built and installed."
      PT_OK=true
    fi
  fi
  if [[ "$PT_OK" == "false" ]]; then
    log_warn "Pluggable transport binary not installed."
    log_warn "obfs4 bridges will fall back to TCP reachability probe."
    log_warn "Install manually: https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird"
  fi
fi

# ── 7. Create required directories ───────────────────────────────────────────
mkdir -p bridge export data docs
touch bridge/.gitkeep export/.gitkeep

# ── 8. Summary ───────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║                    Installation Complete                     ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Run full pipeline:  ${CYAN}python main.py${NC}"
echo -e "  Collect only:       ${CYAN}python main.py --mode collect${NC}"
echo -e "  NIN mode (cut):     ${CYAN}NIN_MODE=true python main.py${NC}"
echo -e "  Check connectivity: ${CYAN}python main.py --detect-iran${NC}"
echo ""
log_ok "TorShield-IR is ready."
