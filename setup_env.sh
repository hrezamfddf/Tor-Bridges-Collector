#!/usr/bin/env bash
# =============================================================================
# setup_env.sh — TorShield-IR Automated Prerequisites Bootstrapper
#
# Idempotent: safe to run multiple times; skips already-installed tools.
# Supports: Ubuntu/Debian 20.04+, Fedora/RHEL 8+, macOS (Homebrew)
# Installs: Go 1.22, Rust (stable), Python 3.11, jq, curl, fuser (psmisc)
#
# Usage:
#   chmod +x setup_env.sh
#   ./setup_env.sh
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[✔]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
die()  { echo -e "${RED}[✘]${NC} $*" >&2; exit 1; }

# ── OS detection ──────────────────────────────────────────────────────────────
detect_os() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS_ID="${ID:-linux}"
        OS_FAMILY="${ID_LIKE:-$OS_ID}"
    elif [[ "$(uname)" == "Darwin" ]]; then
        OS_ID="macos"
        OS_FAMILY="macos"
    else
        die "Unsupported OS. Please install manually."
    fi
}

# ── Package manager abstraction ──────────────────────────────────────────────
install_pkg() {
    local pkg="$1"
    case "$OS_FAMILY" in
        *debian*|*ubuntu*)  sudo apt-get install -y "$pkg" ;;
        *fedora*|*rhel*|*centos*)  sudo dnf install -y "$pkg" ;;
        macos)              brew install "$pkg" ;;
        *)                  die "Cannot install $pkg: unknown package manager." ;;
    esac
}

update_pkg_cache() {
    case "$OS_FAMILY" in
        *debian*|*ubuntu*)  sudo apt-get update -qq ;;
        *fedora*|*rhel*|*centos*)  sudo dnf check-update -q || true ;;
        macos)              brew update --quiet || true ;;
    esac
}

# ── Tool version checks ──────────────────────────────────────────────────────
GO_VERSION="1.22.4"
PYTHON_MIN="3.11"

need_go() {
    if command -v go &>/dev/null; then
        local v; v=$(go version | awk '{print $3}' | sed 's/go//')
        if [[ "$v" == "$GO_VERSION"* ]]; then
            ok "Go $v already installed."; return 1
        fi
        warn "Go $v found but $GO_VERSION required — reinstalling."
    fi
    return 0
}

need_rust() {
    if command -v rustc &>/dev/null && command -v cargo &>/dev/null; then
        ok "Rust $(rustc --version 2>&1 | awk '{print $2}') already installed."; return 1
    fi
    return 0
}

need_python() {
    local py; py=$(python3 --version 2>&1 | awk '{print $2}')
    local major minor; IFS='.' read -r major minor _ <<< "$py"
    if (( major >= 3 && minor >= 11 )); then
        ok "Python $py already installed."; return 1
    fi
    warn "Python $py found; $PYTHON_MIN+ required."
    return 0
}

# ── Go installation ───────────────────────────────────────────────────────────
install_go() {
    need_go || return 0
    local arch; arch=$(uname -m)
    case "$arch" in
        x86_64)   GOARCH="amd64" ;;
        aarch64)  GOARCH="arm64" ;;
        *)        die "Unsupported arch: $arch" ;;
    esac
    local tarball="go${GO_VERSION}.linux-${GOARCH}.tar.gz"
    local url="https://go.dev/dl/${tarball}"
    echo "Downloading Go ${GO_VERSION} (${GOARCH})…"
    curl -fsSL "$url" -o "/tmp/${tarball}"
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf "/tmp/${tarball}"
    rm -f "/tmp/${tarball}"
    # Persist PATH in shell profiles
    for profile in ~/.bashrc ~/.zshrc ~/.profile; do
        grep -q '/usr/local/go/bin' "$profile" 2>/dev/null \
            || echo 'export PATH="$PATH:/usr/local/go/bin"' >> "$profile"
    done
    export PATH="$PATH:/usr/local/go/bin"
    ok "Go $(go version) installed."
}

# ── Rust installation ─────────────────────────────────────────────────────────
install_rust() {
    need_rust || return 0
    echo "Installing Rust via rustup…"
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --no-modify-path --default-toolchain stable
    source "$HOME/.cargo/env" 2>/dev/null || true
    export PATH="$HOME/.cargo/bin:$PATH"
    ok "Rust $(rustc --version) installed."
}

# ── Python 3.11 installation ──────────────────────────────────────────────────
install_python() {
    need_python || return 0
    case "$OS_FAMILY" in
        *debian*|*ubuntu*)
            sudo add-apt-repository -y ppa:deadsnakes/ppa 2>/dev/null || true
            sudo apt-get update -qq
            sudo apt-get install -y python3.11 python3.11-venv python3.11-dev python3-pip
            sudo update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 11 \
                2>/dev/null || true
            ;;
        *fedora*|*rhel*)
            sudo dnf install -y python3.11 python3.11-pip python3.11-devel
            ;;
        macos)
            brew install python@3.11
            ;;
        *)
            die "Cannot install Python 3.11 automatically on this OS."
            ;;
    esac
    ok "Python $(python3 --version) installed."
}

# ── System utilities ──────────────────────────────────────────────────────────
install_utils() {
    for tool in curl jq; do
        if command -v "$tool" &>/dev/null; then
            ok "$tool already installed."
        else
            echo "Installing $tool…"
            install_pkg "$tool"
            ok "$tool installed."
        fi
    done

    # fuser (psmisc) — needed by workflow Stage 4 cleanup
    if command -v fuser &>/dev/null; then
        ok "fuser (psmisc) already installed."
    else
        echo "Installing psmisc (provides fuser)…"
        case "$OS_FAMILY" in
            *debian*|*ubuntu*)  install_pkg psmisc ;;
            *fedora*|*rhel*)    install_pkg psmisc ;;
            macos)              warn "fuser not available on macOS; skipping." ;;
        esac
        ok "fuser installed."
    fi
}

# ── Python project dependencies ───────────────────────────────────────────────
install_python_deps() {
    if [[ ! -f requirements.txt ]]; then
        warn "requirements.txt not found — skipping Python dep install."
        return
    fi
    echo "Installing Python dependencies from requirements.txt…"
    python3 -m pip install --upgrade pip --quiet
    python3 -m pip install -r requirements.txt --quiet
    ok "Python dependencies installed."
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    echo "═══════════════════════════════════════════════"
    echo "  TorShield-IR Environment Bootstrapper"
    echo "═══════════════════════════════════════════════"
    detect_os
    echo "Detected OS: ${OS_ID} (family: ${OS_FAMILY})"
    update_pkg_cache
    install_utils
    install_go
    install_rust
    install_python
    install_python_deps

    echo ""
    echo "═══════════════════════════════════════════════"
    echo "  Environment Summary"
    echo "═══════════════════════════════════════════════"
    command -v go     &>/dev/null && ok "Go:     $(go version)"
    command -v rustc  &>/dev/null && ok "Rust:   $(rustc --version)"
    command -v python3 &>/dev/null && ok "Python: $(python3 --version)"
    command -v jq     &>/dev/null && ok "jq:     $(jq --version)"
    command -v curl   &>/dev/null && ok "curl:   $(curl --version | head -1)"
    echo "═══════════════════════════════════════════════"
    echo ""
    ok "Setup complete. Run 'source ~/.bashrc' (or restart shell) to refresh PATH."
}

main "$@"


# APPEND AFTER EXISTING INSTALL BLOCKS
# ── aioquic (HTTP/3 QUIC probing) ──────────────────────────────────────────
if ! python3 -c "import aioquic" 2>/dev/null; then
  sudo apt-get install -y libssl-dev openssl 2>/dev/null || true
  pip install aioquic --break-system-packages 2>/dev/null \
    || pip install aioquic
fi

# ── libbpf headers (eBPF/XDP blueprint documentation) ─────────────────────
sudo apt-get install -y libbpf-dev linux-headers-$(uname -r) \
  2>/dev/null || true

# ── cryptography (X25519 key generation for XTLS-Reality) ──────────────────
pip install cryptography --upgrade --break-system-packages 2>/dev/null \
  || pip install cryptography --upgrade

# ── aiohttp (NIN cut tester async HTTP) ────────────────────────────────────
if ! python3 -c "import aiohttp" 2>/dev/null; then
  pip install aiohttp --break-system-packages 2>/dev/null \
    || pip install aiohttp
fi

# ── Zig 0.12 (quantum-core optional; skip gracefully if unavailable) ────────
if ! command -v zig &>/dev/null; then
  ZIG_URL="https://ziglang.org/download/0.12.0/zig-linux-x86_64-0.12.0.tar.xz"
  ZIG_DIR="/opt/zig-0.12.0"
  if [[ ! -d "$ZIG_DIR" ]]; then
    curl -sSL "$ZIG_URL" | sudo tar -xJ -C /opt/ 2>/dev/null || true
    sudo mv /opt/zig-linux-x86_64-0.12.0 "$ZIG_DIR" 2>/dev/null || true
  fi
  if [[ -f "$ZIG_DIR/zig" ]]; then
    sudo ln -sf "$ZIG_DIR/zig" /usr/local/bin/zig
    echo "[OK] Zig 0.12 installed"
  else
    echo "[WARN] Zig install failed — quantum-core features will be skipped"
  fi
fi

# ── Verify all Python dependencies ─────────────────────────────────────────
echo "=== Dependency verification ==="
for pkg in aiohttp aioquic cryptography requests scikit-learn numpy; do
  if python3 -c "import ${pkg//-/_}" 2>/dev/null; then
    echo "  [OK] $pkg"
  else
    echo "  [MISSING] $pkg — attempting install"
    pip install "$pkg" --break-system-packages 2>/dev/null || pip install "$pkg" || true
  fi
done
echo "=== Setup complete ==="
