#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
# Tor-Bridges-Collector Build & Package Script
# ══════════════════════════════════════════════════════════════════════════════
#
# Creates a distributable tar.gz package containing all source code,
# documentation, configs, tests, and workflows.
#
# Usage:
#   bash packaging/build_package.sh
#   bash packaging/build_package.sh --output /tmp/
#
# Output:
#   Tor-Bridges-Collector-main-ultra-quantum-vip-vip-super-ultra-vip-ultra-quantum-ultra-vip-ultra-quantum-ultra-quantum-vip.tar.gz
#   MANIFEST.txt (file listing)
#   checksums.sha256 (SHA-256 checksums)
#
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────

PACKAGE_NAME="Tor-Bridges-Collector-main-ultra-quantum-vip-vip-super-ultra-vip-ultra-quantum-ultra-vip-ultra-quantum-ultra-quantum-vip"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
OUTPUT_DIR="${1:-${PROJECT_ROOT}}"
TIMESTAMP="$(date -u '+%Y-%m-%dT%H:%M:%SZ')"

# ── Colors ────────────────────────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
log_ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# ── Pre-flight Checks ─────────────────────────────────────────────────────────

log_info "Tor-Bridges-Collector Package Builder"
log_info "====================================="
log_info "Project root: ${PROJECT_ROOT}"
log_info "Output dir:   ${OUTPUT_DIR}"
log_info "Package:      ${PACKAGE_NAME}.tar.gz"
echo ""

if [[ ! -d "${PROJECT_ROOT}/core" ]]; then
    log_error "Project root does not appear valid (missing core/ directory)"
    exit 1
fi

if ! command -v tar &>/dev/null; then
    log_error "tar command not found"
    exit 1
fi

if ! command -v sha256sum &>/dev/null; then
    log_warn "sha256sum not found — checksums will use shasum fallback"
    SHA_CMD="shasum -a 256"
else
    SHA_CMD="sha256sum"
fi

# ── Build Staging Area ────────────────────────────────────────────────────────

STAGING_DIR=$(mktemp -d)
trap 'rm -rf "${STAGING_DIR}"' EXIT

log_info "Creating staging directory: ${STAGING_DIR}/${PACKAGE_NAME}"
mkdir -p "${STAGING_DIR}/${PACKAGE_NAME}"

# ── Copy Files ────────────────────────────────────────────────────────────────

log_info "Copying project files..."

# Copy directories (excluding unwanted ones)
INCLUDE_DIRS=(
    "core"
    "sources"
    "torshield_ai_gateway"
    "providers"
    "gateway"
    "model_selector"
    "monitoring"
    "diagnostics"
    "anti_censorship"
    "tests"
    "configs"
    "scripts"
    "docs"
    "export"
    "data"
    "reports"
    "packaging"
    "internal"
    "cmd"
    "go_tester"
    "bridge-probe"
    "zig-scanner"
)

for dir in "${INCLUDE_DIRS[@]}"; do
    if [[ -d "${PROJECT_ROOT}/${dir}" ]]; then
        log_info "  Including ${dir}/"
        mkdir -p "${STAGING_DIR}/${PACKAGE_NAME}/${dir}"
        # Copy files, excluding __pycache__ and .pyc
        cd "${PROJECT_ROOT}"
        find "${dir}" \
            -not -path '*/__pycache__/*' \
            -not -name '*.pyc' \
            -not -name '*.pyo' \
            -type f \
            -exec cp --parents {} "${STAGING_DIR}/${PACKAGE_NAME}/" \; 2>/dev/null || true
    fi
done

# Copy root-level Python files
log_info "  Including root-level Python files..."
cd "${PROJECT_ROOT}"
for f in *.py; do
    if [[ -f "$f" ]]; then
        cp "$f" "${STAGING_DIR}/${PACKAGE_NAME}/"
    fi
done

# Copy other important root files
ROOT_FILES=(
    "README.md"
    "README_FA.md"
    "requirements.txt"
    "config.py"
    "main.py"
    "setup_env.sh"
    "install.sh"
    "go.mod"
)

for f in "${ROOT_FILES[@]}"; do
    if [[ -f "${PROJECT_ROOT}/${f}" ]]; then
        cp "${PROJECT_ROOT}/${f}" "${STAGING_DIR}/${PACKAGE_NAME}/"
    fi
done

# Copy .github/workflows if it exists
if [[ -d "${PROJECT_ROOT}/.github" ]]; then
    log_info "  Including .github/"
    mkdir -p "${STAGING_DIR}/${PACKAGE_NAME}/.github"
    cp -r "${PROJECT_ROOT}/.github/"* "${STAGING_DIR}/${PACKAGE_NAME}/.github/" 2>/dev/null || true
fi

# ── Generate MANIFEST ─────────────────────────────────────────────────────────

log_info "Generating MANIFEST..."
cd "${STAGING_DIR}/${PACKAGE_NAME}"
find . -type f \
    -not -path '*/__pycache__/*' \
    -not -name '*.pyc' \
    -not -name '*.pyo' \
    -not -name '.git/*' \
    | sort \
    > "${STAGING_DIR}/MANIFEST.txt"

FILE_COUNT=$(wc -l < "${STAGING_DIR}/MANIFEST.txt")
log_ok "MANIFEST contains ${FILE_COUNT} files"

# ── Add Build Metadata ────────────────────────────────────────────────────────

cat > "${STAGING_DIR}/${PACKAGE_NAME}/BUILD_INFO" <<EOF
Package:      ${PACKAGE_NAME}
Build Time:   ${TIMESTAMP}
Builder:      build_package.sh
Git SHA:      $(cd "${PROJECT_ROOT}" && git rev-parse HEAD 2>/dev/null || echo "unknown")
Git Branch:   $(cd "${PROJECT_ROOT}" && git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
File Count:   ${FILE_COUNT}
EOF

# ── Create Tarball ────────────────────────────────────────────────────────────

log_info "Creating tar.gz package..."
mkdir -p "${OUTPUT_DIR}"
cd "${STAGING_DIR}"
tar -czf "${OUTPUT_DIR}/${PACKAGE_NAME}.tar.gz" \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='*.pyo' \
    --exclude='.git' \
    --exclude='.gitignore' \
    --exclude='.env' \
    "${PACKAGE_NAME}"

TARBALL_SIZE=$(du -h "${OUTPUT_DIR}/${PACKAGE_NAME}.tar.gz" | cut -f1)
log_ok "Created ${PACKAGE_NAME}.tar.gz (${TARBALL_SIZE})"

# ── Generate Checksums ───────────────────────────────────────────────────────

log_info "Generating SHA-256 checksums..."
cd "${OUTPUT_DIR}"
${SHA_CMD} "${PACKAGE_NAME}.tar.gz" > "${STAGING_DIR}/checksums.sha256" 2>/dev/null || {
    # Fallback: compute manually
    HASH=$(shasum -a 256 "${PACKAGE_NAME}.tar.gz" 2>/dev/null | cut -d' ' -f1 || echo "unavailable")
    echo "${HASH}  ${PACKAGE_NAME}.tar.gz" > "${STAGING_DIR}/checksums.sha256"
}

# Copy manifest and checksums to output
cp "${STAGING_DIR}/MANIFEST.txt" "${OUTPUT_DIR}/"
cp "${STAGING_DIR}/checksums.sha256" "${OUTPUT_DIR}/"

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
log_ok "═══════════════════════════════════════════════════════════"
log_ok "Package built successfully!"
log_ok "═══════════════════════════════════════════════════════════"
echo ""
log_ok "  Package:   ${OUTPUT_DIR}/${PACKAGE_NAME}.tar.gz"
log_ok "  Size:      ${TARBALL_SIZE}"
log_ok "  Files:     ${FILE_COUNT}"
log_ok "  MANIFEST:  ${OUTPUT_DIR}/MANIFEST.txt"
log_ok "  Checksums: ${OUTPUT_DIR}/checksums.sha256"
echo ""
log_info "To verify:"
log_info "  ${SHA_CMD} -c checksums.sha256"
log_info "  tar -tzf ${PACKAGE_NAME}.tar.gz | head -20"
echo ""
