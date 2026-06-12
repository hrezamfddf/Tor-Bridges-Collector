#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════
# package.sh — Tor-Bridges-Collector Packaging Script v1.0
# ═══════════════════════════════════════════════════════════════════════════
# Creates a production-ready tar.gz archive of the entire project.
# The archive name includes a descriptive version string.
#
# USAGE:
#   ./scripts/package.sh
#
# OUTPUT:
#   Tor-Bridges-Collector-main-ultra-quantum-vip-vip-super-ultra-vip-ultra-
#   quantum-ultra-vip-ultra-quantum-ultra-quantum-vip-fg-ds-ddhd-ghj-vgg.tar.gz
#
# EXIT CODES:
#   0 — Success
#   1 — Failure (missing directory, tar error, etc.)
# ═══════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────────────
ARCHIVE_NAME="Tor-Bridges-Collector-main-ultra-quantum-vip-vip-super-ultra-vip-ultra-quantum-ultra-vip-ultra-quantum-ultra-quantum-vip-fg-ds-ddhd-ghj-vgg"

# Determine project root (parent of scripts/ directory)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Output directory (defaults to project root, can be overridden)
OUTPUT_DIR="${OUTPUT_DIR:-${PROJECT_ROOT}}"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   Tor-Bridges-Collector — Packaging Script v1.0            ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "  Project root : ${PROJECT_ROOT}"
echo "  Archive name : ${ARCHIVE_NAME}.tar.gz"
echo "  Output dir   : ${OUTPUT_DIR}"
echo ""

# ── Validation ─────────────────────────────────────────────────────────────
if [[ ! -d "${PROJECT_ROOT}" ]]; then
    echo "ERROR: Project root directory does not exist: ${PROJECT_ROOT}" >&2
    exit 1
fi

if [[ ! -f "${PROJECT_ROOT}/main.py" ]]; then
    echo "WARNING: main.py not found in project root — verify project structure" >&2
fi

# ── Clean up any previous build artifacts ──────────────────────────────────
echo "[1/4] Cleaning previous build artifacts..."
find "${PROJECT_ROOT}" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find "${PROJECT_ROOT}" -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
find "${PROJECT_ROOT}" -type f -name "*.pyc" -delete 2>/dev/null || true
find "${PROJECT_ROOT}" -type f -name "*.pyo" -delete 2>/dev/null || true

echo "[2/4] Verifying project structure..."
# Count key files to verify we have a complete project
PY_COUNT=$(find "${PROJECT_ROOT}" -name "*.py" -not -path "*/__pycache__/*" | wc -l)
YML_COUNT=$(find "${PROJECT_ROOT}" -name "*.yml" -o -name "*.yaml" | wc -l)
echo "  Python files : ${PY_COUNT}"
echo "  YAML files   : ${YML_COUNT}"

if [[ ${PY_COUNT} -lt 5 ]]; then
    echo "ERROR: Too few Python files found — project may be incomplete" >&2
    exit 1
fi

echo "[3/4] Creating tar.gz archive..."
# Create the archive from the project root
# We use --transform to rename the top-level directory in the archive
cd "${PROJECT_ROOT}/.."
BASENAME="$(basename "${PROJECT_ROOT}")"

tar czf "${OUTPUT_DIR}/${ARCHIVE_NAME}.tar.gz" \
    --transform="s/^${BASENAME}/${ARCHIVE_NAME}/" \
    --exclude="*.pyc" \
    --exclude="*.pyo" \
    --exclude="__pycache__" \
    --exclude=".pytest_cache" \
    --exclude=".git" \
    --exclude="*.egg-info" \
    --exclude="dist" \
    --exclude="build" \
    --exclude=".env" \
    "${BASENAME}"

TAR_EXIT=$?

if [[ ${TAR_EXIT} -ne 0 ]]; then
    echo "ERROR: tar failed with exit code ${TAR_EXIT}" >&2
    exit 1
fi

echo "[4/4] Verifying archive..."
ARCHIVE_PATH="${OUTPUT_DIR}/${ARCHIVE_NAME}.tar.gz"
if [[ ! -f "${ARCHIVE_PATH}" ]]; then
    echo "ERROR: Archive not found at expected path: ${ARCHIVE_PATH}" >&2
    exit 1
fi

ARCHIVE_SIZE=$(du -h "${ARCHIVE_PATH}" | cut -f1)
FILE_COUNT=$(tar tzf "${ARCHIVE_PATH}" | wc -l)

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║   PACKAGING COMPLETE                                        ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║   Archive : ${ARCHIVE_NAME}.tar.gz"
echo "║   Size    : ${ARCHIVE_SIZE}"
echo "║   Files   : ${FILE_COUNT}"
echo "║   Path    : ${ARCHIVE_PATH}"
echo "╚══════════════════════════════════════════════════════════════╝"

exit 0
