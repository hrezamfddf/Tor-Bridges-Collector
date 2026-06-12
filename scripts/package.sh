#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════
# Tor-Bridges-Collector — Build & Package Script
# ══════════════════════════════════════════════════════════════════════════
# Creates a tar.gz archive of the project with the specified naming.
# Excludes build artifacts, caches, and sensitive files.
# ══════════════════════════════════════════════════════════════════════════

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PROJECT_NAME="Tor-Bridges-Collector"
TAR_NAME="${PROJECT_NAME}-main-ultra-quantum-vip-vip-super-ultra-vip-ultra-quantum-ultra-vip-ultra-quantum-ultra-quantum-vip-fg-ds-ddhd-ghj-vgg-vggggh.tar.gz"

echo "═══════════════════════════════════════════════════════════════════════"
echo "  Tor-Bridges-Collector — Build & Package"
echo "═══════════════════════════════════════════════════════════════════════"
echo ""
echo "  Project root: ${PROJECT_ROOT}"
echo "  Archive name: ${TAR_NAME}"
echo ""

# Step 1: Syntax check all Python files
echo "── Step 1: Python syntax check ─────────────────────────────────────"
PASS=0
FAIL=0
while IFS= read -r -d '' f; do
    if python3 -m py_compile "$f" 2>/dev/null; then
        PASS=$((PASS + 1))
    else
        echo "  ✗ SYNTAX ERROR: $f"
        python3 -m py_compile "$f" 2>&1 || true
        FAIL=$((FAIL + 1))
    fi
done < <(find "${PROJECT_ROOT}" -name '*.py' -not -path '*/vendor/*' -not -path '*/.git/*' -not -path '*/node_modules/*' -print0 2>/dev/null | sort -z)
echo "  ✓ Passed: ${PASS}  ✗ Failed: ${FAIL}"
if [ "$FAIL" -gt 0 ]; then
    echo "  ⚠ WARNING: ${FAIL} Python file(s) have syntax errors!"
    echo "  Continuing with packaging anyway (errors should be fixed before release)."
fi
echo ""

# Step 2: Create the archive
echo "── Step 2: Creating tar.gz archive ─────────────────────────────────"
cd "${PROJECT_ROOT}"

# Create archive in the download directory
OUTPUT_DIR="${PROJECT_ROOT}/../download"
mkdir -p "${OUTPUT_DIR}"

tar -czf "${OUTPUT_DIR}/${TAR_NAME}" \
    --exclude='.git' \
    --exclude='__pycache__' \
    --exclude='*.pyc' \
    --exclude='*.pyo' \
    --exclude='.env' \
    --exclude='.venv' \
    --exclude='venv' \
    --exclude='node_modules' \
    --exclude='.mypy_cache' \
    --exclude='.pytest_cache' \
    --exclude='.tox' \
    --exclude='*.egg-info' \
    --exclude='dist' \
    --exclude='build' \
    --exclude='data/*.json' \
    --exclude='export/*' \
    --exclude='bridge/*' \
    --exclude='reports/coverage' \
    --exclude='*.tar.gz' \
    --exclude='*.zip' \
    --transform "s|^|${PROJECT_NAME}-main/|" \
    .

echo "  ✓ Archive created: ${OUTPUT_DIR}/${TAR_NAME}"
echo ""

# Step 3: Verify the archive
echo "── Step 3: Verifying archive ───────────────────────────────────────"
if [ -f "${OUTPUT_DIR}/${TAR_NAME}" ]; then
    FILESIZE=$(stat -f%z "${OUTPUT_DIR}/${TAR_NAME}" 2>/dev/null || stat -c%s "${OUTPUT_DIR}/${TAR_NAME}" 2>/dev/null || echo "unknown")
    echo "  ✓ File exists"
    echo "  ✓ File size: ${FILESIZE} bytes"

    # List top-level contents
    echo "  ✓ Top-level contents:"
    tar -tzf "${OUTPUT_DIR}/${TAR_NAME}" 2>/dev/null | head -20 | sed 's/^/    /' || true

    # Count files
    FILE_COUNT=$(tar -tzf "${OUTPUT_DIR}/${TAR_NAME}" 2>/dev/null | wc -l | tr -d ' ')
    echo "  ✓ Total entries: ${FILE_COUNT}"
else
    echo "  ✗ Archive file NOT found!"
    exit 1
fi
echo ""

# Step 4: Compute checksums
echo "── Step 4: Checksums ───────────────────────────────────────────────"
cd "${OUTPUT_DIR}"
if command -v sha256sum &>/dev/null; then
    sha256sum "${TAR_NAME}"
elif command -v shasum &>/dev/null; then
    shasum -a 256 "${TAR_NAME}"
else
    echo "  ⚠ No sha256sum/shasum available — skipping checksum"
fi
echo ""

echo "═══════════════════════════════════════════════════════════════════════"
echo "  ✓ Package complete!"
echo "  Output: ${OUTPUT_DIR}/${TAR_NAME}"
echo "═══════════════════════════════════════════════════════════════════════"
