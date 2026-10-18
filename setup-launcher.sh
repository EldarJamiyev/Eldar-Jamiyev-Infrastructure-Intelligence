#!/usr/bin/env bash
set -e

echo "========================================================================"
echo "  EJII - Eldar Jamiyev's Infrastructure Intelligence"
echo "  NOC Topology & Wire-Level Packet Dissection Workstation (POSIX/Linux)"
echo "  Unprivileged Operator Workstation (Zero Administrative Elevation)"
echo "========================================================================"
echo ""

# 1. Check Node.js
if ! command -v node &> /dev/null; then
    echo "[ERROR] Node.js is not installed or not in PATH."
    exit 1
fi
echo "[OK] Detected Node.js: $(node -v)"

# 2. Check Dependencies
if [ ! -d "node_modules" ]; then
    echo "[INFO] Installing required dependencies..."
    npm install --no-audit --no-fund
else
    echo "[OK] Node modules verified."
fi

# 3. Run Automated Verification Test Suite (Strictly Isolated Pre-Flight Environment)
echo ""
echo "[INFO] Running Zero-Simulation Automated Verification Test Suite..."
PREFLIGHT_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t 'ejii_preflight')
EJII_DATA_DIR="$PREFLIGHT_DIR" node src/db/seed.js >/dev/null 2>&1
NODE_ENV=test EJII_DATA_DIR="$PREFLIGHT_DIR" node tests/run-all-tests.js
rm -rf "$PREFLIGHT_DIR"

# 4. Start Server
echo ""
echo "========================================================================"
echo "  Starting EJII NOC Workstation on http://localhost:8443"
echo "  Access Mode: Unprivileged NOC Operator Access"
echo "========================================================================"
export NODE_ENV=${NODE_ENV:-development}
if [ "$NODE_ENV" = "test" ]; then export NODE_ENV=development; fi
node src/server.js
