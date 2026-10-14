#!/usr/bin/env bash
set -e

echo "========================================================================"
echo "  EJII - Eldar Jamiyev's Infrastructure Intelligence Platform"
echo "  Production Setup & Operational Launcher (POSIX/Linux)"
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

# 3. Run Automated Verification Test Suite
echo ""
echo "[INFO] Running Zero-Simulation Automated Verification Test Suite..."
node tests/run-all-tests.js

# 4. Start Server
echo ""
echo "========================================================================"
echo "  Starting EJII Enterprise Server on http://localhost:8443"
echo "========================================================================"
node src/server.js
