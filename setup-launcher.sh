#!/usr/bin/env bash
set -e

# Change to script directory
cd "$(dirname "$0")"

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

# 3. Verification Pre-Flight Check
if [ "$1" = "--verify" ] || [ "$1" = "--test" ] || [ "$EJII_RUN_FULL_TESTS" = "1" ]; then
    echo ""
    echo "[INFO] Running Deep Zero-Simulation Verification Test Battery..."
    PREFLIGHT_DIR=$(mktemp -d 2>/dev/null || mktemp -d -t 'ejii_preflight')
    NODE_ENV=test EJII_DATA_DIR="$PREFLIGHT_DIR" node src/db/seed.js >/dev/null 2>&1
    TEST_EXIT_CODE=0
    NODE_ENV=test EJII_DATA_DIR="$PREFLIGHT_DIR" node tests/run-all-tests.js || TEST_EXIT_CODE=$?
    rm -rf "$PREFLIGHT_DIR"
    if [ "$TEST_EXIT_CODE" -ne 0 ]; then
        echo "[ERROR] Test verification failed with exit code $TEST_EXIT_CODE. Halting startup."
        exit "$TEST_EXIT_CODE"
    fi
else
    # High-Speed Pre-Flight (< 150ms) for Instant Launch
    node scripts/verify-fast-preflight.js
    echo "[TIP] To run the full 153-suite deep regression battery, use: ./setup-launcher.sh --verify"
fi

# 4. Start Server
echo ""
echo "========================================================================"
echo "  Starting EJII NOC Workstation on http://localhost:8443"
echo "  Access Mode: Unprivileged NOC Operator Access"
echo "========================================================================"
export NODE_ENV=${NODE_ENV:-development}
if [ "$NODE_ENV" = "test" ]; then export NODE_ENV=development; fi

if [ "$1" = "--supervised" ]; then
    node scripts/ejii-supervisor.js
else
    node src/server.js
fi
