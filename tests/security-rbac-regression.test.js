/**
 * Test Suite 23: Security & RBAC Hostile Regression Test Suite
 * Explicitly attacks and verifies that:
 * 1. Unauthenticated requests are rejected with 401.
 * 2. Spoofed headers (X-EJII-Role: ADMIN) are completely ignored.
 * 3. Verified session tokens govern authorization.
 * 4. Role hierarchy and permission boundaries in middleware.js are strictly enforced.
 */

'use strict';

const assert = require('node:assert/strict');
const http = require('http');
const express = require('express');
const { generateToken } = require('../src/core/security');
const { requireRole, requirePermission } = require('../src/api/middleware');
const toolsRouter = require('../src/api/routes-tools');

async function runSecurityRbacRegressionTests() {
  console.log('\n========================================================================');
  console.log('  SUITE 23: SECURITY & RBAC HOSTILE REGRESSION TEST SUITE               ');
  console.log('  Zero-Trust Identity, Header Spoofing Attack Defense & Role Enforcement');
  console.log('========================================================================');

  // 1. Direct Unit Verification of requireRole Middleware
  console.log('[23.1] Testing requireRole middleware with role hierarchy...');
  
  // Test A: Unauthenticated request (no req.user)
  let statusCaptured = null;
  let jsonCaptured = null;
  const mockRes = {
    status: (code) => {
      statusCaptured = code;
      return {
        json: (data) => { jsonCaptured = data; }
      };
    }
  };

  const adminGuard = requireRole('ADMIN');
  let nextCalled = false;
  adminGuard({ headers: {} }, mockRes, () => { nextCalled = true; });
  assert.strictEqual(statusCaptured, 401, 'Unauthenticated request must receive 401');
  assert.strictEqual(nextCalled, false, 'next() must NOT be called for unauthenticated request');
  console.log('  ✓ Unauthenticated caller blocked with 401.');

  // Test B: READONLY user attempting to access OPERATOR-guarded endpoint
  const operatorGuard = requireRole('OPERATOR');
  nextCalled = false;
  statusCaptured = null;
  operatorGuard({ user: { role: 'READONLY', username: 'auditor' } }, mockRes, () => { nextCalled = true; });
  assert.strictEqual(statusCaptured, 403, 'READONLY user must receive 403 on OPERATOR route');
  assert.strictEqual(nextCalled, false);
  console.log('  ✓ READONLY user blocked from OPERATOR route with 403.');

  // Test C: OPERATOR user attempting to access ADMIN route
  nextCalled = false;
  statusCaptured = null;
  adminGuard({ user: { role: 'OPERATOR', username: 'junior_tech' } }, mockRes, () => { nextCalled = true; });
  assert.strictEqual(statusCaptured, 403, 'OPERATOR user must receive 403 on ADMIN route');
  assert.strictEqual(nextCalled, false);
  console.log('  ✓ OPERATOR user blocked from ADMIN route with 403.');

  // Test D: ADMIN user allowed on OPERATOR route (Hierarchy: ADMIN >= OPERATOR)
  nextCalled = false;
  operatorGuard({ user: { role: 'ADMIN', username: 'sec_admin' } }, mockRes, () => { nextCalled = true; });
  assert.strictEqual(nextCalled, true, 'ADMIN must be permitted on OPERATOR route');
  console.log('  ✓ Role hierarchy inheritance verified (ADMIN inherits OPERATOR permissions).');

  // 2. Hostile Red-Team HTTP Attack on /api/tools Endpoints
  console.log('[23.2] Attacking /api/tools with spoofed headers and forged requests...');

  const { db } = require('../src/db/database');
  const insertUser = db.prepare(`
    INSERT OR REPLACE INTO users (id, username, password_hash, salt, full_name, role, is_active, created_at)
    VALUES (?, ?, 'fake_hash', 'fake_salt', ?, ?, 1, datetime('now'))
  `);
  insertUser.run('TEST-RO-01', 'readonly_user', 'Read Only User', 'readonly');
  insertUser.run('TEST-OP-01', 'operator_user', 'Operator User', 'operator');
  insertUser.run('TEST-AN-01', 'analyst_user', 'Analyst User', 'analyst');

  const app = express();
  app.use(express.json());
  app.use('/api/tools', toolsRouter);

  const server = http.createServer(app);
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  const baseUrl = `http://127.0.0.1:${port}/api/tools`;

  try {
    // Attack 1: Unauthenticated caller sending X-EJII-Role: ADMIN header
    console.log('  -> Attack 1: Spoofed X-EJII-Role: ADMIN without token...');
    const resAttack1 = await fetch(`${baseUrl}/execute`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-EJII-Role': 'ADMIN',
        'X-EJII-User': 'evil_attacker'
      },
      body: JSON.stringify({ tool: 'pmtu_sweep', params: { target: '127.0.0.1' } })
    });
    assert.strictEqual(resAttack1.status, 401, 'Unauthenticated spoofed header MUST be rejected with 401');
    const attack1Data = await resAttack1.json();
    assert.ok(attack1Data.error.includes('Authentication required'));
    console.log('  ✓ Attack 1 defeated: 401 Unauthorized returned.');

    // Attack 2: Authenticated READONLY user trying to spoof X-EJII-Role: ADMIN
    console.log('  -> Attack 2: Valid READONLY token attempting X-EJII-Role: ADMIN privilege escalation...');
    const readonlyToken = generateToken({ id: 'TEST-RO-01', username: 'readonly_user', role: 'readonly' });
    const resAttack2 = await fetch(`${baseUrl}/execute`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${readonlyToken}`,
        'X-EJII-Role': 'ADMIN' // Malicious attempt to override token role
      },
      body: JSON.stringify({ tool: 'ping', params: { target: '127.0.0.1', count: 1 } })
    });
    assert.strictEqual(resAttack2.status, 403, 'READONLY user must be rejected with 403 despite sending X-EJII-Role: ADMIN');
    const attack2Data = await resAttack2.json();
    assert.ok(attack2Data.error.includes('RBAC Violation') || attack2Data.error.includes('Access denied'));
    console.log('  ✓ Attack 2 defeated: X-EJII-Role ignored, verified token role READONLY strictly enforced (403 Forbidden).');

    // Attack 3: Authenticated OPERATOR user attempting to run ANALYST tool (pmtu_sweep) with spoofed ADMIN header
    console.log('  -> Attack 3: Valid OPERATOR token attempting to run pmtu_sweep with spoofed ADMIN header...');
    const operatorToken = generateToken({ id: 'TEST-OP-01', username: 'operator_user', role: 'operator' });
    const resAttack3 = await fetch(`${baseUrl}/execute`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${operatorToken}`,
        'X-EJII-Role': 'ADMIN'
      },
      body: JSON.stringify({ tool: 'pmtu_sweep', params: { target: '127.0.0.1' } })
    });
    assert.strictEqual(resAttack3.status, 403, 'OPERATOR user must be denied 403 on pmtu_sweep despite spoofed header');
    console.log('  ✓ Attack 3 defeated: OPERATOR blocked from ANALYST tool (403 Forbidden).');

    // Legit 1: Authenticated OPERATOR user running ping (permitted)
    console.log('  -> Legit 1: Valid OPERATOR token executing permitted tool (ping)...');
    const resLegit1 = await fetch(`${baseUrl}/execute`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${operatorToken}`
      },
      body: JSON.stringify({ tool: 'ping', params: { target: '127.0.0.1', count: 1 } })
    });
    assert.strictEqual(resLegit1.status, 200, 'OPERATOR must be allowed to execute ping');
    const legit1Data = await resLegit1.json();
    assert.strictEqual(legit1Data.success, true);
    console.log('  ✓ Legit 1 verified: OPERATOR successfully executed permitted tool.');

    // Legit 2: Authenticated ANALYST user viewing audit log
    console.log('  -> Legit 2: Valid ANALYST token accessing audit trail...');
    const analystToken = generateToken({ id: 'TEST-AN-01', username: 'analyst_user', role: 'analyst' });
    const resLegit2 = await fetch(`${baseUrl}/audit`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${analystToken}`
      }
    });
    assert.strictEqual(resLegit2.status, 200, 'ANALYST must be permitted to access audit log');
    const legit2Data = await resLegit2.json();
    assert.strictEqual(legit2Data.success, true);
    console.log('  ✓ Legit 2 verified: ANALYST successfully retrieved audit trail.');

  } finally {
    await new Promise(resolve => server.close(resolve));
  }

  console.log('\n>>> ALL SUITE 23 SECURITY & RBAC HOSTILE REGRESSION TESTS PASSED (ZERO EXPLOITS).\n');
}

if (require.main === module) {
  runSecurityRbacRegressionTests().catch((err) => {
    console.error('Suite 23 failed:', err);
    process.exit(1);
  });
}

module.exports = { runSecurityRbacRegressionTests };
