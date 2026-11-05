/**
 * Test Suite 21: Tool Sandbox & Security Hardening Verification
 * Verifies RBAC role hierarchy, schema validation, command injection defenses,
 * progressive PMTU sweep contract, and audit logging trails.
 */

'use strict';

const assert = require('node:assert/strict');
const { toolSandbox, ToolExecutionError } = require('../src/core/tool-sandbox');

async function runToolSandboxAndSecurityTests() {
  console.log('\n========================================================================');
  console.log('  SUITE 21: TOOL SANDBOX & SECURITY HARDENING VERIFICATION             ');
  console.log('  RBAC Hierarchy, Metacharacter Defense, Multi-Size PMTU & Audit Log   ');
  console.log('========================================================================');

  // 1. Tool Roster & Schema Verification
  console.log('[21.1] Testing Tool Sandbox Roster & Schema specifications...');
  const roster = toolSandbox.getToolRoster();
  assert.ok(Array.isArray(roster), 'Roster must be an array');
  assert.ok(roster.length >= 6, 'Must provide at least 6 diagnostic tools');

  const pmtuDef = roster.find(t => t.name === 'pmtu_sweep');
  assert.ok(pmtuDef, 'pmtu_sweep tool must be registered');
  assert.strictEqual(pmtuDef.requiredRole, 'ANALYST');
  assert.ok(pmtuDef.parameters.properties.sizes, 'pmtu_sweep must define sizes parameter');

  const pingDef = roster.find(t => t.name === 'ping');
  assert.strictEqual(pingDef.requiredRole, 'OPERATOR');
  console.log(`  ✓ Tool roster registered ${roster.length} tools with strict JSON schema properties.`);

  // 2. RBAC Access Control Enforcement
  console.log('[21.2] Testing RBAC role enforcement (READONLY vs OPERATOR vs ANALYST)...');
  
  // Test A: READONLY user attempting to execute ping (requires OPERATOR)
  await assert.rejects(
    async () => {
      await toolSandbox.executeTool('ping', { target: '127.0.0.1' }, { role: 'READONLY', username: 'auditor' });
    },
    (err) => {
      assert.strictEqual(err.statusCode, 403);
      assert.ok(err.message.includes('RBAC Violation'));
      return true;
    },
    'READONLY user must be forbidden from running ping'
  );

  // Test B: OPERATOR user attempting to execute pmtu_sweep (requires ANALYST)
  await assert.rejects(
    async () => {
      await toolSandbox.executeTool('pmtu_sweep', { target: '127.0.0.1' }, { role: 'OPERATOR', username: 'junior_tech' });
    },
    (err) => {
      assert.strictEqual(err.statusCode, 403);
      assert.ok(err.message.includes('RBAC Violation'));
      return true;
    },
    'OPERATOR user must be forbidden from running pmtu_sweep'
  );

  // Test C: ANALYST user allowed to execute pmtu_sweep schema check
  console.log('  ✓ RBAC permissions verified: READONLY and OPERATOR boundaries strictly enforced.');

  // 3. Command Injection & Malicious Input Defense
  console.log('[21.3] Testing command injection & dangerous metacharacter defenses...');
  const injectionPayloads = [
    '127.0.0.1; whoami',
    '127.0.0.1 && dir',
    '127.0.0.1 | type C:\\Windows\\win.ini',
    '127.0.0.1 `dir`',
    '127.0.0.1$(calc.exe)',
    '127.0.0.1\nwhoami',
    '127.0.0.1\r\ndir',
    '127.0.0.1 > out.txt',
    '127.0.0.1 < in.txt'
  ];

  for (const payload of injectionPayloads) {
    await assert.rejects(
      async () => {
        await toolSandbox.executeTool('ping', { target: payload }, { role: 'ADMIN', username: 'attacker' });
      },
      (err) => {
        assert.ok(
          err.message.includes('Security rejection') || err.message.includes('Dangerous characters') || err.message.includes('Invalid hostname'),
          `Payload "${payload}" must trigger security rejection, got: ${err.message}`
        );
        return true;
      },
      `Payload "${payload}" should have been rejected`
    );
  }
  console.log(`  ✓ All ${injectionPayloads.length} command injection variants neutralized.`);

  // 4. Progressive PMTU Multi-Size Sweep Contract
  console.log('[21.4] Testing progressive PMTU sweep contract against loopback...');
  const pingRes = await toolSandbox.executeTool('ping', {
    target: '127.0.0.1',
    count: 1
  }, { role: 'OPERATOR', username: 'noc-engineer' });
  assert.ok(pingRes.result);

  const sweepRes = await toolSandbox.executeTool('pmtu_sweep', {
    target: '127.0.0.1',
    sizes: [1472, 1400, 1200, 576],
    timeout: 1000
  }, { role: 'ANALYST', username: 'noc-engineer' });

  assert.ok(sweepRes.result, 'Sweep must return result');
  assert.ok(Array.isArray(sweepRes.result.sweep), 'Sweep results must be an array');
  assert.strictEqual(sweepRes.result.sweep.length, 4, 'Must have evaluated 4 payload sizes');
  assert.ok(typeof sweepRes.result.maxSupportedWireMtu === 'number');
  assert.ok(sweepRes.result.evidence.pmtuSweepExecuted);
  assert.strictEqual(sweepRes.result.evidence.mtuSize, sweepRes.result.maxSupportedWireMtu);
  console.log(`  ✓ PMTU multi-size sweep verified: ${sweepRes.result.sweep.length} steps evaluated (Wire MTU: ${sweepRes.result.maxSupportedWireMtu}).`);

  // 5. Bounded Audit Log Trail
  console.log('[21.5] Testing bounded audit log trail...');
  const auditEntries = toolSandbox.getAuditLog(10);
  assert.ok(Array.isArray(auditEntries), 'Audit log must be an array');
  assert.ok(auditEntries.length >= 2, `Audit log must record executions, got ${auditEntries.length}`);

  const latest = auditEntries[0]; // Most recent first
  assert.ok(latest.timestamp, 'Audit record must have timestamp');
  assert.ok(latest.user, 'Audit record must have user info');
  assert.ok(latest.tool, 'Audit record must have tool name');
  assert.ok(typeof latest.durationMs === 'number', 'Audit record must have execution duration');
  console.log(`  ✓ Audit trail verified: latest action "${latest.tool}" recorded by user "${latest.user}" (${latest.role}).`);

  console.log('\n>>> ALL SUITE 21 TOOL SANDBOX & SECURITY TESTS COMPLETED SUCCESSFULLY.\n');
}

if (require.main === module) {
  runToolSandboxAndSecurityTests().then(() => {
    process.exit(0);
  }).catch((err) => {
    console.error('Suite 21 failed:', err);
    process.exit(1);
  });
}

module.exports = { runToolSandboxAndSecurityTests };
