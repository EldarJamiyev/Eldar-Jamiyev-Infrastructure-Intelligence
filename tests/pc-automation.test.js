/**
 * EJII Test Suite: Local PC Automation Bridge (e:\Scripts)
 * Verifies real file system access, metadata extraction, path traversal defense, and script execution.
 * Zero-Simulation Mandate.
 */

const assert = require('assert');
const path = require('path');
const fs = require('fs');
const {
  listAutomationScripts,
  getScriptContent,
  executeScript,
  resolveScriptPath,
  getActiveScriptsDirectory,
  scriptAutomation
} = require('../src/tools/script-automation');

async function runPcAutomationTests() {
  console.log('\n========================================================================');
  console.log('  TEST SUITE: LOCAL PC AUTOMATION (BAT FILES @ e:\\Scripts)              ');
  console.log('========================================================================');

  // [Test 1] Read real e:\Scripts directory and inspect metadata (Portable Mount Mode)
  const SCRIPTS_DIR = typeof scriptAutomation.getActiveScriptsDirectory === 'function'
    ? scriptAutomation.getActiveScriptsDirectory()
    : (fs.existsSync('e:\\Scripts') ? 'e:\\Scripts' : path.resolve(__dirname, '../data/scripts_mount/Scripts'));

  console.log(`[Test 1] Scanning ${SCRIPTS_DIR} directory on host machine (Portable Mount Mode)...`);
  assert.strictEqual(fs.existsSync(SCRIPTS_DIR), true, `Active scripts directory (${SCRIPTS_DIR}) must exist on this host`);

  const result = await listAutomationScripts(SCRIPTS_DIR);
  
  assert.ok(result.exists, `Active scripts directory (${SCRIPTS_DIR}) must exist on this host`);
  assert.ok(result.count >= 20, `Expected at least 20 automation scripts, found: ${result.count}`);
  console.log(`  ✓ Successfully enumerated ${result.count} automation scripts from ${result.directory}.`);

  // Verify categories
  const categories = new Set(result.scripts.map(s => s.category));
  assert.ok(categories.has('Network & DNS Stack'), 'Must have Network & DNS Stack scripts');
  assert.ok(categories.has('System Diagnostics & Health'), 'Must have System Diagnostics & Health scripts');
  console.log(`  ✓ Auto-categorized scripts into ${categories.size} distinct operational badges.`);

  // [Test 2] Verify Path Traversal Attack Defense
  console.log('[Test 2] Testing Path Traversal Attack Defense...');
  const maliciousPaths = [
    '../../Windows/System32',
    '..\\..\\Windows\\System32',
    '/etc/passwd',
    '..\\boot.ini',
    'subfolder/../../secret.txt',
    'script.bat\0.txt'
  ];

  for (const badPath of maliciousPaths) {
    assert.throws(
      () => resolveScriptPath(badPath),
      (err) => err.code === 'TRAVERSAL_ATTEMPT' || err.message.includes('Path traversal') || err.message.includes('Access denied'),
      `Path traversal "${badPath}" must be strictly rejected`
    );
  }
  console.log('  ✓ 100% of directory traversal attacks safely blocked.');

  // [Test 3] Test getScriptContent for code inspection
  console.log('[Test 3] Testing Script Code Inspection (/api/network/automation/view)...');
  const targetScript = result.scripts.find(s => s.filename.includes('Uptime') || s.filename.includes('DNS'));
  assert.ok(targetScript, 'Target script for inspection must exist');

  const inspected = await getScriptContent(targetScript.filename);
  assert.strictEqual(inspected.filename, targetScript.filename);
  assert.ok(inspected.content && inspected.content.length > 0, 'Script content must not be empty');
  assert.ok(inspected.executionType === 'powershell' || inspected.executionType === 'batch');
  console.log(`  ✓ Inspected "${inspected.title}": ${inspected.sizeBytes} B, Type: [${inspected.executionType}].`);

  // [Test 4] Real Host Execution of Non-Destructive Telemetry Script
  console.log('[Test 4] Executing non-destructive telemetry script against host Windows OS...');
  const uptimeScript = result.scripts.find(s => s.filename.includes('Uptime'));
  assert.ok(uptimeScript, 'Identify System Uptime script must exist in e:\\Scripts');

  const execRes = await executeScript(uptimeScript.filename);
  assert.strictEqual(execRes.exitCode, 0, 'Uptime script must exit with code 0');
  assert.strictEqual(execRes.success, true, 'Execution must succeed');
  assert.ok(execRes.stdout.includes('LastBootUpTime') || execRes.stdout.includes('Days'), 'Output must contain real system telemetry');
  assert.ok(execRes.durationMs > 0, 'Execution duration must be non-zero');
  console.log(`  ✓ Real host script executed in ${execRes.durationMs}ms with Exit Code: 0 [SUCCESS].`);
  console.log(`    Sample Output: ${execRes.stdout.split('\n')[0]}`);

  // [Test 5] Test Router Endpoints
  console.log('[Test 5] Testing Express Router Endpoints (/api/network/automation/*)...');
  const routesNetwork = require('../src/api/routes-network');
  
  // Test /automation/scripts handler
  const scriptsLayer = routesNetwork.stack.find(l => l.route && l.route.path === '/automation/scripts');
  assert.ok(scriptsLayer, 'Route /automation/scripts must exist');

  let scriptsPayload = null;
  await new Promise((resolve) => {
    scriptsLayer.route.stack[0].handle({}, {
      json: (data) => {
        scriptsPayload = data;
        resolve();
      },
      status: () => ({ json: resolve })
    });
  });
  assert.ok(scriptsPayload && scriptsPayload.count >= 20, 'Route must return 20+ scripts');
  console.log(`  ✓ Endpoint GET /api/network/automation/scripts verified: ${scriptsPayload.count} scripts.`);

  console.log('\n========================================================================');
  console.log('  ALL LOCAL PC AUTOMATION TESTS PASSED 100% GREEN!                      ');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runPcAutomationTests().then(() => process.exit(0)).catch(err => {
    console.error('Automation test suite failed:', err);
    process.exit(1);
  });
}

module.exports = { runPcAutomationTests };
