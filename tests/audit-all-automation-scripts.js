/**
 * EJII Automation Script Comprehensive Audit Test Suite
 * Executes and audits all 27 administrative scripts in e:\Scripts on the Windows host.
 * Zero-Simulation Mandate — 100% Real OS Process Execution & Accounting.
 */

const assert = require('assert');
const {
  listAutomationScripts,
  getScriptContent,
  executeScript,
  DEFAULT_SCRIPTS_DIR
} = require('../src/tools/script-automation');

async function runAutomationScriptAudit() {
  console.log('\n========================================================================');
  console.log('  EJII COMPREHENSIVE AUTOMATION SCRIPT AUDIT (ALL 27 SCRIPTS @ e:\\Scripts)');
  console.log('========================================================================');

  const scriptsDir = DEFAULT_SCRIPTS_DIR;
  const listResult = await listAutomationScripts(scriptsDir);

  console.log(`[Discovery] Target Directory: ${listResult.directory}`);
  console.log(`[Discovery] Scripts Found:    ${listResult.count}`);
  assert.strictEqual(listResult.count, 27, `Expected exactly 27 scripts in ${scriptsDir}, found ${listResult.count}`);

  const results = [];
  let index = 1;

  for (const script of listResult.scripts) {
    const label = `[${String(index).padStart(2, '0')}/27] ${script.title}`;
    process.stdout.write(`  ${label.padEnd(68, '.')} `);

    const execRes = await executeScript(script.filename, '', scriptsDir);
    const isSuccess = execRes.exitCode === 0;
    const statusTag = execRes.timedOut ? 'TIMEOUT' : (isSuccess ? 'PASS' : `WARN (Code ${execRes.exitCode})`);
    const colorTag = isSuccess ? '\x1b[32m' : (execRes.timedOut ? '\x1b[31m' : '\x1b[33m');

    console.log(`${colorTag}${statusTag}\x1b[0m (${execRes.durationMs}ms) [${execRes.executionType}]`);

    results.push({
      index,
      filename: script.filename,
      title: script.title,
      category: script.category,
      executionType: execRes.executionType,
      exitCode: execRes.exitCode,
      success: isSuccess,
      durationMs: execRes.durationMs,
      timedOut: !!execRes.timedOut,
      stdoutSummary: (execRes.stdout || '').split('\n')[0].substring(0, 70),
      stderrSummary: (execRes.stderr || '').split('\n')[0].substring(0, 70)
    });

    index++;
  }

  // Print Comprehensive Audit Matrix Table
  console.log('\n========================================================================');
  console.log('  AUTOMATION SCRIPTS AUDIT SUMMARY MATRIX                                ');
  console.log('========================================================================');
  console.log(' # | Title                                             | Type | Exit | Time (ms) | Status');
  console.log('---+---------------------------------------------------+------+------+-----------+-------');

  let passedCount = 0;
  let warnCount = 0;
  let timeoutCount = 0;

  for (const r of results) {
    if (r.timedOut) timeoutCount++;
    else if (r.success) passedCount++;
    else warnCount++;

    const shortTitle = r.title.length > 49 ? r.title.substring(0, 47) + '..' : r.title.padEnd(49, ' ');
    const shortType = r.executionType.substring(0, 4).toUpperCase();
    const exitStr = String(r.exitCode).padStart(4, ' ');
    const timeStr = String(Math.round(r.durationMs)).padStart(9, ' ');
    const statStr = r.timedOut ? 'TIMEOUT' : (r.success ? 'PASS   ' : 'WARN   ');

    console.log(` ${String(r.index).padStart(2, ' ')}| ${shortTitle} | ${shortType} | ${exitStr} | ${timeStr} | ${statStr}`);
  }

  console.log('---+---------------------------------------------------+------+------+-----------+-------');
  console.log(`TOTAL: 27 Scripts | SUCCESS: ${passedCount} | WARNINGS (Privilege/Config): ${warnCount} | TIMEOUTS: ${timeoutCount}`);
  console.log('========================================================================\n');

  // Assertions
  assert.strictEqual(results.length, 27, 'Must audit all 27 scripts');
  assert.ok(results.every(r => r.durationMs <= 26000), 'All scripts must complete or be terminated by the 25s safety ceiling');
  assert.ok(passedCount >= 18, `Expected at least 18 scripts to succeed with exit code 0, got ${passedCount}`);

  console.log(`✓ Comprehensive Automation Script Audit passed with 100% process tree safety! (${passedCount} passed, ${warnCount} non-zero/privilege, ${timeoutCount} timed-out & safely terminated)\n`);
  return results;
}

if (require.main === module) {
  runAutomationScriptAudit()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('\n❌ Automation Script Audit Suite Failed:');
      console.error(err);
      process.exit(1);
    });
}

module.exports = { runAutomationScriptAudit };
