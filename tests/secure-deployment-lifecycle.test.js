/**
 * Test Suite 30: Secure Deployment Lifecycle & Isolated Clean Initialization
 * Verifies:
 *   1. Fail-closed production secret enforcement (NODE_ENV=production rejects missing/default/<32-char secrets).
 *   2. Clean first-run initialization against an isolated empty $EJII_DATA_DIR.
 *   3. Custom EJII_ADMIN_PASSWORD honoring during clean first boot.
 *   4. Password persistence across idempotent restarts (prevents credential reversion to defaults).
 *   5. Action token replay defense and audit persistence across simulated restart in isolated data dir.
 *   6. Dual-layer HMAC audit trail integrity and cryptographic tamper detection.
 */

'use strict';

const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { spawnSync } = require('child_process');
const crypto = require('crypto');

async function runSecureDeploymentLifecycleTests() {
  console.log('\n========================================================================');
  console.log('  SUITE 30: SECURE DEPLOYMENT LIFECYCLE & CLEAN INITIALIZATION AUDIT    ');
  console.log('  Production Secrets, First-Run Bootstrap, Password Persistence & Replay');
  console.log('========================================================================');

  // TEMPORARY DELIBERATE FAULT INJECTION FOR TEST-RUNNER INTEGRITY VERIFICATION
  assert.equal(process.env.EJII_TEST_INDUCED_FAULT ? 1 : 0, 1, 'DELIBERATE_TEST_RUNNER_INTEGRITY_FAULT: Verifying test runner exits with code 1 on failed assertion');

  const rootDir = path.resolve(__dirname, '..');
  const tempBase = fs.mkdtempSync(path.join(os.tmpdir(), 'ejii-lifecycle-test-'));

  try {
    // -------------------------------------------------------------------------
    // TEST 1: Fail-Closed Production Secret Enforcement
    // -------------------------------------------------------------------------
    console.log('[30.1] Verifying fail-closed production secret enforcement (NODE_ENV=production)...');

    // 1a. Missing secrets in production must throw and exit non-zero
    const procMissing = spawnSync(process.execPath, [
      '-e', 'require("./src/config.js")'
    ], {
      cwd: rootDir,
      env: {
        ...process.env,
        NODE_ENV: 'production',
        EJII_HMAC_SECRET: '',
        EJII_JWT_SECRET: ''
      },
      encoding: 'utf8'
    });
    assert.notEqual(procMissing.status, 0, 'Production boot without secrets must fail non-zero');
    assert.match(procMissing.stderr, /FATAL CONFIGURATION ERROR/i, 'Must emit fatal configuration error');
    console.log('  ✓ Production boot without secrets strictly failed with fatal error.');

    // 1b. Default secrets in production must fail closed
    const procDefault = spawnSync(process.execPath, [
      '-e', 'require("./src/config.js")'
    ], {
      cwd: rootDir,
      env: {
        ...process.env,
        NODE_ENV: 'production',
        EJII_HMAC_SECRET: 'EJII-ENTERPRISE-INTELLIGENCE-HMAC-SECURE-KEY-2026',
        EJII_JWT_SECRET: 'EJII-ENTERPRISE-TOKEN-KEY-98471298471928471'
      },
      encoding: 'utf8'
    });
    assert.notEqual(procDefault.status, 0, 'Production boot with default secrets must fail non-zero');
    assert.match(procDefault.stderr, /Refusing to boot with missing or insecure default secret/i);
    console.log('  ✓ Production boot with hardcoded fallback secrets strictly rejected.');

    // 1c. Short secrets (< 32 chars) in production must fail closed
    const procShort = spawnSync(process.execPath, [
      '-e', 'require("./src/config.js")'
    ], {
      cwd: rootDir,
      env: {
        ...process.env,
        NODE_ENV: 'production',
        EJII_HMAC_SECRET: 'short-secret-under-32-chars',
        EJII_JWT_SECRET: 'short-secret-under-32-chars'
      },
      encoding: 'utf8'
    });
    assert.notEqual(procShort.status, 0, 'Production boot with secrets < 32 chars must fail non-zero');
    assert.match(procShort.stderr, /must be explicitly configured with at least 32 characters/i);
    console.log('  ✓ Production boot with secrets < 32 chars strictly rejected.');

    // 1d. Valid 32+ char custom production secrets must succeed
    const procValid = spawnSync(process.execPath, [
      '-e', 'require("./src/config.js"); console.log("CONFIG_VALIDATED_SUCCESSFULLY");'
    ], {
      cwd: rootDir,
      env: {
        ...process.env,
        NODE_ENV: 'production',
        EJII_HMAC_SECRET: 'SUPER-SECURE-PRODUCTION-HMAC-KEY-OF-HIGH-ENTROPY-2026',
        EJII_JWT_SECRET: 'SUPER-SECURE-PRODUCTION-JWT-SECRET-OF-HIGH-ENTROPY-2026'
      },
      encoding: 'utf8'
    });
    assert.equal(procValid.status, 0, 'Production boot with valid secrets must succeed');
    assert.match(procValid.stdout, /CONFIG_VALIDATED_SUCCESSFULLY/);
    console.log('  ✓ Production boot with valid high-entropy secrets succeeded.');

    // -------------------------------------------------------------------------
    // TEST 2: Clean First-Run Initialization against Empty $EJII_DATA_DIR
    // -------------------------------------------------------------------------
    console.log('\n[30.2] Testing clean first-run initialization against empty $EJII_DATA_DIR...');

    const isolatedDataDir = path.join(tempBase, 'clean-data');
    fs.mkdirSync(isolatedDataDir, { recursive: true });

    const customAdminPassword = 'CustomEnterpriseAdminPassword2026#Secure';

    const procSeedInit = spawnSync(process.execPath, [
      'src/db/seed.js'
    ], {
      cwd: rootDir,
      env: {
        ...process.env,
        NODE_ENV: 'test',
        EJII_DATA_DIR: isolatedDataDir,
        EJII_ADMIN_PASSWORD: customAdminPassword
      },
      encoding: 'utf8'
    });

    assert.equal(procSeedInit.status, 0, `Seeder failed on clean directory: ${procSeedInit.stderr}`);
    assert.match(procSeedInit.stdout, /Created Initial Account: \[admin\]/i);
    assert.match(procSeedInit.stdout, /Cryptographic Genesis Audit Log Initialized/i);

    const isolatedDbPath = path.join(isolatedDataDir, 'ejii.sqlite');
    assert.equal(fs.existsSync(isolatedDbPath), true, 'Isolated SQLite DB must be created');

    // Inspect database content using sqlite
    const { DatabaseSync } = require('node:sqlite');
    const isoDb = new DatabaseSync(isolatedDbPath);

    const usersCount = isoDb.prepare('SELECT COUNT(*) as cnt FROM users').get().cnt;
    assert.equal(usersCount, 4, 'Must seed exactly 4 NOC operator accounts');

    const adminUser = isoDb.prepare('SELECT * FROM users WHERE username = ?').get('admin');
    assert.equal(adminUser.role, 'ADMIN');

    // Verify custom admin password was used
    const { hashPassword, verifyPassword } = require('../src/core/security');
    assert.equal(verifyPassword(customAdminPassword, adminUser.password_hash, adminUser.salt), true, 'Admin account must authenticate with custom EJII_ADMIN_PASSWORD');

    const topoNodesCount = isoDb.prepare('SELECT COUNT(*) as cnt FROM topology_nodes').get().cnt;
    assert.ok(topoNodesCount > 0, 'Must seed baseline topology nodes');

    // Verify genesis audit record in DB
    const genesisDbLog = isoDb.prepare('SELECT * FROM audit_logs WHERE action = ?').get('SYSTEM_INITIALIZATION');
    assert.ok(genesisDbLog, 'Genesis audit entry must exist in SQLite audit_logs table');
    assert.equal(genesisDbLog.prev_hash, '0000000000000000000000000000000000000000000000000000000000000000');

    // Verify genesis audit record on disk in audit-trail.jsonl and .chain_head
    const auditFile = path.join(isolatedDataDir, 'audit', 'audit-trail.jsonl');
    const chainHeadFile = path.join(isolatedDataDir, 'audit', '.chain_head');
    assert.equal(fs.existsSync(auditFile), true, 'audit-trail.jsonl must exist on disk');
    assert.equal(fs.existsSync(chainHeadFile), true, '.chain_head anchor must exist on disk');

    const auditLines = fs.readFileSync(auditFile, 'utf8').trim().split('\n');
    assert.equal(auditLines.length, 1, 'Audit trail must contain genesis entry');
    const genesisRecord = JSON.parse(auditLines[0]);
    assert.equal(genesisRecord.action, 'SYSTEM_INITIALIZATION');
    assert.equal(genesisRecord.seq, 1);
    isoDb.close();

    console.log('  ✓ Clean first-run bootstrap completed: schema, accounts, custom admin password & genesis audit chain.');

    // -------------------------------------------------------------------------
    // TEST 3: Idempotent Restart & Password Persistence
    // -------------------------------------------------------------------------
    console.log('\n[30.3] Testing idempotent restart and password persistence (no password reversion)...');

    // Mutate the admin password in the isolated database (simulating user-initiated password change)
    const { hash: changedHash, salt: changedSalt } = hashPassword('ChangedAdminPassword999!');

    const isoDbMutate = new DatabaseSync(isolatedDbPath);
    isoDbMutate.prepare('UPDATE users SET password_hash = ?, salt = ? WHERE username = ?').run(changedHash, changedSalt, 'admin');
    isoDbMutate.close();

    // Re-run seed on the same data directory (simulating server restart)
    const procSeedRestart = spawnSync(process.execPath, [
      'src/db/seed.js'
    ], {
      cwd: rootDir,
      env: {
        ...process.env,
        NODE_ENV: 'test',
        EJII_DATA_DIR: isolatedDataDir
      },
      encoding: 'utf8'
    });

    assert.equal(procSeedRestart.status, 0, `Restart seeding failed: ${procSeedRestart.stderr}`);
    assert.match(procSeedRestart.stdout, /Synchronized Account: \[admin\] \(ADMIN\) \[Credentials Preserved\]/i);

    const isoDbVerify = new DatabaseSync(isolatedDbPath);
    const reloadedAdmin = isoDbVerify.prepare('SELECT password_hash, salt FROM users WHERE username = ?').get('admin');
    assert.equal(reloadedAdmin.password_hash, changedHash, 'Admin password must NOT be reverted back to default seed value!');
    assert.equal(reloadedAdmin.salt, changedSalt, 'Admin salt must NOT be overwritten');
    isoDbVerify.close();

    console.log('  ✓ Password persistence verified across server restart: credentials strictly preserved.');

    // -------------------------------------------------------------------------
    // TEST 4: Action Token Persistence & Replay Protection Across Restarts
    // -------------------------------------------------------------------------
    console.log('\n[30.4] Testing action token persistence and replay protection across restarts...');

    // Run a script to generate preview, execute remediation, and verify token recording
    const testScript = `
      const path = require('path');
      const { autonomousRemediationEngine } = require('./src/systems/remediation/autonomous-remediation-engine');
      
      async function main() {
        const preview = await autonomousRemediationEngine.executePreview('flush_dns', {}, { role: 'ADMIN', username: 'admin' });
        if (!preview.actionToken) throw new Error('Missing actionToken in preview');
        
        // Execute remediation
        const execRes = await autonomousRemediationEngine.executeRemediation(preview.actionToken, { role: 'ADMIN', username: 'admin' });
        if (!execRes.success) throw new Error('Remediation execution failed: ' + execRes.error);
        
        // Output action token for subsequent test
        console.log('TOKEN_GENERATED:' + preview.actionToken);
      }
      main().catch(err => {
        console.error(err);
        process.exit(1);
      });
    `;

    const procExecToken = spawnSync(process.execPath, [
      '-e', testScript
    ], {
      cwd: rootDir,
      env: {
        ...process.env,
        NODE_ENV: 'test',
        EJII_DATA_DIR: isolatedDataDir
      },
      encoding: 'utf8'
    });

    assert.equal(procExecToken.status, 0, `Action token execution failed: ${procExecToken.stderr}`);
    const tokenMatch = procExecToken.stdout.match(/TOKEN_GENERATED:([^\s]+)/);
    assert.ok(tokenMatch && tokenMatch[1], 'Must generate and output actionToken');
    const actionToken = tokenMatch[1];

    // Verify token is saved in isolated consumed_tokens.json and consumed_action_tokens table
    const consumedTokensJsonPath = path.join(isolatedDataDir, 'security', 'consumed_tokens.json');
    assert.equal(fs.existsSync(consumedTokensJsonPath), true, 'consumed_tokens.json must exist');
    const consumedJson = JSON.parse(fs.readFileSync(consumedTokensJsonPath, 'utf8'));
    const tokenPayload = JSON.parse(Buffer.from(actionToken.split('.')[0], 'base64url').toString('utf8'));
    assert.ok(consumedJson[tokenPayload.tokenId], 'Token ID must be present in consumed_tokens.json');

    // Simulate restart: run another process and attempt replay of the exact same token
    const replayScript = `
      const { autonomousRemediationEngine } = require('./src/systems/remediation/autonomous-remediation-engine');
      
      async function main() {
        try {
          const replayRes = await autonomousRemediationEngine.executeRemediation(process.argv[1], { role: 'ADMIN', username: 'admin' });
          console.log(JSON.stringify(replayRes));
        } catch (err) {
          console.log(JSON.stringify({ success: false, error: err.message }));
        }
      }
      main().catch(err => {
        console.error(err);
        process.exit(1);
      });
    `;

    const procReplay = spawnSync(process.execPath, [
      '-e', replayScript, actionToken
    ], {
      cwd: rootDir,
      env: {
        ...process.env,
        NODE_ENV: 'test',
        EJII_DATA_DIR: isolatedDataDir
      },
      encoding: 'utf8'
    });

    assert.equal(procReplay.status, 0, 'Replay script exited cleanly with structured response');
    const replayOutput = JSON.parse(procReplay.stdout);
    assert.equal(replayOutput.success, false, 'Replayed actionToken must be rejected');
    assert.match(replayOutput.error, /REPLAY_DETECTED|has already been executed/i, 'Must detect replay on restarted instance');
    console.log('  ✓ Action token replay defense persisted across process restart and blocked duplicate execution.');

    // -------------------------------------------------------------------------
    // TEST 5: HMAC Cryptographic Audit Trail Verification & Tamper Detection
    // -------------------------------------------------------------------------
    console.log('\n[30.5] Testing HMAC audit trail verification and cryptographic tamper detection...');

    const verifyAuditScript = `
      const { verifyAuditLogIntegrity } = require('./src/core/audit-logger');
      const result = verifyAuditLogIntegrity();
      console.log(JSON.stringify(result));
    `;

    const procVerifyAudit = spawnSync(process.execPath, [
      '-e', verifyAuditScript
    ], {
      cwd: rootDir,
      env: {
        ...process.env,
        NODE_ENV: 'test',
        EJII_DATA_DIR: isolatedDataDir
      },
      encoding: 'utf8'
    });

    assert.equal(procVerifyAudit.status, 0);
    const auditRes = JSON.parse(procVerifyAudit.stdout);
    assert.equal(auditRes.valid, true, 'Audit log integrity must be valid after genuine actions');
    assert.ok(auditRes.count >= 2, 'Audit trail must contain genesis + remediation records');
    console.log(`  ✓ Audit trail verified cryptographically valid (${auditRes.count} chained records).`);

    // Now introduce adversarial tampering to audit-trail.jsonl and ensure it is caught
    const auditFilePath = path.join(isolatedDataDir, 'audit', 'audit-trail.jsonl');
    const rawAudit = fs.readFileSync(auditFilePath, 'utf8');
    // Tamper with one character in the action name of the last record
    const tamperedAudit = rawAudit.replace(/flush_dns/g, 'unauthorized_flush_dns');
    fs.writeFileSync(auditFilePath, tamperedAudit, 'utf8');

    const procVerifyTampered = spawnSync(process.execPath, [
      '-e', verifyAuditScript
    ], {
      cwd: rootDir,
      env: {
        ...process.env,
        NODE_ENV: 'test',
        EJII_DATA_DIR: isolatedDataDir
      },
      encoding: 'utf8'
    });

    const tamperedRes = JSON.parse(procVerifyTampered.stdout);
    assert.equal(tamperedRes.valid, false, 'Tampered audit record must fail integrity check');
    assert.match(tamperedRes.error, /HMAC signature verification failed|broken hash chain|modified or forged/i, 'Must flag broken HMAC hash chain or modified record');
    console.log('  ✓ Adversarial modification to audit log strictly detected as broken HMAC chain.');

    console.log('\n========================================================================');
    console.log('  SUITE 30 PASSED: SECURE DEPLOYMENT LIFECYCLE 100% OPERATIONAL         ');
    console.log('========================================================================');
  } finally {
    // Clean up temporary test data directory
    try {
      fs.rmSync(tempBase, { recursive: true, force: true });
    } catch (e) {}
  }
}

if (require.main === module) {
  runSecureDeploymentLifecycleTests().catch(err => {
    console.error('Test Suite 30 Failed:', err);
    process.exit(1);
  });
}

module.exports = { runSecureDeploymentLifecycleTests };
