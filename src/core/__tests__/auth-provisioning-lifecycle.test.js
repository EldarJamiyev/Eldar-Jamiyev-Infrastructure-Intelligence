/**
 * Authentication Provisioning, Self-Healing Recovery, Password Rotation, MFA & Session Invalidation Tests
 */

'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const crypto = require('node:crypto');
const express = require('express');
const { DatabaseSync } = require('node:sqlite');

const { db, initSchema } = require('../../db/database');
const { seedDatabase, getFirstRunCredentialsPath, clearFirstRunCredentialsFile } = require('../../db/seed');
const { hashPassword, verifyPassword, createToken, verifyToken } = require('../security');
const { generateTOTP } = require('../totp');
const authRouter = require('../../api/routes-auth');
const { authenticate } = require('../../api/middleware');

function parseCredentialsFile(filePath) {
  const content = fs.readFileSync(filePath, 'utf8');
  const accounts = {};
  let current = null;
  for (const rawLine of content.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#') || line.startsWith('=')) continue;
    const secMatch = line.match(/^\[([a-z0-9_-]+)\]$/i);
    if (secMatch) {
      current = secMatch[1].toLowerCase();
      accounts[current] = accounts[current] || {};
      continue;
    }
    const kv = line.match(/^([a-z_]+)=(.+)$/i);
    if (kv && current) {
      accounts[current][kv[1].toLowerCase()] = kv[2];
    }
  }
  return accounts;
}

async function createAuthTestServer() {
  const app = express();
  app.use(express.json());
  app.use('/api/auth', authRouter);
  app.get('/api/protected-ping', authenticate, (req, res) => {
    res.json({ ok: true, user: req.user });
  });
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    close: () => new Promise((resolve) => server.close(resolve))
  };
}

describe('P0 Authentication Provisioning, Self-Healing Recovery & Session Lifecycle', () => {
  it('Test 1 (Fresh Installation): isolated temp DB + seedDatabase() writes 0o600 credentials file, login succeeds with generated password and rejects admin2026! with 401', async () => {
    const origEnvPw = process.env.EJII_ADMIN_PASSWORD;
    delete process.env.EJII_ADMIN_PASSWORD;

    // 1a. Verify isolated fresh temp directory + DatabaseSync seeding
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ejii-auth-fresh-'));
    const tmpDbPath = path.join(tmpDir, 'ejii.sqlite');
    const isolatedDb = new DatabaseSync(tmpDbPath);

    try {
      seedDatabase(isolatedDb, { dataDir: tmpDir });

      const { secDir, credFile } = getFirstRunCredentialsPath(tmpDir);
      assert.ok(fs.existsSync(secDir), 'data/security directory must be created');
      assert.ok(fs.existsSync(credFile), 'FIRST_RUN_ADMIN_CREDENTIALS.txt must be created on fresh install');

      if (process.platform !== 'win32') {
        const dirMode = fs.statSync(secDir).mode & 0o777;
        const fileMode = fs.statSync(credFile).mode & 0o777;
        assert.strictEqual(dirMode, 0o700, `Expected data/security mode 0o700, got ${dirMode.toString(8)}`);
        assert.strictEqual(fileMode, 0o600, `Expected FIRST_RUN_ADMIN_CREDENTIALS.txt mode 0o600, got ${fileMode.toString(8)}`);
      }

      const parsed = parseCredentialsFile(credFile);
      assert.ok(parsed.admin && parsed.admin.password, 'admin credentials must exist in FIRST_RUN_ADMIN_CREDENTIALS.txt');
      assert.ok(parsed.sysadmin && parsed.sysadmin.password, 'sysadmin credentials must exist');
      assert.ok(parsed.netadmin && parsed.netadmin.password, 'netadmin credentials must exist');
      assert.ok(parsed.noc && parsed.noc.password, 'noc credentials must exist');

      const adminDbRow = isolatedDb.prepare("SELECT password_hash, salt, bootstrap_state FROM users WHERE username = 'admin'").get();
      assert.ok(verifyPassword(parsed.admin.password, adminDbRow.password_hash, adminDbRow.salt));
      assert.strictEqual(verifyPassword('admin2026!', adminDbRow.password_hash, adminDbRow.salt), false);
      assert.strictEqual(adminDbRow.bootstrap_state, 'UNCLAIMED');
    } finally {
      isolatedDb.close();
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }

    // 1b. Verify live Express HTTP /api/auth/login against seeded isolated runtime DB
    db.exec('DELETE FROM revoked_tokens; DELETE FROM users;');
    clearFirstRunCredentialsFile();
    seedDatabase(db);

    const { credFile } = getFirstRunCredentialsPath();
    assert.ok(fs.existsSync(credFile), 'Process DATA_DIR FIRST_RUN_ADMIN_CREDENTIALS.txt must exist');
    const parsedRuntime = parseCredentialsFile(credFile);

    const srv = await createAuthTestServer();
    try {
      const staleDefaultRes = await fetch(`${srv.baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'admin', password: 'admin2026!' })
      });
      assert.strictEqual(staleDefaultRes.status, 401, 'Legacy fallback admin2026! must be rejected with HTTP 401');

      const emptyBodyRes = await fetch(`${srv.baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });
      assert.strictEqual(emptyBodyRes.status, 400, 'Empty login body must be rejected with HTTP 400 (no silent admin2026! fallback)');

      const loginRes = await fetch(`${srv.baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'admin', password: parsedRuntime.admin.password })
      });
      assert.strictEqual(loginRes.status, 200, 'Login with provisioned password from FIRST_RUN_ADMIN_CREDENTIALS.txt must return 200');
      const loginJson = await loginRes.json();
      assert.strictEqual(loginJson.success, true);
      assert.ok(loginJson.token);
      assert.strictEqual(loginJson.user.username, 'admin');

      const quickNocRes = await fetch(`${srv.baseUrl}/api/auth/quick-noc`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });
      assert.strictEqual(quickNocRes.status, 200, 'Quick-NOC on loopback must succeed with seeded noc operator account');
      const quickJson = await quickNocRes.json();
      assert.strictEqual(quickJson.user.username, 'noc');
    } finally {
      await srv.close();
      if (origEnvPw !== undefined) process.env.EJII_ADMIN_PASSWORD = origEnvPw;
    }
  });

  it('Test 2 (Existing DB Preservation): re-running seedDatabase() preserves an existing admin rotated password hash & salt', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ejii-auth-preserve-'));
    const tmpDbPath = path.join(tmpDir, 'ejii.sqlite');
    const customDb = new DatabaseSync(tmpDbPath);

    try {
      seedDatabase(customDb, { dataDir: tmpDir });

      // Simulate operator claiming & rotating admin password with 32-byte salt
      const rotatedPassword = 'Sovereign!Rotated#Password2026';
      const { hash, salt } = hashPassword(rotatedPassword, null, 32);
      const nowIso = new Date().toISOString();
      customDb.prepare(`
        UPDATE users
        SET password_hash = ?, salt = ?, password_rotated_at = ?, bootstrap_state = 'CLAIMED', last_login = ?
        WHERE username = 'admin'
      `).run(hash, salt, nowIso, nowIso);

      // Remove credential file after claim (standard operator hardening)
      clearFirstRunCredentialsFile(tmpDir);
      assert.strictEqual(fs.existsSync(getFirstRunCredentialsPath(tmpDir).credFile), false);

      // Re-run seedDatabase multiple times
      seedDatabase(customDb, { dataDir: tmpDir });
      seedDatabase(customDb, { dataDir: tmpDir });

      const after = customDb.prepare("SELECT password_hash, salt, password_rotated_at, bootstrap_state FROM users WHERE username = 'admin'").get();
      assert.strictEqual(after.password_hash, hash, 'Existing admin password_hash must never be overwritten');
      assert.strictEqual(after.salt, salt, 'Existing admin salt must never be overwritten');
      assert.strictEqual(after.bootstrap_state, 'CLAIMED');
      assert.strictEqual(verifyPassword(rotatedPassword, after.password_hash, after.salt), true);
    } finally {
      customDb.close();
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('Test 3 (Unclaimed Lockout Recovery): unclaimed seeded DB missing FIRST_RUN_ADMIN_CREDENTIALS.txt recovers cleanly on boot without losing operational rows', () => {
    const origEnvPw = process.env.EJII_ADMIN_PASSWORD;
    delete process.env.EJII_ADMIN_PASSWORD;

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ejii-auth-recover-'));
    const tmpDbPath = path.join(tmpDir, 'ejii.sqlite');
    const lockedDb = new DatabaseSync(tmpDbPath);

    try {
      initSchema(lockedDb);
      const nowIso = new Date().toISOString();

      // Simulate pre-fix bug state: topology exists, ONLY admin exists with unrecoverable random hash,
      // last_login is NULL, password_rotated_at is NULL, bootstrap_state = 'UNCLAIMED', and NO credentials file.
      const lostPassword = crypto.randomBytes(18).toString('base64url');
      const { hash: lostHash, salt: lostSalt } = hashPassword(lostPassword, null, 16);
      lockedDb.prepare(`
        INSERT INTO users (id, username, password_hash, salt, full_name, role, is_active, created_at)
        VALUES ('USR-NOC-01', 'admin', ?, ?, 'Senior NOC Infrastructure Engineer', 'admin', 1, ?)
      `).run(lostHash, lostSalt, nowIso);

      // Insert operational topology + claimed secondary user that MUST survive recovery
      lockedDb.prepare(`
        INSERT INTO topology_nodes (id, name, hostname_or_ip, type, layer, layer_level, status)
        VALUES ('NODE-OP-KEEP', 'Production Core Switch', '10.20.30.1', 'switch', 'core', 3, 'healthy')
      `).run();

      const customOpPw = 'CustomOperator!Pass99';
      const { hash: opHash, salt: opSalt } = hashPassword(customOpPw, null, 32);
      lockedDb.prepare(`
        INSERT INTO users (id, username, password_hash, salt, full_name, role, is_active, password_rotated_at, bootstrap_state, created_at)
        VALUES ('USR-CUSTOM-01', 'custom_op', ?, ?, 'Custom Operator', 'operator', 1, ?, 'CLAIMED', ?)
      `).run(opHash, opSalt, nowIso, nowIso);

      const { credFile } = getFirstRunCredentialsPath(tmpDir);
      assert.strictEqual(fs.existsSync(credFile), false);

      // Run self-healing seedDatabase() recovery
      seedDatabase(lockedDb, { dataDir: tmpDir });

      // 1. Operational row & claimed secondary account strictly preserved
      const keptNode = lockedDb.prepare("SELECT id, hostname_or_ip, status FROM topology_nodes WHERE id = 'NODE-OP-KEEP'").get();
      assert.ok(keptNode && keptNode.hostname_or_ip === '10.20.30.1', 'Operational topology rows must be preserved');

      const keptCustomUser = lockedDb.prepare("SELECT password_hash, salt FROM users WHERE username = 'custom_op'").get();
      assert.strictEqual(keptCustomUser.password_hash, opHash, 'Claimed operator account must remain untouched');

      // 2. Fresh credentials file written with mode 0o600 and matching admin hash in DB
      assert.ok(fs.existsSync(credFile), 'FIRST_RUN_ADMIN_CREDENTIALS.txt must be regenerated on unclaimed lockout recovery');
      if (process.platform !== 'win32') {
        assert.strictEqual(fs.statSync(credFile).mode & 0o777, 0o600);
      }
      const recovered = parseCredentialsFile(credFile);
      assert.ok(recovered.admin && recovered.admin.password);
      assert.notStrictEqual(recovered.admin.password, lostPassword);

      const recoveredAdminRow = lockedDb.prepare("SELECT password_hash, salt, token_version FROM users WHERE username = 'admin'").get();
      assert.strictEqual(verifyPassword(recovered.admin.password, recoveredAdminRow.password_hash, recoveredAdminRow.salt), true);
      assert.strictEqual(verifyPassword(lostPassword, recoveredAdminRow.password_hash, recoveredAdminRow.salt), false);
    } finally {
      lockedDb.close();
      fs.rmSync(tmpDir, { recursive: true, force: true });
      if (origEnvPw !== undefined) process.env.EJII_ADMIN_PASSWORD = origEnvPw;
    }
  });

  it('Test 4 (Password Change, MFA Replay Protection & Immediate Session Invalidation): covers rotation, TOTP counter guard, deactivation & deletion', async () => {
    const origEnvPw = process.env.EJII_ADMIN_PASSWORD;
    delete process.env.EJII_ADMIN_PASSWORD;

    db.exec('DELETE FROM revoked_tokens; DELETE FROM users;');
    clearFirstRunCredentialsFile();
    seedDatabase(db);

    const { credFile } = getFirstRunCredentialsPath();
    const initialCreds = parseCredentialsFile(credFile);
    const initialAdminPw = initialCreds.admin.password;
    const rotatedAdminPw = 'EJII#NewSovereignPass2026!';

    const srv = await createAuthTestServer();
    try {
      // 1. Authenticate as admin with first-run password
      const login1 = await fetch(`${srv.baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'admin', password: initialAdminPw })
      });
      assert.strictEqual(login1.status, 200);
      const { token: oldToken, user: adminUser } = await login1.json();

      // Verify oldToken works before rotation
      const meBefore = await fetch(`${srv.baseUrl}/api/auth/me`, {
        headers: { Authorization: `Bearer ${oldToken}` }
      });
      assert.strictEqual(meBefore.status, 200);

      // 2. Reject wrong current password on /api/auth/change-password
      const badChange = await fetch(`${srv.baseUrl}/api/auth/change-password`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${oldToken}`
        },
        body: JSON.stringify({ currentPassword: 'WrongPassword123', newPassword: rotatedAdminPw })
      });
      assert.strictEqual(badChange.status, 401);

      // 3. Rotate password cleanly via /api/auth/change-password
      const goodChange = await fetch(`${srv.baseUrl}/api/auth/change-password`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${oldToken}`
        },
        body: JSON.stringify({ currentPassword: initialAdminPw, newPassword: rotatedAdminPw })
      });
      assert.strictEqual(goodChange.status, 200);
      const changeJson = await goodChange.json();
      assert.strictEqual(changeJson.success, true);
      assert.strictEqual(changeJson.credentialsFileCleared, true);
      assert.strictEqual(fs.existsSync(credFile), false, 'FIRST_RUN_ADMIN_CREDENTIALS.txt must be cleared when admin rotates password');

      // Check 32-byte salt (64 hex chars) & password_rotated_at persisted
      const rotatedRow = db.prepare("SELECT salt, password_rotated_at, bootstrap_state, token_version FROM users WHERE id = ?").get(adminUser.id);
      assert.strictEqual(rotatedRow.salt.length, 64, 'change-password must store a fresh 32-byte (64-hex) salt');
      assert.ok(rotatedRow.password_rotated_at, 'password_rotated_at must be set');
      assert.strictEqual(rotatedRow.bootstrap_state, 'CLAIMED');

      // 4. Old token must be IMMEDIATELY invalidated
      assert.strictEqual(verifyToken(oldToken), null, 'Old JWT token must fail verifyToken() immediately after password change');
      const meAfterRotate = await fetch(`${srv.baseUrl}/api/auth/me`, {
        headers: { Authorization: `Bearer ${oldToken}` }
      });
      assert.strictEqual(meAfterRotate.status, 401, 'Prior JWT session must be rejected with 401 after password rotation');

      // Old password must fail; new password must succeed
      const loginOldPw = await fetch(`${srv.baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'admin', password: initialAdminPw })
      });
      assert.strictEqual(loginOldPw.status, 401);

      const login2 = await fetch(`${srv.baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'admin', password: rotatedAdminPw })
      });
      assert.strictEqual(login2.status, 200);
      const { token: freshToken } = await login2.json();

      // 5. MFA Enrollment & RFC 6238 Replay Protection
      const totpSetupRes = await fetch(`${srv.baseUrl}/api/auth/totp/setup`, {
        headers: { Authorization: `Bearer ${freshToken}` }
      });
      assert.strictEqual(totpSetupRes.status, 200);
      const { secret } = await totpSetupRes.json();
      const validTotpCode = generateTOTP(secret, Date.now());

      const mfaVerifyRes = await fetch(`${srv.baseUrl}/api/auth/mfa/verify-totp`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${freshToken}`
        },
        body: JSON.stringify({ token: validTotpCode })
      });
      assert.strictEqual(mfaVerifyRes.status, 200);
      const mfaVerifyJson = await mfaVerifyRes.json();
      assert.strictEqual(mfaVerifyJson.verified, true);
      assert.strictEqual(mfaVerifyJson.mfaEnabled, true);

      // Replaying the exact same TOTP code on /api/auth/login must be blocked via mfa_last_counter
      const mfaReplayLogin = await fetch(`${srv.baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'admin', password: rotatedAdminPw, totpCode: validTotpCode })
      });
      assert.strictEqual(mfaReplayLogin.status, 401);
      const replayJson = await mfaReplayLogin.json();
      assert.strictEqual(replayJson.replayDetected, true);

      // 6. Immediate JWT invalidation on user deactivation & deletion
      const sysadminPw = initialCreds.sysadmin.password;
      const sysLogin = await fetch(`${srv.baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'sysadmin', password: sysadminPw })
      });
      assert.strictEqual(sysLogin.status, 200);
      const { token: sysToken, user: sysUser } = await sysLogin.json();

      const sysMeBefore = await fetch(`${srv.baseUrl}/api/auth/me`, {
        headers: { Authorization: `Bearer ${sysToken}` }
      });
      assert.strictEqual(sysMeBefore.status, 200);

      // Deactivate sysadmin -> immediate rejection
      db.prepare('UPDATE users SET is_active = 0 WHERE id = ?').run(sysUser.id);
      assert.strictEqual(verifyToken(sysToken), null, 'Deactivated user token must fail verifyToken() immediately');
      const sysMeDisabled = await fetch(`${srv.baseUrl}/api/auth/me`, {
        headers: { Authorization: `Bearer ${sysToken}` }
      });
      assert.ok([401, 403].includes(sysMeDisabled.status), `Deactivated user /me must fail immediately, got ${sysMeDisabled.status}`);

      // Reactivate, verify works, then DELETE user -> immediate 401
      db.prepare('UPDATE users SET is_active = 1 WHERE id = ?').run(sysUser.id);
      const sysMeReenabled = await fetch(`${srv.baseUrl}/api/auth/me`, {
        headers: { Authorization: `Bearer ${sysToken}` }
      });
      assert.strictEqual(sysMeReenabled.status, 200);

      db.prepare('DELETE FROM users WHERE id = ?').run(sysUser.id);
      assert.strictEqual(verifyToken(sysToken), null, 'Deleted user db-backed token must fail verifyToken() immediately');
      const sysMeDeleted = await fetch(`${srv.baseUrl}/api/auth/me`, {
        headers: { Authorization: `Bearer ${sysToken}` }
      });
      assert.strictEqual(sysMeDeleted.status, 401, 'Deleted user session must be rejected with 401 immediately');
    } finally {
      await srv.close();
      if (origEnvPw !== undefined) process.env.EJII_ADMIN_PASSWORD = origEnvPw;
    }
  });

  it('Test 5 (Admin Env Override + Independent Random Role Passwords): EJII_ADMIN_PASSWORD applies specifically to admin while sysadmin/netadmin/noc generate unique random passwords', async () => {
    const origEnvPw = process.env.EJII_ADMIN_PASSWORD;
    process.env.EJII_ADMIN_PASSWORD = 'ConfiguredAdminOnly!Pass99';

    db.exec('DELETE FROM revoked_tokens; DELETE FROM users;');
    clearFirstRunCredentialsFile();
    seedDatabase(db);

    const { credFile } = getFirstRunCredentialsPath();
    assert.ok(fs.existsSync(credFile), 'FIRST_RUN_ADMIN_CREDENTIALS.txt must be written for generated role accounts');
    const parsedCreds = parseCredentialsFile(credFile);
    assert.strictEqual(parsedCreds.admin, undefined, 'env-configured admin password should not be written into FIRST_RUN_ADMIN_CREDENTIALS.txt');
    assert.ok(parsedCreds.sysadmin?.password && parsedCreds.netadmin?.password && parsedCreds.noc?.password);
    assert.notStrictEqual(parsedCreds.sysadmin.password, parsedCreds.netadmin.password);
    assert.notStrictEqual(parsedCreds.netadmin.password, parsedCreds.noc.password);

    const srv = await createAuthTestServer();
    try {
      const adminOk = await fetch(`${srv.baseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'admin', password: 'ConfiguredAdminOnly!Pass99' })
      });
      assert.strictEqual(adminOk.status, 200, 'admin must log in with EJII_ADMIN_PASSWORD');

      for (const uname of ['sysadmin', 'netadmin', 'noc']) {
        const sharedRejected = await fetch(`${srv.baseUrl}/api/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: uname, password: 'ConfiguredAdminOnly!Pass99' })
        });
        assert.strictEqual(sharedRejected.status, 401, `${uname} must not share EJII_ADMIN_PASSWORD`);

        const ownOk = await fetch(`${srv.baseUrl}/api/auth/login`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username: uname, password: parsedCreds[uname].password })
        });
        assert.strictEqual(ownOk.status, 200, `${uname} must log in with its generated password from FIRST_RUN_ADMIN_CREDENTIALS.txt`);
      }

      // If admin claims/rotates password, subsequent seedDatabase() with EJII_ADMIN_PASSWORD must preserve rotated hash
      const rotated = 'Claimed!UserRotated#2026';
      const { hash, salt } = hashPassword(rotated, null, 32);
      const nowIso = new Date().toISOString();
      db.prepare("UPDATE users SET password_hash = ?, salt = ?, password_rotated_at = ?, bootstrap_state = 'CLAIMED' WHERE username = 'admin'")
        .run(hash, salt, nowIso);

      process.env.EJII_ADMIN_PASSWORD = 'DifferentEnvPassword!2026';
      seedDatabase(db);

      const adminAfter = db.prepare("SELECT password_hash FROM users WHERE username = 'admin'").get();
      assert.strictEqual(adminAfter.password_hash, hash, 'Claimed admin password must not be overwritten by EJII_ADMIN_PASSWORD');
    } finally {
      await srv.close();
      if (origEnvPw !== undefined) {
        process.env.EJII_ADMIN_PASSWORD = origEnvPw;
      } else {
        delete process.env.EJII_ADMIN_PASSWORD;
      }
    }
  });
});
