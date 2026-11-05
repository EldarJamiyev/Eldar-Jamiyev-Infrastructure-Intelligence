/**
 * Suite: Mobile WebAuthn Biometric & Dual-Custody Approval Verification
 * Verifies cryptographic challenges, token validation, expiration, and separation of duties.
 */

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const express = require('express');
const { createToken } = require('../src/core/security');
const authRouter = require('../src/api/routes-auth');
const diagRouter = require('../src/api/routes-diagnostics-remediation');
const {
  activeChallenges,
  pendingRemediationActions,
  createBiometricTicket,
  verifyBiometricTicket
} = require('../src/api/webauthn-automation');
const rcaRouter = require('../src/api/routes-rca');
const { aiBrain } = require('../src/core/ai-brain');

function setupTestServer() {
  const app = express();
  app.use(express.json());
  app.use('/api/auth', authRouter);
  app.use('/api', diagRouter);
  app.use('/api/rca', rcaRouter);
  const server = http.createServer(app);
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      resolve({ server, port });
    });
  });
}

function request(port, path, method = 'GET', token = null, body = null) {
  return new Promise((resolve, reject) => {
    const headers = { 'Content-Type': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const payload = body ? JSON.stringify(body) : null;
    if (payload) headers['Content-Length'] = Buffer.byteLength(payload);

    const req = http.request({
      hostname: '127.0.0.1',
      port,
      path,
      method,
      headers
    }, (res) => {
      let data = '';
      res.on('data', chunk => { data += chunk; });
      res.on('end', () => {
        try {
          const json = data ? JSON.parse(data) : {};
          resolve({ status: res.statusCode, data: json });
        } catch (_) {
          resolve({ status: res.statusCode, data });
        }
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

test('Mobile WebAuthn Biometric Security & Dual-Custody Approval Suite', async (t) => {
  const { server, port } = await setupTestServer();

  const operatorUser = { id: 'usr-op-101', username: 'operator_dan', role: 'OPERATOR' };
  const adminUser = { id: 'usr-adm-201', username: 'admin_elena', role: 'ADMIN' };
  const readonlyUser = { id: 'usr-ro-301', username: 'auditor_bob', role: 'READONLY' };

  const operatorToken = createToken(operatorUser);
  const adminToken = createToken(adminUser);
  const readonlyToken = createToken(readonlyUser);

  t.after(() => {
    server.close();
  });

  await t.test('1. WebAuthn: Generates cryptographically secure challenge', async () => {
    const res = await request(port, '/api/auth/webauthn/login-challenge', 'POST');
    assert.equal(res.status, 200);
    assert.ok(res.data.success);
    assert.ok(typeof res.data.challenge === 'string');
    assert.ok(res.data.challenge.length >= 32);
    assert.equal(res.data.userVerification, 'required');
  });

  await t.test('2. WebAuthn: Unauthenticated verify request is rejected (401)', async () => {
    const res = await request(port, '/api/auth/webauthn/login-verify', 'POST', null, {
      challenge: 'random_challenge',
      credentialId: 'cred_123'
    });
    assert.equal(res.status, 401);
  });

  await t.test('3. WebAuthn: Missing or invalid challenge is rejected (401/400)', async () => {
    const res = await request(port, '/api/auth/webauthn/login-verify', 'POST', operatorToken, {
      challenge: 'non_existent_fake_challenge',
      credentialId: 'cred_123'
    });
    assert.equal(res.status, 401);
    assert.match(res.data.error, /expired or unrecognized/i);
  });

  await t.test('4. WebAuthn: Expired challenge is strictly rejected', async () => {
    // Inject an expired challenge directly into the challenge store
    const expiredChallenge = 'expired_challenge_proof_token_abc123';
    activeChallenges.set(expiredChallenge, {
      challenge: expiredChallenge,
      type: 'authentication',
      createdAt: Date.now() - 600000,
      expiresAt: Date.now() - 1000 // expired
    });

    const res = await request(port, '/api/auth/webauthn/login-verify', 'POST', operatorToken, {
      challenge: expiredChallenge,
      credentialId: 'cred_123'
    });
    assert.equal(res.status, 401);
    assert.match(res.data.error, /expired/i);
  });

  await t.test('5. WebAuthn: Valid challenge verification issues server-signed biometric ticket', async () => {
    const chRes = await request(port, '/api/auth/webauthn/login-challenge', 'POST');
    const challenge = chRes.data.challenge;

    const verifyRes = await request(port, '/api/auth/webauthn/login-verify', 'POST', operatorToken, {
      challenge,
      credentialId: 'biometric_yubikey_01'
    });

    assert.equal(verifyRes.status, 200);
    assert.ok(verifyRes.data.success);
    assert.ok(verifyRes.data.verified);
    assert.ok(verifyRes.data.biometricTicket);

    // Cryptographic ticket validation
    const ticketPayload = verifyBiometricTicket(verifyRes.data.biometricTicket);
    assert.ok(ticketPayload);
    assert.equal(ticketPayload.username, 'operator_dan');
    assert.equal(ticketPayload.purpose, 'dual-custody-biometric-authorization');
  });

  await t.test('6. Dual-Custody: Unauthenticated review attempt is rejected (401)', async () => {
    const res = await request(port, '/api/automation/actions/ACT-TIER3-101/review', 'POST', null, {
      approved: true
    });
    assert.equal(res.status, 401);
  });

  await t.test('7. Dual-Custody: READONLY user review attempt is rejected (403)', async () => {
    const res = await request(port, '/api/automation/actions/ACT-TIER3-101/review', 'POST', readonlyToken, {
      approved: true
    });
    assert.equal(res.status, 403);
  });

  await t.test('8. Dual-Custody: Client cannot bypass biometric requirement with fake client-side state', async () => {
    // Attempting to approve an action that requires biometric without a ticket fails with 403
    const res = await request(port, '/api/automation/actions/ACT-TIER3-101/review', 'POST', operatorToken, {
      approved: true,
      comment: 'Attempting approval without biometric ticket'
    });
    assert.equal(res.status, 403);
    assert.match(res.data.error, /Biometric authorization required/i);
  });

  await t.test('9. Dual-Custody: Invalid or forged biometric ticket is rejected (403)', async () => {
    const forgedTicket = 'header.payload.invalid_signature_attempt';
    const res = await request(port, '/api/automation/actions/ACT-TIER3-101/review', 'POST', operatorToken, {
      approved: true,
      biometricTicket: forgedTicket
    });
    assert.equal(res.status, 403);
    assert.match(res.data.error, /Invalid or expired biometric ticket/i);
  });

  await t.test('10. Dual-Custody: Ticket issued for User A cannot be used by User B', async () => {
    // Ticket issued for operator_dan
    const ticketForDan = createBiometricTicket(operatorUser);

    // Elena (Admin) tries to use Dan's ticket
    const res = await request(port, '/api/automation/actions/ACT-TIER3-101/review', 'POST', adminToken, {
      approved: true,
      biometricTicket: ticketForDan
    });
    assert.equal(res.status, 403);
    assert.match(res.data.error, /Biometric ticket identity mismatch/i);
  });

  await t.test('11. Dual-Custody: Separation of duties prevents requester from self-approving', async () => {
    const action = pendingRemediationActions.get('ACT-TIER3-101');
    assert.ok(action);
    const originalRequester = action.requester_username; // 'sysadmin_automated'

    // Create user matching requester
    const requesterUser = { id: 'usr-sys-99', username: originalRequester, role: 'SYSADMIN' };
    const requesterToken = createToken(requesterUser);
    const requesterTicket = createBiometricTicket(requesterUser);

    const res = await request(port, '/api/automation/actions/ACT-TIER3-101/review', 'POST', requesterToken, {
      approved: true,
      biometricTicket: requesterTicket
    });
    assert.equal(res.status, 403);
    assert.match(res.data.error, /Requester cannot self-approve/i);
  });

  await t.test('12. Dual-Custody: Legitimate operator with verified biometric ticket authorizes action', async () => {
    const validTicket = createBiometricTicket(operatorUser);
    const res = await request(port, '/api/automation/actions/ACT-TIER3-101/review', 'POST', operatorToken, {
      approved: true,
      comment: 'Verified via Touch WebAuthn',
      biometricTicket: validTicket
    });
    assert.equal(res.status, 200);
    assert.equal(res.data.status, 'approved');
    assert.equal(res.data.reviewedBy, 'operator_dan');

    // Confirm action state is updated
    const updated = pendingRemediationActions.get('ACT-TIER3-101');
    assert.equal(updated.approval_status, 'approved');
  });

  await t.test('13. RCA Incidents: Unauthenticated GET /api/rca/incidents is rejected (401)', async () => {
    const res = await request(port, '/api/rca/incidents', 'GET');
    assert.equal(res.status, 401);
  });

  await t.test('14. RCA Incidents: Authenticated GET with status filtering works', async () => {
    // Add test active incident
    aiBrain.activeIncidents.set('INC-TEST-001', {
      incidentKey: 'INC-TEST-001',
      incidentType: 'LINK_FLAP',
      target: '10.0.0.1',
      createdAt: new Date().toISOString()
    });

    const resOpen = await request(port, '/api/rca/incidents?status=open', 'GET', operatorToken);
    assert.equal(resOpen.status, 200);
    assert.ok(resOpen.data.success);
    assert.ok(Array.isArray(resOpen.data.incidents));
    assert.ok(resOpen.data.incidents.some(i => i.id === 'INC-TEST-001'));
  });

  await t.test('15. RCA Incidents: Resolving unknown incident returns 404', async () => {
    const res = await request(port, '/api/rca/incidents/NON_EXISTENT_INCIDENT/resolve', 'POST', operatorToken);
    assert.equal(res.status, 404);
    assert.match(res.data.error, /not found/i);
  });

  await t.test('16. RCA Incidents: READONLY cannot resolve incident (403)', async () => {
    const res = await request(port, '/api/rca/incidents/INC-TEST-001/resolve', 'POST', readonlyToken);
    assert.equal(res.status, 403);
  });

  await t.test('17. RCA Incidents: OPERATOR successfully resolves incident with state update', async () => {
    const res = await request(port, '/api/rca/incidents/INC-TEST-001/resolve', 'POST', operatorToken);
    assert.equal(res.status, 200);
    assert.ok(res.data.success);
    assert.equal(res.data.resolved, true);

    // Confirm incident is removed from active and moved to history
    assert.equal(aiBrain.activeIncidents.has('INC-TEST-001'), false);
    assert.ok(aiBrain.incidentHistory.some(h => h.incidentKey === 'INC-TEST-001' && h.status === 'resolved'));
  });
});
