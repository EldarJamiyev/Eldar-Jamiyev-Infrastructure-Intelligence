/**
 * EJII — Project Atlas REST API Router (`/api/atlas/*` & `/api/v6/atlas/*`)
 * Zero-Trust Reverse Proxy, NAT Traversal, Relay Mesh, JIT Governance & VirtualNet Control Plane
 *
 * Cycle 1 Security Hardening:
 * - Enforces route-level JWT/cookie authentication (`authenticate`) and explicit RBAC (`requireRole`)
 *   across all mutating control-plane, cryptographic key, relay failover, proxy, VirtualNet, SSH gateway,
 *   and closed-loop recovery endpoints.
 * - Enforces hostile-input sanitization (prototype-pollution guard, strict type & numeric range validation).
 * - Enforces session-ownership / cryptographic proof or authenticated operator identity on client heartbeats
 *   and reconnections.
 */

'use strict';

const express = require('express');
const router = express.Router();
const { projectAtlasEngine } = require('../network/atlas/project-atlas-engine');
const { authenticate, requireRole } = require('./middleware');
const { verifyToken } = require('../core/security');

const crypto = require('node:crypto');
const { db } = require('../db/database');

const ADMIN_ROLES = ['ADMIN', 'SYSADMIN', 'NETWORK_ADMIN'];
const OPERATOR_ROLES = ['ADMIN', 'SYSADMIN', 'NETWORK_ADMIN', 'OPERATOR', 'NOC_OPERATOR'];

/**
 * Resolves and verifies an operator identity from `req.user` or `Authorization: Bearer <jwt>`,
 * enforcing SQLite active-account status (`is_active === 1`) so disabled or revoked accounts
 * are rejected consistently across all Atlas routes.
 */
function resolveVerifiedActiveOperator(req) {
  let candidate = req.user && (req.user.id || req.user.username) ? req.user : null;
  if (!candidate) {
    const auth = String(req.headers?.authorization || '');
    if (auth.startsWith('Bearer ')) {
      const decoded = verifyToken(auth.slice(7).trim());
      if (decoded && (decoded.id || decoded.username)) {
        candidate = decoded;
      }
    }
  }
  if (!candidate) return null;

  try {
    if (db && typeof db.prepare === 'function' && candidate.id) {
      const row = db
        .prepare('SELECT id, username, full_name, role, is_active FROM users WHERE id = ?')
        .get(candidate.id);
      if (row) {
        if (Number(row.is_active) !== 1) {
          return { disabled: true, id: row.id, username: row.username };
        }
        return {
          id: row.id,
          username: row.username,
          fullName: row.full_name,
          role: String(row.role || candidate.role || 'VIEWER').toUpperCase()
        };
      }
    }
  } catch (_) {}

  return {
    id: candidate.id || candidate.username,
    username: candidate.username || candidate.id,
    role: String(candidate.role || 'VIEWER').toUpperCase()
  };
}

function extractOperator(req) {
  const op = resolveVerifiedActiveOperator(req);
  if (!op || op.disabled) return null;
  return op;
}

/**
 * Hostile-input guard: recursively inspects objects AND arrays up to MAX_DEPTH=16,
 * blocking `__proto__`, `constructor`, `prototype`, circular structures, and excessive nesting.
 */
function sanitizeAndValidateBody(req, res, next) {
  if (req.body !== undefined && req.body !== null && (typeof req.body !== 'object' || Array.isArray(req.body))) {
    return res.status(400).json({
      success: false,
      code: 'ATLAS_MALFORMED_REQUEST_BODY',
      error: 'Request body must be a JSON object.'
    });
  }
  const rawBody = req.body || {};
  const forbiddenKeys = new Set(['__proto__', 'constructor', 'prototype']);
  const seenObjects = new WeakSet();
  const MAX_DEPTH = 16;

  const inspectDeep = (node, depth = 0) => {
    if (node === null || typeof node !== 'object') return { ok: true };
    if (depth > MAX_DEPTH) {
      return {
        ok: false,
        code: 'ATLAS_PAYLOAD_DEPTH_EXCEEDED',
        error: `Request body exceeds maximum nesting depth (${MAX_DEPTH}).`
      };
    }
    if (seenObjects.has(node)) {
      return {
        ok: false,
        code: 'ATLAS_CIRCULAR_PAYLOAD_REJECTED',
        error: 'Circular object reference rejected.'
      };
    }
    seenObjects.add(node);

    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i++) {
        const sub = inspectDeep(node[i], depth + 1);
        if (!sub.ok) return sub;
      }
      return { ok: true };
    }

    if (Object.prototype.hasOwnProperty.call(node, '__proto__') || node.polluted === true) {
      return {
        ok: false,
        code: 'ATLAS_MALFORMED_REQUEST_BODY',
        error: 'Prototype-pollution property rejected.'
      };
    }

    for (const k of Object.getOwnPropertyNames(node)) {
      if (forbiddenKeys.has(k)) {
        return {
          ok: false,
          code: 'ATLAS_MALFORMED_REQUEST_BODY',
          error: `Forbidden property key "${k}" rejected.`
        };
      }
      const val = node[k];
      if (val !== null && typeof val === 'object') {
        const sub = inspectDeep(val, depth + 1);
        if (!sub.ok) return sub;
      }
    }
    return { ok: true };
  };

  const validation = inspectDeep(rawBody, 0);
  if (!validation.ok) {
    return res.status(400).json({
      success: false,
      code: validation.code,
      error: validation.error
    });
  }
  req.body = rawBody;
  next();
}

/**
 * Verifies that a client session operation (heartbeat / reconnect) is performed either by:
 *   1. An active, non-disabled operator with `OPERATOR_ROLES` (`ADMIN`, `SYSADMIN`, `NETWORK_ADMIN`, `OPERATOR`, `NOC_OPERATOR`) —
 *      explicitly blocking `READONLY` / `VIEWER` accounts from hijacking client sessions; OR
 *   2. The enrolled edge agent presenting its cryptographic enrollment token (`X-Atlas-Enrollment-Token` / `enrollmentToken`)
 *      matching `client.enrolledWithTokenDigest` in constant time.
 */
function requireClientSessionOwnershipOrAuth(req, res, next) {
  const op = resolveVerifiedActiveOperator(req);
  if (op) {
    if (op.disabled) {
      return res.status(403).json({
        success: false,
        code: 'USER_DISABLED',
        error: 'User account has been disabled.'
      });
    }
    if (!OPERATOR_ROLES.includes(op.role)) {
      return res.status(403).json({
        success: false,
        code: 'ATLAS_INSUFFICIENT_ROLE_FOR_CLIENT_SESSION',
        error: `Role '${op.role}' is not permitted to mutate or claim ownership of client sessions.`
      });
    }
    req.user = op;
    return next();
  }

  const clientId = String(req.params?.clientId || '').trim();
  const client = projectAtlasEngine.clientsMemory.get(clientId);
  const suppliedToken = req.body?.enrollmentToken || req.headers?.['x-atlas-enrollment-token'];
  if (client && !client.revoked && client.enrolledWithTokenDigest && typeof suppliedToken === 'string' && suppliedToken.trim()) {
    const digestHex = crypto.createHash('sha256').update(suppliedToken.trim()).digest('hex');
    const aBuf = Buffer.from(digestHex, 'utf8');
    const bBuf = Buffer.from(String(client.enrolledWithTokenDigest), 'utf8');
    if (aBuf.length === bBuf.length && crypto.timingSafeEqual(aBuf, bBuf)) {
      return next();
    }
  }
  return res.status(401).json({
    success: false,
    code: 'ATLAS_CLIENT_SESSION_OWNERSHIP_REQUIRED',
    error: 'Client session ownership proof (X-Atlas-Enrollment-Token) or authenticated operator JWT with OPERATOR/ADMIN role is required.'
  });
}

router.use(sanitizeAndValidateBody);

// GET /api/atlas/status — Real-time observability snapshot
router.get('/status', (req, res) => {
  try {
    const snapshot = projectAtlasEngine.getObservabilitySnapshot();
    res.json({
      success: true,
      ...snapshot
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/atlas/feature-matrix — FRP vs. Project Atlas IV+ feature coverage matrix
router.get('/feature-matrix', (req, res) => {
  try {
    res.json({
      success: true,
      ...projectAtlasEngine.getFeatureCoverageMatrix()
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/atlas/metrics — Prometheus exposition format
router.get('/metrics', (req, res) => {
  try {
    const promText = projectAtlasEngine.exportPrometheusMetrics();
    res.setHeader('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
    res.send(promText);
  } catch (err) {
    res.status(500).send(`# ERROR: ${err.message}\n`);
  }
});

// POST /api/atlas/rotate-key — Rotate Atlas control-plane HMAC secret with grace-period retention (ADMIN ONLY)
router.post('/rotate-key', authenticate, requireRole(...ADMIN_ROLES), (req, res) => {
  try {
    const { newSecret, keyId, gracePeriodMs } = req.body || {};
    if (typeof newSecret !== 'string' || newSecret.trim().length < 32) {
      return res.status(400).json({
        success: false,
        code: 'ATLAS_WEAK_SECRET_REJECTED',
        error: 'newSecret must be a string of at least 32 characters.'
      });
    }
    const result = projectAtlasEngine.rotateSecretKey(newSecret, { keyId, gracePeriodMs });
    res.json({
      success: true,
      rotatedBy: req.user.username || req.user.id,
      ...result
    });
  } catch (err) {
    res.status(err.statusCode || 400).json({
      success: false,
      code: err.code || 'ATLAS_KEY_ROTATION_ERROR',
      error: err.message
    });
  }
});

// POST /api/atlas/revoke-key — Explicitly revoke compromised or retired Atlas HMAC key (ADMIN ONLY)
router.post('/revoke-key', authenticate, requireRole(...ADMIN_ROLES), (req, res) => {
  try {
    const { keyId, reason, cascadeRevokeSessions } = req.body || {};
    const result = projectAtlasEngine.revokeSecretKey(keyId, reason, {
      cascadeRevokeSessions: cascadeRevokeSessions !== false
    });
    res.json({
      success: true,
      revokedBy: req.user.username || req.user.id,
      ...result
    });
  } catch (err) {
    res.status(err.statusCode || 400).json({
      success: false,
      code: err.code || 'ATLAS_KEY_REVOKE_ERROR',
      error: err.message
    });
  }
});

// POST /api/atlas/config — Validate, version, persist, and activate configuration
router.post('/config', authenticate, requireRole(...ADMIN_ROLES), (req, res) => {
  try {
    const op = extractOperator(req);
    const { profileName, config, envVars, fragments, format } = req.body || {};
    const record = projectAtlasEngine.saveAndActivateConfig(profileName || 'default', config || req.body, {
      envVars,
      fragments,
      format,
      createdBy: op ? String(op.username || op.id) : 'operator'
    });
    res.json({
      success: true,
      configRecord: record
    });
  } catch (err) {
    res.status(err.statusCode || 400).json({
      success: false,
      code: err.code || 'ATLAS_CONFIG_ERROR',
      validationErrors: err.validationErrors || [],
      error: err.message
    });
  }
});

// POST /api/atlas/config/rollback — Atomic configuration rollback
router.post('/config/rollback', authenticate, requireRole(...ADMIN_ROLES), (req, res) => {
  try {
    const { profileName, targetVersion } = req.body || {};
    const record = projectAtlasEngine.rollbackConfig(profileName || 'default', targetVersion);
    res.json({
      success: true,
      configRecord: record
    });
  } catch (err) {
    res.status(err.statusCode || 400).json({
      success: false,
      code: err.code || 'ATLAS_ROLLBACK_ERROR',
      error: err.message
    });
  }
});

// POST /api/atlas/tokens/issue — Issue cryptographic client enrollment token
router.post('/tokens/issue', authenticate, requireRole(...ADMIN_ROLES), (req, res) => {
  try {
    const op = extractOperator(req);
    const { clientName, relayId, ttlMs, certFingerprintSha256 } = req.body || {};
    if (!clientName || typeof clientName !== 'string' || !clientName.trim()) {
      return res.status(400).json({
        success: false,
        code: 'ATLAS_CLIENT_NAME_REQUIRED',
        error: 'clientName is required to issue an enrollment token.'
      });
    }
    const tokenBundle = projectAtlasEngine.issueClientEnrollmentToken({
      clientName: clientName.trim(),
      relayId,
      operatorId: op ? String(op.username || op.id) : 'admin',
      ttlMs,
      certFingerprintSha256
    });
    res.json({
      success: true,
      ...tokenBundle
    });
  } catch (err) {
    res.status(err.statusCode || 400).json({
      success: false,
      code: err.code || 'ATLAS_TOKEN_ISSUE_ERROR',
      error: err.message
    });
  }
});

// POST /api/atlas/tokens/revoke — Explicitly revoke an enrollment token
router.post('/tokens/revoke', authenticate, requireRole(...ADMIN_ROLES), (req, res) => {
  try {
    const { enrollmentToken, reason } = req.body || {};
    const out = projectAtlasEngine.revokeEnrollmentToken(enrollmentToken, reason);
    res.json({
      success: true,
      ...out
    });
  } catch (err) {
    res.status(err.statusCode || 400).json({
      success: false,
      code: err.code || 'ATLAS_TOKEN_REVOKE_ERROR',
      error: err.message
    });
  }
});

// POST /api/atlas/jit-grants — Issue time-bounded JIT administrative access grant (Dual-Control Enforced)
router.post('/jit-grants', authenticate, requireRole(...ADMIN_ROLES), (req, res) => {
  try {
    const op = extractOperator(req);
    const grant = projectAtlasEngine.issueJitAdminAccessGrant({
      ...(req.body || {}),
      operatorId: req.body?.operatorId || (op ? String(op.username || op.id) : 'admin')
    });
    res.json({
      success: true,
      grant
    });
  } catch (err) {
    res.status(err.statusCode || 400).json({
      success: false,
      code: err.code || 'ATLAS_JIT_GRANT_ERROR',
      error: err.message
    });
  }
});

// POST /api/atlas/jit-grants/sweep — Sweep expired JIT grants and terminate expired privileged proxies
router.post('/jit-grants/sweep', authenticate, requireRole(...OPERATOR_ROLES), async (req, res) => {
  try {
    const out = await projectAtlasEngine.sweepExpiredJitGrants();
    res.json({
      success: true,
      ...out
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

// POST /api/atlas/clients/enroll — Enroll tunnel client with TLS, anti-replay & cryptographic token verification
router.post('/clients/enroll', (req, res) => {
  try {
    if (!req.body?.enrollmentToken || typeof req.body.enrollmentToken !== 'string') {
      return res.status(401).json({
        success: false,
        code: 'ATLAS_AUTH_TOKEN_REQUIRED',
        error: 'A signed single-use enrollmentToken is required to enroll a client.'
      });
    }
    const client = projectAtlasEngine.enrollClient(req.body || {});
    res.json({
      success: true,
      client
    });
  } catch (err) {
    res.status(err.statusCode || 401).json({
      success: false,
      code: err.code || 'ATLAS_ENROLL_ERROR',
      error: err.message
    });
  }
});

// POST /api/atlas/clients/:clientId/heartbeat — Record live client heartbeat telemetry
router.post('/clients/:clientId/heartbeat', requireClientSessionOwnershipOrAuth, (req, res) => {
  try {
    const result = projectAtlasEngine.recordClientHeartbeat(req.params.clientId, req.body || {});
    res.json({
      success: true,
      ...result
    });
  } catch (err) {
    res.status(err.statusCode || 400).json({
      success: false,
      code: err.code || 'ATLAS_HEARTBEAT_ERROR',
      error: err.message
    });
  }
});

// POST /api/atlas/clients/:clientId/reconnect — Reconnect client session with generation increment
router.post('/clients/:clientId/reconnect', requireClientSessionOwnershipOrAuth, (req, res) => {
  try {
    const result = projectAtlasEngine.reconnectClientSession(req.params.clientId, req.body || {});
    res.json({
      success: true,
      ...result
    });
  } catch (err) {
    res.status(err.statusCode || 400).json({
      success: false,
      code: err.code || 'ATLAS_RECONNECT_ERROR',
      error: err.message
    });
  }
});

// POST /api/atlas/clients/sweep-stale — Sweep silent or stale client sessions
router.post('/clients/sweep-stale', authenticate, requireRole(...OPERATOR_ROLES), (req, res) => {
  try {
    const result = projectAtlasEngine.sweepStaleClientSessions(req.body?.maxSilenceMs);
    res.json({
      success: true,
      ...result
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

// POST /api/atlas/clients/:clientId/revoke — Immediate zero-trust session revocation
router.post('/clients/:clientId/revoke', authenticate, requireRole(...ADMIN_ROLES), async (req, res) => {
  try {
    const result = await projectAtlasEngine.revokeClientSession(
      req.params.clientId,
      req.body?.reason || `Operator-initiated revocation by ${req.user.username || req.user.id}`
    );
    res.json({
      success: true,
      ...result
    });
  } catch (err) {
    res.status(err.statusCode || 404).json({
      success: false,
      code: err.code || 'ATLAS_REVOKE_ERROR',
      error: err.message
    });
  }
});

// POST /api/atlas/proxies — Create and start a live socket-backed reverse proxy
router.post('/proxies', authenticate, requireRole(...OPERATOR_ROLES), async (req, res) => {
  try {
    const proxy = await projectAtlasEngine.createLiveProxy(req.body || {});
    res.json({
      success: true,
      proxy
    });
  } catch (err) {
    res.status(err.statusCode || 400).json({
      success: false,
      code: err.code || 'ATLAS_PROXY_CREATE_ERROR',
      error: err.message
    });
  }
});

// POST /api/atlas/port-range/expand — Expand a port-range proxy declaration
router.post('/port-range/expand', authenticate, requireRole(...OPERATOR_ROLES), (req, res) => {
  try {
    const expanded = projectAtlasEngine.expandPortRangeProxies(req.body || {});
    res.json({
      success: true,
      count: expanded.length,
      proxies: expanded
    });
  } catch (err) {
    res.status(err.statusCode || 400).json({
      success: false,
      code: err.code || 'ATLAS_PORT_RANGE_ERROR',
      error: err.message
    });
  }
});

// POST /api/atlas/stcp/connect — Verify STCP visitor secretKey & ACL
router.post('/stcp/connect', authenticate, (req, res) => {
  try {
    const result = projectAtlasEngine.connectStcpVisitor(req.body || {});
    res.json({
      success: true,
      ...result
    });
  } catch (err) {
    res.status(err.statusCode || 401).json({
      success: false,
      code: err.code || 'ATLAS_STCP_CONNECT_ERROR',
      error: err.message
    });
  }
});

// POST /api/atlas/p2p/negotiate — Negotiate XTCP P2P hole-punching session with STCP relay fallback
router.post('/p2p/negotiate', authenticate, requireRole(...OPERATOR_ROLES), (req, res) => {
  try {
    const session = projectAtlasEngine.negotiateXtcpP2pSession(req.body || {});
    res.json({
      success: true,
      session
    });
  } catch (err) {
    res.status(400).json({
      success: false,
      error: err.message
    });
  }
});

// POST /api/atlas/p2p/:p2pSessionId/verify-dataplane — Verify P2P data-plane connectivity or trigger relay fallback
router.post('/p2p/:p2pSessionId/verify-dataplane', authenticate, requireRole(...OPERATOR_ROLES), async (req, res) => {
  try {
    const result = await projectAtlasEngine.verifyXtcpP2pDataPlane(req.params.p2pSessionId, req.body || {});
    res.json({
      success: true,
      ...result
    });
  } catch (err) {
    res.status(err.statusCode || 404).json({
      success: false,
      code: err.code || 'ATLAS_P2P_VERIFY_ERROR',
      error: err.message
    });
  }
});

// POST /api/atlas/ssh-gateway/register — Register an SSH Tunnel Gateway reverse tunnel session
router.post('/ssh-gateway/register', authenticate, requireRole(...OPERATOR_ROLES), (req, res) => {
  try {
    const session = projectAtlasEngine.registerSshTunnelGatewaySession({
      ...(req.body || {}),
      operatorId: req.body?.operatorId || (req.user ? String(req.user.username || req.user.id) : 'operator')
    });
    res.json({
      success: true,
      session
    });
  } catch (err) {
    res.status(err.statusCode || 400).json({
      success: false,
      code: err.code || 'ATLAS_SSH_GATEWAY_ERROR',
      error: err.message
    });
  }
});

// POST /api/atlas/ssh-gateway/:gatewaySessionId/revoke — Revoke and terminate an SSH Tunnel Gateway session
router.post('/ssh-gateway/:gatewaySessionId/revoke', authenticate, requireRole(...OPERATOR_ROLES), (req, res) => {
  try {
    const result = projectAtlasEngine.revokeSshTunnelGatewaySession(
      req.params.gatewaySessionId,
      req.body?.reason || `Operator revocation by ${req.user.username || req.user.id}`
    );
    res.json({
      success: true,
      ...result
    });
  } catch (err) {
    res.status(err.statusCode || 404).json({
      success: false,
      code: err.code || 'ATLAS_SSH_GATEWAY_REVOKE_ERROR',
      error: err.message
    });
  }
});

// POST /api/atlas/relays/register — Register or update a relay node in the mesh
router.post('/relays/register', authenticate, requireRole(...ADMIN_ROLES), (req, res) => {
  try {
    const relay = projectAtlasEngine.registerRelayNode(req.body || {});
    res.json({
      success: true,
      relay
    });
  } catch (err) {
    res.status(err.statusCode || 400).json({
      success: false,
      code: err.code || 'ATLAS_RELAY_REGISTER_ERROR',
      error: err.message
    });
  }
});

// POST /api/atlas/relays/recommend — Recommend optimal relay across RTT, loss, jitter, load & stability
router.post('/relays/recommend', authenticate, (req, res) => {
  try {
    const recommendation = projectAtlasEngine.recommendOptimalRelay(req.body || {});
    res.json({
      success: true,
      ...recommendation
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

// DELETE /api/atlas/proxies/:proxyId — Stop and remove a live proxy listener
router.delete('/proxies/:proxyId', authenticate, requireRole(...OPERATOR_ROLES), async (req, res) => {
  try {
    const result = await projectAtlasEngine.stopProxy(req.params.proxyId);
    res.json({
      success: true,
      ...result
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

// POST /api/atlas/proxies/:proxyId/health-check — Run live backend health check
router.post('/proxies/:proxyId/health-check', authenticate, requireRole(...OPERATOR_ROLES), async (req, res) => {
  try {
    const result = await projectAtlasEngine.runProxyHealthCheck(req.params.proxyId);
    res.json({
      success: true,
      ...result
    });
  } catch (err) {
    res.status(err.statusCode || 404).json({
      success: false,
      code: err.code || 'ATLAS_HEALTH_CHECK_ERROR',
      error: err.message
    });
  }
});

// POST /api/atlas/proxies/:proxyId/diagnose — AI-Native root-cause diagnosis for a proxy/tunnel
router.post('/proxies/:proxyId/diagnose', authenticate, async (req, res) => {
  try {
    const diagnosis = await projectAtlasEngine.diagnoseProxyOrTunnel(req.params.proxyId);
    res.json({
      success: true,
      ...diagnosis
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

// POST /api/atlas/vnets — Create VirtualNet zero-trust mesh subnet
router.post('/vnets', authenticate, requireRole(...ADMIN_ROLES), (req, res) => {
  try {
    const vnet = projectAtlasEngine.createVirtualNetwork(req.body || {});
    res.json({
      success: true,
      virtualNetwork: vnet
    });
  } catch (err) {
    res.status(err.statusCode || 400).json({
      success: false,
      code: err.code || 'ATLAS_VNET_ERROR',
      error: err.message
    });
  }
});

// POST /api/atlas/vnets/:vnetId/peers — Allocate peer IP in VirtualNet subnet
router.post('/vnets/:vnetId/peers', authenticate, requireRole(...OPERATOR_ROLES), (req, res) => {
  try {
    const peer = projectAtlasEngine.allocateVirtualNetPeer(req.params.vnetId, req.body || {});
    res.json({
      success: true,
      peer
    });
  } catch (err) {
    res.status(err.statusCode || 400).json({
      success: false,
      code: err.code || 'ATLAS_VNET_ALLOCATE_PEER_ERROR',
      error: err.message
    });
  }
});

// POST /api/atlas/vnets/:vnetId/evaluate-flow — Evaluate zero-trust ACL flow decision
router.post('/vnets/:vnetId/evaluate-flow', authenticate, (req, res) => {
  try {
    const evaluation = projectAtlasEngine.evaluateVirtualNetFlow(req.params.vnetId, req.body || {});
    res.json({
      success: true,
      ...evaluation
    });
  } catch (err) {
    res.status(400).json({
      success: false,
      error: err.message
    });
  }
});

// POST /api/atlas/vnets/:vnetId/deliver-packet — End-to-end VirtualNet L3 packet delivery with fragmentation/reassembly
router.post('/vnets/:vnetId/deliver-packet', authenticate, requireRole(...OPERATOR_ROLES), async (req, res) => {
  try {
    const outcome = await Promise.resolve(projectAtlasEngine.deliverVirtualNetPacket(req.params.vnetId, req.body || {}));
    res.json({
      success: outcome.delivered,
      ...outcome
    });
  } catch (err) {
    res.status(err.statusCode || 400).json({
      success: false,
      code: err.code || 'ATLAS_VNET_DELIVERY_ERROR',
      error: err.message
    });
  }
});

// POST /api/atlas/vnets/decapsulate — Decapsulate ATLASL3V1 frame and verify integrity
router.post('/vnets/decapsulate', authenticate, (req, res) => {
  try {
    const outcome = projectAtlasEngine.decapsulateVirtualNetPacket(req.body?.frame || req.body?.frameHex || '');
    res.json({
      success: outcome.decapsulated,
      ...outcome
    });
  } catch (err) {
    res.status(400).json({
      success: false,
      error: err.message
    });
  }
});

// POST /api/atlas/sites — Register or update a remote infrastructure site
router.post('/sites', authenticate, requireRole(...ADMIN_ROLES), (req, res) => {
  try {
    const site = projectAtlasEngine.registerSite(req.body || {});
    res.json({
      success: true,
      site
    });
  } catch (err) {
    res.status(err.statusCode || 400).json({
      success: false,
      code: err.code || 'ATLAS_SITE_ERROR',
      error: err.message
    });
  }
});

// POST /api/atlas/relays/:relayId/health — Record live relay health measurements (RTT, loss, jitter)
router.post('/relays/:relayId/health', authenticate, requireRole(...OPERATOR_ROLES), (req, res) => {
  try {
    const body = req.body || {};
    if (body.measuredRttMs !== undefined && body.measuredRttMs !== null && (typeof body.measuredRttMs !== 'number' || !Number.isFinite(body.measuredRttMs) || body.measuredRttMs < 0 || body.measuredRttMs > 60000)) {
      return res.status(400).json({
        success: false,
        code: 'ATLAS_INVALID_RTT_TELEMETRY',
        error: 'measuredRttMs must be a finite number between 0 and 60000.'
      });
    }
    if (body.packetLossPct !== undefined && (typeof body.packetLossPct !== 'number' || !Number.isFinite(body.packetLossPct) || body.packetLossPct < 0 || body.packetLossPct > 100)) {
      return res.status(400).json({
        success: false,
        code: 'ATLAS_INVALID_LOSS_TELEMETRY',
        error: 'packetLossPct must be a finite number between 0 and 100.'
      });
    }
    const userRole = String(req.user?.role || '').toUpperCase();
    const isAdmin = ADMIN_ROLES.includes(userRole);
    const safeTelemetry = {
      ...body,
      measurementProvenance: isAdmin
        ? body.measurementProvenance || 'OPERATOR_SUPPLIED_OBSERVATION'
        : 'OPERATOR_SUPPLIED_OBSERVATION',
      disallowArbitraryStatusOverride: !isAdmin,
      autoFailoverOnOffline: Boolean(body.autoFailoverOnOffline && isAdmin),
      sourceIdentity: req.user?.username || req.user?.id || 'operator',
      recordedByOperator: req.user?.username || req.user?.id || 'operator'
    };
    const relay = projectAtlasEngine.recordRelayHealthMeasurement(req.params.relayId, safeTelemetry);
    res.json({
      success: true,
      relay
    });
  } catch (err) {
    res.status(err.statusCode || 404).json({
      success: false,
      code: err.code || 'ATLAS_RELAY_HEALTH_ERROR',
      error: err.message
    });
  }
});

// POST /api/atlas/relays/:relayId/failover — Controlled failover of clients and proxies from a degraded relay (ADMIN ONLY)
router.post('/relays/:relayId/failover', authenticate, requireRole(...ADMIN_ROLES), (req, res) => {
  try {
    const outcome = projectAtlasEngine.failoverRelayTraffic(
      req.params.relayId,
      req.body?.targetRelayId || null,
      req.body?.reason || `Authorized failover by ${req.user.username || req.user.id}`
    );
    res.json({
      success: true,
      authorizedBy: req.user.username || req.user.id,
      ...outcome
    });
  } catch (err) {
    res.status(err.statusCode || 400).json({
      success: false,
      code: err.code || 'ATLAS_RELAY_FAILOVER_ERROR',
      error: err.message
    });
  }
});

// POST /api/atlas/reconcile — Run distributed desired-vs-actual control-plane state reconciliation
router.post('/reconcile', authenticate, requireRole(...OPERATOR_ROLES), (req, res) => {
  try {
    const userRole = String(req.user?.role || '').toUpperCase();
    const allowAutoRepair = req.body?.autoRepair !== false && ADMIN_ROLES.includes(userRole);
    const report = projectAtlasEngine.reconcileDistributedState({
      ...(req.body || {}),
      autoRepair: req.body?.autoRepair === true ? ADMIN_ROLES.includes(userRole) : allowAutoRepair
    });
    res.json({
      success: true,
      ...report
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

// POST /api/atlas/proxies/:proxyId/drain — Gracefully drain active connections from a proxy backend
router.post('/proxies/:proxyId/drain', authenticate, requireRole(...OPERATOR_ROLES), async (req, res) => {
  try {
    const outcome = await projectAtlasEngine.drainProxyBackend(req.params.proxyId, req.body || {});
    res.json({
      success: true,
      ...outcome
    });
  } catch (err) {
    res.status(err.statusCode || 404).json({
      success: false,
      code: err.code || 'ATLAS_PROXY_DRAIN_ERROR',
      error: err.message
    });
  }
});

// POST /api/atlas/mux/streams — Open a multiplexed stream over a client control channel
router.post('/mux/streams', authenticate, requireRole(...OPERATOR_ROLES), (req, res) => {
  try {
    const outcome = projectAtlasEngine.openMultiplexedStream(req.body?.clientId, req.body || {});
    res.json({
      success: true,
      ...outcome
    });
  } catch (err) {
    res.status(err.statusCode || 400).json({
      success: false,
      code: err.code || 'ATLAS_MUX_STREAM_ERROR',
      error: err.message
    });
  }
});

// POST /api/atlas/approvals/issue — Issue a cryptographically signed single-use Secondary Operator Approval Token
router.post('/approvals/issue', authenticate, requireRole(...OPERATOR_ROLES), (req, res) => {
  try {
    const approval = projectAtlasEngine.issueControlPlaneApproval({
      approverId: req.user?.username || req.user?.id || 'operator',
      approverRole: String(req.user?.role || 'OPERATOR').toUpperCase(),
      targetId: req.body?.targetId || '*',
      actionType: req.body?.actionType || 'CLOSED_LOOP_REMEDIATION',
      reason: req.body?.reason || 'Secondary operator dual-control approval',
      ttlMs: req.body?.ttlMs
    });
    res.json({
      success: true,
      approval
    });
  } catch (err) {
    res.status(err.statusCode || 400).json({
      success: false,
      code: err.code || 'ATLAS_APPROVAL_ISSUE_ERROR',
      error: err.message
    });
  }
});

// POST /api/atlas/approvals/:approvalId/revoke — Explicitly revoke an unconsumed Control-Plane Approval Token (Cycle 2)
router.post('/approvals/:approvalId/revoke', authenticate, requireRole(...OPERATOR_ROLES), (req, res) => {
  try {
    const outcome = projectAtlasEngine.revokeControlPlaneApproval(
      req.params.approvalId,
      req.body?.reason || `Revoked by ${req.user?.username || req.user?.id || 'operator'}`,
      {
        revokedByOperatorId: req.user?.username || req.user?.id || null
      }
    );
    res.json({
      success: true,
      ...outcome
    });
  } catch (err) {
    res.status(err.statusCode || 404).json({
      success: false,
      code: err.code || 'ATLAS_APPROVAL_REVOKE_ERROR',
      error: err.message
    });
  }
});

// POST /api/atlas/vnets/:vnetId/deliver-packet-ack — End-to-end VirtualNet packet delivery with authenticated remote peer ACK (Cycle 6)
router.post('/vnets/:vnetId/deliver-packet-ack', authenticate, requireRole(...OPERATOR_ROLES), async (req, res) => {
  try {
    const outcome = await projectAtlasEngine.deliverVirtualNetPacketWithAck(req.params.vnetId, req.body || {});
    res.json({
      success: outcome.delivered,
      ...outcome
    });
  } catch (err) {
    res.status(err.statusCode || 400).json({
      success: false,
      code: err.code || 'ATLAS_VNET_ACK_DELIVERY_ERROR',
      error: err.message
    });
  }
});

// POST /api/atlas/clients/batch-heartbeats — Coalesced batch client heartbeat telemetry ingestion (Cycle 7)
router.post('/clients/batch-heartbeats', authenticate, requireRole(...OPERATOR_ROLES), async (req, res) => {
  try {
    const heartbeats = Array.isArray(req.body?.heartbeats) ? req.body.heartbeats : [];
    const results = await Promise.all(
      heartbeats.map((hb) =>
        projectAtlasEngine
          .recordClientHeartbeatAsync(hb.clientId, hb)
          .then((r) => ({ clientId: hb.clientId, ok: true, ...r }))
          .catch((e) => ({ clientId: hb?.clientId || null, ok: false, code: e.code, error: e.message }))
      )
    );
    res.json({
      success: true,
      processedCount: results.length,
      results
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

// POST /api/atlas/incidents/closed-loop — Execute end-to-end closed-loop disconnection/incident workflow
router.post('/incidents/closed-loop', authenticate, requireRole(...OPERATOR_ROLES), async (req, res) => {
  try {
    const userRole = String(req.user?.role || '').toUpperCase();
    const wantsAutoRemediate = req.body?.autoRemediate !== false;
    const isAdmin = ADMIN_ROLES.includes(userRole);
    const needsDualControl = (wantsAutoRemediate && !isAdmin) || req.body?.requireDualControl === true;

    if (needsDualControl && !req.body?.secondaryApprovalToken) {
      return res.status(403).json({
        success: false,
        code: 'ATLAS_REMEDIATION_AUTHORIZATION_REQUIRED',
        error: `Role '${userRole}' cannot execute autonomous relay failover without ADMIN privileges or a verified cryptographic secondaryApprovalToken (raw secondaryApproverId strings are rejected).`
      });
    }

    const incident = await projectAtlasEngine.executeClosedLoopDisconnectionWorkflow({
      ...(req.body || {}),
      operatorId: req.user?.username || req.user?.id || 'operator',
      operatorRole: userRole,
      requireCryptographicApproval: needsDualControl,
      secondaryApprovalToken: req.body?.secondaryApprovalToken || null
    });
    res.json({
      success: true,
      incident
    });
  } catch (err) {
    res.status(err.statusCode || 500).json({
      success: false,
      code: err.code || 'ATLAS_CLOSED_LOOP_ERROR',
      error: err.message
    });
  }
});

module.exports = router;
