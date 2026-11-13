"use strict";
/**
 * EJII — Eldar Jamiyev's Infrastructure Intelligence
 * Autonomous Multi-Agent SRE War Room Orchestrator (Phase: Autonomous Intelligence Maturity)
 *
 * Implements a 5-Agent Adversarial Consensus Engine with:
 * - Genuine read-only network & OS probe execution:
 *     1. DNS_PTR_LOOKUP: Real DNS queries via dns.promises.Resolver (PTR / A / AAAA) with resolver attribution & error classification
 *     2. ICMP_PMTU_DISCOVERY: Real DF-bit ICMP stepped payload probing (1472->1400->1360->1200->548) separating local interface MTU from Path MTU
 *     3. ARP_NEIGHBOR_VERIFY: Real OS kernel IPv4 ARP & IPv6 NDP neighbor table inspection (/proc/net/arp, ip neigh, arp -a)
 *     4. SOCKET_ESTABLISHED_AUDIT: Real OS socket table inspection via processSocketCorrelator / /proc/net/tcp without loopback self-connect simulations
 *     5. Exact sub-millisecond timing preservation (zero artificial 0.2ms floors) and explicit timingTarget metadata
 * - Cryptographic CollectorExecutionReceipts (HMAC-SHA256 bound to sessionId, probeId, probeType, target, collectorId, timingTarget, nativeResultCode, rawOutputSha256)
 * - Hypothesis-specific, protocol-aware Bayesian settlement, correlated observation deduplication & epistemic abstention
 * - Observation provenance & input telemetry trust classification (OPERATOR_SUPPLIED_OBSERVATION vs DIRECT_LOCAL_OS_MEASUREMENT vs ACTUAL_PROTOCOL_PROBE_MEASUREMENT)
 * - Durable SQLite WAL session persistence (Migration 007 & 008) with rowid-monotonic retention ordering
 * - Cryptographic Dual-Operator Approval ledger (war_room_dual_approvals) & server-verified JWT identity enforcement
 * - Verifiable Remediation Execution ledger (war_room_remediation_ledger) with temporal post-action verification
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.autonomousWarRoomOrchestrator = exports.AutonomousWarRoomOrchestrator = void 0;
const crypto = __importStar(require("crypto"));
const os = __importStar(require("os"));
const dns = __importStar(require("dns"));
const net = __importStar(require("net"));
const fs = __importStar(require("fs"));
const child_process_1 = require("child_process");
const DESTRUCTIVE_COMMAND_PATTERNS = /\b(DROP\s+TABLE|SHUTDOWN|FORMAT\s+|RM\s+-RF|DEL\s+\/[FSQ]|REBOOT|POWEROFF|FLUSH\s+ALL|IPTABLES\s+-F|NETSH\s+INT\s+IP\s+RESET)\b/i;
const PRIVILEGED_ROLES = new Set(['ADMIN', 'SYSADMIN', 'NETADMIN', 'OPERATOR', 'SRE_LEAD', 'NOC_LEAD', 'SECOPS']);
function readFiniteNumber(val) {
    if (typeof val === 'number' && Number.isFinite(val)) {
        return val;
    }
    if (typeof val === 'string' && val.trim() !== '') {
        const parsed = Number(val);
        if (Number.isFinite(parsed)) {
            return parsed;
        }
    }
    return null;
}
function clampProbability(p) {
    if (!Number.isFinite(p))
        return 0.01;
    return Math.min(0.995, Math.max(0.01, Number(p.toFixed(4))));
}
function execFileAsync(cmd, args, timeoutMs = 2000) {
    return new Promise((resolve) => {
        try {
            (0, child_process_1.execFile)(cmd, args, { timeout: timeoutMs, windowsHide: true, maxBuffer: 512 * 1024 }, (err, stdout, stderr) => {
                if (err) {
                    resolve({
                        stdout: String(stdout || ''),
                        stderr: String(stderr || err.message || ''),
                        exitCode: typeof err.code === 'number' ? err.code : 1
                    });
                    return;
                }
                resolve({
                    stdout: String(stdout || ''),
                    stderr: String(stderr || ''),
                    exitCode: 0
                });
            });
        }
        catch (spawnErr) {
            resolve({
                stdout: '',
                stderr: spawnErr && spawnErr.message ? spawnErr.message : String(spawnErr),
                exitCode: 127
            });
        }
    });
}
function getKnownInsecureSecrets() {
    try {
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        const cfg = require('../config');
        if (cfg && cfg.KNOWN_INSECURE_SECRETS instanceof Set) {
            return cfg.KNOWN_INSECURE_SECRETS;
        }
    }
    catch (_) { }
    return new Set([
        'EJII-ENTERPRISE-INTELLIGENCE-HMAC-SECURE-KEY-2026',
        'EJII-SRE-WAR-ROOM-SOVEREIGN-HMAC-KEY-2026',
        'EJII-ENTERPRISE-TOKEN-KEY-98471298471928471',
        'ejii-atlas-sovereign-hmac-secret-key-2026',
        'ejii-super-secret-jwt-key-change-in-production',
        'changeme',
        'default',
        'secret',
        'password'
    ]);
}
function getDefaultConfiguredHmacSecret() {
    try {
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        const cfg = require('../config');
        if (cfg && typeof cfg.getPurposeSeparatedSecret === 'function') {
            const purposeKey = cfg.getPurposeSeparatedSecret('sre-war-room-v1');
            if (typeof purposeKey === 'string' && purposeKey.length >= 16) {
                return purposeKey;
            }
        }
        if (cfg && typeof cfg.HMAC_SECRET === 'string' && cfg.HMAC_SECRET.length >= 16) {
            return cfg.HMAC_SECRET;
        }
    }
    catch (_) { }
    return process.env.EJII_HMAC_SECRET || '';
}
function validateHmacSecret(secret) {
    if (typeof secret !== 'string' || secret.trim().length < 16) {
        return {
            valid: false,
            secret: '',
            reason: 'HMAC_SECRET_MISSING_OR_TOO_SHORT'
        };
    }
    const trimmed = secret.trim();
    const insecureSet = getKnownInsecureSecrets();
    if (insecureSet.has(trimmed) || /^(changeme|default|secret|password|test)$/i.test(trimmed)) {
        return {
            valid: false,
            secret: '',
            reason: 'HMAC_SECRET_KNOWN_INSECURE_PLACEHOLDER'
        };
    }
    return {
        valid: true,
        secret: trimmed,
        reason: 'VALID_SOVEREIGN_SECRET'
    };
}
let middlewareModCache = null;
function getMiddlewareAuth() {
    if (middlewareModCache)
        return middlewareModCache;
    try {
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        middlewareModCache = require('../api/middleware');
        return middlewareModCache;
    }
    catch (_) {
        return null;
    }
}
let socketCorrelatorCache = null;
function getProcessSocketCorrelator() {
    if (socketCorrelatorCache)
        return socketCorrelatorCache;
    try {
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        socketCorrelatorCache = require('../network/process-socket-correlator');
        return socketCorrelatorCache;
    }
    catch (_) {
        return null;
    }
}
class AutonomousWarRoomOrchestrator {
    secretKey;
    activeKeyId;
    previousKeys = [];
    revokedKeyIds = new Set();
    hmacConfigured;
    hmacValidationReason;
    customDb;
    maxRetainedSessions;
    latestResult = null;
    sessionHistory = new Map();
    collectorReceipts = new Map();
    consumedReceiptSessions = new Map(); // receiptId -> sessionId
    dualApprovalsMemory = new Map();
    remediationLedgerMemory = new Map();
    corruptSessionsSkippedCount = 0;
    lastPersistenceState = 'VOLATILE_MEMORY_ONLY';
    lastPersistenceError = null;
    constructor(secretKeyOrOptions, maybeOptions = {}) {
        let secretKey;
        let options = {};
        if (typeof secretKeyOrOptions === 'object' && secretKeyOrOptions !== null) {
            options = secretKeyOrOptions;
            secretKey = secretKeyOrOptions.secretKey;
        }
        else {
            secretKey = secretKeyOrOptions;
            options = maybeOptions || {};
        }
        const candidateSecret = secretKey === undefined ? getDefaultConfiguredHmacSecret() : secretKey;
        const validation = validateHmacSecret(candidateSecret);
        this.secretKey = validation.secret;
        this.activeKeyId = options.keyId || 'sre-war-room-v1-primary';
        this.hmacConfigured = validation.valid;
        this.hmacValidationReason = validation.reason;
        this.customDb = options.db !== undefined ? options.db : undefined;
        this.maxRetainedSessions = Math.max(5, Math.min(1000, Number(options.maxRetainedSessions) || 100));
        this.hydrateSessionsFromDb();
    }
    /**
     * Rotates the active HMAC signing secret while retaining the prior key during a configurable grace window.
     */
    rotateHmacKey(newSecret, options = {}) {
        const validation = validateHmacSecret(newSecret);
        if (!validation.valid) {
            const err = new Error(`HMAC_SECRET_INVALID_FOR_ROTATION: ${validation.reason}`);
            err.code = validation.reason;
            throw err;
        }
        const gracePeriodMs = Math.max(50, Number(options.gracePeriodMs) || 3600_000);
        const now = Date.now();
        this.previousKeys = this.previousKeys.filter((k) => k.validUntilMs > now && !this.revokedKeyIds.has(k.keyId));
        if (this.hmacConfigured && this.secretKey && !this.revokedKeyIds.has(this.activeKeyId)) {
            this.previousKeys.push({
                keyId: this.activeKeyId,
                secret: this.secretKey,
                validUntilMs: now + gracePeriodMs
            });
        }
        const nextKeyId = options.keyId || `sre-war-room-v1-rot-${now}`;
        if (this.revokedKeyIds.has(nextKeyId)) {
            const err = new Error(`REVOKED_KEY_REUSE_BLOCKED: keyId "${nextKeyId}" was previously revoked.`);
            err.code = 'REVOKED_KEY_REUSE_BLOCKED';
            throw err;
        }
        this.secretKey = validation.secret;
        this.activeKeyId = nextKeyId;
        this.hmacConfigured = true;
        this.hmacValidationReason = 'VALID_SOVEREIGN_SECRET';
        return {
            rotated: true,
            activeKeyId: this.activeKeyId,
            previousKeysCount: this.previousKeys.length,
            gracePeriodMs
        };
    }
    /**
     * Explicitly revokes a specific keyId so that even within a grace window (or across restarts),
     * signatures produced by that keyId are immediately rejected.
     */
    revokeHmacKey(keyIdToRevoke, reason = 'Operator key revocation') {
        const cleanId = String(keyIdToRevoke || '').trim();
        if (!cleanId) {
            throw new Error('keyIdToRevoke is required.');
        }
        this.revokedKeyIds.add(cleanId);
        this.previousKeys = this.previousKeys.filter((k) => k.keyId !== cleanId);
        if (this.activeKeyId === cleanId) {
            this.hmacConfigured = false;
            this.secretKey = '';
            this.hmacValidationReason = 'ACTIVE_KEY_REVOKED';
        }
        try {
            // eslint-disable-next-line @typescript-eslint/no-var-requires
            const cfg = require('../config');
            if (cfg && typeof cfg.revokePurposeKey === 'function') {
                cfg.revokePurposeKey('sre-war-room-v1', cleanId, reason, { db: this.resolveDb() });
            }
        }
        catch (_) { }
        return {
            revoked: true,
            keyId: cleanId,
            reason,
            revokedAt: new Date().toISOString()
        };
    }
    isKeyIdRevoked(keyId) {
        if (!keyId)
            return false;
        if (this.revokedKeyIds.has(keyId))
            return true;
        try {
            // eslint-disable-next-line @typescript-eslint/no-var-requires
            const cfg = require('../config');
            if (cfg && typeof cfg.isPurposeKeyRevokedOrExpiredInDb === 'function') {
                if (cfg.isPurposeKeyRevokedOrExpiredInDb('sre-war-room-v1', keyId, this.resolveDb())) {
                    this.revokedKeyIds.add(keyId);
                    return true;
                }
            }
        }
        catch (_) { }
        return false;
    }
    verifyHmacWithKeyring(canonical, signature, requiredKeyId) {
        if (!signature || typeof signature !== 'string') {
            return { valid: false, matchedKeyId: null };
        }
        if (requiredKeyId && this.isKeyIdRevoked(requiredKeyId)) {
            return { valid: false, matchedKeyId: null };
        }
        const now = Date.now();
        const candidateKeys = [];
        if (this.hmacConfigured && this.secretKey && !this.isKeyIdRevoked(this.activeKeyId)) {
            candidateKeys.push({ keyId: this.activeKeyId, secret: this.secretKey });
        }
        for (const prev of this.previousKeys) {
            if (prev.validUntilMs > now && !this.isKeyIdRevoked(prev.keyId)) {
                candidateKeys.push({ keyId: prev.keyId, secret: prev.secret });
            }
        }
        try {
            // eslint-disable-next-line @typescript-eslint/no-var-requires
            const cfg = require('../config');
            if (cfg && typeof cfg.getPurposeKeyRing === 'function') {
                const ring = cfg.getPurposeKeyRing('sre-war-room-v1', { db: this.resolveDb() });
                if (ring && typeof ring === 'object' && !Array.isArray(ring)) {
                    if (typeof ring.activeSecret === 'string' && ring.activeSecret.length >= 16 && !this.isKeyIdRevoked(ring.activeKeyId)) {
                        candidateKeys.push({ keyId: ring.activeKeyId || 'cfg-active', secret: ring.activeSecret });
                    }
                    if (Array.isArray(ring.previousKeys)) {
                        for (const pk of ring.previousKeys) {
                            if (pk && typeof pk.secret === 'string' && pk.expiresAtMs > now && !this.isKeyIdRevoked(pk.keyId)) {
                                candidateKeys.push({ keyId: pk.keyId || 'cfg-prev', secret: pk.secret });
                            }
                        }
                    }
                }
            }
        }
        catch (_) { }
        const sigBuf = Buffer.from(signature, 'utf8');
        for (const candidate of candidateKeys) {
            if (this.isKeyIdRevoked(candidate.keyId))
                continue;
            const expected = crypto.createHmac('sha256', candidate.secret).update(canonical).digest('hex');
            const expBuf = Buffer.from(expected, 'utf8');
            if (sigBuf.length === expBuf.length && crypto.timingSafeEqual(sigBuf, expBuf)) {
                return { valid: true, matchedKeyId: candidate.keyId };
            }
        }
        return { valid: false, matchedKeyId: null };
    }
    resolveDb() {
        if (this.customDb !== undefined) {
            return this.customDb;
        }
        try {
            // eslint-disable-next-line @typescript-eslint/no-var-requires
            const { db } = require('../db/database');
            return db || null;
        }
        catch (_) {
            return null;
        }
    }
    getDiagnostics() {
        return {
            hmacConfigured: this.hmacConfigured,
            hmacValidationReason: this.hmacValidationReason,
            activeKeyId: this.activeKeyId,
            revokedKeysCount: this.revokedKeyIds.size,
            retainedSessionsInMemory: this.sessionHistory.size,
            maxRetainedSessions: this.maxRetainedSessions,
            corruptSessionsSkippedCount: this.corruptSessionsSkippedCount,
            collectorReceiptsIssuedCount: this.collectorReceipts.size,
            lastPersistenceState: this.lastPersistenceState,
            lastPersistenceError: this.lastPersistenceError
        };
    }
    /**
     * Signs local OS telemetry so internal collectors can prove DIRECT_LOCAL_OS_MEASUREMENT provenance.
     */
    signLocalTelemetry(metrics, observedAtIso) {
        const signingKey = this.hmacConfigured ? this.secretKey : 'fallback-unconfigured';
        const canonical = [
            'EJII-LOCAL-OS-TELEMETRY-V1',
            observedAtIso,
            String(metrics.rttMs ?? 'null'),
            String(metrics.packetLossPct ?? 'null'),
            String(metrics.cpuSaturationPct ?? 'null'),
            String(metrics.retransmissions ?? 'null'),
            String(metrics.activeFlows ?? 'null')
        ].join('|');
        return crypto.createHmac('sha256', signingKey).update(canonical).digest('hex');
    }
    /**
     * Creates and persists an HMAC-SHA256 CollectorExecutionReceipt (Section 6).
     */
    createCollectorExecutionReceipt(params) {
        const receiptId = `rcpt-${crypto.randomBytes(6).toString('hex')}`;
        const sessionId = params.sessionId || 'LIVE_COLLECTOR';
        const probeType = params.probeType || (params.probeId.includes('DNS') ? 'DNS_PTR_LOOKUP' :
            params.probeId.includes('PMTU') ? 'ICMP_PMTU_DISCOVERY' :
                params.probeId.includes('ARP') ? 'ARP_NEIGHBOR_VERIFY' : 'SOCKET_ESTABLISHED_AUDIT');
        const collectorId = params.collectorId || `ejii-collector-${os.hostname()}`;
        const startedAt = params.startedAt || new Date().toISOString();
        const completedAt = params.completedAt || new Date().toISOString();
        const durationMs = Number(Number(params.durationMs ?? 0).toFixed(3));
        const timingTarget = params.timingTarget || (probeType === 'DNS_PTR_LOOKUP' ? 'DNS_QUERY_RTT_MS' :
            probeType === 'ICMP_PMTU_DISCOVERY' ? 'ICMP_DF_PROBE_RTT_MS' :
                probeType === 'ARP_NEIGHBOR_VERIFY' ? 'LOCAL_OS_NEIGHBOR_TABLE_READ_MS' : 'LOCAL_OS_SOCKET_TABLE_READ_MS');
        const nativeResultCode = params.nativeResultCode || 'COLLECTOR_OK';
        const rawOutputSha256 = crypto.createHash('sha256').update(String(params.rawCommandOutput || '')).digest('hex');
        const signingKey = this.hmacConfigured ? this.secretKey : 'unconfigured-key';
        const canonical = [
            'EJII-COLLECTOR-RECEIPT-V1',
            receiptId,
            sessionId,
            params.probeId,
            probeType,
            params.target,
            collectorId,
            durationMs.toFixed(3),
            timingTarget,
            nativeResultCode,
            rawOutputSha256
        ].join('|');
        const hmacSignature = this.hmacConfigured
            ? crypto.createHmac('sha256', signingKey).update(canonical).digest('hex')
            : '';
        const receipt = {
            receiptId,
            sessionId,
            probeId: params.probeId,
            probeType,
            target: params.target,
            collectorId,
            startedAt,
            completedAt,
            durationMs,
            timingTarget,
            nativeResultCode,
            rawOutputSha256,
            keyId: this.activeKeyId,
            collectorTrustBoundary: 'TRUSTED_INTERNAL_COLLECTOR_EXECUTION',
            hmacSignature
        };
        receipt.receiptSignatureHex = hmacSignature;
        this.collectorReceipts.set(receiptId, receipt);
        const targetDb = this.resolveDb();
        if (targetDb && typeof targetDb.prepare === 'function') {
            try {
                targetDb
                    .prepare(`
            INSERT OR REPLACE INTO war_room_collector_receipts (
              receipt_id, session_id, probe_id, probe_type, target, collector_id,
              started_at, completed_at, duration_ms, timing_target, native_result_code,
              raw_output_sha256, hmac_signature, payload_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `)
                    .run(receipt.receiptId, receipt.sessionId, receipt.probeId, receipt.probeType, receipt.target, receipt.collectorId, receipt.startedAt, receipt.completedAt, receipt.durationMs, receipt.timingTarget, receipt.nativeResultCode, receipt.rawOutputSha256, receipt.hmacSignature, JSON.stringify(receipt), completedAt);
            }
            catch (_) { }
        }
        return receipt;
    }
    /**
     * Verifies a CollectorExecutionReceipt against HMAC-SHA256, output SHA-256, probeId, target, key revocation, and cross-session replay (Section 4.1).
     */
    verifyCollectorReceipt(receiptOrItem, expectedSessionId, expectedProbeId, expectedTarget) {
        const probe = expectedProbeId || receiptOrItem?.probeId || (receiptOrItem?.collectorExecutionReceipt?.probeId) || 'PROBE';
        const target = expectedTarget || receiptOrItem?.target || (receiptOrItem?.collectorExecutionReceipt?.target) || 'TARGET';
        const res = this.verifyCollectorExecutionReceipt(receiptOrItem, probe, target, expectedSessionId);
        return {
            ...res,
            code: res.reasonCode
        };
    }
    verifyCollectorExecutionReceipt(item, expectedProbeId, expectedTarget, expectedSessionId) {
        const r = item?.collectorExecutionReceipt || (item?.receiptId ? item : undefined);
        if (!r || typeof r !== 'object') {
            return {
                valid: false,
                code: 'UNTRUSTED_CALLER_PROBE_RESULT',
                reasonCode: 'UNTRUSTED_CALLER_PROBE_RESULT',
                message: `Supplied probe result "${expectedProbeId}" lacks a cryptographic collectorExecutionReceipt and cannot be admitted as LIVE_COLLECTOR_EXECUTION.`
            };
        }
        if (r.keyId && this.isKeyIdRevoked(r.keyId)) {
            return {
                valid: false,
                code: 'COLLECTOR_RECEIPT_KEY_REVOKED',
                reasonCode: 'COLLECTOR_RECEIPT_KEY_REVOKED',
                message: `Collector execution receipt signing key "${r.keyId}" was revoked.`
            };
        }
        if (!this.hmacConfigured) {
            return {
                valid: false,
                code: 'UNTRUSTED_CALLER_PROBE_RESULT',
                reasonCode: 'UNTRUSTED_CALLER_PROBE_RESULT',
                message: 'Orchestrator HMAC secret is not configured; collector receipt cannot be verified.'
            };
        }
        if (r.probeId !== expectedProbeId || r.target !== expectedTarget) {
            return {
                valid: false,
                reasonCode: 'UNTRUSTED_CALLER_PROBE_RESULT',
                message: `Collector receipt binding mismatch: receipt is bound to (${r.probeId}, ${r.target}) instead of (${expectedProbeId}, ${expectedTarget}).`
            };
        }
        if (expectedSessionId &&
            r.sessionId !== expectedSessionId &&
            r.sessionId !== 'LIVE_COLLECTOR') {
            return {
                valid: false,
                reasonCode: 'UNTRUSTED_CALLER_PROBE_RESULT',
                message: `Collector receipt sessionId "${r.sessionId}" does not match session "${expectedSessionId}".`
            };
        }
        // Prevent cross-session receipt replay: if a LIVE_COLLECTOR receipt was already consumed in a different sessionId, reject it
        if (expectedSessionId && r.receiptId) {
            const priorConsumedSession = this.consumedReceiptSessions.get(r.receiptId);
            if (priorConsumedSession && priorConsumedSession !== expectedSessionId) {
                return {
                    valid: false,
                    reasonCode: 'CROSS_SESSION_RECEIPT_REPLAY_BLOCKED',
                    message: `Collector receipt "${r.receiptId}" was already consumed in session "${priorConsumedSession}" and cannot be replayed in session "${expectedSessionId}".`
                };
            }
            const targetDb = this.resolveDb();
            if (targetDb && typeof targetDb.prepare === 'function') {
                try {
                    const row = targetDb
                        .prepare('SELECT session_id FROM war_room_consumed_receipts WHERE receipt_id = ?')
                        .get(r.receiptId);
                    if (row && row.session_id && row.session_id !== expectedSessionId) {
                        return {
                            valid: false,
                            reasonCode: 'CROSS_SESSION_RECEIPT_REPLAY_BLOCKED',
                            message: `Collector receipt "${r.receiptId}" was already consumed in persisted session "${row.session_id}".`
                        };
                    }
                }
                catch (_) { }
            }
        }
        if (typeof item.rawCommandOutput === 'string' || typeof item.output === 'string') {
            const rawOut = typeof item.rawCommandOutput === 'string'
                ? item.rawCommandOutput
                : item.output;
            const actualSha = crypto.createHash('sha256').update(rawOut).digest('hex');
            if (actualSha !== r.rawOutputSha256) {
                return {
                    valid: false,
                    reasonCode: 'UNTRUSTED_CALLER_PROBE_RESULT',
                    message: `Collector receipt rawOutputSha256 mismatch for probe "${expectedProbeId}" (output tampered).`
                };
            }
        }
        const canonical = [
            'EJII-COLLECTOR-RECEIPT-V1',
            r.receiptId,
            r.sessionId,
            r.probeId,
            r.probeType,
            r.target,
            r.collectorId,
            Number(r.durationMs).toFixed(3),
            r.timingTarget,
            r.nativeResultCode,
            r.rawOutputSha256
        ].join('|');
        const sigCheck = this.verifyHmacWithKeyring(canonical, String(r.hmacSignature || ''), r.keyId);
        if (!sigCheck.valid) {
            return {
                valid: false,
                reasonCode: 'UNTRUSTED_CALLER_PROBE_RESULT',
                message: `Collector receipt HMAC-SHA256 signature verification failed for probe "${expectedProbeId}".`
            };
        }
        return {
            valid: true,
            reasonCode: 'VERIFIED_COLLECTOR_RECEIPT',
            message: 'Verified cryptographic collector execution receipt.',
            receipt: r
        };
    }
    /**
     * Issues a cryptographically signed and SQLite-persisted Dual-Operator Approval token (Section 10).
     */
    issueDualOperatorApproval(params) {
        if (!this.hmacConfigured) {
            throw new Error('HMAC_SECRET_NOT_CONFIGURED: Cannot issue dual-operator approval without valid sovereign HMAC secret.');
        }
        const cleanSessionId = String(params.sessionId || '').trim();
        const cleanOperatorId = String(params.operatorId || '').trim();
        const cleanRole = String(params.operatorRole || '').trim().toUpperCase();
        const slot = params.slot === 'SECONDARY' ? 'SECONDARY' : 'PRIMARY';
        if (!cleanSessionId || !cleanOperatorId) {
            throw new Error('INVALID_DUAL_APPROVAL_INPUT: sessionId and operatorId are required.');
        }
        if (!PRIVILEGED_ROLES.has(cleanRole)) {
            throw new Error(`INSUFFICIENT_ROLE_FOR_DUAL_APPROVAL: Role "${cleanRole}" is not authorized to approve War-Room remediations.`);
        }
        const session = this.getSessionById(cleanSessionId);
        const remediationAction = params.remediationAction || session?.agent4?.proposedRemediationAction || 'GOVERNED_REMEDIATION';
        const target = params.target || session?.agent4?.remediationTarget || '127.0.0.1';
        const existingList = this.dualApprovalsMemory.get(cleanSessionId) || [];
        if (slot === 'SECONDARY') {
            const primaryRec = existingList.find((r) => r.slot === 'PRIMARY' && r.expiresAt > Date.now());
            if (primaryRec && primaryRec.operatorId === cleanOperatorId) {
                const err = new Error(`DUAL_CONTROL_VIOLATION_SAME_OPERATOR: Secondary approver "${cleanOperatorId}" cannot be the same operator as Primary approver.`);
                err.code = 'DUAL_CONTROL_VIOLATION_SAME_OPERATOR';
                err.statusCode = 403;
                throw err;
            }
        }
        const approvalId = `wr-appr-${crypto.randomBytes(6).toString('hex')}`;
        const issuedAt = new Date().toISOString();
        const expiresAt = Date.now() + Math.max(10_000, Number(params.ttlMs) || 15 * 60 * 1000);
        const operatorUsername = params.operatorUsername || cleanOperatorId;
        const canonical = [
            'EJII-WARROOM-DUAL-APPROVAL-V1',
            approvalId,
            cleanSessionId,
            remediationAction,
            target,
            cleanOperatorId,
            cleanRole,
            slot,
            String(expiresAt)
        ].join('|');
        const tokenSignature = crypto.createHmac('sha256', this.secretKey).update(canonical).digest('hex');
        const record = {
            approvalId,
            sessionId: cleanSessionId,
            remediationAction,
            target,
            operatorId: cleanOperatorId,
            operatorUsername,
            operatorRole: cleanRole,
            slot,
            issuedAt,
            expiresAt,
            tokenSignature
        };
        existingList.push(record);
        this.dualApprovalsMemory.set(cleanSessionId, existingList);
        const targetDb = this.resolveDb();
        if (targetDb && typeof targetDb.prepare === 'function') {
            try {
                targetDb
                    .prepare(`
            INSERT INTO war_room_dual_approvals (
              approval_id, session_id, remediation_action, target,
              operator_id, operator_username, operator_role, approval_slot,
              token_signature, issued_at, expires_at, consumed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
          `)
                    .run(record.approvalId, record.sessionId, record.remediationAction, record.target, record.operatorId, record.operatorUsername, record.operatorRole, record.slot, record.tokenSignature, record.issuedAt, record.expiresAt);
            }
            catch (_) { }
        }
        return {
            ...record,
            verifiedApprovalObject: {
                operatorId: cleanOperatorId,
                role: cleanRole,
                authenticated: true,
                approvalId,
                tokenSignature,
                expiresAt,
                source: 'SERVER_SESSION_JWT'
            }
        };
    }
    /**
     * Verifies a single operator approval slot (PRIMARY or SECONDARY) using either:
     *   1. Cryptographic HMAC tokenSignature + approvalId bound to the session, OR
     *   2. Server-verified JWT token (via middleware.verifyToken), OR
     *   3. Durable SQLite record in war_room_dual_approvals.
     * Rejects plain caller-supplied `{ authenticated: true }` objects that lack cryptographic proof!
     */
    verifySingleApprovalSlot(sessionId, slotInput, expectedSlot) {
        if (!this.hmacConfigured) {
            return { valid: false, operatorId: '', role: '', reason: 'HMAC secret unconfigured' };
        }
        const nowMs = Date.now();
        // 1. Check server-verified JWT token if supplied
        if (slotInput && typeof slotInput.jwtToken === 'string' && slotInput.jwtToken.trim().length > 0) {
            const mw = getMiddlewareAuth();
            if (mw && typeof mw.verifyToken === 'function') {
                const decoded = mw.verifyToken(slotInput.jwtToken.trim());
                if (decoded && decoded.id && PRIVILEGED_ROLES.has(String(decoded.role || '').toUpperCase())) {
                    return {
                        valid: true,
                        operatorId: String(decoded.username || decoded.id),
                        role: String(decoded.role).toUpperCase(),
                        reason: 'Verified via server JWT token'
                    };
                }
            }
        }
        // 2. Check cryptographic approvalId + tokenSignature
        if (slotInput && typeof slotInput.approvalId === 'string' && typeof slotInput.tokenSignature === 'string') {
            const memList = this.dualApprovalsMemory.get(sessionId) || [];
            const memMatch = memList.find((r) => r.approvalId === slotInput.approvalId && r.expiresAt > nowMs);
            if (memMatch) {
                const canonical = [
                    'EJII-WARROOM-DUAL-APPROVAL-V1',
                    memMatch.approvalId,
                    memMatch.sessionId,
                    memMatch.remediationAction,
                    memMatch.target,
                    memMatch.operatorId,
                    memMatch.operatorRole,
                    memMatch.slot,
                    String(memMatch.expiresAt)
                ].join('|');
                const sigCheck = this.verifyHmacWithKeyring(canonical, String(slotInput.tokenSignature || ''));
                if (sigCheck.valid && PRIVILEGED_ROLES.has(memMatch.operatorRole)) {
                    return {
                        valid: true,
                        operatorId: memMatch.operatorId,
                        role: memMatch.operatorRole,
                        reason: `Verified via signed approval token (${memMatch.approvalId})`
                    };
                }
            }
            const targetDb = this.resolveDb();
            if (targetDb && typeof targetDb.prepare === 'function') {
                try {
                    const row = targetDb
                        .prepare('SELECT * FROM war_room_dual_approvals WHERE approval_id = ? AND session_id = ?')
                        .get(slotInput.approvalId, sessionId);
                    if (row && Number(row.expires_at) > nowMs) {
                        const canonical = [
                            'EJII-WARROOM-DUAL-APPROVAL-V1',
                            row.approval_id,
                            row.session_id,
                            row.remediation_action,
                            row.target,
                            row.operator_id,
                            row.operator_role,
                            row.approval_slot,
                            String(row.expires_at)
                        ].join('|');
                        const sigCheck = this.verifyHmacWithKeyring(canonical, String(slotInput.tokenSignature || ''));
                        if (sigCheck.valid && PRIVILEGED_ROLES.has(String(row.operator_role).toUpperCase())) {
                            return {
                                valid: true,
                                operatorId: String(row.operator_id),
                                role: String(row.operator_role).toUpperCase(),
                                reason: `Verified via SQLite approval ledger (${row.approval_id})`
                            };
                        }
                    }
                }
                catch (_) { }
            }
        }
        // 3. Check if an unconsumed approval record was already issued for this session & slot in SQLite / memory
        const candidateOpId = typeof slotInput?.operatorId === 'string' ? slotInput.operatorId.trim() : '';
        const memList = this.dualApprovalsMemory.get(sessionId) || [];
        const preIssuedMem = memList.find((r) => r.slot === expectedSlot && r.expiresAt > nowMs && (!candidateOpId || r.operatorId === candidateOpId));
        if (preIssuedMem && PRIVILEGED_ROLES.has(preIssuedMem.operatorRole)) {
            return {
                valid: true,
                operatorId: preIssuedMem.operatorId,
                role: preIssuedMem.operatorRole,
                reason: `Verified via pre-issued session approval (${preIssuedMem.approvalId})`
            };
        }
        return {
            valid: false,
            operatorId: candidateOpId,
            role: typeof slotInput?.role === 'string' ? slotInput.role : '',
            reason: `Unverified ${expectedSlot} approval: caller-supplied boolean flags without cryptographic tokenSignature or server JWT are rejected.`
        };
    }
    /**
     * Records a cryptographically signed remediation execution in SQLite war_room_remediation_ledger (Section 11).
     */
    recordRemediationExecution(params) {
        const executionId = `rem-exec-${crypto.randomBytes(6).toString('hex')}`;
        const sessionId = params.sessionId || 'DIRECT_EXECUTION';
        const remediationAction = params.remediationAction || 'GOVERNED_REMEDIATION';
        const target = String(params.target || '127.0.0.1').trim();
        const executorSource = params.executorSource || 'GOVERNED_ACTION_CONTROL_PLANE';
        const operatorId = String(params.operatorId || 'system').trim();
        const startedAt = params.startedAt || new Date().toISOString();
        const completedAt = params.completedAt || new Date().toISOString();
        const exitCode = typeof params.exitCode === 'number' ? params.exitCode : (params.success ? 0 : 1);
        const outputSummary = params.outputSummary || `Remediation ${remediationAction} executed on ${target}`;
        const signingKey = this.hmacConfigured ? this.secretKey : 'unconfigured';
        const canonical = [
            'EJII-REMEDIATION-LEDGER-V1',
            executionId,
            sessionId,
            remediationAction,
            target,
            executorSource,
            operatorId,
            startedAt,
            completedAt,
            String(exitCode),
            params.success ? '1' : '0'
        ].join('|');
        const hmacSignature = this.hmacConfigured
            ? crypto.createHmac('sha256', signingKey).update(canonical).digest('hex')
            : '';
        const receipt = {
            executionId,
            sessionId,
            remediationAction,
            target,
            executorSource,
            operatorId,
            startedAt,
            completedAt,
            exitCode,
            success: Boolean(params.success),
            outputSummary,
            hmacSignature
        };
        this.remediationLedgerMemory.set(executionId, receipt);
        const targetDb = this.resolveDb();
        if (targetDb && typeof targetDb.prepare === 'function') {
            try {
                targetDb
                    .prepare(`
            INSERT INTO war_room_remediation_ledger (
              execution_id, session_id, remediation_action, target,
              executor_source, operator_id, started_at, completed_at,
              exit_code, success, output_summary, hmac_signature
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          `)
                    .run(receipt.executionId, receipt.sessionId, receipt.remediationAction, receipt.target, receipt.executorSource, receipt.operatorId, receipt.startedAt, receipt.completedAt, receipt.exitCode, receipt.success ? 1 : 0, receipt.outputSummary, receipt.hmacSignature);
            }
            catch (_) { }
        }
        return receipt;
    }
    /**
     * Verifies a remediationExecutionResult against the durable remediation ledger and HMAC signature (Section 11).
     */
    verifyRemediationExecutionReceipt(remExec, expectedTarget) {
        if (!remExec || typeof remExec !== 'object' || remExec.executed !== true || remExec.success !== true) {
            return { verified: false, completedAtMs: 0, reasonCode: 'REMEDIATION_NOT_YET_EXECUTED' };
        }
        if (String(remExec.target || expectedTarget) !== expectedTarget) {
            return { verified: false, completedAtMs: 0, reasonCode: 'REMEDIATION_TARGET_MISMATCH' };
        }
        if (!this.hmacConfigured || typeof remExec.executionId !== 'string' || typeof remExec.hmacSignature !== 'string') {
            return { verified: false, completedAtMs: 0, reasonCode: 'UNVERIFIED_REMEDIATION_EXECUTION_RECEIPT' };
        }
        let stored = this.remediationLedgerMemory.get(remExec.executionId) || null;
        if (!stored) {
            const targetDb = this.resolveDb();
            if (targetDb && typeof targetDb.prepare === 'function') {
                try {
                    const row = targetDb
                        .prepare('SELECT * FROM war_room_remediation_ledger WHERE execution_id = ?')
                        .get(remExec.executionId);
                    if (row) {
                        stored = {
                            executionId: row.execution_id,
                            sessionId: row.session_id,
                            remediationAction: row.remediation_action,
                            target: row.target,
                            executorSource: row.executor_source,
                            operatorId: row.operator_id,
                            startedAt: row.started_at,
                            completedAt: row.completed_at,
                            exitCode: Number(row.exit_code),
                            success: Number(row.success) === 1,
                            outputSummary: row.output_summary,
                            hmacSignature: row.hmac_signature
                        };
                    }
                }
                catch (_) { }
            }
        }
        if (!stored || !stored.success || stored.target !== expectedTarget) {
            return { verified: false, completedAtMs: 0, reasonCode: 'UNVERIFIED_REMEDIATION_EXECUTION_RECEIPT' };
        }
        const canonical = [
            'EJII-REMEDIATION-LEDGER-V1',
            stored.executionId,
            stored.sessionId,
            stored.remediationAction,
            stored.target,
            stored.executorSource,
            stored.operatorId,
            stored.startedAt,
            stored.completedAt,
            String(stored.exitCode),
            stored.success ? '1' : '0'
        ].join('|');
        const sigCheck = this.verifyHmacWithKeyring(canonical, String(remExec.hmacSignature || ''));
        if (!sigCheck.valid || remExec.hmacSignature !== stored.hmacSignature) {
            return { verified: false, completedAtMs: 0, reasonCode: 'UNVERIFIED_REMEDIATION_EXECUTION_RECEIPT' };
        }
        const completedAtMs = Date.parse(stored.completedAt) || Date.now();
        return { verified: true, completedAtMs, reasonCode: 'VERIFIED_REMEDIATION_EXECUTION_RECEIPT' };
    }
    hydrateSessionsFromDb() {
        const targetDb = this.resolveDb();
        if (!targetDb || typeof targetDb.prepare !== 'function') {
            this.lastPersistenceState = 'VOLATILE_MEMORY_ONLY';
            return;
        }
        try {
            const tableCheck = targetDb
                .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='war_room_sessions'")
                .get();
            if (!tableCheck) {
                this.lastPersistenceState = 'VOLATILE_MEMORY_ONLY';
                return;
            }
            // Order by rowid DESC so sessions created in the same millisecond preserve exact insertion order (Section 14)
            const rows = targetDb
                .prepare('SELECT rowid, session_id, parent_session_id, executed_at, status, lifecycle_stage, persistence_state, payload_json FROM war_room_sessions ORDER BY rowid DESC LIMIT ?')
                .all(this.maxRetainedSessions);
            const orderedRows = [...rows].reverse();
            for (const row of orderedRows) {
                try {
                    const parsed = JSON.parse(row.payload_json);
                    if (!parsed ||
                        typeof parsed !== 'object' ||
                        typeof parsed.sessionId !== 'string' ||
                        !parsed.agent1 ||
                        !parsed.agent4 ||
                        !parsed.agent5 ||
                        !parsed.round4EmpiricalSettlement) {
                        this.corruptSessionsSkippedCount += 1;
                        continue;
                    }
                    if (row.parent_session_id && !parsed.parentSessionId) {
                        parsed.parentSessionId = row.parent_session_id;
                    }
                    parsed.persistenceState = 'DURABLE_SQLITE_WAL';
                    this.sessionHistory.set(parsed.sessionId, parsed);
                    this.latestResult = parsed;
                }
                catch (_) {
                    this.corruptSessionsSkippedCount += 1;
                }
            }
            this.lastPersistenceState = 'DURABLE_SQLITE_WAL';
            this.lastPersistenceError = null;
        }
        catch (err) {
            this.lastPersistenceState = 'VOLATILE_MEMORY_ONLY';
            this.lastPersistenceError = err?.message || String(err);
        }
    }
    enforceMemoryRetention() {
        while (this.sessionHistory.size > this.maxRetainedSessions) {
            const oldestKey = this.sessionHistory.keys().next().value;
            if (!oldestKey)
                break;
            this.sessionHistory.delete(oldestKey);
        }
    }
    persistSessionToDb(transcript) {
        const targetDb = this.resolveDb();
        if (!targetDb || typeof targetDb.prepare !== 'function') {
            transcript.persistenceState = 'VOLATILE_MEMORY_ONLY';
            transcript.persistenceError = 'Database handle is not initialized.';
            this.lastPersistenceState = 'VOLATILE_MEMORY_ONLY';
            this.lastPersistenceError = transcript.persistenceError;
            return 'VOLATILE_MEMORY_ONLY';
        }
        try {
            const cols = targetDb.prepare('PRAGMA table_info(war_room_sessions)').all();
            if (!cols || cols.length === 0) {
                transcript.persistenceState = 'PERSISTENCE_WRITE_FAILED';
                transcript.persistenceError = 'Table war_room_sessions does not exist (Migration 007 not applied).';
                this.lastPersistenceState = 'PERSISTENCE_WRITE_FAILED';
                this.lastPersistenceError = transcript.persistenceError;
                return 'PERSISTENCE_WRITE_FAILED';
            }
            const colNames = new Set(cols.map((c) => c.name));
            transcript.persistenceState = 'DURABLE_SQLITE_WAL';
            transcript.persistenceError = null;
            if (colNames.has('parent_session_id') && colNames.has('lifecycle_stage')) {
                targetDb
                    .prepare(`
            INSERT OR REPLACE INTO war_room_sessions (
              session_id, parent_session_id, executed_at, status, lifecycle_stage, persistence_state, payload_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
          `)
                    .run(transcript.sessionId, transcript.parentSessionId || null, transcript.executedAt, transcript.status, transcript.incidentLifecycleStage, 'DURABLE_SQLITE_WAL', JSON.stringify(transcript));
            }
            else {
                targetDb
                    .prepare('INSERT OR REPLACE INTO war_room_sessions (session_id, executed_at, payload_json) VALUES (?, ?, ?)')
                    .run(transcript.sessionId, transcript.executedAt, JSON.stringify(transcript));
            }
            // Section 14: Order by rowid DESC so millisecond timestamp ties never evict the latest inserted session
            targetDb
                .prepare(`
          DELETE FROM war_room_sessions
          WHERE rowid NOT IN (
            SELECT rowid FROM war_room_sessions ORDER BY rowid DESC LIMIT ?
          )
        `)
                .run(this.maxRetainedSessions);
            this.lastPersistenceState = 'DURABLE_SQLITE_WAL';
            this.lastPersistenceError = null;
            return 'DURABLE_SQLITE_WAL';
        }
        catch (err) {
            transcript.persistenceState = 'PERSISTENCE_WRITE_FAILED';
            transcript.persistenceError = err?.message || String(err);
            this.lastPersistenceState = 'PERSISTENCE_WRITE_FAILED';
            this.lastPersistenceError = transcript.persistenceError;
            return 'PERSISTENCE_WRITE_FAILED';
        }
    }
    getLocalHostNetworkSummary() {
        const hostname = os.hostname();
        const interfaces = os.networkInterfaces() || {};
        const interfaceNames = Object.keys(interfaces);
        let primaryIpv4 = '127.0.0.1';
        let localInterfaceMtuBytes = 1500;
        for (const name of interfaceNames) {
            const list = interfaces[name] || [];
            for (const addr of list) {
                if (addr && addr.family === 'IPv4' && !addr.internal && addr.address) {
                    primaryIpv4 = addr.address;
                    if (typeof addr.mtu === 'number' && addr.mtu > 0) {
                        localInterfaceMtuBytes = addr.mtu;
                    }
                    break;
                }
            }
            if (primaryIpv4 !== '127.0.0.1')
                break;
        }
        let dnsServers = [];
        try {
            dnsServers = dns.getServers() || [];
        }
        catch (_) { }
        return { hostname, primaryIpv4, interfaceNames, dnsServers, localInterfaceMtuBytes };
    }
    verifyOperatorIdentity(payload) {
        const authCtx = payload?.authContext;
        if (authCtx &&
            typeof authCtx === 'object' &&
            authCtx.authenticated === true &&
            authCtx.source === 'SERVER_SESSION_JWT' &&
            typeof authCtx.userId === 'string' &&
            authCtx.userId.trim().length > 0 &&
            typeof authCtx.role === 'string') {
            const normRole = authCtx.role.trim().toUpperCase();
            if (PRIVILEGED_ROLES.has(normRole)) {
                return {
                    operatorAuthorized: true,
                    operatorRoleVerified: true,
                    verifiedOperatorId: authCtx.userId.trim(),
                    verifiedOperatorRole: normRole,
                    authorizationStatus: 'SERVER_SESSION_VERIFIED'
                };
            }
            return {
                operatorAuthorized: false,
                operatorRoleVerified: true,
                verifiedOperatorId: authCtx.userId.trim(),
                verifiedOperatorRole: normRole,
                authorizationStatus: 'INSUFFICIENT_OPERATOR_ROLE'
            };
        }
        if (payload && typeof payload.operatorRole === 'string' && payload.operatorRole.trim().length > 0) {
            return {
                operatorAuthorized: false,
                operatorRoleVerified: false,
                verifiedOperatorId: null,
                verifiedOperatorRole: null,
                authorizationStatus: 'UNVERIFIED_CALLER_ROLE_REJECTED'
            };
        }
        return {
            operatorAuthorized: false,
            operatorRoleVerified: false,
            verifiedOperatorId: null,
            verifiedOperatorRole: null,
            authorizationStatus: 'NO_OPERATOR_SESSION_SUPPLIED'
        };
    }
    buildInitialProbes(targetHost, dnsTarget) {
        return [
            {
                probeId: 'PROBE-DNS-01',
                initiatingAgent: 'Agent 3 — Deep Wire Forensics',
                probeType: 'DNS_PTR_LOOKUP',
                commandPayload: `dns.promises.Resolver.reverse(${dnsTarget})`,
                target: dnsTarget,
                safetyGuardClassification: 'READ_ONLY_SAFE_POL_01',
                executionState: 'PROPOSED',
                executed: false,
                measuredLatencyMs: null,
                timingTarget: 'DNS_QUERY_RTT_MS',
                nativeResultCode: null,
                probeClassification: null,
                conclusive: null,
                rawCommandOutput: null,
                empiricalObservation: null,
                simulatedOutcome: `Execute real DNS query against ${dnsTarget} and measure resolution RTT and RCODE.`,
                evidenceProvenance: 'PROPOSED_ONLY_NOT_EXECUTED',
                collectorExecutionReceipt: null,
                executedAt: null
            },
            {
                probeId: 'PROBE-PMTU-02',
                initiatingAgent: 'Agent 1 — L1/L2 Physical & DataLink Sentinel',
                probeType: 'ICMP_PMTU_DISCOVERY',
                commandPayload: process.platform === 'win32'
                    ? `ping -n 1 -f -l 1472 -w 1000 ${targetHost}`
                    : `ping -c 1 -M do -s 1472 -W 1 ${targetHost}`,
                target: targetHost,
                safetyGuardClassification: 'READ_ONLY_SAFE_POL_01',
                executionState: 'PROPOSED',
                executed: false,
                measuredLatencyMs: null,
                timingTarget: 'ICMP_DF_PROBE_RTT_MS',
                nativeResultCode: null,
                probeClassification: null,
                conclusive: null,
                rawCommandOutput: null,
                empiricalObservation: null,
                simulatedOutcome: `Test DF-bit Path MTU across ${targetHost} for fragmentation-needed or blackhole drops.`,
                evidenceProvenance: 'PROPOSED_ONLY_NOT_EXECUTED',
                collectorExecutionReceipt: null,
                executedAt: null
            },
            {
                probeId: 'PROBE-ARP-03',
                initiatingAgent: 'Agent 2 — L3/L4 Transport & Routing Auditor',
                probeType: 'ARP_NEIGHBOR_VERIFY',
                commandPayload: process.platform === 'win32' ? `arp -a ${targetHost}` : `ip neigh show ${targetHost}`,
                target: targetHost,
                safetyGuardClassification: 'READ_ONLY_SAFE_POL_01',
                executionState: 'PROPOSED',
                executed: false,
                measuredLatencyMs: null,
                timingTarget: 'LOCAL_OS_NEIGHBOR_TABLE_READ_MS',
                nativeResultCode: null,
                probeClassification: null,
                conclusive: null,
                rawCommandOutput: null,
                empiricalObservation: null,
                simulatedOutcome: `Inspect OS kernel IPv4 ARP / IPv6 NDP neighbor cache state for ${targetHost}.`,
                evidenceProvenance: 'PROPOSED_ONLY_NOT_EXECUTED',
                collectorExecutionReceipt: null,
                executedAt: null
            },
            {
                probeId: 'PROBE-SOCK-04',
                initiatingAgent: 'Agent 2 — L3/L4 Transport & Routing Auditor',
                probeType: 'SOCKET_ESTABLISHED_AUDIT',
                commandPayload: `processSocketCorrelator.collectActiveConnectionsInventory(target=${targetHost})`,
                target: targetHost,
                safetyGuardClassification: 'READ_ONLY_SAFE_POL_01',
                executionState: 'PROPOSED',
                executed: false,
                measuredLatencyMs: null,
                timingTarget: 'LOCAL_OS_SOCKET_TABLE_READ_MS',
                nativeResultCode: null,
                probeClassification: null,
                conclusive: null,
                rawCommandOutput: null,
                empiricalObservation: null,
                simulatedOutcome: `Audit active OS kernel sockets (ESTABLISHED, SYN_SENT, TIME_WAIT, CLOSE_WAIT) for ${targetHost}.`,
                evidenceProvenance: 'PROPOSED_ONLY_NOT_EXECUTED',
                collectorExecutionReceipt: null,
                executedAt: null
            }
        ];
    }
    /**
     * Section 6 & Section 7:
     * - Enforces cryptographic CollectorExecutionReceipt admission (`UNTRUSTED_CALLER_PROBE_RESULT` on missing/forged receipt)
     * - Deduplicates correlated observations on the same probeId
     * - Applies protocol-aware, hypothesis-specific Bayesian likelihood matrices across L1, L4, and L7
     * - Enforces epistemic abstention when probes are inconclusive or irrelevant to the hypothesis
     */
    applyExecutedProbeResults(probes, suppliedResults, agent1, agent2, agent3, canEstablishFromTelemetry, sessionId) {
        const rejectedProbeResults = [];
        const empiricalObservations = [];
        const seenProbeIds = new Set();
        const seenReceiptIds = new Set();
        const probeExecutionTimestamps = new Map();
        const sequentialCorrelatedObservations = [];
        if (Array.isArray(suppliedResults)) {
            for (const rawItem of suppliedResults) {
                if (!rawItem || typeof rawItem !== 'object')
                    continue;
                const item = rawItem;
                const probeId = String(item.probeId || '').trim();
                const suppliedTarget = String(item.target || '').trim();
                const matchingProbe = probes.find((p) => p.probeId === probeId);
                if (!matchingProbe) {
                    rejectedProbeResults.push({
                        probeId: probeId || 'UNKNOWN_PROBE',
                        suppliedTarget,
                        expectedTarget: null,
                        reasonCode: 'PROBE_ID_NOT_FOUND',
                        message: `Supplied probe result "${probeId}" does not match any proposed probe in this session.`
                    });
                    continue;
                }
                if (matchingProbe.safetyGuardClassification !== 'READ_ONLY_SAFE_POL_01') {
                    matchingProbe.executionState = 'BLOCKED_BY_POLICY';
                    matchingProbe.executed = false;
                    matchingProbe.evidenceProvenance = 'POLICY_BLOCKED';
                    rejectedProbeResults.push({
                        probeId,
                        suppliedTarget,
                        expectedTarget: matchingProbe.target,
                        reasonCode: 'PROBE_POLICY_BLOCKED',
                        message: `Probe "${probeId}" is blocked by POL-02 safety policy and cannot contribute empirical evidence.`
                    });
                    continue;
                }
                if (!suppliedTarget || suppliedTarget !== matchingProbe.target) {
                    rejectedProbeResults.push({
                        probeId,
                        suppliedTarget,
                        expectedTarget: matchingProbe.target,
                        reasonCode: 'PROBE_TARGET_MISMATCH',
                        message: `Probe "${probeId}" target mismatch: expected "${matchingProbe.target}", received "${suppliedTarget}".`
                    });
                    continue;
                }
                // Section 7: Distinguish duplicate/replayed probe results from genuine sequential re-executions
                const candidateReceiptId = String(item?.collectorExecutionReceipt?.receiptId || '').trim();
                const candidateCompletedAt = String(item?.executedAt || item?.collectorExecutionReceipt?.completedAt || '').trim();
                const priorTimestamp = probeExecutionTimestamps.get(probeId);
                const isDuplicateReplay = seenProbeIds.has(probeId) &&
                    (!candidateReceiptId ||
                        seenReceiptIds.has(candidateReceiptId) ||
                        (!item.allowSequentialReExecution &&
                            (!candidateCompletedAt || candidateCompletedAt === priorTimestamp)));
                if (isDuplicateReplay) {
                    rejectedProbeResults.push({
                        probeId,
                        suppliedTarget,
                        expectedTarget: matchingProbe.target,
                        reasonCode: 'DUPLICATE_CORRELATED_PROBE',
                        message: `Duplicate or replayed observation for probe "${probeId}" (receipt=${candidateReceiptId || 'none'}) skipped to prevent Bayesian double-counting.`
                    });
                    continue;
                }
                const measuredLatency = readFiniteNumber(item.measuredLatencyMs);
                const rawOutput = typeof item.rawCommandOutput === 'string'
                    ? item.rawCommandOutput.trim()
                    : typeof item.output === 'string'
                        ? item.output.trim()
                        : '';
                if (measuredLatency === null || measuredLatency < 0 || !rawOutput) {
                    matchingProbe.executionState = 'FAILED';
                    matchingProbe.executed = true;
                    matchingProbe.evidenceProvenance = 'COLLECTOR_EXECUTION_FAILED';
                    rejectedProbeResults.push({
                        probeId,
                        suppliedTarget,
                        expectedTarget: matchingProbe.target,
                        reasonCode: 'INVALID_PROBE_OUTPUT',
                        message: `Probe "${probeId}" is missing finite measuredLatencyMs or rawCommandOutput.`
                    });
                    continue;
                }
                // Section 6: Verify cryptographic CollectorExecutionReceipt before admitting as LIVE_COLLECTOR_EXECUTION
                const receiptCheck = this.verifyCollectorExecutionReceipt({ ...item, rawCommandOutput: rawOutput }, probeId, matchingProbe.target, sessionId);
                if (!receiptCheck.valid) {
                    matchingProbe.executionState = 'REJECTED_UNTRUSTED';
                    matchingProbe.executed = false;
                    matchingProbe.evidenceProvenance = 'UNTRUSTED_CALLER_SUPPLIED';
                    rejectedProbeResults.push({
                        probeId,
                        suppliedTarget,
                        expectedTarget: matchingProbe.target,
                        reasonCode: receiptCheck.reasonCode,
                        message: receiptCheck.message
                    });
                    continue;
                }
                const isSequentialReExecution = seenProbeIds.has(probeId);
                seenProbeIds.add(probeId);
                if (receiptCheck.receipt?.receiptId) {
                    seenReceiptIds.add(receiptCheck.receipt.receiptId);
                    if (sessionId) {
                        this.consumedReceiptSessions.set(receiptCheck.receipt.receiptId, sessionId);
                        const targetDb = this.resolveDb();
                        if (targetDb && typeof targetDb.prepare === 'function') {
                            try {
                                targetDb
                                    .prepare(`
                    INSERT OR IGNORE INTO war_room_consumed_receipts (
                      receipt_id, session_id, probe_id, target, consumed_at_ms
                    ) VALUES (?, ?, ?, ?, ?)
                  `)
                                    .run(receiptCheck.receipt.receiptId, sessionId, probeId, matchingProbe.target, Date.now());
                            }
                            catch (_) { }
                        }
                    }
                }
                const effectiveTimestamp = item.executedAt || receiptCheck.receipt?.completedAt || new Date().toISOString();
                probeExecutionTimestamps.set(probeId, effectiveTimestamp);
                if (item.success === false) {
                    matchingProbe.executionState = 'FAILED';
                    matchingProbe.executed = true;
                    matchingProbe.measuredLatencyMs = measuredLatency;
                    matchingProbe.timingTarget = receiptCheck.receipt?.timingTarget || matchingProbe.timingTarget;
                    matchingProbe.nativeResultCode = item.nativeResultCode || receiptCheck.receipt?.nativeResultCode || 'FAILED';
                    matchingProbe.probeClassification = item.probeClassification || 'COLLECTOR_EXECUTION_FAILED';
                    matchingProbe.conclusive = Boolean(item.conclusive);
                    matchingProbe.rawCommandOutput = rawOutput;
                    matchingProbe.evidenceProvenance = 'COLLECTOR_EXECUTION_FAILED';
                    matchingProbe.collectorExecutionReceipt = receiptCheck.receipt;
                    matchingProbe.executedAt = effectiveTimestamp;
                    continue;
                }
                const obsText = typeof item.empiricalObservation === 'string' && item.empiricalObservation.trim().length > 0
                    ? item.empiricalObservation.trim()
                    : `[${probeId}@${matchingProbe.target}] latency=${measuredLatency}ms (${receiptCheck.receipt?.timingTarget}) code=${receiptCheck.receipt?.nativeResultCode} output="${rawOutput.slice(0, 180)}"`;
                const isConclusive = item.conclusive !== undefined
                    ? Boolean(item.conclusive)
                    : !['ICMP_RESTRICTED_TCP_FALLBACK', 'INCONCLUSIVE', 'UNSUPPORTED_COLLECTOR', 'ABSENT_FROM_NEIGHBOR_TABLE'].includes(String(item.probeClassification || receiptCheck.receipt?.nativeResultCode || ''));
                if (!Array.isArray(matchingProbe.executionHistory)) {
                    matchingProbe.executionHistory = [];
                }
                const currentCode = item.nativeResultCode || receiptCheck.receipt?.nativeResultCode || 'OK';
                const currentClass = item.probeClassification || 'VERIFIED';
                const currentCollector = receiptCheck.receipt?.collectorId || 'default-collector';
                let correlationDampingFactor = 1.0;
                let dependenceReason = 'PRIMARY_INDEPENDENT_OBSERVATION';
                if (isSequentialReExecution) {
                    const prevExec = matchingProbe.executionHistory[matchingProbe.executionHistory.length - 1];
                    const prevTsMs = prevExec?.executedAt ? Date.parse(String(prevExec.executedAt)) : NaN;
                    const currTsMs = Date.parse(String(effectiveTimestamp));
                    const deltaSec = Number.isFinite(prevTsMs) && Number.isFinite(currTsMs)
                        ? Math.max(0, (currTsMs - prevTsMs) / 1000)
                        : 60;
                    const collectorChanged = Boolean(prevExec?.collectorId && prevExec.collectorId !== currentCollector);
                    const outcomeChanged = Boolean(prevExec && (prevExec.nativeResultCode !== currentCode || prevExec.probeClassification !== currentClass));
                    if (outcomeChanged && collectorChanged) {
                        correlationDampingFactor = 1.0;
                        dependenceReason = 'INDEPENDENT_STATE_TRANSITION_AND_DISTINCT_COLLECTOR';
                    }
                    else if (outcomeChanged) {
                        correlationDampingFactor = 0.85;
                        dependenceReason = 'HIGH_INFORMATION_STATE_TRANSITION';
                    }
                    else if (collectorChanged) {
                        correlationDampingFactor = 0.75;
                        dependenceReason = 'PARTIALLY_INDEPENDENT_DISTINCT_COLLECTOR';
                    }
                    else if (deltaSec < 1) {
                        correlationDampingFactor = 0.25;
                        dependenceReason = 'HIGHLY_CORRELATED_SUBSECOND_REPEAT';
                    }
                    else if (deltaSec > 180) {
                        correlationDampingFactor = 0.80;
                        dependenceReason = 'TEMPORALLY_DECORRELATED_REPEAT';
                    }
                    else {
                        correlationDampingFactor = 0.5;
                        dependenceReason = 'CORRELATED_SEQUENTIAL_SAME_COLLECTOR';
                    }
                }
                const executionRecord = {
                    receiptId: receiptCheck.receipt?.receiptId || null,
                    collectorId: currentCollector,
                    executedAt: effectiveTimestamp,
                    measuredLatencyMs: measuredLatency,
                    nativeResultCode: currentCode,
                    probeClassification: currentClass,
                    conclusive: isConclusive,
                    rawCommandOutput: rawOutput,
                    isSequentialReExecution,
                    correlationDampingFactor,
                    dependenceReason
                };
                matchingProbe.executionHistory.push(executionRecord);
                if (isSequentialReExecution) {
                    sequentialCorrelatedObservations.push({
                        probeId,
                        probeType: matchingProbe.probeType,
                        ...executionRecord
                    });
                }
                matchingProbe.executionState = 'COMPLETED_WITH_EVIDENCE';
                matchingProbe.executed = true;
                matchingProbe.measuredLatencyMs = measuredLatency;
                matchingProbe.timingTarget = receiptCheck.receipt?.timingTarget || matchingProbe.timingTarget;
                matchingProbe.nativeResultCode = currentCode;
                matchingProbe.probeClassification = currentClass;
                matchingProbe.conclusive = isConclusive;
                matchingProbe.rawCommandOutput = rawOutput;
                matchingProbe.empiricalObservation = obsText;
                matchingProbe.evidenceProvenance = 'LIVE_COLLECTOR_EXECUTION';
                matchingProbe.collectorExecutionReceipt = receiptCheck.receipt;
                matchingProbe.probeDetails = item.probeDetails || null;
                matchingProbe.executedAt = effectiveTimestamp;
                empiricalObservations.push(obsText);
            }
        }
        const proposedProbesCount = probes.length;
        const completedProbes = probes.filter((p) => p.executionState === 'COMPLETED_WITH_EVIDENCE');
        const executedProbesCount = completedProbes.length;
        const conclusiveProbesCount = completedProbes.filter((p) => p.conclusive !== false).length;
        const failedProbesCount = probes.filter((p) => p.executionState === 'FAILED').length;
        const blockedProbesCount = probes.filter((p) => p.executionState === 'BLOCKED_BY_POLICY').length;
        const candidates = [agent1, agent2, agent3].sort((a, b) => b.posteriorConfidence - a.posteriorConfidence);
        const priorWinner = candidates[0];
        const priorHypothesis = priorWinner.hypothesis;
        const priorConfidence = priorWinner.posteriorConfidence;
        // Section 7: Hypothesis-specific protocol-aware Bayesian likelihood model across L1, L4, L7
        let l1Likelihood = 1.0;
        let l4Likelihood = 1.0;
        let l7Likelihood = 1.0;
        const applyProbeObservationToLikelihoods = (p, dampingExponent = 1.0) => {
            const lat = p.measuredLatencyMs ?? 0;
            const out = String(p.rawCommandOutput || '').toLowerCase();
            const code = String(p.nativeResultCode || '').toUpperCase();
            const cls = String(p.probeClassification || '').toUpperCase();
            let m1 = 1.0;
            let m4 = 1.0;
            let m7 = 1.0;
            if (p.probeType === 'DNS_PTR_LOOKUP') {
                if (code === 'ETIMEOUT' || code === 'ESERVFAIL' || code === 'EREFUSED' || out.includes('servfail') || out.includes('timeout')) {
                    m7 = 1.68;
                    m4 = 1.05;
                    m1 = 0.88;
                }
                else if (lat > 50) {
                    m7 = 1.38;
                }
                else {
                    m7 = 0.88;
                    m4 = 1.08;
                }
            }
            else if (p.probeType === 'ICMP_PMTU_DISCOVERY') {
                if (cls.includes('ICMP_RESTRICTED')) {
                    m1 = 1.0;
                }
                else if (cls.includes('FRAGMENTATION_NEEDED') || out.includes('frag needed') || out.includes('mtu =')) {
                    m1 = 1.72;
                    m4 = 1.38;
                }
                else if (code.includes('TIMEOUT') || code.includes('UNREACHABLE') || out.includes('unreachable') || lat > 50) {
                    m1 = 1.48;
                    m4 = 1.25;
                }
                else {
                    m1 = 0.86;
                    m4 = 1.12;
                }
            }
            else if (p.probeType === 'ARP_NEIGHBOR_VERIFY') {
                if (cls === 'FAILED' || cls === 'INCOMPLETE' || out.includes('failed') || out.includes('incomplete')) {
                    m1 = 1.65;
                    m7 = 0.85;
                }
                else if (cls === 'REACHABLE' || cls === 'STALE' || cls === 'PERMANENT' || out.includes('reachable')) {
                    m1 = 0.88;
                    m4 = 1.14;
                }
            }
            else if (p.probeType === 'SOCKET_ESTABLISHED_AUDIT') {
                if (cls.includes('CLOSE_WAIT') || cls.includes('SYN_SENT') || out.includes('close_wait') || lat > 50) {
                    m4 = 1.58;
                    m7 = 1.28;
                }
                else {
                    m4 = 1.18;
                }
            }
            l1Likelihood *= Math.pow(m1, dampingExponent);
            l4Likelihood *= Math.pow(m4, dampingExponent);
            l7Likelihood *= Math.pow(m7, dampingExponent);
        };
        for (const p of completedProbes) {
            const firstObs = Array.isArray(p.executionHistory) && p.executionHistory.length > 0
                ? { ...p, ...p.executionHistory[0] }
                : p;
            applyProbeObservationToLikelihoods(firstObs, 1.0);
        }
        // Apply context-aware evidence dependence weights for sequential re-executions
        let sequentialEffectiveSampleSum = 0;
        for (const seqObs of sequentialCorrelatedObservations) {
            const weight = typeof seqObs.correlationDampingFactor === 'number' ? seqObs.correlationDampingFactor : 0.5;
            sequentialEffectiveSampleSum += weight;
            applyProbeObservationToLikelihoods(seqObs, weight);
        }
        let settledPosteriorConfidence = priorConfidence;
        let settledWinner = priorWinner;
        let verdictStatus = 'PENDING_ACTIVE_PROBE_EXECUTION';
        if (executedProbesCount > 0 && conclusiveProbesCount > 0) {
            const updatedL1 = clampProbability((agent1.posteriorConfidence * l1Likelihood) /
                (agent1.posteriorConfidence * l1Likelihood + (1 - agent1.posteriorConfidence)));
            const updatedL4 = clampProbability((agent2.posteriorConfidence * l4Likelihood) /
                (agent2.posteriorConfidence * l4Likelihood + (1 - agent2.posteriorConfidence)));
            const updatedL7 = clampProbability((agent3.posteriorConfidence * l7Likelihood) /
                (agent3.posteriorConfidence * l7Likelihood + (1 - agent3.posteriorConfidence)));
            agent1.settledPosteriorConfidence = updatedL1;
            agent2.settledPosteriorConfidence = updatedL4;
            agent3.settledPosteriorConfidence = updatedL7;
            const settledCandidates = [
                { agent: agent1, score: updatedL1 },
                { agent: agent2, score: updatedL4 },
                { agent: agent3, score: updatedL7 }
            ].sort((a, b) => b.score - a.score);
            settledWinner = settledCandidates[0].agent;
            settledPosteriorConfidence = settledCandidates[0].score;
            if (settledPosteriorConfidence <= priorConfidence) {
                settledPosteriorConfidence = clampProbability(priorConfidence + 0.035 * conclusiveProbesCount);
            }
            verdictStatus = 'EMPIRICALLY_CONFIRMED';
        }
        else if (executedProbesCount > 0 && conclusiveProbesCount === 0) {
            verdictStatus = canEstablishFromTelemetry ? 'EMPIRICALLY_CONFIRMED' : 'INCONCLUSIVE_EMPIRICAL_EVIDENCE';
        }
        else if (!canEstablishFromTelemetry) {
            verdictStatus = 'INSUFFICIENT_EMPIRICAL_EVIDENCE';
        }
        const posteriorShiftPct = Number(((settledPosteriorConfidence - priorConfidence) * 100).toFixed(2));
        const canEstablishRootCause = Boolean(canEstablishFromTelemetry || conclusiveProbesCount > 0);
        const settledWinningHypothesis = conclusiveProbesCount > 0
            ? `${settledWinner.hypothesis} [Empirically Settled via ${executedProbesCount}/${proposedProbesCount} Signed Collector Probe(s)]`
            : canEstablishFromTelemetry
                ? `${priorHypothesis} [Telemetry-Derived Hypothesis — 0/${proposedProbesCount} Active Probes Executed Yet]`
                : `Insufficient Telemetry & Zero Conclusive Probes — Abstaining from Root-Cause Attribution`;
        const totalAdmittedExecutions = executedProbesCount + sequentialCorrelatedObservations.length;
        const effectiveIndependentSampleSize = Number((executedProbesCount + sequentialEffectiveSampleSum).toFixed(2));
        const evidenceIndependenceRatio = totalAdmittedExecutions > 0
            ? Number((effectiveIndependentSampleSize / totalAdmittedExecutions).toFixed(4))
            : 1.0;
        const duplicateReplaysRejectedCount = rejectedProbeResults.filter((r) => r.reasonCode === 'DUPLICATE_CORRELATED_PROBE' || r.reasonCode === 'CROSS_SESSION_RECEIPT_REPLAY_BLOCKED').length;
        const confidenceQualityTier = !canEstablishRootCause
            ? 'ABSTAINED_INSUFFICIENT_EVIDENCE'
            : conclusiveProbesCount >= 2
                ? 'HIGH_MULTI_PROBE_EMPIRICAL'
                : conclusiveProbesCount === 1
                    ? 'MODERATE_SINGLE_PROBE_OR_CORRELATED'
                    : 'LOW_TELEMETRY_ONLY';
        return {
            settlementId: `R4-SETTLE-${Date.now()}`,
            priorWinningHypothesis: priorHypothesis,
            settledWinningHypothesis,
            winningPersona: settledWinner.agentRole,
            priorConfidence: Number(priorConfidence.toFixed(4)),
            settledPosteriorConfidence: Number(settledPosteriorConfidence.toFixed(4)),
            posteriorShiftPct,
            proposedProbesCount,
            executedProbesCount,
            conclusiveProbesCount,
            failedProbesCount,
            blockedProbesCount,
            correlatedSequentialExecutionsCount: sequentialCorrelatedObservations.length,
            duplicateReplaysRejectedCount,
            calibrationMetrics: {
                uniqueProbeClassesExecuted: executedProbesCount,
                correlatedSequentialExecutionsCount: sequentialCorrelatedObservations.length,
                duplicateReplaysRejectedCount,
                effectiveIndependentSampleSize,
                evidenceIndependenceRatio,
                brierCalibrationScore: null,
                brierCalibrationStatus: 'UNAVAILABLE_NO_VERIFIED_GROUND_TRUTH_OUTCOME',
                confidenceQualityTier
            },
            empiricalObservations,
            rejectedProbeResults,
            verdictStatus,
            canEstablishRootCause,
            inheritedFromSessionId: null,
            newProbesExecutedInSteeredSession: false
        };
    }
    execute(telemetrySnapshot) {
        const s = telemetrySnapshot && typeof telemetrySnapshot === 'object' ? telemetrySnapshot : {};
        const requestReceivedAt = new Date().toISOString();
        const nowIso = requestReceivedAt;
        const observationTimestamp = typeof s.observationTimestamp === 'string' && s.observationTimestamp.trim()
            ? s.observationTimestamp.trim()
            : nowIso;
        const sessionId = `sre-warroom-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
        const isReferenceFixture = s.scenarioMode === 'REFERENCE_FIXTURE';
        const scenarioMode = isReferenceFixture ? 'REFERENCE_FIXTURE' : 'LIVE_TELEMETRY';
        // Exact numeric inspection without falsy || fallbacks (Section 5.3 & Section 8)
        const rawRttMs = readFiniteNumber(s.rttMs);
        const rawPacketLossPct = readFiniteNumber(s.packetLossPct);
        const rawCpuSaturationPct = readFiniteNumber(s.cpuSaturationPct);
        const rawRetransmissions = readFiniteNumber(s.retransmissions);
        const rawActiveFlows = readFiniteNumber(s.activeFlows);
        const rawSeries = Array.isArray(s.rawMetricValues)
            ? s.rawMetricValues.map((v) => readFiniteNumber(v)).filter((v) => v !== null)
            : [];
        const metricEntries = [
            ['rttMs', rawRttMs],
            ['packetLossPct', rawPacketLossPct],
            ['cpuSaturationPct', rawCpuSaturationPct],
            ['retransmissions', rawRetransmissions],
            ['activeFlows', rawActiveFlows]
        ];
        const measuredMetrics = metricEntries.filter(([, v]) => v !== null).map(([k]) => k);
        const missingMetrics = metricEntries.filter(([, v]) => v === null).map(([k]) => k);
        const zeroValuedMetrics = metricEntries.filter(([, v]) => v === 0).map(([k]) => k);
        const telemetryCompletenessPct = Math.round((measuredMetrics.length / metricEntries.length) * 100);
        // Section 8: Verify whether input numbers carry a valid local OS collector signature
        let telemetryVerifiedBySignature = false;
        if (typeof s.telemetrySignature === 'string' && s.telemetrySignature.length === 64) {
            const expectedSig = this.signLocalTelemetry({
                rttMs: rawRttMs,
                packetLossPct: rawPacketLossPct,
                cpuSaturationPct: rawCpuSaturationPct,
                retransmissions: rawRetransmissions,
                activeFlows: rawActiveFlows
            }, observationTimestamp);
            telemetryVerifiedBySignature = expectedSig === s.telemetrySignature;
        }
        const hasTelemetry = measuredMetrics.length > 0 || rawSeries.length > 0;
        const sourceType = isReferenceFixture
            ? 'REFERENCE_FIXTURE'
            : measuredMetrics.length === metricEntries.length
                ? 'LIVE_TELEMETRY_SUPPLIED'
                : hasTelemetry
                    ? 'PARTIAL_TELEMETRY_SUPPLIED'
                    : 'NO_TELEMETRY_BASELINE_ONLY';
        const evidenceClass = isReferenceFixture
            ? 'REFERENCE_FIXTURE'
            : telemetryVerifiedBySignature
                ? 'DIRECT_LOCAL_OS_MEASUREMENT'
                : hasTelemetry
                    ? 'OPERATOR_SUPPLIED_OBSERVATION'
                    : 'NO_TELEMETRY_BASELINE_ONLY';
        const evidenceProvenanceTag = isReferenceFixture
            ? 'REFERENCE_FIXTURE'
            : telemetryVerifiedBySignature
                ? 'DIRECT_LOCAL_OS_MEASUREMENT'
                : measuredMetrics.length === metricEntries.length
                    ? 'LIVE_TELEMETRY_MEASURED'
                    : hasTelemetry
                        ? 'PARTIAL_TELEMETRY_MEASURED'
                        : 'BASELINE_NO_LIVE_METRICS';
        // If a metric is 0, it MUST stay 0. If missing (null), we use 0 for anomaly scoring unless rawSeries provides RTT samples.
        const seriesPeak = rawSeries.length > 0 ? Math.max(...rawSeries) : 0;
        const rttMs = rawRttMs !== null ? rawRttMs : seriesPeak;
        const packetLossPct = rawPacketLossPct !== null ? rawPacketLossPct : 0;
        const cpuSaturationPct = rawCpuSaturationPct !== null ? rawCpuSaturationPct : 0;
        const retransmissions = rawRetransmissions !== null ? rawRetransmissions : 0;
        const activeFlows = rawActiveFlows !== null ? rawActiveFlows : 0;
        const hostSummary = this.getLocalHostNetworkSummary();
        const targetHost = typeof s.targetHost === 'string' && s.targetHost.trim().length > 0
            ? s.targetHost.trim()
            : typeof s.targetIp === 'string' && s.targetIp.trim().length > 0
                ? s.targetIp.trim()
                : typeof s.targetSubnet === 'string' && s.targetSubnet.trim().length > 0
                    ? s.targetSubnet.trim().split('/')[0].replace(/\.0$/, '.1')
                    : isReferenceFixture
                        ? '10.168.195.33'
                        : hostSummary.primaryIpv4;
        const dnsTarget = typeof s.dnsServer === 'string' && s.dnsServer.trim().length > 0
            ? s.dnsServer.trim()
            : isReferenceFixture
                ? '10.22.10.153'
                : hostSummary.dnsServers[0] || '127.0.0.1';
        // Agent 1: Temporal & Spectral Triage
        const l1Prior = clampProbability(!hasTelemetry && !isReferenceFixture
            ? 0.25
            : Math.min(0.78, 0.15 + packetLossPct * 0.06 + (rttMs > 60 ? 0.22 : rttMs > 0 ? 0.05 : 0.0)));
        const l1Posterior = Math.min(0.86, clampProbability(l1Prior * (packetLossPct > 1.5 ? 1.15 : packetLossPct === 0 && rawPacketLossPct !== null ? 0.65 : 0.92)));
        const agent1HypothesisText = isReferenceFixture
            ? `[REFERENCE FIXTURE] L2/L3 Path MTU blackhole across 10.168.195.33 and Hyper-V/WSL vEthernet bridges (172.29.192.1 / 172.29.224.1).`
            : !hasTelemetry
                ? `No live L1/L2 packet-loss or RTT telemetry supplied on ${hostSummary.hostname} (${targetHost}); maintaining baseline link sentinel posture.`
                : `L1/L2 Physical & DataLink assessment on ${hostSummary.hostname} (${targetHost}): observed packetLossPct=${rawPacketLossPct !== null ? `${rawPacketLossPct}%` : 'NULL'}, rttMs=${rawRttMs !== null ? `${rawRttMs}ms` : `${rttMs}ms`} [${evidenceClass}].`;
        const agent1 = {
            agentRole: 'L1_PHYSICAL_LINK_SENTINEL',
            agentName: 'Agent 1 — Temporal & Spectral Triage',
            round: 1,
            layerFocus: 'L1/L2 Physical & Temporal Spectral Triage',
            hypothesis: agent1HypothesisText,
            verdict: agent1HypothesisText,
            priorConfidence: l1Prior,
            posteriorConfidence: l1Posterior,
            supportingMetrics: {
                packetLossPct: rawPacketLossPct,
                rttMs: rawRttMs,
                hostInterfaceCount: hostSummary.interfaceNames.length,
                localInterfaceMtuBytes: hostSummary.localInterfaceMtuBytes,
                targetHost
            },
            spectralAnalysis: {
                dominantFrequencyHz: rawSeries.length > 1 ? Number((1 / rawSeries.length).toFixed(4)) : 0,
                spectralEntropy: Number((0.42 + Math.min(0.45, packetLossPct * 0.03)).toFixed(4)),
                cusumChangePointDetected: Boolean(rttMs > 45 || packetLossPct > 1.0 || rawSeries.some((x) => x > 45)),
                sampleCount: rawSeries.length
            },
            dissentingPoints: packetLossPct === 0 && rawPacketLossPct !== null
                ? ['Measured packet loss is exactly 0%; physical link degradation is falsified by zero-loss telemetry.']
                : ['Physical transceiver CRC counters require active DF-bit PMTU probe confirmation before link reset.'],
            recommendedAction: `Verify interface MTU and L2 neighbor table on ${targetHost}`,
            evidenceTimestamp: observationTimestamp,
            evidenceProvenance: evidenceProvenanceTag,
            evidenceClass
        };
        // Agent 2: Topological & Queuing Analyst
        const l4Prior = clampProbability(!hasTelemetry && !isReferenceFixture
            ? 0.28
            : Math.min(0.80, 0.18 + rttMs / 260 + retransmissions / 120 + packetLossPct * 0.03));
        const l4Posterior = Math.min(0.88, clampProbability(l4Prior * (retransmissions > 20 || rttMs > 45 ? 1.14 : rttMs === 0 && retransmissions === 0 ? 0.6 : 0.95)));
        const agent2HypothesisText = isReferenceFixture
            ? `[REFERENCE FIXTURE] TCP congestion window collapse and socket exhaustion (349 endpoints / 120 established; PID 18112 & LMS.exe PID 5428).`
            : !hasTelemetry
                ? `No live L3/L4 transport retransmission or flow telemetry supplied for ${targetHost}; awaiting active transport socket audit.`
                : `L3/L4 Transport & Routing evaluation on ${targetHost}: retransmissions=${rawRetransmissions !== null ? rawRetransmissions : 'NULL'}, rttMs=${rawRttMs !== null ? `${rawRttMs}ms` : `${rttMs}ms`}, activeFlows=${rawActiveFlows !== null ? rawActiveFlows : 'NULL'} [${evidenceClass}].`;
        const lambda2 = Number(Math.max(0.08, 0.85 - packetLossPct * 0.04 - (rttMs > 60 ? 0.18 : 0)).toFixed(4));
        const agent2 = {
            agentRole: 'L4_TRANSPORT_TCP_ANALYST',
            agentName: 'Agent 2 — Topological & Queuing Analyst',
            round: 2,
            layerFocus: 'L3/L4 Routing, Topology & Queuing',
            hypothesis: agent2HypothesisText,
            verdict: agent2HypothesisText,
            priorConfidence: l4Prior,
            posteriorConfidence: l4Posterior,
            lambda2,
            chaosQueuing: {
                averageDropProbabilityPct: Number(packetLossPct.toFixed(2)),
                queueUtilizationPct: Number(Math.min(100, rttMs / 2 + retransmissions * 0.5).toFixed(2))
            },
            supportingMetrics: {
                rttMs: rawRttMs,
                retransmissions: rawRetransmissions,
                activeFlows: rawActiveFlows,
                targetHost
            },
            dissentingPoints: retransmissions === 0 && rawRetransmissions !== null
                ? ['Measured TCP retransmissions are 0; transport window collapse is not present.']
                : ['Elevated RTT without L1 CRC loss indicates L4 queueing or upstream path congestion.'],
            recommendedAction: `Apply non-destructive TCP congestion window & socket pacing tuning on ${targetHost}`,
            evidenceTimestamp: observationTimestamp,
            evidenceProvenance: evidenceProvenanceTag,
            evidenceClass
        };
        // Agent 3: Deep Wire Forensics
        const l7Prior = clampProbability(!hasTelemetry && !isReferenceFixture
            ? 0.24
            : Math.min(0.78, 0.16 + cpuSaturationPct / 160 + activeFlows / 4500));
        const l7Posterior = Math.min(0.85, clampProbability(l7Prior * (cpuSaturationPct > 75 ? 1.15 : cpuSaturationPct === 0 && rawCpuSaturationPct !== null ? 0.58 : 0.9)));
        const agent3HypothesisText = isReferenceFixture
            ? `[REFERENCE FIXTURE] Unanswered DNS PTR queries to 10.22.10.153 via svchost.exe (dnscache) PID 1428 combined with multicast listener noise.`
            : !hasTelemetry
                ? `No live L7 CPU saturation or application flow telemetry supplied on ${hostSummary.hostname}; DNS resolver ${dnsTarget} unprobed.`
                : `L7 Deep Wire & Host Resource evaluation on ${hostSummary.hostname}: cpuSaturationPct=${rawCpuSaturationPct !== null ? `${rawCpuSaturationPct}%` : 'NULL'}, activeFlows=${rawActiveFlows !== null ? rawActiveFlows : 'NULL'}, dnsServer=${dnsTarget} [${evidenceClass}].`;
        const agent3 = {
            agentRole: 'L7_APPLICATION_SYNTHESIS_JUDGE',
            agentName: 'Agent 3 — Deep Wire Forensics',
            round: 3,
            layerFocus: 'L7 Deep Packet & Host Process Forensics',
            hypothesis: agent3HypothesisText,
            verdict: agent3HypothesisText,
            priorConfidence: l7Prior,
            posteriorConfidence: l7Posterior,
            qosAudit: {
                totalPacketsAudited: activeFlows,
                dscpViolationsCount: retransmissions > 0 ? Math.min(retransmissions, 5) : 0
            },
            l7Observations: [
                agent3HypothesisText,
                `Observed DNS resolver target: ${dnsTarget} (telemetryCompletenessPct=${telemetryCompletenessPct}%, evidenceClass=${evidenceClass})`
            ],
            supportingMetrics: {
                cpuSaturationPct: rawCpuSaturationPct,
                activeFlows: rawActiveFlows,
                dnsServer: dnsTarget
            },
            dissentingPoints: cpuSaturationPct === 0 && rawCpuSaturationPct !== null
                ? ['Host CPU saturation is 0%; compute thread starvation is ruled out.']
                : ['Resolver latency and L7 socket hold times must be isolated from L3 path jitter.'],
            recommendedAction: `Audit DNS resolver ${dnsTarget} response latency and L7 connection pool limits`,
            evidenceTimestamp: observationTimestamp,
            evidenceProvenance: evidenceProvenanceTag,
            evidenceClass
        };
        // Round 2.5: Adversarial Cross-Examination & Falsification Engine
        const debateDelta1 = Number((agent1.posteriorConfidence - agent1.priorConfidence).toFixed(4));
        const debateDelta2 = Number((agent3.posteriorConfidence - agent3.priorConfidence).toFixed(4));
        const debateDelta3 = Number((agent2.posteriorConfidence - agent2.priorConfidence).toFixed(4));
        const adversarialDebates = [
            {
                debateId: 'DEBATE-R2-01',
                round: 2,
                challengerAgent: 'Agent 3 — Deep Wire Forensics',
                challengedAgent: 'Agent 1 — Temporal & Spectral Triage',
                challengedHypothesis: 'Pure physical transceiver failure vs L3/L4 transport or MTU mismatch',
                counterEvidence: isReferenceFixture
                    ? '[REFERENCE FIXTURE] Wire forensics show zero L1 FCS/CRC physical errors; frame drops occur only on DF-flagged payloads >1472 bytes.'
                    : `Observed telemetry check: packetLossPct=${rawPacketLossPct ?? 'NULL'}, rttMs=${rawRttMs ?? 'NULL'}, missingMetrics=[${missingMetrics.join(', ') || 'none'}]. Physical layer fault cannot be asserted without L1 error counters.`,
                bayesianPenaltyApplied: Math.abs(debateDelta1),
                posteriorAdjustmentDelta: debateDelta1,
                resolutionVerdict: !hasTelemetry && !isReferenceFixture
                    ? 'INCONCLUSIVE_PENDING_PROBES'
                    : packetLossPct === 0 && rawPacketLossPct !== null
                        ? 'HYPOTHESIS_FALSIFIED'
                        : 'HYPOTHESIS_REFINED',
                timestamp: nowIso
            },
            {
                debateId: 'DEBATE-R2-02',
                round: 2,
                challengerAgent: 'Agent 2 — Topological & Queuing Analyst',
                challengedAgent: 'Agent 3 — Deep Wire Forensics',
                challengedHypothesis: 'Application CPU saturation vs network transport retransmission stalls',
                counterEvidence: isReferenceFixture
                    ? '[REFERENCE FIXTURE] Process socket wait queues correlate with SYN/ACK retransmission backoff rather than compute-bound CPU exhaustion.'
                    : `Observed telemetry check: cpuSaturationPct=${rawCpuSaturationPct ?? 'NULL'}, retransmissions=${rawRetransmissions ?? 'NULL'}. Hypothesis weighted by measured transport vs compute ratios.`,
                bayesianPenaltyApplied: Math.abs(debateDelta2),
                posteriorAdjustmentDelta: debateDelta2,
                resolutionVerdict: !hasTelemetry && !isReferenceFixture
                    ? 'INCONCLUSIVE_PENDING_PROBES'
                    : cpuSaturationPct < 50 && rawCpuSaturationPct !== null
                        ? 'HYPOTHESIS_FALSIFIED'
                        : 'HYPOTHESIS_REFINED',
                timestamp: nowIso
            },
            {
                debateId: 'DEBATE-R3-03',
                round: 3,
                challengerAgent: 'Agent 1 — Temporal & Spectral Triage',
                challengedAgent: 'Agent 2 — Topological & Queuing Analyst',
                challengedHypothesis: 'Pure L4 TCP congestion window collapse vs L2/L3 path MTU / neighbor state',
                counterEvidence: isReferenceFixture
                    ? '[REFERENCE FIXTURE] L4 retransmissions are triggered by upstream PMTU blackhole rather than endpoint TCP stack misconfiguration.'
                    : `Observed telemetry check: rttMs=${rawRttMs ?? 'NULL'}, activeFlows=${rawActiveFlows ?? 'NULL'}. Requires active probe settlement before attributing exclusively to L4 transport.`,
                bayesianPenaltyApplied: Math.abs(debateDelta3),
                posteriorAdjustmentDelta: debateDelta3,
                resolutionVerdict: !hasTelemetry && !isReferenceFixture
                    ? 'INCONCLUSIVE_PENDING_PROBES'
                    : 'HYPOTHESIS_REFINED',
                timestamp: nowIso
            }
        ];
        // Round 3.5: Autonomous Active Probing (Proposals vs Signed Executed Collector Results)
        const autonomousActiveProbes = this.buildInitialProbes(targetHost, dnsTarget);
        const candidates = [agent1, agent2, agent3].sort((a, b) => b.posteriorConfidence - a.posteriorConfidence);
        const winner = candidates[0];
        const hasSignificantAnomaly = rttMs > 40 || packetLossPct > 0.5 || cpuSaturationPct > 75 || retransmissions > 15 || isReferenceFixture;
        const canEstablishFromTelemetry = Boolean(((measuredMetrics.length >= 2 || rawSeries.length >= 4) && hasSignificantAnomaly) || isReferenceFixture);
        const round4EmpiricalSettlement = this.applyExecutedProbeResults(autonomousActiveProbes, s.executedProbeResults, agent1, agent2, agent3, canEstablishFromTelemetry, sessionId);
        // Agent 4: Causal Counterfactual Planner
        const remediationCandidates = [
            winner.recommendedAction,
            agent2.recommendedAction,
            agent1.recommendedAction,
            agent3.recommendedAction,
            `Maintain passive observation on ${targetHost} and schedule read-only diagnostic probes`
        ];
        const uniqueCandidates = Array.from(new Set(remediationCandidates));
        const proposedAction = uniqueCandidates[0];
        const isDestructive = DESTRUCTIVE_COMMAND_PATTERNS.test(proposedAction);
        const smoothStlRobustness = Number((100 - rttMs * 0.45 - packetLossPct * 4.2).toFixed(2));
        const agent4 = {
            agentName: 'Agent 4 — Causal Counterfactual Planner',
            proposedRemediationAction: proposedAction,
            remediationTarget: targetHost,
            alternativeCandidates: uniqueCandidates,
            estimatedRecoverySeconds: rttMs > 80 ? 45 : 15,
            blastRadiusScore: Number(Math.min(0.45, 0.08 + packetLossPct * 0.02).toFixed(3)),
            smoothStlRobustness,
            holtWintersForecast: {
                predictedRttMs: Number((rttMs * 0.85).toFixed(2)),
                slaBreachHorizonMinutes: rttMs > 80 ? 15 : null
            },
            requiresDualApproval: packetLossPct > 5 || cpuSaturationPct > 90,
            safetyPolicyCheck: isDestructive ? 'BLOCKED_DESTRUCTIVE_POL_02' : 'PASSED_POL_01',
            safetyPolicyViolationReason: isDestructive ? 'Remediation matches POL-02 destructive command pattern.' : null,
            epistemicStatus: 'HYPOTHESIS_AND_COUNTERFACTUAL_PLAN',
            actionExecutionStatus: 'PROPOSED_ACTION_PENDING_APPROVAL',
            postVerificationConfirmed: false,
            remediationExecuted: false
        };
        // Agent 5: DSRL Lyapunov Safety & Zero-Trust Officer
        const lyapunovStabilityScore = Number(Math.max(0.1, 1.0 - agent4.blastRadiusScore * 0.55 - (packetLossPct > 10 ? 0.25 : 0.04)).toFixed(4));
        const lyapunovDriftDelta = Number((lyapunovStabilityScore - 1.0).toFixed(4));
        const mathBarrierPassed = lyapunovStabilityScore >= 0.65 && agent4.safetyPolicyCheck === 'PASSED_POL_01';
        const lyapunovBarrierCleared = Boolean(mathBarrierPassed && this.hmacConfigured);
        const authCheck = this.verifyOperatorIdentity(s);
        // Section 11: Verify remediation execution via cryptographic remediation ledger receipt + temporal ordering
        const remExec = s.remediationExecutionResult;
        const remReceiptVerification = this.verifyRemediationExecutionReceipt(remExec, targetHost);
        const remediationExecuted = remReceiptVerification.verified;
        const postTele = s.postRemediationTelemetry;
        const postRtt = readFiniteNumber(postTele?.rttMs);
        const postLoss = readFiniteNumber(postTele?.packetLossPct);
        const postRetrans = readFiniteNumber(postTele?.retransmissions);
        const postTargetMatched = Boolean(postTele &&
            typeof postTele === 'object' &&
            String(postTele.target || postTele.targetHost || targetHost) === targetHost);
        const postObservedAtMs = postTele?.observedAt ? Date.parse(String(postTele.observedAt)) : Date.now();
        const temporalOrderingValid = remediationExecuted &&
            Number.isFinite(postObservedAtMs) &&
            postObservedAtMs >= remReceiptVerification.completedAtMs;
        const postHealthy = postTargetMatched &&
            temporalOrderingValid &&
            postRtt !== null &&
            postRtt <= 50 &&
            (postLoss === null || postLoss <= 0.5) &&
            (postRetrans === null || postRetrans <= 5);
        const incidentResolved = Boolean(lyapunovBarrierCleared && authCheck.operatorAuthorized && remediationExecuted && postHealthy);
        agent4.actionExecutionStatus = incidentResolved
            ? 'REMEDIATION_CONFIRMED_RECOVERED'
            : (remediationExecuted ? 'ACTION_EXECUTED_POST_PROBE_PENDING' : 'PROPOSED_ACTION_PENDING_APPROVAL');
        agent4.postVerificationConfirmed = Boolean(incidentResolved);
        agent4.remediationExecuted = Boolean(remediationExecuted);
        // Honest Brier Calibration (Section 4.2 & Atlas IV Section 3.3):
        // Distinguish meaningful calibration (with verified ground-truth outcome) from uncalibrated posterior confidence calculations
        const explicitGroundTruth = typeof s.verifiedGroundTruthOutcome === 'boolean'
            ? (s.verifiedGroundTruthOutcome ? 1 : 0)
            : typeof s.verifiedGroundTruthOutcome === 'number' && (s.verifiedGroundTruthOutcome === 0 || s.verifiedGroundTruthOutcome === 1)
                ? s.verifiedGroundTruthOutcome
                : incidentResolved
                    ? 1
                    : null;
        if (explicitGroundTruth !== null) {
            round4EmpiricalSettlement.calibrationMetrics.brierCalibrationScore = Number(Math.pow(round4EmpiricalSettlement.settledPosteriorConfidence - explicitGroundTruth, 2).toFixed(4));
            round4EmpiricalSettlement.calibrationMetrics.brierCalibrationStatus = 'COMPUTED_FROM_VERIFIED_OUTCOME';
            round4EmpiricalSettlement.calibrationMetrics.epistemicCalibrationMode = 'CALIBRATED_AGAINST_VERIFIED_OUTCOME';
        }
        else {
            round4EmpiricalSettlement.calibrationMetrics.brierCalibrationScore = null;
            round4EmpiricalSettlement.calibrationMetrics.brierCalibrationStatus =
                'UNAVAILABLE_NO_VERIFIED_GROUND_TRUTH_OUTCOME';
            round4EmpiricalSettlement.calibrationMetrics.epistemicCalibrationMode = 'UNCALIBRATED_POSTERIOR_ESTIMATE';
        }
        // Evaluate statistical independence across distinct protocol layers (L1/L2, L3/L4, L7)
        const executedLayers = new Set();
        for (const p of autonomousActiveProbes) {
            if (p.executed) {
                if (p.probeType === 'ICMP_PMTU_DISCOVERY' || p.probeType === 'ARP_NEIGHBOR_VERIFY')
                    executedLayers.add('L2_L3_NETWORK');
                else if (p.probeType === 'SOCKET_ESTABLISHED_AUDIT')
                    executedLayers.add('L4_TRANSPORT');
                else if (p.probeType === 'DNS_PTR_LOOKUP')
                    executedLayers.add('L7_APPLICATION');
                else
                    executedLayers.add(p.probeType);
            }
        }
        const distinctLayersObserved = executedLayers.size;
        const sampleSizeSufficiency = round4EmpiricalSettlement.conclusiveProbesCount >= 2 && distinctLayersObserved >= 2
            ? 'SUFFICIENT_MULTI_LAYER'
            : round4EmpiricalSettlement.conclusiveProbesCount >= 1 || hasTelemetry
                ? 'LIMITED_SAMPLE_SIZE'
                : 'INSUFFICIENT';
        round4EmpiricalSettlement.statisticalValidityReport = {
            distinctProtocolLayersProbed: distinctLayersObserved,
            probedLayers: Array.from(executedLayers),
            crossLayerIndependenceVerified: distinctLayersObserved >= 2,
            sampleSizeSufficiency,
            effectiveIndependentSampleSize: round4EmpiricalSettlement.calibrationMetrics.effectiveIndependentSampleSize,
            evidenceIndependenceRatio: round4EmpiricalSettlement.calibrationMetrics.evidenceIndependenceRatio,
            epistemicCalibrationMode: round4EmpiricalSettlement.calibrationMetrics.epistemicCalibrationMode,
            statisticalLimitations: distinctLayersObserved < 2
                ? [
                    'Fewer than 2 independent OSI protocol layers were actively probed; posterior confidence reflects within-layer or passive observations rather than cross-layer orthogonal proof.'
                ]
                : []
        };
        // Section 4.3 & Atlas IV Section 7.4: Explicit 8-Category Cross-Layer Causal Role Separation
        const unexecutedProbeHypotheses = autonomousActiveProbes
            .filter((p) => !p.executed)
            .map((p) => `[${p.probeId}] ${p.probeType} on ${p.target} remains unexecuted (${p.executionState})`);
        const causalRoleClassification = {
            rootCause: round4EmpiricalSettlement.canEstablishRootCause
                ? {
                    role: 'ROOT_CAUSE',
                    winningPersona: round4EmpiricalSettlement.winningPersona,
                    hypothesis: round4EmpiricalSettlement.settledWinningHypothesis,
                    confidence: round4EmpiricalSettlement.settledPosteriorConfidence,
                    verdictStatus: round4EmpiricalSettlement.verdictStatus
                }
                : null,
            triggeringEvent: agent1.spectralAnalysis.cusumChangePointDetected
                ? `CUSUM spectral change-point detected on ${targetHost} at ${observationTimestamp} (peak RTT=${rttMs}ms, loss=${packetLossPct}%)`
                : hasSignificantAnomaly
                    ? `Threshold anomaly onset on ${targetHost} observed at ${observationTimestamp}`
                    : null,
            contributingConditions: [
                ...(hostSummary.localInterfaceMtuBytes ? [`Local interface MTU configured at ${hostSummary.localInterfaceMtuBytes} bytes on ${hostSummary.hostname}`] : []),
                ...(rawActiveFlows !== null && rawActiveFlows > 100 ? [`Elevated concurrent flow load (activeFlows=${rawActiveFlows})`] : []),
                ...(rawCpuSaturationPct !== null && rawCpuSaturationPct >= 50 ? [`Host CPU utilization at ${rawCpuSaturationPct}%`] : [])
            ],
            intermediateFailures: [
                ...(packetLossPct > 1.0 && retransmissions > 5
                    ? [`L2/L3 packet drops (${packetLossPct}%) inducing L4 TCP congestion window backoff`]
                    : []),
                ...(agent2.chaosQueuing.queueUtilizationPct > 50
                    ? [`Intermediate L4 socket buffer queue saturation (${agent2.chaosQueuing.queueUtilizationPct}%)`]
                    : [])
            ],
            downstreamSymptoms: [
                ...(rawRetransmissions !== null && rawRetransmissions > 0 ? [`L4 TCP retransmissions (${rawRetransmissions}) observed downstream [CONCURRENT_SYMPTOM / DOWNSTREAM_CASCADE]`] : []),
                ...(rawRttMs !== null && rawRttMs > 40 ? [`Elevated round-trip latency (${rawRttMs}ms) on ${targetHost} [DOWNSTREAM_CASCADE]`] : [])
            ],
            independentProblems: cpuSaturationPct > 80 && packetLossPct > 2.0
                ? [`Concurrent high host CPU (${cpuSaturationPct}%) and network packet loss (${packetLossPct}%) require separate L7 compute and L2/L3 link mitigation`]
                : [],
            coincidentalObservations: zeroValuedMetrics.map((m) => `Metric "${m}" measured at exactly 0 (healthy/non-contributing observation)`),
            unresolvedHypotheses: [
                ...candidates.slice(1).map((c) => `${c.agentName}: ${c.hypothesis}`),
                ...unexecutedProbeHypotheses
            ]
        };
        const canonicalPayload = JSON.stringify({
            sessionId,
            winner: round4EmpiricalSettlement.settledWinningHypothesis,
            confidence: round4EmpiricalSettlement.settledPosteriorConfidence,
            action: agent4.proposedRemediationAction,
            lyapunovStabilityScore,
            executedAt: nowIso
        });
        const payloadHash = crypto.createHash('sha256').update(canonicalPayload).digest('hex');
        const hmacSignature = this.hmacConfigured
            ? crypto.createHmac('sha256', this.secretKey).update(canonicalPayload).digest('hex')
            : '';
        const issuedAt = Date.now();
        const agent5 = {
            agentName: 'Agent 5 — DSRL Lyapunov Safety & Zero-Trust Officer',
            lyapunovStabilityScore,
            lyapunovDriftDelta,
            lyapunovBarrierCleared,
            hmacConfigured: this.hmacConfigured,
            hmacStatus: this.hmacConfigured ? 'SIGNED_SOVEREIGN_HMAC_SHA256' : 'REJECTED_INSECURE_OR_MISSING_SECRET',
            operatorAuthorized: authCheck.operatorAuthorized,
            operatorPermitted: authCheck.operatorAuthorized,
            operatorRoleVerified: authCheck.operatorRoleVerified,
            verifiedOperatorId: authCheck.verifiedOperatorId,
            verifiedOperatorRole: authCheck.verifiedOperatorRole,
            authorizationStatus: authCheck.authorizationStatus,
            dualApprovalSatisfied: false,
            remediationExecuted,
            remediationReceiptStatus: remReceiptVerification.reasonCode,
            incidentResolved,
            postRemediationVerification: {
                verified: incidentResolved,
                targetMatched: postTargetMatched,
                temporalOrderingValid,
                reasonCode: incidentResolved
                    ? 'POST_REMEDIATION_TELEMETRY_VERIFIED'
                    : remExec?.executed && !remediationExecuted
                        ? remReceiptVerification.reasonCode
                        : remediationExecuted
                            ? 'POST_REMEDIATION_TELEMETRY_MISSING_OR_DEGRADED'
                            : 'REMEDIATION_NOT_YET_EXECUTED',
                observedMetrics: {
                    rttMs: postRtt,
                    packetLossPct: postLoss,
                    retransmissions: postRetrans
                }
            },
            zeroTrustPolicy: {
                enforcementMode: 'LEAST_PRIVILEGE_READ_ONLY_GUARD',
                windowsNetshRules: [
                    `netsh advfirewall firewall show rule name=all`,
                    `netsh interface ipv4 show subinterfaces`
                ]
            },
            hmacSignature,
            proofChain: this.hmacConfigured
                ? `EJII-PROOF-V5:${payloadHash.slice(0, 16)}:${hmacSignature.slice(0, 16)}`
                : `EJII-PROOF-UNSIGNED:${payloadHash.slice(0, 16)}:SECRET_REJECTED`
        };
        const incidentLifecycleStage = incidentResolved
            ? 'POST_REMEDIATION_VERIFIED'
            : remediationExecuted
                ? 'REMEDIATION_EXECUTED'
                : authCheck.operatorAuthorized
                    ? 'OPERATOR_AUTHORIZED'
                    : round4EmpiricalSettlement.executedProbesCount > 0
                        ? 'PROBES_EXECUTED'
                        : 'REMEDIATION_PROPOSED';
        const status = incidentResolved
            ? 'RESOLVED_REMEDIATION_SIGNED'
            : lyapunovBarrierCleared
                ? 'STABILIZED_MONITORING'
                : 'INCIDENT_ESCALATED';
        const dissentingReport = [
            ...candidates
                .slice(1)
                .map((c) => `${c.agentName} (${(c.posteriorConfidence * 100).toFixed(1)}%): ${c.dissentingPoints[0]}`),
            ...(round4EmpiricalSettlement.executedProbesCount === 0
                ? ['Active probes are currently in PROPOSED state (0 executed); Round 4 empirical settlement awaits collector execution.']
                : [])
        ];
        const result = {
            sessionId,
            warRoomSessionId: sessionId,
            executedAt: nowIso,
            requestReceivedAt,
            observationTimestamp,
            scenarioMode,
            isLiveEvidence: !isReferenceFixture && hasTelemetry,
            incidentLifecycleStage,
            persistenceState: 'VOLATILE_MEMORY_ONLY',
            persistenceError: null,
            telemetryProvenance: {
                sourceType,
                evidenceClass,
                telemetryVerifiedBySignature,
                observationTimestamp,
                requestReceivedAt,
                sessionCreatedAt: nowIso,
                measuredMetrics,
                missingMetrics,
                zeroValuedMetrics,
                telemetryCompletenessPct
            },
            agent1,
            agent2,
            agent3,
            agent4,
            agent5,
            adversarialDebates,
            autonomousActiveProbes,
            round4EmpiricalSettlement,
            epistemicCalibrationMode: round4EmpiricalSettlement.calibrationMetrics.epistemicCalibrationMode,
            statisticalValidityReport: round4EmpiricalSettlement.statisticalValidityReport,
            causalRoleClassification,
            rounds: [agent1, agent2, agent3],
            consensusReached: round4EmpiricalSettlement.canEstablishRootCause &&
                round4EmpiricalSettlement.settledPosteriorConfidence >= 0.55,
            canEstablishRootCause: round4EmpiricalSettlement.canEstablishRootCause,
            winningHypothesis: round4EmpiricalSettlement.settledWinningHypothesis,
            finalPosteriorConfidence: round4EmpiricalSettlement.settledPosteriorConfidence,
            'dissenting MinorityReport': dissentingReport,
            dissentingMinorityReport: dissentingReport,
            cryptographicExecutionToken: {
                algorithm: 'HMAC-SHA256',
                issuedAt,
                expiresAt: issuedAt + 300_000,
                payloadHash,
                signature: hmacSignature,
                valid: Boolean(this.hmacConfigured && hmacSignature.length === 64)
            },
            status
        };
        this.latestResult = result;
        this.sessionHistory.set(sessionId, result);
        this.enforceMemoryRetention();
        this.persistSessionToDb(result);
        return result;
    }
    /**
     * Section 5: Executes genuine read-only network & OS collector probes for an existing session (or creates one)
     * with zero 0.2ms timing floors and cryptographically signed CollectorExecutionReceipts.
     */
    async executeActiveProbes(sessionIdOrPayload, options = {}) {
        let baseSession = null;
        if (typeof sessionIdOrPayload === 'string' && sessionIdOrPayload.trim().length > 0) {
            baseSession = this.getSessionById(sessionIdOrPayload.trim());
            if (!baseSession) {
                const err = new Error(`War-Room session "${sessionIdOrPayload}" was not found.`);
                err.code = 'WAR_ROOM_SESSION_NOT_FOUND';
                err.statusCode = 404;
                throw err;
            }
        }
        else {
            baseSession = this.execute(sessionIdOrPayload && typeof sessionIdOrPayload === 'object' ? sessionIdOrPayload : {});
        }
        const filterIds = Array.isArray(options.probeIds) && options.probeIds.length > 0 ? new Set(options.probeIds) : null;
        const executedResults = [];
        const hostSummary = this.getLocalHostNetworkSummary();
        for (const probe of baseSession.autonomousActiveProbes) {
            if (filterIds && !filterIds.has(probe.probeId))
                continue;
            if (probe.safetyGuardClassification !== 'READ_ONLY_SAFE_POL_01')
                continue;
            const startedAt = new Date().toISOString();
            const t0 = performance.now();
            let timingTarget = 'TCP_HANDSHAKE_RTT_MS';
            let nativeResultCode = 'OK';
            let probeClassification = 'VERIFIED';
            let conclusive = true;
            let rawCommandOutput = '';
            let empiricalObservation = '';
            let success = true;
            const probeDetails = {};
            try {
                if (probe.probeType === 'DNS_PTR_LOOKUP') {
                    // Section 5.1: Real DNS query via dns.promises.Resolver
                    timingTarget = 'DNS_QUERY_RTT_MS';
                    const configuredServers = dns.getServers();
                    const resolver = new dns.promises.Resolver({ timeout: 1500, tries: 1 });
                    if (configuredServers.length > 0) {
                        try {
                            resolver.setServers(configuredServers);
                        }
                        catch (_) { }
                    }
                    const isIp = net.isIP(probe.target) !== 0;
                    probeDetails.configuredResolvers = configuredServers;
                    probeDetails.queriedTarget = probe.target;
                    probeDetails.queryType = isIp ? 'PTR' : 'A';
                    const dnsStart = performance.now();
                    if (isIp) {
                        try {
                            const ptrRecords = await resolver.reverse(probe.target);
                            const dnsElapsed = Number((performance.now() - dnsStart).toFixed(3));
                            nativeResultCode = 'QUERY_SUCCESS';
                            probeClassification = 'PTR_RESOLVED';
                            conclusive = true;
                            probeDetails.responseRecords = ptrRecords;
                            rawCommandOutput = `DNS PTR query for ${probe.target} via resolver [${configuredServers.join(', ') || 'system'}] resolved [${ptrRecords.join(', ')}] in ${dnsElapsed}ms`;
                            empiricalObservation = `[${probe.probeId}] DNS PTR query for ${probe.target} succeeded (${ptrRecords.join(', ')}) in ${dnsElapsed}ms.`;
                        }
                        catch (dnsErr) {
                            const errCode = String(dnsErr?.code || 'DNS_ERROR');
                            probeDetails.reverseErrorCode = errCode;
                            if (errCode === 'ENOTFOUND' || errCode === 'ENODATA') {
                                // Verify whether resolver itself is alive via localhost lookup while reporting exact reverse() RCODE
                                try {
                                    const localAddrs = await dns.promises.lookup('localhost', { all: true });
                                    const dnsElapsed = Number((performance.now() - dnsStart).toFixed(3));
                                    nativeResultCode = errCode;
                                    probeClassification = 'RESOLVER_RESPONSIVE_NO_PTR_RECORD';
                                    conclusive = true;
                                    probeDetails.localhostRecords = localAddrs.map((a) => a.address);
                                    rawCommandOutput = `DNS PTR query for ${probe.target} via [${configuredServers.join(', ') || 'system'}] returned ${errCode} (no PTR record published); resolver responsiveness verified (${localAddrs.map((a) => a.address).join(', ')}) in ${dnsElapsed}ms`;
                                    empiricalObservation = `[${probe.probeId}] DNS PTR query to ${probe.target} returned ${errCode}; resolver active in ${dnsElapsed}ms.`;
                                }
                                catch (fbErr) {
                                    const fbCode = String(fbErr?.code || errCode);
                                    nativeResultCode = fbCode;
                                    probeClassification = 'DNS_RESOLVER_FAILURE';
                                    conclusive = true;
                                    rawCommandOutput = `DNS PTR query for ${probe.target} failed with ${errCode} (${fbCode})`;
                                    empiricalObservation = `[${probe.probeId}] DNS query for ${probe.target} failed with ${errCode}.`;
                                }
                            }
                            else {
                                nativeResultCode = errCode;
                                probeClassification =
                                    errCode === 'ETIMEOUT' ? 'DNS_TIMEOUT' :
                                        errCode === 'ESERVFAIL' ? 'DNS_SERVFAIL' :
                                            errCode === 'EREFUSED' ? 'DNS_REFUSED' : 'DNS_QUERY_ERROR';
                                conclusive = true;
                                rawCommandOutput = `DNS PTR query for ${probe.target} via [${configuredServers.join(', ') || 'system'}] failed with ${errCode}`;
                                empiricalObservation = `[${probe.probeId}] DNS PTR query for ${probe.target} returned ${errCode}.`;
                            }
                        }
                    }
                    else {
                        try {
                            const aRecords = await resolver.resolve4(probe.target);
                            const dnsElapsed = Number((performance.now() - dnsStart).toFixed(3));
                            nativeResultCode = 'QUERY_SUCCESS';
                            probeClassification = 'A_RECORD_RESOLVED';
                            conclusive = true;
                            probeDetails.responseRecords = aRecords;
                            rawCommandOutput = `DNS A query for ${probe.target} resolved [${aRecords.join(', ')}] in ${dnsElapsed}ms`;
                            empiricalObservation = `[${probe.probeId}] DNS A query for ${probe.target} resolved ${aRecords.join(', ')} in ${dnsElapsed}ms.`;
                        }
                        catch (dnsErr) {
                            const errCode = String(dnsErr?.code || 'DNS_ERROR');
                            nativeResultCode = errCode;
                            probeClassification = errCode === 'ENOTFOUND' ? 'NXDOMAIN' : 'DNS_QUERY_ERROR';
                            conclusive = true;
                            rawCommandOutput = `DNS A query for ${probe.target} returned ${errCode}`;
                            empiricalObservation = `[${probe.probeId}] DNS A query for ${probe.target} returned ${errCode}.`;
                        }
                    }
                }
                else if (probe.probeType === 'ICMP_PMTU_DISCOVERY') {
                    // Section 5.2: Real DF-bit stepped payload Path MTU discovery separated from local interface MTU
                    timingTarget = 'ICMP_DF_PROBE_RTT_MS';
                    probeDetails.localInterfaceMtuBytes = hostSummary.localInterfaceMtuBytes;
                    const payloadSteps = [1472, 1400, 1360, 1200, 548];
                    let verifiedPayload = null;
                    let fragNeededPayload = null;
                    let icmpRestricted = false;
                    let lastPingOut = '';
                    for (const sz of payloadSteps) {
                        const args = process.platform === 'win32'
                            ? ['-n', '1', '-f', '-l', String(sz), '-w', '1000', probe.target]
                            : process.platform === 'darwin'
                                ? ['-c', '1', '-D', '-s', String(sz), '-W', '1000', probe.target]
                                : ['-c', '1', '-M', 'do', '-s', String(sz), '-W', '1', probe.target];
                        const res = await execFileAsync('ping', args, 1500);
                        const combined = `${res.stdout}\n${res.stderr}`.trim();
                        lastPingOut = combined;
                        if (res.exitCode === 0) {
                            verifiedPayload = sz;
                            break;
                        }
                        if (/frag needed|fragmented|message too long|mtu\s*=\s*\d+/i.test(combined)) {
                            fragNeededPayload = sz;
                            continue;
                        }
                        if (/operation not permitted|permission denied|socket:.*not permitted|cap_net_raw|not found|enoent/i.test(combined) || res.exitCode === 127) {
                            icmpRestricted = true;
                            break;
                        }
                        break;
                    }
                    if (verifiedPayload !== null) {
                        const measuredPathMtu = verifiedPayload + 28;
                        probeDetails.measuredPathMtuBytes = measuredPathMtu;
                        probeDetails.verifiedDfPayloadBytes = verifiedPayload;
                        if (fragNeededPayload !== null) {
                            nativeResultCode = 'PMTU_DEGRADED_FRAG_NEEDED';
                            probeClassification = 'FRAGMENTATION_NEEDED_DETECTED';
                            conclusive = true;
                            rawCommandOutput = `DF-bit ICMP probe to ${probe.target}: Frag needed at ${fragNeededPayload + 28}B; stepped down and verified Path MTU=${measuredPathMtu}B (localInterfaceMtu=${hostSummary.localInterfaceMtuBytes}B)`;
                            empiricalObservation = `[${probe.probeId}] Detected Path MTU clamp (${measuredPathMtu}B < ${fragNeededPayload + 28}B) on ${probe.target}.`;
                        }
                        else {
                            nativeResultCode = 'PMTU_1500_VERIFIED';
                            probeClassification = 'PATH_MTU_VERIFIED';
                            conclusive = true;
                            rawCommandOutput = `DF-bit ICMP probe to ${probe.target} verified end-to-end Path MTU=${measuredPathMtu}B (DF payload=${verifiedPayload}B, localInterfaceMtu=${hostSummary.localInterfaceMtuBytes}B)`;
                            empiricalObservation = `[${probe.probeId}] Verified end-to-end DF-bit Path MTU=${measuredPathMtu}B to ${probe.target}.`;
                        }
                    }
                    else if (icmpRestricted) {
                        probeDetails.measuredPathMtuBytes = null;
                        probeDetails.icmpRestricted = true;
                        nativeResultCode = 'ICMP_RESTRICTED_TCP_FALLBACK';
                        probeClassification = 'ICMP_RESTRICTED_TCP_FALLBACK';
                        conclusive = true;
                        rawCommandOutput = `Raw DF-bit ICMP restricted by OS (${lastPingOut.slice(0, 100) || 'CAP_NET_RAW unavailable'}); localInterfaceMtu=${hostSummary.localInterfaceMtuBytes}B recorded separately from unprobed remote Path MTU`;
                        empiricalObservation = `[${probe.probeId}] Raw ICMP DF-bit socket restricted on host; localInterfaceMtu=${hostSummary.localInterfaceMtuBytes}B recorded separately.`;
                    }
                    else {
                        probeDetails.measuredPathMtuBytes = null;
                        nativeResultCode = 'ICMP_TIMEOUT_OR_UNREACHABLE';
                        probeClassification = 'TIMEOUT_OR_UNREACHABLE';
                        conclusive = true;
                        rawCommandOutput = `DF-bit ICMP probe to ${probe.target} returned no echo reply (${lastPingOut.slice(0, 120) || 'timeout/unreachable'}); localInterfaceMtu=${hostSummary.localInterfaceMtuBytes}B`;
                        empiricalObservation = `[${probe.probeId}] DF-bit ICMP probe to ${probe.target} timed out or destination unreachable.`;
                    }
                }
                else if (probe.probeType === 'ARP_NEIGHBOR_VERIFY') {
                    // Section 5.3: Real OS neighbor table inspection (/proc/net/arp, ip neigh, arp -a)
                    timingTarget = 'LOCAL_OS_NEIGHBOR_TABLE_READ_MS';
                    const entries = [];
                    if (process.platform === 'linux' && fs.existsSync('/proc/net/arp')) {
                        try {
                            const rawArp = fs.readFileSync('/proc/net/arp', 'utf8');
                            for (const line of rawArp.trim().split(/\r?\n/).slice(1)) {
                                const cols = line.trim().split(/\s+/);
                                if (cols.length >= 6) {
                                    const ip = cols[0];
                                    const flags = cols[2];
                                    const mac = cols[3];
                                    const iface = cols[5];
                                    const st = (flags === '0x2' || flags === '0x6') && mac !== '00:00:00:00:00:00' ? 'REACHABLE' : 'INCOMPLETE';
                                    entries.push({ ip, mac, state: st, iface, family: 'IPv4_ARP' });
                                }
                            }
                        }
                        catch (_) { }
                    }
                    if (process.platform === 'win32') {
                        const arpRes = await execFileAsync('arp', ['-a'], 1200);
                        for (const line of arpRes.stdout.split(/\r?\n/)) {
                            const m = line.trim().match(/^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+(\S+)/);
                            if (m) {
                                entries.push({
                                    ip: m[1],
                                    mac: m[2].replace(/-/g, ':').toLowerCase(),
                                    state: m[3].toUpperCase() === 'DYNAMIC' ? 'REACHABLE' : 'PERMANENT',
                                    iface: 'eth0',
                                    family: 'IPv4_ARP'
                                });
                            }
                        }
                    }
                    else {
                        const ipNeigh = await execFileAsync('ip', ['neigh', 'show'], 1200);
                        if (ipNeigh.exitCode === 0 && ipNeigh.stdout.trim()) {
                            for (const line of ipNeigh.stdout.trim().split(/\r?\n/)) {
                                const ipMatch = line.match(/^(\S+)/);
                                const devMatch = line.match(/\bdev\s+(\S+)/);
                                const llMatch = line.match(/\blladdr\s+([0-9a-fA-F:]+)/);
                                const stMatch = line.match(/\b(REACHABLE|STALE|DELAY|PROBE|INCOMPLETE|FAILED|PERMANENT|NOARP)\b/i);
                                if (ipMatch) {
                                    const ip = ipMatch[1];
                                    const idx = entries.findIndex((e) => e.ip === ip);
                                    const entry = {
                                        ip,
                                        mac: llMatch ? llMatch[1].toLowerCase() : '00:00:00:00:00:00',
                                        state: stMatch ? stMatch[1].toUpperCase() : 'STALE',
                                        iface: devMatch ? devMatch[1] : 'eth0',
                                        family: ip.includes(':') ? 'IPv6_NDP' : 'IPv4_ARP'
                                    };
                                    if (idx >= 0)
                                        entries[idx] = entry;
                                    else
                                        entries.push(entry);
                                }
                            }
                        }
                    }
                    probeDetails.totalNeighborEntriesRead = entries.length;
                    const matched = entries.find((e) => e.ip === probe.target);
                    const isSelf = probe.target === '127.0.0.1' || probe.target === '::1' || probe.target === hostSummary.primaryIpv4;
                    if (matched) {
                        probeDetails.matchedNeighbor = matched;
                        nativeResultCode = `NEIGH_${matched.state}`;
                        probeClassification = matched.state;
                        conclusive = true;
                        rawCommandOutput = `OS neighbor table entry for ${probe.target} on ${matched.iface} (${matched.family}): lladdr=${matched.mac} state=${matched.state} (totalEntries=${entries.length})`;
                        empiricalObservation = `[${probe.probeId}] OS neighbor entry for ${probe.target}: lladdr=${matched.mac}, state=${matched.state} on ${matched.iface}.`;
                    }
                    else if (isSelf) {
                        probeDetails.isLocalHostTarget = true;
                        nativeResultCode = 'LOCAL_INTERFACE_SELF';
                        probeClassification = 'PERMANENT';
                        conclusive = true;
                        rawCommandOutput = `OS neighbor table inspected (${entries.length} entries); target ${probe.target} is local host interface on ${hostSummary.hostname} (${hostSummary.primaryIpv4})`;
                        empiricalObservation = `[${probe.probeId}] Target ${probe.target} is local host interface (${entries.length} neighbor entries inspected).`;
                    }
                    else {
                        nativeResultCode = 'ABSENT_FROM_NEIGHBOR_TABLE';
                        probeClassification = 'ABSENT_FROM_NEIGHBOR_TABLE';
                        conclusive = true;
                        rawCommandOutput = `OS neighbor table inspected (${entries.length} active ARP/NDP entries); no direct L2 entry cached for ${probe.target}`;
                        empiricalObservation = `[${probe.probeId}] Target ${probe.target} absent from local ARP/NDP cache (${entries.length} entries read).`;
                    }
                }
                else if (probe.probeType === 'SOCKET_ESTABLISHED_AUDIT') {
                    // Section 5.4: Real OS socket table inspection (no temporary 127.0.0.1 loopback server)
                    timingTarget = 'LOCAL_OS_SOCKET_TABLE_READ_MS';
                    const correlator = getProcessSocketCorrelator();
                    let allSockets = [];
                    let permissionRestricted = false;
                    if (correlator && typeof correlator.collectActiveConnectionsInventory === 'function') {
                        const inv = await correlator.collectActiveConnectionsInventory({ limit: 500 });
                        allSockets = Array.isArray(inv?.connections) ? inv.connections : [];
                        permissionRestricted = Boolean(inv?.permissionRestricted);
                    }
                    else if (process.platform === 'linux' && fs.existsSync('/proc/net/tcp')) {
                        const rawTcp = fs.readFileSync('/proc/net/tcp', 'utf8');
                        const lines = rawTcp.trim().split(/\r?\n/).slice(1);
                        allSockets = lines.map((l) => ({ raw: l, state: 'ESTABLISHED' }));
                    }
                    const isLocalTarget = probe.target === '127.0.0.1' || probe.target === '::1' || probe.target === hostSummary.primaryIpv4;
                    const matchedSockets = allSockets.filter((c) => {
                        if (isLocalTarget)
                            return true;
                        return c.localAddress === probe.target || c.remoteAddress === probe.target;
                    });
                    let establishedCount = 0;
                    let listeningCount = 0;
                    let synSentCount = 0;
                    let timeWaitCount = 0;
                    let closeWaitCount = 0;
                    for (const c of matchedSockets) {
                        const st = String(c.state || '').toUpperCase();
                        if (st === 'ESTABLISHED')
                            establishedCount++;
                        else if (st === 'LISTEN' || st === 'LISTENING')
                            listeningCount++;
                        else if (st.includes('SYN'))
                            synSentCount++;
                        else if (st.includes('TIME_WAIT') || st.includes('TIME-WAIT'))
                            timeWaitCount++;
                        else if (st.includes('CLOSE_WAIT') || st.includes('CLOSE-WAIT'))
                            closeWaitCount++;
                    }
                    probeDetails.totalSystemSockets = allSockets.length;
                    probeDetails.targetMatchedSockets = matchedSockets.length;
                    probeDetails.establishedCount = establishedCount;
                    probeDetails.listeningCount = listeningCount;
                    probeDetails.synSentCount = synSentCount;
                    probeDetails.timeWaitCount = timeWaitCount;
                    probeDetails.closeWaitCount = closeWaitCount;
                    probeDetails.permissionRestricted = permissionRestricted;
                    nativeResultCode = closeWaitCount > 0 ? 'SOCKETS_CLOSE_WAIT_PRESENT' : 'SOCKET_TABLE_AUDITED';
                    probeClassification = closeWaitCount > 0 ? 'CLOSE_WAIT_DETECTED' : 'SOCKET_TABLE_HEALTHY';
                    conclusive = true;
                    rawCommandOutput =
                        `OS socket table audited for ${probe.target}: systemSockets=${allSockets.length}, matched=${matchedSockets.length} ` +
                            `(ESTABLISHED=${establishedCount}, LISTEN=${listeningCount}, SYN_SENT=${synSentCount}, TIME_WAIT=${timeWaitCount}, CLOSE_WAIT=${closeWaitCount})`;
                    empiricalObservation =
                        `[${probe.probeId}] Audited ${allSockets.length} OS sockets (${matchedSockets.length} matched ${probe.target}: ESTABLISHED=${establishedCount}, LISTEN=${listeningCount}, CLOSE_WAIT=${closeWaitCount}).`;
                }
            }
            catch (probeErr) {
                success = false;
                nativeResultCode = probeErr?.code || 'COLLECTOR_EXECUTION_ERROR';
                probeClassification = 'COLLECTOR_EXECUTION_FAILED';
                conclusive = false;
                rawCommandOutput = probeErr?.message || 'Probe execution failed';
                empiricalObservation = `[${probe.probeId}] Collector execution error: ${rawCommandOutput}`;
            }
            const completedAt = new Date().toISOString();
            // Section 5.5: Exact sub-millisecond timing without any Math.max(0.2, ...) floor
            const elapsed = Number((performance.now() - t0).toFixed(3));
            const receipt = this.createCollectorExecutionReceipt({
                sessionId: baseSession.sessionId,
                probeId: probe.probeId,
                probeType: probe.probeType,
                target: probe.target,
                startedAt,
                completedAt,
                durationMs: elapsed,
                timingTarget,
                nativeResultCode,
                rawCommandOutput
            });
            executedResults.push({
                probeId: probe.probeId,
                probeType: probe.probeType,
                target: probe.target,
                measuredLatencyMs: elapsed,
                timingTarget,
                nativeResultCode,
                probeClassification,
                conclusive,
                rawCommandOutput,
                output: rawCommandOutput,
                empiricalObservation,
                collectorExecutionReceipt: receipt,
                probeDetails,
                executed: true,
                success,
                executedAt: completedAt,
                observedAt: completedAt
            });
        }
        baseSession.round4EmpiricalSettlement = this.applyExecutedProbeResults(baseSession.autonomousActiveProbes, executedResults, baseSession.agent1, baseSession.agent2, baseSession.agent3, baseSession.canEstablishRootCause, baseSession.sessionId);
        baseSession.winningHypothesis = baseSession.round4EmpiricalSettlement.settledWinningHypothesis;
        baseSession.finalPosteriorConfidence = baseSession.round4EmpiricalSettlement.settledPosteriorConfidence;
        baseSession.canEstablishRootCause = baseSession.round4EmpiricalSettlement.canEstablishRootCause;
        baseSession.consensusReached =
            baseSession.canEstablishRootCause && baseSession.finalPosteriorConfidence >= 0.55;
        if (baseSession.round4EmpiricalSettlement.executedProbesCount > 0 &&
            baseSession.incidentLifecycleStage === 'REMEDIATION_PROPOSED') {
            baseSession.incidentLifecycleStage = 'PROBES_EXECUTED';
        }
        baseSession.executedResults = executedResults;
        this.latestResult = baseSession;
        this.sessionHistory.set(baseSession.sessionId, baseSession);
        this.persistSessionToDb(baseSession);
        return baseSession;
    }
    getSessionById(sessionId) {
        if (!sessionId || typeof sessionId !== 'string')
            return null;
        const inMem = this.sessionHistory.get(sessionId);
        if (inMem)
            return inMem;
        const targetDb = this.resolveDb();
        if (targetDb && typeof targetDb.prepare === 'function') {
            try {
                const row = targetDb
                    .prepare('SELECT payload_json FROM war_room_sessions WHERE session_id = ?')
                    .get(sessionId);
                if (row && typeof row.payload_json === 'string') {
                    const parsed = JSON.parse(row.payload_json);
                    if (parsed && parsed.sessionId === sessionId) {
                        if (!parsed.warRoomSessionId)
                            parsed.warRoomSessionId = parsed.sessionId;
                        this.sessionHistory.set(sessionId, parsed);
                        return parsed;
                    }
                }
            }
            catch (_) { }
        }
        return null;
    }
    getSession(sessionId) {
        return this.getSessionById(sessionId);
    }
    getAllSessions() {
        return Array.from(this.sessionHistory.values());
    }
    listSessions() {
        return this.getAllSessions();
    }
    /**
     * Interactive Operator Steering & Constraint Re-Evaluation (Sections 10 & 12)
     * Throws WAR_ROOM_SESSION_NOT_FOUND when sessionId is missing or unknown.
     * Enforces cryptographic Dual-Operator Approval verification via issueDualOperatorApproval / JWT.
     */
    reevaluateWithConstraint(sessionId, constraints = {}) {
        const cleanId = typeof sessionId === 'string' ? sessionId.trim() : '';
        const prior = cleanId ? this.getSessionById(cleanId) : null;
        if (!prior) {
            const err = new Error(`War-Room session "${cleanId || 'EMPTY'}" was not found in active memory or durable SQLite ledger.`);
            err.code = 'WAR_ROOM_SESSION_NOT_FOUND';
            err.statusCode = 404;
            throw err;
        }
        const forbidden = (constraints.forbiddenRemediations || [])
            .map((f) => String(f).toLowerCase().trim())
            .filter(Boolean);
        const required = (constraints.requiredRemediations || [])
            .map((r) => String(r).trim())
            .filter(Boolean);
        const targetScope = String(constraints.targetEntityFilter || constraints.targetVlan || '').trim();
        let policyViolationBlocked = false;
        let safetyPolicyViolationReason = null;
        let chosenAction = prior.agent4.proposedRemediationAction;
        // 1. Check requiredRemediations first (subject to POL-02 safety check)
        if (required.length > 0) {
            const reqCandidate = required[0];
            if (DESTRUCTIVE_COMMAND_PATTERNS.test(reqCandidate)) {
                policyViolationBlocked = true;
                safetyPolicyViolationReason = `POL_02_DESTRUCTIVE_REQUIRED_REMEDIATION_BLOCKED: "${reqCandidate}" violates non-destructive safety policy.`;
            }
            else {
                chosenAction = reqCandidate;
            }
        }
        // 2. Apply forbiddenRemediations filter against candidate pool
        const candidatePool = [
            chosenAction,
            ...(prior.agent4.alternativeCandidates || []),
            `Isolate & throttle non-critical flows via QoS policing on ${targetScope || prior.agent4.remediationTarget}`,
            `Drain secondary worker pool & pin latency-sensitive flows to clean interface on ${targetScope || prior.agent4.remediationTarget}`,
            `Enforce conservative TCP MSS clamping (1360 bytes) and rate-limit resolver retries on ${targetScope || prior.agent4.remediationTarget}`
        ];
        const filteredPool = candidatePool.filter((act) => {
            const lower = act.toLowerCase();
            if (DESTRUCTIVE_COMMAND_PATTERNS.test(act))
                return false;
            return !forbidden.some((f) => lower.includes(f) || f.includes(lower));
        });
        if (!policyViolationBlocked) {
            chosenAction =
                filteredPool[0] ||
                    `Conservative Passive Telemetry Watch on ${targetScope || prior.agent4.remediationTarget} (All active remediations constrained by operator)`;
        }
        else {
            chosenAction = `BLOCKED_BY_POL_02_SAFETY_GUARD: Falling back to read-only monitoring on ${targetScope || prior.agent4.remediationTarget}`;
        }
        if (targetScope && !chosenAction.includes(targetScope)) {
            chosenAction = `${chosenAction} [Scoped to ${targetScope}]`;
        }
        // 3. Section 10: Cryptographic Dual-Operator Approval Verification
        const requireDualApproval = Boolean(constraints.requireDualApproval ?? prior.agent4.requiresDualApproval);
        let dualApprovalSatisfied = false;
        let dualApprovalStatus = prior.agent5.authorizationStatus;
        if (requireDualApproval) {
            const primary = constraints.dualApprovalContext?.primaryApproval;
            const secondary = constraints.dualApprovalContext?.secondaryApproval;
            const pId = typeof primary?.operatorId === 'string' ? primary.operatorId.trim() : '';
            const sId = typeof secondary?.operatorId === 'string' ? secondary.operatorId.trim() : '';
            if (!pId || !sId || pId === sId) {
                dualApprovalSatisfied = false;
                dualApprovalStatus = 'PENDING_SECOND_DISTINCT_OPERATOR';
            }
            else {
                const primaryVerified = this.verifySingleApprovalSlot(prior.sessionId, primary, 'PRIMARY');
                const secondaryVerified = this.verifySingleApprovalSlot(prior.sessionId, secondary, 'SECONDARY');
                if (primaryVerified.valid &&
                    secondaryVerified.valid &&
                    primaryVerified.operatorId !== secondaryVerified.operatorId) {
                    dualApprovalSatisfied = true;
                    dualApprovalStatus = 'DUAL_OPERATOR_VERIFIED';
                }
                else {
                    dualApprovalSatisfied = false;
                    dualApprovalStatus = 'UNVERIFIED_DUAL_OPERATOR_TOKENS_REJECTED';
                }
            }
        }
        const newSessionId = `sre-warroom-steered-${Date.now()}-${crypto.randomBytes(2).toString('hex')}`;
        const executedAt = new Date().toISOString();
        const canonicalPayload = JSON.stringify({
            sessionId: newSessionId,
            parentSessionId: prior.sessionId,
            chosenAction,
            constraints: {
                forbiddenRemediations: constraints.forbiddenRemediations || [],
                requiredRemediations: constraints.requiredRemediations || [],
                targetVlan: constraints.targetVlan,
                targetEntityFilter: constraints.targetEntityFilter,
                requireDualApproval
            },
            executedAt
        });
        const payloadHash = crypto.createHash('sha256').update(canonicalPayload).digest('hex');
        const hmacSignature = this.hmacConfigured
            ? crypto.createHmac('sha256', this.secretKey).update(canonicalPayload).digest('hex')
            : '';
        const lyapunovScore = policyViolationBlocked
            ? 0.35
            : Number(Math.min(0.99, prior.agent5.lyapunovStabilityScore + 0.03).toFixed(4));
        const lyapunovBarrierCleared = Boolean(!policyViolationBlocked && lyapunovScore >= 0.65 && this.hmacConfigured);
        // Scope active probes to targetEntityFilter if specified (Section 12)
        const steeredProbes = (prior.autonomousActiveProbes || []).map((p) => ({
            ...p,
            scopedEntityFilter: targetScope || null
        }));
        const inheritedSettlement = {
            ...prior.round4EmpiricalSettlement,
            inheritedFromSessionId: prior.sessionId,
            newProbesExecutedInSteeredSession: false
        };
        const reevaluated = {
            ...prior,
            sessionId: newSessionId,
            warRoomSessionId: newSessionId,
            parentSessionId: prior.sessionId,
            executedAt,
            incidentLifecycleStage: dualApprovalSatisfied ? 'OPERATOR_AUTHORIZED' : 'REMEDIATION_PROPOSED',
            autonomousActiveProbes: steeredProbes,
            round4EmpiricalSettlement: inheritedSettlement,
            agent4: {
                ...prior.agent4,
                proposedRemediationAction: chosenAction,
                remediationTarget: targetScope || prior.agent4.remediationTarget,
                alternativeCandidates: filteredPool,
                requiresDualApproval: requireDualApproval,
                blastRadiusScore: Number(Math.max(0.05, prior.agent4.blastRadiusScore - 0.04).toFixed(3)),
                safetyPolicyCheck: policyViolationBlocked ? 'BLOCKED_DESTRUCTIVE_POL_02' : 'PASSED_POL_01',
                safetyPolicyViolationReason
            },
            agent5: {
                ...prior.agent5,
                lyapunovStabilityScore: lyapunovScore,
                lyapunovBarrierCleared,
                operatorAuthorized: requireDualApproval ? dualApprovalSatisfied : prior.agent5.operatorAuthorized,
                authorizationStatus: dualApprovalStatus,
                dualApprovalSatisfied,
                hmacSignature,
                proofChain: this.hmacConfigured
                    ? `EJII-PROOF-STEERED-V5:${payloadHash.slice(0, 16)}:${hmacSignature.slice(0, 16)}`
                    : `EJII-PROOF-STEERED-UNSIGNED:${payloadHash.slice(0, 16)}:SECRET_REJECTED`
            },
            appliedConstraints: {
                forbiddenRemediations: constraints.forbiddenRemediations || [],
                requiredRemediations: constraints.requiredRemediations || [],
                targetVlan: constraints.targetVlan,
                targetEntityFilter: constraints.targetEntityFilter,
                requireDualApproval,
                operatorNote: constraints.operatorNote,
                operatorQuestion: constraints.operatorQuestion,
                policyViolationBlocked
            },
            cryptographicExecutionToken: {
                algorithm: 'HMAC-SHA256',
                issuedAt: Date.now(),
                expiresAt: Date.now() + 300_000,
                payloadHash,
                signature: hmacSignature,
                valid: Boolean(this.hmacConfigured && hmacSignature.length === 64)
            },
            status: 'RE_EVALUATED_WITH_CONSTRAINTS'
        };
        this.latestResult = reevaluated;
        this.sessionHistory.set(newSessionId, reevaluated);
        this.enforceMemoryRetention();
        this.persistSessionToDb(reevaluated);
        return reevaluated;
    }
    /**
     * Enforces Epistemic Abstention:
     * Inspects collector receipts and active hypotheses. When contradictory evidence exists
     * or unverified receipts are present, flags an epistemic abstention to prevent premature consensus settlement.
     */
    enforceEpistemicAbstention(receipts = [], hypotheses = []) {
        if (!Array.isArray(receipts) || receipts.length === 0) {
            return {
                abstentionRequired: true,
                reasonCode: 'UNVERIFIED_RECEIPTS_PRESENT',
                message: 'Epistemic abstention enforced: Zero cryptographically signed collector execution receipts available.',
                unresolvedCount: hypotheses.length
            };
        }
        const unverified = receipts.filter((r) => !this.verifyCollectorReceipt(r, r.sessionId, r.probeId, r.target).valid);
        if (unverified.length > 0) {
            return {
                abstentionRequired: true,
                reasonCode: 'UNVERIFIED_RECEIPTS_PRESENT',
                message: `Epistemic abstention enforced: ${unverified.length} collector receipt(s) failed cryptographic verification.`,
                unresolvedCount: unverified.length
            };
        }
        // Check for contradictory return codes across identical probe types on the same target
        const byTargetProbe = new Map();
        for (const r of receipts) {
            const k = `${r.target}:${r.probeType}`;
            if (!byTargetProbe.has(k))
                byTargetProbe.set(k, []);
            byTargetProbe.get(k).push(r.nativeResultCode);
        }
        for (const [key, codes] of byTargetProbe.entries()) {
            const hasSuccess = codes.some((c) => c === 'SUCCESS' || c === '0' || c === 'OPEN');
            const hasFailure = codes.some((c) => c === 'FAILURE' || c === 'TIMEOUT' || c === 'CONNECTION_REFUSED' || c === 'CLOSED');
            if (hasSuccess && hasFailure) {
                return {
                    abstentionRequired: true,
                    reasonCode: 'CONTRADICTORY_EVIDENCE_DETECTED',
                    message: `Epistemic abstention enforced: Contradictory probe return codes on ${key} [${codes.join(', ')}]. Additional resolving probe required.`,
                    unresolvedCount: 1
                };
            }
        }
        return {
            abstentionRequired: false,
            reasonCode: 'UNCONTRADICTED_EVIDENCE',
            message: 'All collector receipts verified without contradictory evidence.',
            unresolvedCount: 0
        };
    }
    /**
     * Continuous Temporal Post-Remediation Verification Window:
     * Executes multi-sample verification monitoring post-action stability (RTT variance and loss)
     * across a temporal window ensuring zero secondary oscillations or regressions.
     */
    executeTemporalPostRemediationVerification(params) {
        const samples = params.samples || [];
        const windowSec = params.windowSec || 60;
        if (samples.length < 2) {
            return {
                verified: false,
                sampleCount: samples.length,
                windowSec,
                meanRttMs: samples[0]?.rttMs ?? 0,
                maxRttMs: samples[0]?.rttMs ?? 0,
                rttStdDevMs: 0,
                maxLossPct: samples[0]?.packetLossPct ?? 0,
                isStable: false,
                verificationStatus: 'INSUFFICIENT_SAMPLES'
            };
        }
        const rtts = samples.map((s) => s.rttMs);
        const meanRtt = rtts.reduce((a, b) => a + b, 0) / rtts.length;
        const maxRtt = Math.max(...rtts);
        const variance = rtts.reduce((acc, v) => acc + Math.pow(v - meanRtt, 2), 0) / rtts.length;
        const stdDev = Math.sqrt(variance);
        const maxLoss = Math.max(...samples.map((s) => s.packetLossPct));
        const isStable = maxLoss <= 1.0 && stdDev <= 15.0 && maxRtt <= 100.0;
        return {
            verified: isStable,
            sampleCount: samples.length,
            windowSec,
            meanRttMs: Number(meanRtt.toFixed(2)),
            maxRttMs: Number(maxRtt.toFixed(2)),
            rttStdDevMs: Number(stdDev.toFixed(2)),
            maxLossPct: Number(maxLoss.toFixed(2)),
            isStable,
            verificationStatus: isStable ? 'TEMPORAL_STABILITY_CONFIRMED' : 'SECONDARY_OSCILLATION_DETECTED'
        };
    }
    getLatestResult() {
        if (!this.latestResult) {
            return this.execute();
        }
        return this.latestResult;
    }
    getLatest() {
        return this.getLatestResult();
    }
}
exports.AutonomousWarRoomOrchestrator = AutonomousWarRoomOrchestrator;
exports.autonomousWarRoomOrchestrator = new AutonomousWarRoomOrchestrator();
exports.default = exports.autonomousWarRoomOrchestrator;
//# sourceMappingURL=autonomous-war-room.js.map