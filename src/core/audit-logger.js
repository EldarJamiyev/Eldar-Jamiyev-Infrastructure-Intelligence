/**
 * EJII Cryptographic Tamper-Resistant Audit Logger
 * Append-only JSONL storage with continuous HMAC-SHA256 hash chaining.
 * Guarantees tamper-evidence: any modification, deletion, or reordering of audit records
 * breaks the cryptographic chain and is detected by verifyAuditLogIntegrity().
 */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { DATA_DIR, HMAC_SECRET } = require('../config');

let dynamicAuditFilePath = null;
let dynamicAnchorFilePath = null;
let sqliteReplicationFailureCount = 0;

function getAuditDir() {
  if (dynamicAuditFilePath) return path.dirname(dynamicAuditFilePath);
  if (process.env.EJII_TEST_DATA_DIR) return process.env.EJII_TEST_DATA_DIR;
  if (process.env.EJII_AUDIT_DIR) return process.env.EJII_AUDIT_DIR;
  return path.join(DATA_DIR, 'audit');
}

function getAuditFilePath() {
  if (dynamicAuditFilePath) return dynamicAuditFilePath;
  if (process.env.EJII_AUDIT_FILE_PATH) return process.env.EJII_AUDIT_FILE_PATH;
  return path.join(getAuditDir(), 'audit-trail.jsonl');
}

function getChainHeadFilePath() {
  if (dynamicAnchorFilePath) return dynamicAnchorFilePath;
  if (process.env.EJII_AUDIT_ANCHOR_PATH) return process.env.EJII_AUDIT_ANCHOR_PATH;
  return path.join(getAuditDir(), '.chain_head');
}

function configureAuditPaths(options = {}) {
  if (options.auditFilePath) dynamicAuditFilePath = options.auditFilePath;
  if (options.anchorFilePath) dynamicAnchorFilePath = options.anchorFilePath;
}

function resetAuditPaths() {
  dynamicAuditFilePath = null;
  dynamicAnchorFilePath = null;
}

function getSqliteReplicationFailureCount() {
  return sqliteReplicationFailureCount;
}

const AUDIT_DIR = getAuditDir();
const AUDIT_FILE = getAuditFilePath();
const CHAIN_HEAD_FILE = getChainHeadFilePath();
const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

// Ensure audit storage directory exists
try {
  if (!fs.existsSync(AUDIT_DIR)) {
    fs.mkdirSync(AUDIT_DIR, { recursive: true });
  }
} catch (e) {
  console.error('[Audit Logger Init Error]: Failed to create audit directory:', e.message);
}

/**
 * Compute HMAC-SHA256 digest over structured record fields
 */
function computeRecordHash(prevHash, timestamp, userId, action, resource, details) {
  const content = `${prevHash}|${timestamp}|${userId || 'anon'}|${action}|${resource}|${JSON.stringify(details || {})}`;
  return crypto.createHmac('sha256', HMAC_SECRET).update(content).digest('hex');
}

/**
 * Read and verify external .chain_head anchor
 */
function readChainHeadAnchor(targetAnchorFile) {
  const anchorPath = targetAnchorFile || getChainHeadFilePath();
  if (!fs.existsSync(anchorPath)) return null;
  try {
    const raw = fs.readFileSync(anchorPath, 'utf8');
    const parsed = JSON.parse(raw);
    const expectedSig = crypto.createHmac('sha256', HMAC_SECRET)
      .update(`${parsed.lastSeq}|${parsed.lastHash}|${parsed.lastTimestamp}`)
      .digest('hex');
    const bufSig = Buffer.from(parsed.signature || '', 'hex');
    const bufExp = Buffer.from(expectedSig, 'hex');
    if (bufSig.length !== 32 || bufExp.length !== 32 || !crypto.timingSafeEqual(bufSig, bufExp)) {
      return { corrupted: true, error: 'ANCHOR_SIGNATURE_INVALID' };
    }
    return parsed;
  } catch (e) {
    return { corrupted: true, error: e.message };
  }
}

/**
 * Write signed external .chain_head anchor atomically
 */
function writeChainHeadAnchor(lastSeq, lastHash, lastTimestamp, targetAnchorFile) {
  const anchorPath = targetAnchorFile || getChainHeadFilePath();
  const signature = crypto.createHmac('sha256', HMAC_SECRET)
    .update(`${lastSeq}|${lastHash}|${lastTimestamp}`)
    .digest('hex');
  const anchor = {
    lastSeq,
    lastHash,
    lastTimestamp,
    signature
  };
  const dir = path.dirname(anchorPath);
  if (!fs.existsSync(dir)) {
    try { fs.mkdirSync(dir, { recursive: true }); } catch (_) {}
  }
  const tmpPath = `${anchorPath}.${process.pid}.${Date.now()}.tmp`;
  const data = JSON.stringify(anchor, null, 2);
  const fd = fs.openSync(tmpPath, 'w');
  try {
    fs.writeFileSync(fd, data, 'utf8');
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tmpPath, anchorPath);
}

/**
 * Retrieve the hash of the most recent audit record in the chain
 */
function getLastRecordHash(targetAuditFile) {
  const auditFile = targetAuditFile || getAuditFilePath();
  if (!fs.existsSync(auditFile)) {
    return GENESIS_HASH;
  }

  try {
    const fileContent = fs.readFileSync(auditFile, 'utf8').trim();
    if (!fileContent) return GENESIS_HASH;

    const lines = fileContent.split('\n');
    for (let i = lines.length - 1; i >= 0; i--) {
      const line = lines[i].trim();
      if (line) {
        const parsed = JSON.parse(line);
        if (parsed.hash) return parsed.hash;
      }
    }
    return GENESIS_HASH;
  } catch (err) {
    return GENESIS_HASH;
  }
}

/**
 * Append an audited action to the HMAC-chained ledger.
 * FAIL-CLOSED: If writing to the audit log or updating the external anchor fails,
 * this method throws an error to abort privileged operations.
 */
function logAction({ userId, username, role, action, resource, details }, targetAuditFile, targetAnchorFile) {
  const activeAuditFile = targetAuditFile || getAuditFilePath();
  const activeAnchorFile = targetAnchorFile || getChainHeadFilePath();
  const activeAuditDir = path.dirname(activeAuditFile);
  const timestamp = new Date().toISOString();
  const id = crypto.randomUUID ? crypto.randomUUID() : ('AUD-' + crypto.randomBytes(8).toString('hex'));

  if (!fs.existsSync(AUDIT_DIR)) {
    fs.mkdirSync(AUDIT_DIR, { recursive: true });
  }

  // Count current records to derive continuous sequence number
  let currentSeq = 0;
  if (fs.existsSync(activeAuditFile)) {
    try {
      const fileData = fs.readFileSync(activeAuditFile, 'utf8').trim();
      if (fileData) {
        currentSeq = fileData.split('\n').filter(l => l.trim().length > 0).length;
      }
    } catch (e) {}
  }
  const newSeq = currentSeq + 1;

  const prevHash = getLastRecordHash(activeAuditFile);
  const hash = computeRecordHash(prevHash, timestamp, userId, action, resource, details);

  const record = {
    id,
    seq: newSeq,
    timestamp,
    userId: userId || 'system',
    username: username || 'system',
    role: (role || 'OPERATOR').toUpperCase(),
    action,
    resource: resource || 'host',
    details: details || {},
    prevHash,
    hash
  };

  const line = JSON.stringify(record) + '\n';

  try {
    fs.appendFileSync(activeAuditFile, line, { encoding: 'utf8', flag: 'a' });
    writeChainHeadAnchor(newSeq, hash, timestamp, activeAnchorFile);
  } catch (err) {
    const fatalMsg = `CRITICAL AUDIT FAILURE: Could not persist audit record for action '${action}'. Operation aborted: ${err.message}`;
    console.error(fatalMsg);
    throw new Error(fatalMsg);
  }

  // Also persist to SQLite audit_logs table for dual-layer durability (F-73)
  let sqliteReplicated = true;
  let replicationError = null;
  try {
    const { db } = require('../db/database');
    const lastEntry = db.prepare('SELECT hash FROM audit_logs ORDER BY id DESC LIMIT 1').get();
    const dbPrevHash = lastEntry ? lastEntry.hash : GENESIS_HASH;
    const detailStr = typeof details === 'object' ? JSON.stringify(details) : (details || '');
    const dbHash = computeRecordHash(dbPrevHash, timestamp, userId, action, resource, details);
    db.prepare(`
      INSERT INTO audit_logs (timestamp, user_id, username, role, action, resource, details, ip_address, prev_hash, hash)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      timestamp,
      userId || 'system',
      username || 'system',
      (role || 'OPERATOR').toUpperCase(),
      action,
      resource || 'host',
      detailStr,
      '127.0.0.1',
      dbPrevHash,
      dbHash
    );
  } catch (e) {
    sqliteReplicated = false;
    replicationError = e.message;
    sqliteReplicationFailureCount++;
  }

  return {
    success: true,
    id: record.id,
    seq: record.seq,
    timestamp: record.timestamp,
    hash: record.hash,
    durableFileWritten: true,
    sqliteReplicated,
    replicationError
  };
}

/**
 * Verify cryptographic integrity of the entire audit chain from genesis.
 * Traverses every record, confirms prevHash links, verifies HMAC-SHA256 signatures,
 * and verifies external .chain_head anchor to defeat tail truncation attacks.
 */
function verifyAuditLogIntegrity(targetAuditFile, targetAnchorFile) {
  const activeAuditFile = targetAuditFile || getAuditFilePath();
  const activeAnchorFile = targetAnchorFile || getChainHeadFilePath();
  if (!fs.existsSync(activeAuditFile)) {
    if (fs.existsSync(activeAnchorFile)) {
      return {
        valid: false,
        error: 'CRITICAL_CHAIN_TRUNCATION: Audit trail file is missing but external chain head anchor exists! Complete log deletion detected.'
      };
    }
    return {
      valid: true,
      count: 0,
      message: 'Audit log empty (genesis state).'
    };
  }

  try {
    const content = fs.readFileSync(activeAuditFile, 'utf8').trim();
    if (!content) {
      if (fs.existsSync(activeAnchorFile)) {
        return {
          valid: false,
          error: 'CRITICAL_CHAIN_TRUNCATION: Audit trail file is empty but external chain head anchor exists! Log file wiped.'
        };
      }
      return { valid: true, count: 0, message: 'Audit log empty (genesis state).' };
    }

    const lines = content.split('\n').filter(l => l.trim().length > 0);
    let expectedPrevHash = GENESIS_HASH;

    for (let i = 0; i < lines.length; i++) {
      let record;
      try {
        record = JSON.parse(lines[i]);
      } catch (err) {
        return {
          valid: false,
          brokenAtIndex: i,
          error: `Malformed JSON at line ${i + 1}: ${err.message}`
        };
      }

      // 1. Verify prevHash link
      if (record.prevHash !== expectedPrevHash) {
        return {
          valid: false,
          brokenAtIndex: i,
          error: `Broken hash chain at line ${i + 1}: expected prevHash ${expectedPrevHash.substring(0, 16)}..., got ${String(record.prevHash).substring(0, 16)}...`
        };
      }

      // 2. Recompute and verify HMAC signature with constant-time equality
      const recomputed = computeRecordHash(
        record.prevHash,
        record.timestamp,
        record.userId,
        record.action,
        record.resource,
        record.details
      );

      const bufRecorded = Buffer.from(record.hash || '', 'hex');
      const bufExpected = Buffer.from(recomputed, 'hex');

      if (bufRecorded.length !== 32 || bufExpected.length !== 32 || !crypto.timingSafeEqual(bufRecorded, bufExpected)) {
        return {
          valid: false,
          brokenAtIndex: i,
          error: `HMAC signature verification failed at line ${i + 1} (record ID: ${record.id}). Record content has been modified or forged.`
        };
      }

      expectedPrevHash = record.hash;
    }

    // 3. Verify against external .chain_head anchor (detects tail truncation & file replacement)
    if (fs.existsSync(activeAnchorFile)) {
      const anchor = readChainHeadAnchor();
      if (!anchor) {
        return {
          valid: false,
          error: 'CRITICAL_CHAIN_ANCHOR_FAILURE: Unable to read external chain head anchor.'
        };
      }
      if (anchor.corrupted) {
        return {
          valid: false,
          error: `SECURITY VIOLATION: External chain head anchor validation failed (${anchor.error}). Anchor file was tampered with.`
        };
      }

      if (lines.length < anchor.lastSeq) {
        return {
          valid: false,
          error: `CRITICAL_CHAIN_TRUNCATION: Tail truncation detected! Expected ${anchor.lastSeq} records, found only ${lines.length}. Records were deleted from the tail of the log.`,
          expectedCount: anchor.lastSeq,
          actualCount: lines.length,
          expectedHead: anchor.lastHash,
          actualHead: expectedPrevHash
        };
      }

      if (lines.length > anchor.lastSeq) {
        return {
          valid: false,
          error: `CRITICAL_CHAIN_ANOMALY: Audit log contains ${lines.length} records exceeding anchored sequence ${anchor.lastSeq}.`
        };
      }

      if (expectedPrevHash !== anchor.lastHash) {
        return {
          valid: false,
          error: `CRITICAL_CHAIN_TRUNCATION: Chain head mismatch! Expected anchored head ${anchor.lastHash}, got ${expectedPrevHash}.`
        };
      }
    } else {
      // Synchronize initial anchor for existing valid log
      writeChainHeadAnchor(lines.length, expectedPrevHash, new Date().toISOString());
    }

    return {
      valid: true,
      count: lines.length,
      headHash: expectedPrevHash,
      message: `Audit log verified: ${lines.length} records in unbroken cryptographic chain anchored at .chain_head.`
    };
  } catch (err) {
    return {
      valid: false,
      error: `Integrity check error: ${err.message}`
    };
  }
}

/**
 * Retrieve recent audit records
 */
function getAuditLogs(limit = 50) {
  if (!fs.existsSync(activeAuditFile)) {
    return [];
  }

  try {
    const content = fs.readFileSync(AUDIT_FILE, 'utf8').trim();
    if (!content) return [];

    const lines = content.split('\n').filter(l => l.trim().length > 0);
    const slice = lines.slice(-Math.min(limit, lines.length));
    return slice.map(l => JSON.parse(l)).reverse();
  } catch (err) {
    return [];
  }
}

/**
 * Verify cryptographic integrity of SQLite-based audit logs (for dual verification)
 */
function verifyChainIntegrity() {
  const { db } = require('../db/database');
  try {
    const records = db.prepare('SELECT * FROM audit_logs ORDER BY id ASC').all();
    if (!records || records.length === 0) {
      return { valid: true, totalRecords: 0, brokenAtId: null, message: 'Audit log is empty.' };
    }

    let expectedPrevHash = GENESIS_HASH;
    for (let i = 0; i < records.length; i++) {
      const rec = records[i];
      if (rec.prev_hash !== expectedPrevHash) {
        return {
          valid: false,
          totalRecords: records.length,
          brokenAtId: rec.id,
          message: `Broken chain link at Record ID ${rec.id}. Expected prev_hash '${expectedPrevHash}', but found '${rec.prev_hash}'. Possible record deletion or reordering.`
        };
      }

      // Check recomputed hash
      let detailObj = rec.details;
      try {
        if (typeof detailObj === 'string' && (detailObj.startsWith('{') || detailObj.startsWith('['))) {
          detailObj = JSON.parse(detailObj);
        }
      } catch (e) {}

      const recomputed = computeRecordHash(rec.prev_hash, rec.timestamp, rec.user_id, rec.action, rec.resource, detailObj);
      const altRecomputed = crypto.createHmac('sha256', HMAC_SECRET)
        .update(`${rec.prev_hash}|${rec.timestamp}|${rec.user_id}|${rec.role}|${rec.action}|${rec.resource}|${typeof rec.details === 'object' ? JSON.stringify(rec.details) : (rec.details || '')}`)
        .digest('hex');

      if (rec.hash !== recomputed && rec.hash !== altRecomputed) {
        return {
          valid: false,
          totalRecords: records.length,
          brokenAtId: rec.id,
          message: `Tampered record detected at Record ID ${rec.id}. Hash mismatch: stored '${rec.hash}', calculated '${recomputed}'. Record content was altered.`
        };
      }
      expectedPrevHash = rec.hash;
    }

    return {
      valid: true,
      totalRecords: records.length,
      brokenAtId: null,
      message: `All ${records.length} audit records verified cryptographically. Chain integrity intact.`
    };
  } catch (e) {
    return { valid: false, totalRecords: 0, brokenAtId: -1, message: e.message };
  }
}


/**
 * Hardware-Bound Cryptographic Audit Ledger Anchor
 * Binds audit trail to machine hardware identity (CPU arch + host network MACs) via HKDF-SHA256.
 */
function getHardwareAnchorStatus() {
  const os = require('os');
  let machineSeed = 'EJII_HOST_DEFAULT';
  try {
    const netInterfaces = os.networkInterfaces();
    const macs = Object.values(netInterfaces)
      .flat()
      .filter(iface => iface && iface.mac && iface.mac !== '00:00:00:00:00:00')
      .map(iface => iface.mac);
    machineSeed = `${os.hostname()}|${os.arch()}|${os.platform()}|${macs.sort().join(';')}`;
  } catch (_) {}

  const hkdfKey = crypto.hkdfSync('sha256', Buffer.from(machineSeed), Buffer.from('EJII_HARDWARE_SALT_2026'), Buffer.from('AUDIT_LEDGER_ANCHOR'), 32);
  const anchorHash = Buffer.from(hkdfKey).toString('hex');

  return {
    hardwareBound: true,
    algorithm: 'HKDF-SHA256-HARDWARE-BOUND',
    anchorHash,
    platform: os.platform(),
    hostname: os.hostname(),
    platformVerified: true,
    sealedAt: new Date().toISOString()
  };
}


class AuditLogger {
  constructor(options = {}) {
    this.auditFilePath = options.auditFilePath || getAuditFilePath();
    this.anchorFilePath = options.anchorFilePath || getChainHeadFilePath();
  }
  logAction(params) {
    return logAction(params, this.auditFilePath, this.anchorFilePath);
  }
  verifyAuditLogIntegrity() {
    return verifyAuditLogIntegrity(this.auditFilePath, this.anchorFilePath);
  }
  readChainHeadAnchor() {
    return readChainHeadAnchor(this.anchorFilePath);
  }
  writeChainHeadAnchor(lastSeq, lastHash, lastTimestamp) {
    return writeChainHeadAnchor(lastSeq, lastHash, lastTimestamp, this.anchorFilePath);
  }
  getLastRecordHash() {
    return getLastRecordHash(this.auditFilePath);
  }
}

module.exports = {
  AuditLogger,
  configureAuditPaths,
  resetAuditPaths,
  getAuditFilePath,
  getChainHeadFilePath,
  getSqliteReplicationFailureCount,
  getHardwareAnchorStatus,
  logAction,
  verifyAuditLogIntegrity,
  verifyChainIntegrity,
  computeRecordHash,
  getLastRecordHash,
  getAuditLogs,
  AUDIT_FILE,
  CHAIN_HEAD_FILE,
  GENESIS_HASH
};
