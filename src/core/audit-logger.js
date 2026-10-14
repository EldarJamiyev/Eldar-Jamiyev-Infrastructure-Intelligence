/**
 * EJII Cryptographic Tamper-Evident Audit Trail
 * Sequential HMAC-SHA256 chained audit logs.
 */

const crypto = require('crypto');
const { db } = require('../db/database');
const { HMAC_SECRET } = require('../config');

const GENESIS_HASH = 'EJII_GENESIS_ROOT_HASH_00000000000000000000000000000000000000000000000000000000';

/**
 * Compute HMAC-SHA256 hash for an audit record
 */
function computeRecordHash(prevHash, timestamp, userId, role, action, resource, details) {
  const normUserId = userId || 'system';
  const normRole = (role || 'system').toLowerCase();
  const content = `${prevHash}|${timestamp}|${normUserId}|${normRole}|${action}|${resource}|${details || ''}`;
  return crypto.createHmac('sha256', HMAC_SECRET).update(content).digest('hex');
}

/**
 * Log an action to the audit trail
 */
function logAction({ userId, username, role, action, resource, details = '', ipAddress = '127.0.0.1' }) {
  const timestamp = new Date().toISOString();
  const normUserId = userId || 'system';
  const normRole = (role || 'system').toLowerCase();

  // Retrieve the latest audit log entry to get the previous hash
  const lastEntry = db.prepare('SELECT hash FROM audit_logs ORDER BY id DESC LIMIT 1').get();
  const prevHash = lastEntry ? lastEntry.hash : GENESIS_HASH;

  const hash = computeRecordHash(prevHash, timestamp, normUserId, normRole, action, resource, details);

  const stmt = db.prepare(`
    INSERT INTO audit_logs (timestamp, user_id, username, role, action, resource, details, ip_address, prev_hash, hash)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  stmt.run(timestamp, normUserId, username || 'System', normRole, action, resource, details, ipAddress, prevHash, hash);

  return { timestamp, prevHash, hash };
}

/**
 * Verify the cryptographic integrity of the entire audit chain
 * Returns { valid: boolean, totalRecords: number, brokenAtId: number | null, reason: string | null }
 */
function verifyChainIntegrity() {
  const records = db.prepare('SELECT * FROM audit_logs ORDER BY id ASC').all();
  if (records.length === 0) {
    return { valid: true, totalRecords: 0, brokenAtId: null, message: 'Audit log is empty.' };
  }

  let expectedPrevHash = GENESIS_HASH;

  for (let i = 0; i < records.length; i++) {
    const rec = records[i];

    // Check link to previous hash
    if (rec.prev_hash !== expectedPrevHash) {
      return {
        valid: false,
        totalRecords: records.length,
        brokenAtId: rec.id,
        message: `Broken chain link at Record ID ${rec.id}. Expected prev_hash '${expectedPrevHash}', but found '${rec.prev_hash}'. Possible record deletion or reordering.`
      };
    }

    // Check recomputed hash
    const recomputed = computeRecordHash(
      rec.prev_hash,
      rec.timestamp,
      rec.user_id,
      rec.role,
      rec.action,
      rec.resource,
      rec.details
    );

    if (recomputed !== rec.hash) {
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
}

/**
 * Query audit logs with pagination and optional filters
 */
function getAuditLogs(limit = 100, offset = 0, filterAction = null) {
  let query = 'SELECT * FROM audit_logs';
  const params = [];

  if (filterAction) {
    query += ' WHERE action = ?';
    params.push(filterAction);
  }

  query += ' ORDER BY id DESC LIMIT ? OFFSET ?';
  params.push(limit, offset);

  return db.prepare(query).all(...params);
}

module.exports = {
  logAction,
  verifyChainIntegrity,
  getAuditLogs,
  computeRecordHash,
  GENESIS_HASH
};
