/**
 * EJII Pure NOC Workstation Database Seeder
 * Seeds strictly authentic local operator credential, initial Layer 1 - Layer 6 topology nodes,
 * and foundational structural topology edges.
 * Zero-Simulation Standard: Never guesses gateways by substituting `.1`, never fabricates live
 * octet counters or synthetic link utilization, and explicitly labels unprobed reference targets.
 */

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const config = require('../config');
const { resolveCanonicalPath, isPathInsideDir } = config;
const { db: defaultDb, initSchema } = require('./database');
const { hashPassword } = require('../core/security');
const { getPhysicalNetworkInfo } = require('../network/routing/physical-network-detector');
const { GENESIS_HASH, computeRecordHash } = require('../core/audit-logger');

const FIRST_RUN_CREDENTIALS_FILENAME = 'FIRST_RUN_ADMIN_CREDENTIALS.txt';

const SEEDED_OPERATOR_PROFILES = Object.freeze([
  { id: 'USR-NOC-01', username: 'admin', fullName: 'Senior NOC Infrastructure Engineer', role: 'admin' },
  { id: 'USR-SYS-01', username: 'sysadmin', fullName: 'Systems Infrastructure Administrator', role: 'sysadmin' },
  { id: 'USR-NET-01', username: 'netadmin', fullName: 'Network Operations Administrator', role: 'network_admin' },
  { id: 'USR-OP-01', username: 'noc', fullName: 'NOC Watch Floor Operator', role: 'operator' }
]);

function resolveSeedDataDir(targetDb = defaultDb, options = {}) {
  if (options && options.dataDir) {
    return path.resolve(String(options.dataDir));
  }
  if (targetDb && targetDb !== defaultDb && typeof targetDb.prepare === 'function') {
    try {
      const dbList = targetDb.prepare('PRAGMA database_list').all();
      const mainEntry = Array.isArray(dbList) ? dbList.find((r) => r.name === 'main' && r.file) : null;
      if (mainEntry && mainEntry.file && mainEntry.file !== ':memory:') {
        return path.dirname(path.resolve(mainEntry.file));
      }
    } catch (_) {}
  }
  if (process.env.EJII_DATA_DIR && String(process.env.EJII_DATA_DIR).trim()) {
    return path.resolve(String(process.env.EJII_DATA_DIR).trim());
  }
  if ((process.env.EJII_DB_PATH || process.env.DB_PATH || '').trim()) {
    return path.dirname(path.resolve((process.env.EJII_DB_PATH || process.env.DB_PATH).trim()));
  }
  return config.DATA_DIR;
}

function getFirstRunCredentialsPath(dataDir = config.DATA_DIR) {
  const canonicalDataDir = resolveCanonicalPath(dataDir);
  const rawSecDir = path.join(canonicalDataDir, 'security');
  const canonicalSecDir = resolveCanonicalPath(rawSecDir);
  if (!isPathInsideDir(canonicalSecDir, canonicalDataDir)) {
    throw new Error('SECURITY_VIOLATION: security directory resolves outside canonical DATA_DIR.');
  }
  const credPath = path.join(canonicalSecDir, FIRST_RUN_CREDENTIALS_FILENAME);
  if (!isPathInsideDir(credPath, canonicalSecDir)) {
    throw new Error('SECURITY_VIOLATION: FIRST_RUN_ADMIN_CREDENTIALS.txt resolves outside security directory.');
  }
  return {
    canonicalDataDir,
    secDir: canonicalSecDir,
    credFile: credPath
  };
}

function assertNotSymlink(targetPath) {
  try {
    const stat = fs.lstatSync(targetPath);
    if (stat.isSymbolicLink()) {
      throw new Error(`SECURITY_VIOLATION: Symlink prohibited at security path ${targetPath}`);
    }
    return stat;
  } catch (err) {
    if (err && err.code === 'ENOENT') return null;
    throw err;
  }
}

function atomicWriteFirstRunCredentialsFile(dataDir, accounts, recoveryMode = false) {
  const { canonicalDataDir, secDir, credFile } = getFirstRunCredentialsPath(dataDir);

  if (!fs.existsSync(canonicalDataDir)) {
    fs.mkdirSync(canonicalDataDir, { recursive: true, mode: 0o700 });
  }
  assertNotSymlink(canonicalDataDir);

  const existingSecStat = assertNotSymlink(secDir);
  if (!existingSecStat) {
    fs.mkdirSync(secDir, { recursive: true, mode: 0o700 });
  }
  try { fs.chmodSync(secDir, 0o700); } catch (_) {}

  const realSecDir = resolveCanonicalPath(secDir);
  if (!isPathInsideDir(realSecDir, canonicalDataDir)) {
    throw new Error('SECURITY_VIOLATION: Symlink containment breach on data/security directory.');
  }

  const finalCredFile = path.join(realSecDir, FIRST_RUN_CREDENTIALS_FILENAME);
  assertNotSymlink(finalCredFile);

  const nowIso = new Date().toISOString();
  const lines = [
    '========================================================================',
    'EJII — FIRST-RUN BOOTSTRAP OPERATOR CREDENTIALS (CONFIDENTIAL)',
    `Generated At: ${nowIso}`,
    `Provision Mode: ${recoveryMode ? 'UNCLAIMED_LOCKOUT_RECOVERY' : 'INITIAL_BOOTSTRAP'}`,
    'File Mode: 0600 (Owner Read/Write Only)',
    '========================================================================',
    'IMPORTANT: Rotate these credentials immediately via POST /api/auth/change-password',
    'or delete this file once credentials are stored securely.',
    ''
  ];

  for (const entry of accounts) {
    lines.push(`[${entry.username}]`);
    lines.push(`username=${entry.username}`);
    lines.push(`password=${entry.password}`);
    lines.push(`role=${entry.role}`);
    lines.push('');
  }

  const payload = lines.join('\n');
  const tmpFile = path.join(realSecDir, `.${FIRST_RUN_CREDENTIALS_FILENAME}.tmp-${process.pid}-${crypto.randomBytes(4).toString('hex')}`);
  try {
    fs.writeFileSync(tmpFile, payload, { encoding: 'utf8', mode: 0o600, flag: 'wx' });
    try { fs.chmodSync(tmpFile, 0o600); } catch (_) {}
    fs.renameSync(tmpFile, finalCredFile);
    try { fs.chmodSync(finalCredFile, 0o600); } catch (_) {}
  } catch (err) {
    try { fs.unlinkSync(tmpFile); } catch (_) {}
    throw err;
  }

  return finalCredFile;
}

function clearFirstRunCredentialsFile(dataDir = config.DATA_DIR) {
  try {
    const { secDir, credFile } = getFirstRunCredentialsPath(dataDir);
    if (!fs.existsSync(credFile)) return false;
    assertNotSymlink(secDir);
    assertNotSymlink(credFile);
    fs.unlinkSync(credFile);
    return true;
  } catch (_) {
    return false;
  }
}

function isUserClaimed(userRow) {
  if (!userRow) return false;
  return Boolean(
    userRow.password_rotated_at ||
    userRow.bootstrap_state === 'CLAIMED' ||
    userRow.last_login
  );
}

/**
 * Return verified OS route table default gateway if present, or null when no default route is observed.
 * Never guesses a gateway by replacing the last IPv4 octet with `.1`.
 */
function getSystemDefaultGateway() {
  try {
    const netInfo = getPhysicalNetworkInfo();
    if (netInfo && netInfo.gatewayVerified && netInfo.defaultGateway) {
      return netInfo.defaultGateway;
    }
  } catch (_) {}
  return null;
}

/**
 * Seed initial NOC database records (Non-Destructive & Idempotent)
 */
function seedDatabase(targetDb = defaultDb, options = {}) {
  const db = targetDb || defaultDb;
  initSchema(db);

  const dataDir = resolveSeedDataDir(db, options);
  const { credFile } = getFirstRunCredentialsPath(dataDir);
  const credFileExists = fs.existsSync(credFile);
  const explicitAdminPassword =
    typeof process.env.EJII_ADMIN_PASSWORD === 'string' && process.env.EJII_ADMIN_PASSWORD.length > 0
      ? process.env.EJII_ADMIN_PASSWORD
      : null;

  const existingNodesCount = db.prepare('SELECT COUNT(*) as c FROM topology_nodes').get().c;
  const existingUsers = db
    .prepare('SELECT id, username, role, password_hash, salt, last_login, bootstrap_state, password_rotated_at, token_version FROM users')
    .all();
  const existingUserMap = new Map(existingUsers.map((u) => [String(u.username || '').toLowerCase(), u]));

  const adminRow = existingUserMap.get('admin') || null;
  const adminClaimed = isUserClaimed(adminRow);
  const hasMissingProfile = SEEDED_OPERATOR_PROFILES.some((p) => !existingUserMap.has(p.username));
  const needsAdminLockoutRecovery = Boolean(
    adminRow &&
    !adminClaimed &&
    !credFileExists &&
    (explicitAdminPassword !== null || adminRow.bootstrap_state !== 'ENV_CONFIGURED')
  );
  const needsExplicitAdminSync = Boolean(
    adminRow &&
    !adminClaimed &&
    explicitAdminPassword !== null
  );
  const needsUserProvisioning =
    !adminRow ||
    hasMissingProfile ||
    needsAdminLockoutRecovery ||
    needsExplicitAdminSync;

  const existingAuditCount = db.prepare('SELECT COUNT(*) as c FROM audit_logs').get().c;

  // Never wipe or overwrite existing operational telemetry or claimed user data on restart
  if (existingNodesCount > 0 && !needsUserProvisioning && existingAuditCount > 0) {
    return;
  }

  const now = new Date().toISOString();

  // 1. Seed / Recover Operator Accounts (preserving all claimed/rotated user credentials)
  if (needsUserProvisioning) {
    const provisionedAccountsForFile = [];
    const insertUserStmt = db.prepare(`
      INSERT INTO users (id, username, password_hash, salt, full_name, role, is_active, bootstrap_state, token_version, created_at)
      VALUES (?, ?, ?, ?, ?, ?, 1, ?, 1, ?)
    `);
    const updateUnclaimedStmt = db.prepare(`
      UPDATE users
      SET password_hash = ?,
          salt = ?,
          full_name = ?,
          role = ?,
          is_active = 1,
          bootstrap_state = ?,
          token_version = COALESCE(token_version, 1) + 1
      WHERE id = ?
    `);

    for (const profile of SEEDED_OPERATOR_PROFILES) {
      const existingRow = existingUserMap.get(profile.username);
      if (existingRow && isUserClaimed(existingRow)) {
        // Strictly preserve existing claimed/rotated password hash & salt
        continue;
      }

      const shouldRecoverOrSet =
        !existingRow ||
        (profile.username === 'admin' && (needsAdminLockoutRecovery || needsExplicitAdminSync)) ||
        (profile.username !== 'admin' && needsAdminLockoutRecovery);

      if (!shouldRecoverOrSet) {
        continue;
      }

      let rawPassword;
      let nextBootstrapState = 'UNCLAIMED';
      if (profile.username === 'admin' && explicitAdminPassword) {
        rawPassword = explicitAdminPassword;
        nextBootstrapState = 'ENV_CONFIGURED';
      } else {
        rawPassword = crypto.randomBytes(18).toString('base64url');
      }

      const { hash, salt } = hashPassword(rawPassword, null, 32);

      if (!existingRow) {
        insertUserStmt.run(
          profile.id,
          profile.username,
          hash,
          salt,
          profile.fullName,
          profile.role,
          nextBootstrapState,
          now
        );
      } else {
        updateUnclaimedStmt.run(
          hash,
          salt,
          profile.fullName,
          profile.role,
          nextBootstrapState,
          existingRow.id
        );
      }

      if (!(profile.username === 'admin' && explicitAdminPassword)) {
        provisionedAccountsForFile.push({
          username: profile.username,
          password: rawPassword,
          role: profile.role
        });
      }
    }

    if (provisionedAccountsForFile.length > 0) {
      const writtenPath = atomicWriteFirstRunCredentialsFile(
        dataDir,
        provisionedAccountsForFile,
        needsAdminLockoutRecovery
      );
      if (needsAdminLockoutRecovery) {
        console.warn(`[EJII Security Recovery] Unclaimed admin credentials were rotated for recovery. New bootstrap credentials written (0600) to: ${writtenPath}`);
      } else {
        console.log(`[EJII Security Provisioning] First-run operator bootstrap credentials written (0600) to: ${writtenPath}`);
      }
    }
  }

  if (existingNodesCount === 0) {
    console.log('[EJII NOC Seeder] Bootstrapping initial NOC workstation database...');
  }

  // Detect live physical network environment (without guessing .1 gateway)
  const netInfo = getPhysicalNetworkInfo() || {};
  const verifiedGatewayIp = netInfo.gatewayVerified ? (netInfo.defaultGateway || netInfo.gatewayIp) : getSystemDefaultGateway();
  const gatewayNodeAddress = verifiedGatewayIp || 'NO_DEFAULT_ROUTE_OBSERVED';
  const localHostIp = netInfo.localIp || netInfo.hostIp || 'UNOBSERVED_HOST_IP';
  const localSubnetCidr = netInfo.subnetCidr || 'UNOBSERVED_SUBNET';
  const primaryDns = (netInfo.dnsServers && netInfo.dnsServers[0]) || null;
  const hostMac = netInfo.macAddress || null;
  const gwMac = (netInfo.gatewayMac && netInfo.gatewayMac !== 'Unknown') ? netInfo.gatewayMac : null;
  const gwVendor = verifiedGatewayIp ? (netInfo.gatewayVendor || 'Observed Default Gateway') : 'Unverified Default Route (Container / Sandbox)';
  const adapterDesc = netInfo.hardwareDescription || netInfo.adapterName || 'Local Host Network Interface';

  // 2. Seed Hierarchical Layer 1 - Layer 6 Topology Nodes (only if topology_nodes is empty)
  if (existingNodesCount === 0) {
    const topoNodes = [
      {
        id: 'NODE-WAN-01',
        name: 'Upstream Internet Transit (8.8.8.8)',
        hostname_or_ip: '8.8.8.8',
        mac_address: null,
        type: 'wan',
        layer: 'wan',
        layer_level: 1,
        parent_id: null,
        status: 'unprobed',
        latency: null,
        vendor: 'Google Anycast Transit',
        if_name: 'WAN0',
        x: 80,
        y: 140,
        metadata: JSON.stringify({
          role: 'WAN Transit',
          provider: 'Upstream ISP',
          probeState: 'AWAITING_FIRST_PROBE',
          evidenceClassification: 'Configured_Reference_Target'
        })
      },
      {
        id: 'NODE-GW-01',
        name: verifiedGatewayIp
          ? `Edge Perimeter Router (${verifiedGatewayIp})`
          : 'Default Gateway Route (NO_DEFAULT_ROUTE_OBSERVED)',
        hostname_or_ip: gatewayNodeAddress,
        mac_address: gwMac,
        type: 'router',
        layer: 'edge',
        layer_level: 2,
        parent_id: 'NODE-WAN-01',
        status: 'unprobed',
        latency: null,
        vendor: gwVendor,
        if_name: netInfo.interfaceAlias || 'eth0',
        x: 280,
        y: 140,
        metadata: JSON.stringify({
          role: 'Border Router',
          nat: Boolean(verifiedGatewayIp),
          gatewayVerified: Boolean(verifiedGatewayIp),
          gatewayDiscoveryStatus: verifiedGatewayIp ? 'VERIFIED_OS_ROUTE_TABLE' : 'NO_DEFAULT_ROUTE_OBSERVED',
          firewall: 'Stateful Inspection',
          probeState: 'AWAITING_FIRST_PROBE',
          evidenceClassification: verifiedGatewayIp ? 'Observed' : 'Unknown'
        })
      },
      {
        id: 'NODE-CORE-01',
        name: primaryDns
          ? `Core Switch & DNS (${primaryDns})`
          : 'Core Switch & DNS (UNCONFIGURED_DNS_RESOLVER)',
        hostname_or_ip: primaryDns || 'UNCONFIGURED_DNS_RESOLVER',
        mac_address: null,
        type: 'dns_resolver',
        layer: 'core',
        layer_level: 3,
        parent_id: 'NODE-GW-01',
        status: 'unprobed',
        latency: null,
        vendor: primaryDns ? 'Configured System DNS Resolver' : 'Unconfigured System DNS Resolver',
        if_name: null,
        x: 480,
        y: 80,
        metadata: JSON.stringify({
          role: 'Configured DNS Resolver',
          probeState: 'AWAITING_FIRST_PROBE',
          evidenceClassification: primaryDns ? 'Configured' : 'Unknown'
        })
      },
      {
        id: 'NODE-APP-01',
        name: 'Reference Cloud Service Endpoint (1.1.1.1)',
        hostname_or_ip: '1.1.1.1',
        mac_address: null,
        type: 'service',
        layer: 'service',
        layer_level: 4,
        parent_id: 'NODE-CORE-01',
        status: 'unprobed',
        latency: null,
        vendor: 'Cloudflare Anycast Reference',
        if_name: 'eth0',
        x: 680,
        y: 80,
        metadata: JSON.stringify({
          role: 'Reference Service Target',
          port: 443,
          probeState: 'AWAITING_FIRST_PROBE',
          evidenceClassification: 'Configured_Reference_Target'
        })
      },
      {
        id: 'NODE-LAN-01',
        name: `Distribution & Access LAN (${localSubnetCidr})`,
        hostname_or_ip: localSubnetCidr,
        mac_address: null,
        type: 'subnet',
        layer: 'access',
        layer_level: 5,
        parent_id: 'NODE-GW-01',
        status: 'unprobed',
        latency: null,
        vendor: 'Local Subnet Segment',
        if_name: netInfo.interfaceAlias || 'eth0',
        x: 880,
        y: 200,
        metadata: JSON.stringify({
          role: 'Access LAN Subnet',
          hostsCount: netInfo.arpNeighborsCount || 1,
          probeState: 'AWAITING_FIRST_PROBE',
          evidenceClassification: 'Observed'
        })
      },
      {
        id: 'NODE-HOST-01',
        name: `Local Workstation Host (${localHostIp})`,
        hostname_or_ip: localHostIp,
        mac_address: hostMac,
        type: 'host',
        layer: 'endpoint',
        layer_level: 6,
        parent_id: 'NODE-LAN-01',
        status: 'unprobed',
        latency: null,
        vendor: `${adapterDesc} / ${os.platform()}`,
        if_name: netInfo.interfaceAlias || 'eth0',
        x: 1080,
        y: 140,
        metadata: JSON.stringify({
          role: 'NOC Analyst Workstation',
          os: os.platform(),
          probeState: 'LOCAL_OS_OBSERVED',
          evidenceClassification: 'Observed'
        })
      }
    ];

    const insertTopoNode = db.prepare(`
      INSERT INTO topology_nodes (
        id, name, hostname_or_ip, mac_address, type, layer, layer_level, parent_id,
        status, last_checked, last_latency_ms, vendor, if_name, x, y, metadata
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const insertTopoEdge = db.prepare(`
      INSERT INTO topology_edges (
        id, source_id, target_id, link_type, status, bandwidth_mbps, utilization_pct, latency_ms, packet_rate, metadata
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    // 3. Structural Topology Edges (null utilization/latency/packet_rate until measured; zero fake link_telemetry rows)
    const topoEdges = [
      {
        id: 'EDGE-WAN-GW',
        source_id: 'NODE-WAN-01',
        target_id: 'NODE-GW-01',
        link_type: 'wan_uplink',
        status: 'unprobed',
        bandwidth_mbps: null,
        utilization_pct: null,
        latency_ms: null,
        packet_rate: null,
        metadata: JSON.stringify({
          interface: 'WAN0 -> eth0',
          evidenceClassification: 'Architectural_Template',
          telemetryState: 'UNMEASURED_NO_SNMP_COUNTER'
        })
      },
      {
        id: 'EDGE-GW-CORE',
        source_id: 'NODE-GW-01',
        target_id: 'NODE-CORE-01',
        link_type: 'logical_resolver_path',
        status: 'unprobed',
        bandwidth_mbps: null,
        utilization_pct: null,
        latency_ms: null,
        packet_rate: null,
        metadata: JSON.stringify({
          interface: 'Gateway -> DNS Resolver',
          evidenceClassification: 'Architectural_Template',
          telemetryState: 'UNMEASURED_NO_SNMP_COUNTER'
        })
      },
      {
        id: 'EDGE-CORE-APP',
        source_id: 'NODE-CORE-01',
        target_id: 'NODE-APP-01',
        link_type: 'service_path',
        status: 'unprobed',
        bandwidth_mbps: null,
        utilization_pct: null,
        latency_ms: null,
        packet_rate: null,
        metadata: JSON.stringify({
          interface: 'DNS -> Reference Endpoint',
          evidenceClassification: 'Architectural_Template',
          telemetryState: 'UNMEASURED_NO_SNMP_COUNTER'
        })
      },
      {
        id: 'EDGE-GW-LAN',
        source_id: 'NODE-GW-01',
        target_id: 'NODE-LAN-01',
        link_type: 'ethernet',
        status: verifiedGatewayIp ? 'up' : 'unprobed',
        bandwidth_mbps: null,
        utilization_pct: null,
        latency_ms: null,
        packet_rate: null,
        metadata: JSON.stringify({
          interface: 'Gateway -> Local Subnet',
          evidenceClassification: verifiedGatewayIp ? 'Observed' : 'Architectural_Template',
          telemetryState: 'UNMEASURED_NO_SNMP_COUNTER'
        })
      },
      {
        id: 'EDGE-LAN-HOST',
        source_id: 'NODE-LAN-01',
        target_id: 'NODE-HOST-01',
        link_type: 'local_vnic',
        status: 'up',
        bandwidth_mbps: null,
        utilization_pct: null,
        latency_ms: null,
        packet_rate: null,
        metadata: JSON.stringify({
          interface: netInfo.interfaceAlias || 'eth0',
          evidenceClassification: 'Observed',
          telemetryState: 'LOCAL_INTERFACE_BINDING'
        })
      }
    ];

    db.exec('BEGIN IMMEDIATE');
    try {
      for (const n of topoNodes) {
        insertTopoNode.run(
          n.id, n.name, n.hostname_or_ip, n.mac_address, n.type, n.layer, n.layer_level, n.parent_id,
          n.status, n.status === 'healthy' ? now : null, n.latency, n.vendor, n.if_name, n.x, n.y, n.metadata
        );
      }
      for (const e of topoEdges) {
        insertTopoEdge.run(
          e.id, e.source_id, e.target_id, e.link_type, e.status,
          e.bandwidth_mbps, e.utilization_pct, e.latency_ms, e.packet_rate, e.metadata
        );
      }
      db.exec('COMMIT');
    } catch (txErr) {
      try { db.exec('ROLLBACK'); } catch (_) {}
      throw txErr;
    }
  }

  // 5. Seed Initial Cryptographic HMAC Audit Log Record (only if audit_logs is empty)
  if (existingAuditCount === 0) {
    const genesisDetails = { status: 'INITIALIZED' };
    const genesisHash = computeRecordHash(
      GENESIS_HASH,
      now,
      'USR-NOC-01',
      'SYSTEM_BOOT',
      'NOC_ENGINE',
      genesisDetails
    );

    db.prepare(`
      INSERT INTO audit_logs (timestamp, user_id, username, role, action, resource, details, ip_address, prev_hash, hash)
      VALUES (?, 'USR-NOC-01', 'admin', 'admin', 'SYSTEM_BOOT', 'NOC_ENGINE', ?, 'local_process', ?, ?)
    `).run(now, JSON.stringify(genesisDetails), GENESIS_HASH, genesisHash);
  }

  console.log('[EJII NOC Seeder] NOC database seeded cleanly (zero synthetic link_telemetry rows).');
}

if (require.main === module) {
  seedDatabase();
}

module.exports = {
  seedDatabase,
  getSystemDefaultGateway,
  FIRST_RUN_CREDENTIALS_FILENAME,
  SEEDED_OPERATOR_PROFILES,
  resolveSeedDataDir,
  getFirstRunCredentialsPath,
  clearFirstRunCredentialsFile,
  isUserClaimed
};
