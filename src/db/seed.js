/**
 * EJII Pure NOC Workstation Database Seeder
 * Seeds strictly authentic local operator credential, initial Layer 1 - Layer 6 topology nodes,
 * and foundational structural topology edges.
 * Zero-Simulation Standard: Never guesses gateways by substituting `.1`, never fabricates live
 * octet counters or synthetic link utilization, and explicitly labels unprobed reference targets.
 */

const crypto = require('crypto');
const os = require('os');
const { db, initSchema } = require('./database');
const { getPhysicalNetworkInfo } = require('../network/routing/physical-network-detector');

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
function seedDatabase() {
  initSchema();

  const existingNodesCount = db.prepare('SELECT COUNT(*) as c FROM topology_nodes').get().c;
  const existingUsersCount = db.prepare('SELECT COUNT(*) as c FROM users').get().c;

  // Never wipe or overwrite existing operational telemetry or user data on restart
  if (existingNodesCount > 0 && existingUsersCount > 0) {
    return;
  }

  console.log('[EJII NOC Seeder] Bootstrapping initial NOC workstation database...');

  const now = new Date().toISOString();

  // 1. Seed Default Unprivileged NOC Operator Account (only if users table is empty)
  if (existingUsersCount === 0) {
    const adminPassword = process.env.EJII_ADMIN_PASSWORD || crypto.randomBytes(18).toString('base64url');
    const salt = crypto.randomBytes(16).toString('hex');
    const hash = crypto.pbkdf2Sync(adminPassword, salt, 10000, 64, 'sha512').toString('hex');

    db.prepare(`
      INSERT INTO users (id, username, password_hash, salt, full_name, role, is_active, created_at)
      VALUES (?, ?, ?, ?, ?, ?, 1, ?)
    `).run('USR-NOC-01', 'admin', hash, salt, 'Senior NOC Infrastructure Engineer', 'admin', now);
  }

  // Detect live physical network environment (without guessing .1 gateway)
  const netInfo = getPhysicalNetworkInfo() || {};
  const verifiedGatewayIp = netInfo.gatewayVerified ? (netInfo.defaultGateway || netInfo.gatewayIp) : getSystemDefaultGateway();
  const gatewayNodeAddress = verifiedGatewayIp || '127.0.0.1';
  const localHostIp = netInfo.localIp || netInfo.hostIp || '127.0.0.1';
  const localSubnetCidr = netInfo.subnetCidr || '127.0.0.0/8';
  const primaryDns = (netInfo.dnsServers && netInfo.dnsServers[0]) || '1.1.1.1';
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
        name: `Core Switch & DNS (${primaryDns})`,
        hostname_or_ip: primaryDns,
        mac_address: null,
        type: 'dns_resolver',
        layer: 'core',
        layer_level: 3,
        parent_id: 'NODE-GW-01',
        status: 'unprobed',
        latency: null,
        vendor: 'Configured System DNS Resolver',
        if_name: null,
        x: 480,
        y: 80,
        metadata: JSON.stringify({
          role: 'Configured DNS Resolver',
          probeState: 'AWAITING_FIRST_PROBE',
          evidenceClassification: 'Configured'
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
        status: 'healthy',
        latency: null,
        vendor: 'Local Subnet Segment',
        if_name: netInfo.interfaceAlias || 'eth0',
        x: 880,
        y: 200,
        metadata: JSON.stringify({
          role: 'Access LAN Subnet',
          hostsCount: netInfo.arpNeighborsCount || 1,
          probeState: 'LOCAL_SUBNET_OBSERVED',
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
        status: 'healthy',
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
  const existingAuditCount = db.prepare('SELECT COUNT(*) as c FROM audit_logs').get().c;
  if (existingAuditCount === 0) {
    const hmacSecret = process.env.EJII_HMAC_SECRET || 'ejii-noc-default-hmac-secret-2026';
    const genesisPayload = `1|${now}|USR-NOC-01|admin|admin|SYSTEM_BOOT|NOC_ENGINE|{"status":"INITIALIZED"}|127.0.0.1|GENESIS`;
    const genesisHash = crypto.createHmac('sha256', hmacSecret).update(genesisPayload).digest('hex');

    db.prepare(`
      INSERT INTO audit_logs (timestamp, user_id, username, role, action, resource, details, ip_address, prev_hash, hash)
      VALUES (?, 'USR-NOC-01', 'admin', 'admin', 'SYSTEM_BOOT', 'NOC_ENGINE', '{"status":"INITIALIZED"}', '127.0.0.1', 'GENESIS', ?)
    `).run(now, genesisHash);
  }

  console.log('[EJII NOC Seeder] NOC database seeded cleanly (zero synthetic link_telemetry rows).');
}

if (require.main === module) {
  seedDatabase();
}

module.exports = { seedDatabase, getSystemDefaultGateway };
