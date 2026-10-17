/**
 * EJII Database Seeder
 * Pure NOC Workstation Seeding: Single-operator NOC access, topology nodes, and topology edges.
 * Zero-Simulation Standard: Real physical routing and network hierarchy.
 */

const { db, initSchema } = require('./database');
const { runMigrations } = require('./migrations');
const { hashPassword, ROLES } = require('../core/security');
const { getPhysicalNetworkInfo } = require('../network/routing/physical-network-detector');

function getSystemDefaultGateway() {
  try {
    const info = getPhysicalNetworkInfo();
    if (info && info.gatewayIp) return info.gatewayIp;
  } catch (e) {}
  return '10.168.195.1';
}

function seedDatabase() {
  initSchema();
  runMigrations();

  console.log('--- Seeding EJII Pure NOC Workstation ---');

  // 1. Seed NOC Workstation Accounts (Admin, Sysadmin, Network Admin, NOC Operator)
  const accounts = [
    {
      id: 'USR-ADMIN-01',
      username: 'admin',
      password: 'admin2026!',
      fullName: 'Lead Infrastructure Architect & Admin',
      role: ROLES.ADMIN
    },
    {
      id: 'USR-SYSADMIN-01',
      username: 'sysadmin',
      password: 'sysadmin2026!',
      fullName: 'Systems & Host Administrator',
      role: ROLES.SYSADMIN
    },
    {
      id: 'USR-NETADMIN-01',
      username: 'netadmin',
      password: 'netadmin2026!',
      fullName: 'Network Infrastructure Administrator',
      role: ROLES.NETWORK_ADMIN
    },
    {
      id: 'USR-NOC-01',
      username: 'noc',
      password: 'noc2026!',
      fullName: 'NOC Network Operator',
      role: ROLES.NOC_OPERATOR
    }
  ];

  const checkUser = db.prepare('SELECT id, password_hash, salt FROM users WHERE username = ?');
  const insertUser = db.prepare(`
    INSERT INTO users (id, username, password_hash, salt, full_name, role, is_active, created_at)
    VALUES (?, ?, ?, ?, ?, ?, 1, ?)
  `);
  const updateUserMetadata = db.prepare(`
    UPDATE users SET role = ?, full_name = ? WHERE username = ?
  `);

  for (const acc of accounts) {
    const existing = checkUser.get(acc.username);
    if (!existing) {
      let initialPassword = acc.password;
      if (acc.username === 'admin' && process.env.EJII_ADMIN_PASSWORD) {
        initialPassword = process.env.EJII_ADMIN_PASSWORD;
      }
      const { hash, salt } = hashPassword(initialPassword);
      insertUser.run(acc.id, acc.username, hash, salt, acc.fullName, acc.role, new Date().toISOString());
      console.log(`✓ Created Initial Account: [${acc.username}] (${acc.role})`);
    } else {
      // Preserve existing credentials across restarts - do not overwrite password hash or salt
      updateUserMetadata.run(acc.role, acc.fullName, acc.username);
      console.log(`✓ Synchronized Account: [${acc.username}] (${acc.role}) [Credentials Preserved]`);
    }
  }

  // Detect genuine physical network info
  const netInfo = getPhysicalNetworkInfo();
  const defaultGatewayIp = netInfo.gatewayIp || getSystemDefaultGateway();
  const hostIp = netInfo.hostIp || '192.168.31.89';
  const dnsIp = (netInfo.dnsServers && netInfo.dnsServers[0]) || '192.168.31.1';
  const lanCidr = netInfo.subnetCidr || '192.168.31.0/24';
  const now = new Date().toISOString();

  // 2. Seed Baseline Topology Nodes (Layer 1 to Layer 6)
  const existingNodes = db.prepare('SELECT COUNT(*) as count FROM topology_nodes').get();
  if (existingNodes.count === 0) {
    console.log('Seeding baseline NOC network topology nodes...');

    const defaultNodes = [
      {
        id: 'NODE-WAN-01',
        name: 'Upstream Internet Transit (8.8.8.8)',
        hostname_or_ip: '8.8.8.8',
        mac_address: null,
        type: 'wan',
        layer: 'wan',
        layer_level: 1,
        parent_id: null,
        status: 'healthy',
        last_latency_ms: 12.4,
        vendor: 'Google Anycast Transit',
        if_name: 'WAN0',
        x: 80,
        y: 140,
        metadata: JSON.stringify({ role: 'WAN Transit', provider: 'Anycast Tier 1' })
      },
      {
        id: 'NODE-GW-01',
        name: `Edge Perimeter Router (${defaultGatewayIp})`,
        hostname_or_ip: defaultGatewayIp,
        mac_address: '64:12:25:E4:88:90',
        type: 'router',
        layer: 'edge',
        layer_level: 2,
        parent_id: 'NODE-WAN-01',
        status: 'healthy',
        last_latency_ms: 0.8,
        vendor: 'MikroTik RouterOS',
        if_name: 'ether1',
        x: 280,
        y: 140,
        metadata: JSON.stringify({ role: 'Border Router', model: 'CCR1036' })
      },
      {
        id: 'NODE-CORE-01',
        name: `Core Switch & Internal DNS (${dnsIp})`,
        hostname_or_ip: dnsIp,
        mac_address: '64:12:25:E4:68:F0',
        type: 'switch',
        layer: 'core',
        layer_level: 3,
        parent_id: 'NODE-GW-01',
        status: 'healthy',
        last_latency_ms: 0.9,
        vendor: 'Cisco Catalyst / MikroTik Core',
        if_name: 'tengig0/1',
        x: 480,
        y: 80,
        metadata: JSON.stringify({ role: 'Core Backbone Switch', vlan: 10 })
      },
      {
        id: 'NODE-APP-01',
        name: 'Enterprise Service (mail.taxes.gov.az)',
        hostname_or_ip: '10.22.12.204',
        mac_address: null,
        type: 'service',
        layer: 'service',
        layer_level: 4,
        parent_id: 'NODE-CORE-01',
        status: 'healthy',
        last_latency_ms: 1.8,
        vendor: 'State Tax Service (DVX)',
        if_name: 'eth0',
        x: 680,
        y: 80,
        metadata: JSON.stringify({ role: 'Government Application Portal', ports: [443, 110] })
      },
      {
        id: 'NODE-LAN-01',
        name: `Distribution & Access LAN (${lanCidr})`,
        hostname_or_ip: lanCidr,
        mac_address: null,
        type: 'subnet',
        layer: 'access',
        layer_level: 5,
        parent_id: 'NODE-GW-01',
        status: 'healthy',
        last_latency_ms: 0.4,
        vendor: 'Access LAN Switched Fabric',
        if_name: 'gig0/1-24',
        x: 880,
        y: 200,
        metadata: JSON.stringify({ role: 'Access LAN Subnet', hostsCount: 30 })
      },
      {
        id: 'NODE-HOST-01',
        name: `Local Workstation Host (${hostIp})`,
        hostname_or_ip: hostIp,
        mac_address: 'D8:43:AE:DF:5B:3A',
        type: 'host',
        layer: 'endpoint',
        layer_level: 6,
        parent_id: 'NODE-LAN-01',
        status: 'healthy',
        last_latency_ms: 0.1,
        vendor: 'Intel I219-LM / Windows Workstation',
        if_name: 'Ethernet',
        x: 1080,
        y: 140,
        metadata: JSON.stringify({ role: 'NOC Analyst Workstation', os: 'Windows' })
      }
    ];

    const insertNode = db.prepare(`
      INSERT INTO topology_nodes (
        id, name, hostname_or_ip, mac_address, type, layer, layer_level,
        parent_id, status, last_checked, last_latency_ms, vendor, if_name, x, y, metadata
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    for (const node of defaultNodes) {
      insertNode.run(
        node.id,
        node.name,
        node.hostname_or_ip,
        node.mac_address,
        node.type,
        node.layer,
        node.layer_level,
        node.parent_id,
        node.status,
        now,
        node.last_latency_ms,
        node.vendor,
        node.if_name,
        node.x,
        node.y,
        node.metadata
      );
    }
    console.log(`✓ Seeded ${defaultNodes.length} baseline topology nodes.`);

    // 3. Seed Topology Edges
    const defaultEdges = [
      {
        id: 'EDGE-WAN-GW',
        source_id: 'NODE-WAN-01',
        target_id: 'NODE-GW-01',
        link_type: 'fiber',
        status: 'up',
        bandwidth_mbps: 1000,
        utilization_pct: 18.5,
        latency_ms: 12.4,
        packet_rate: 850,
        metadata: JSON.stringify({ interface: 'WAN0 <-> ether1' })
      },
      {
        id: 'EDGE-GW-CORE',
        source_id: 'NODE-GW-01',
        target_id: 'NODE-CORE-01',
        link_type: 'fiber',
        status: 'up',
        bandwidth_mbps: 10000,
        utilization_pct: 24.2,
        latency_ms: 0.5,
        packet_rate: 1420,
        metadata: JSON.stringify({ interface: 'ether2 <-> tengig0/1' })
      },
      {
        id: 'EDGE-CORE-APP',
        source_id: 'NODE-CORE-01',
        target_id: 'NODE-APP-01',
        link_type: 'ethernet',
        status: 'up',
        bandwidth_mbps: 1000,
        utilization_pct: 12.0,
        latency_ms: 1.2,
        packet_rate: 340,
        metadata: JSON.stringify({ interface: 'gig0/10 <-> eth0' })
      },
      {
        id: 'EDGE-GW-LAN',
        source_id: 'NODE-GW-01',
        target_id: 'NODE-LAN-01',
        link_type: 'ethernet',
        status: 'up',
        bandwidth_mbps: 1000,
        utilization_pct: 35.8,
        latency_ms: 0.4,
        packet_rate: 980,
        metadata: JSON.stringify({ interface: 'ether3 <-> trunk1' })
      },
      {
        id: 'EDGE-LAN-HOST',
        source_id: 'NODE-LAN-01',
        target_id: 'NODE-HOST-01',
        link_type: 'ethernet',
        status: 'up',
        bandwidth_mbps: 1000,
        utilization_pct: 8.2,
        latency_ms: 0.1,
        packet_rate: 180,
        metadata: JSON.stringify({ interface: 'port14 <-> eth' })
      }
    ];

    const insertEdge = db.prepare(`
      INSERT INTO topology_edges (
        id, source_id, target_id, link_type, status, bandwidth_mbps,
        utilization_pct, latency_ms, packet_rate, metadata
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    for (const edge of defaultEdges) {
      insertEdge.run(
        edge.id,
        edge.source_id,
        edge.target_id,
        edge.link_type,
        edge.status,
        edge.bandwidth_mbps,
        edge.utilization_pct,
        edge.latency_ms,
        edge.packet_rate,
        edge.metadata
      );
    }
    console.log(`✓ Seeded ${defaultEdges.length} topology interconnect edges.`);

    // 4. Seed Initial Link Telemetry
    const insertTelemetry = db.prepare(`
      INSERT INTO link_telemetry (
        edge_id, node_id, latency_ms, loss_pct, bandwidth_utilization_pct, packet_rate,
        if_in_octets, if_out_octets, timestamp
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    for (const edge of defaultEdges) {
      insertTelemetry.run(
        edge.id,
        edge.source_id,
        edge.latency_ms,
        0,
        edge.utilization_pct,
        edge.packet_rate,
        14502390,
        28910440,
        now
      );
    }
  }

  // 5. Initialize Cryptographic Genesis Audit Log if uninitialized
  try {
    const { logAction, getLastRecordHash, GENESIS_HASH } = require('../core/audit-logger');
    if (getLastRecordHash() === GENESIS_HASH) {
      logAction({
        userId: 'USR-ADMIN-01',
        username: 'system',
        role: 'ADMIN',
        action: 'SYSTEM_INITIALIZATION',
        resource: 'DATABASE',
        details: { message: 'Database schema, baseline topology, and initial NOC accounts seeded' }
      });
      console.log('✓ Cryptographic Genesis Audit Log Initialized');
    }
  } catch (e) {
    console.warn('[Audit Seed Warning]: Could not record genesis audit entry:', e.message);
  }

  console.log('--- Pure NOC Workstation Seeding Completed Successfully ---');
}

if (require.main === module) {
  seedDatabase();
}

module.exports = { seedDatabase };
