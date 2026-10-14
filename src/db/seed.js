/**
 * EJII Database Seeder
 * Initializes default user roles, sample dependency nodes, and cryptographic genesis audit log.
 */

const { db, initSchema } = require('./database');
const { hashPassword, ROLES } = require('../core/security');
const { logAction } = require('../core/audit-logger');

function seedDatabase() {
  initSchema();

  console.log('--- Seeding EJII Enterprise Intelligence Platform ---');

  // Check if users already exist
  const existingUsers = db.prepare('SELECT COUNT(*) as count FROM users').get();
  if (existingUsers.count === 0) {
    console.log('Seeding default operational role accounts...');

    const defaultAccounts = [
      {
        id: 'USR-HELPDESK-01',
        username: 'helpdesk',
        password: 'HelpdeskPassword2026!',
        fullName: 'Helpdesk Technician (Tier 1 Support)',
        role: ROLES.HELPDESK
      },
      {
        id: 'USR-NETADMIN-01',
        username: 'netadmin',
        password: 'NetadminPassword2026!',
        fullName: 'Network Administrator (L2/L3 Infrastructure)',
        role: ROLES.NETWORK_ADMIN
      },
      {
        id: 'USR-SYSADMIN-01',
        username: 'sysadmin',
        password: 'SysadminPassword2026!',
        fullName: 'System Administrator (Host & Services)',
        role: ROLES.SYSADMIN
      },
      {
        id: 'USR-APPOWNER-01',
        username: 'appowner',
        password: 'AppownerPassword2026!',
        fullName: 'Application Owner (EJII Governance)',
        role: ROLES.APP_OWNER
      }
    ];

    const insertUser = db.prepare(`
      INSERT INTO users (id, username, password_hash, salt, full_name, role, is_active, created_at)
      VALUES (?, ?, ?, ?, ?, ?, 1, ?)
    `);

    for (const acc of defaultAccounts) {
      const { hash, salt } = hashPassword(acc.password);
      insertUser.run(acc.id, acc.username, hash, salt, acc.fullName, acc.role, new Date().toISOString());
      console.log(`✓ Created role account: [${acc.role}] Username: ${acc.username}`);
    }
  }

  // Check if default infrastructure nodes exist
  const existingNodes = db.prepare('SELECT COUNT(*) as count FROM nodes').get();
  if (existingNodes.count === 0) {
    console.log('Seeding baseline infrastructure topology nodes...');

    const defaultNodes = [
      {
        id: 'NODE-GW-01',
        name: 'Default Subnet Gateway',
        hostname_or_ip: '10.168.195.1',
        type: 'gateway',
        parent_id: null,
        status: 'healthy',
        metadata: JSON.stringify({ role: 'Core Gateway', vlan: 1 })
      },
      {
        id: 'NODE-LOCAL-HOST',
        name: 'Local Host System (Windows 11)',
        hostname_or_ip: '127.0.0.1',
        type: 'server_windows',
        parent_id: 'NODE-GW-01',
        status: 'healthy',
        metadata: JSON.stringify({ role: 'Primary Host System', os: 'Windows' })
      },
      {
        id: 'NODE-DNS-PUBLIC',
        name: 'Primary Upstream DNS Resolver',
        hostname_or_ip: '1.1.1.1',
        type: 'service_dns',
        parent_id: 'NODE-GW-01',
        status: 'healthy',
        metadata: JSON.stringify({ provider: 'Cloudflare', port: 53 })
      },
      {
        id: 'NODE-WEB-HTTPS',
        name: 'Enterprise Web Application Endpoint',
        hostname_or_ip: 'google.com',
        type: 'service_http',
        parent_id: 'NODE-GW-01',
        status: 'healthy',
        metadata: JSON.stringify({ protocol: 'HTTPS', port: 443 })
      }
    ];

    const insertNode = db.prepare(`
      INSERT INTO nodes (id, name, hostname_or_ip, type, parent_id, status, last_checked, metadata)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    for (const node of defaultNodes) {
      insertNode.run(
        node.id,
        node.name,
        node.hostname_or_ip,
        node.type,
        node.parent_id,
        node.status,
        new Date().toISOString(),
        node.metadata
      );
      console.log(`✓ Registered topology node: ${node.name} (${node.hostname_or_ip})`);
    }
  }

  // Create Genesis Cryptographic Audit Log
  const existingAudit = db.prepare('SELECT COUNT(*) as count FROM audit_logs').get();
  if (existingAudit.count === 0) {
    logAction({
      userId: 'SYSTEM_GENESIS',
      username: 'EJII Core Engine',
      role: 'system',
      action: 'PLATFORM_INITIALIZED',
      resource: 'EJII_DATABASE',
      details: 'Initial database schema and baseline security configuration provisioned.'
    });
    console.log('✓ Cryptographic HMAC genesis audit log established.');
  }

  console.log('--- EJII Platform Seeding Completed Successfully ---');
}

if (require.main === module) {
  seedDatabase();
}

module.exports = { seedDatabase };
