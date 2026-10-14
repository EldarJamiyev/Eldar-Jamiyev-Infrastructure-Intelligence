/**
 * EJII Database Seeder
 * Initializes default user roles, sample dependency nodes, and cryptographic genesis audit log.
 */

const { db, initSchema } = require('./database');
const { runMigrations } = require('./migrations');
const { hashPassword, ROLES } = require('../core/security');
const { logAction } = require('../core/audit-logger');

function getSystemDefaultGateway() {
  if (process.platform === 'win32') {
    try {
      const { execSync } = require('child_process');
      const out = execSync('powershell.exe -NoProfile -Command "(Get-NetRoute -DestinationPrefix \'0.0.0.0/0\' -ErrorAction SilentlyContinue | Select-Object -First 1).NextHop"', { timeout: 3000, encoding: 'utf8' });
      const gw = (out || '').trim();
      if (/^(\d{1,3}\.){3}\d{1,3}$/.test(gw) && gw !== '0.0.0.0') {
        return gw;
      }
    } catch (e) {}
  }
  return '192.168.1.1';
}

function seedDatabase() {
  initSchema();
  runMigrations();

  console.log('--- Seeding EJI Enterprise Intelligence Platform ---');

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
        fullName: 'Application Owner (EJI Governance)',
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

  // Detect genuine default gateway
  const defaultGatewayIp = getSystemDefaultGateway();

  // If NODE-GW-01 exists but has the old dead 10.168.195.1, update it
  const currentGw = db.prepare("SELECT hostname_or_ip FROM nodes WHERE id = 'NODE-GW-01'").get();
  if (currentGw && currentGw.hostname_or_ip === '10.168.195.1' && defaultGatewayIp !== '10.168.195.1') {
    db.prepare("UPDATE nodes SET hostname_or_ip = ?, name = ? WHERE id = 'NODE-GW-01'")
      .run(defaultGatewayIp, `Default Subnet Gateway (${defaultGatewayIp})`);
    console.log(`✓ Updated NODE-GW-01 to actual local gateway: ${defaultGatewayIp}`);
  }

  // Check if default infrastructure nodes exist
  const existingNodes = db.prepare('SELECT COUNT(*) as count FROM nodes').get();
  if (existingNodes.count === 0) {
    console.log('Seeding baseline infrastructure topology nodes...');

    const defaultNodes = [
      {
        id: 'NODE-GW-01',
        name: `Default Subnet Gateway (${defaultGatewayIp})`,
        hostname_or_ip: defaultGatewayIp,
        type: 'gateway',
        parent_id: null,
        status: 'healthy',
        mac_address: null,
        vendor: 'Network Gateway',
        discovery_source: 'system_route',
        is_managed: 1,
        tags: 'network,gateway,core',
        metadata: JSON.stringify({ role: 'Core Gateway', vlan: 1 })
      },
      {
        id: 'NODE-LOCAL-HOST',
        name: 'Local Host System (Windows 11)',
        hostname_or_ip: '127.0.0.1',
        type: 'server_windows',
        parent_id: 'NODE-GW-01',
        status: 'healthy',
        mac_address: null,
        vendor: 'Microsoft Corporation',
        os_name: 'Windows 11 Pro',
        discovery_source: 'system_probe',
        is_managed: 1,
        tags: 'host,server,management',
        metadata: JSON.stringify({ role: 'Primary Host System', os: 'Windows' })
      },
      {
        id: 'NODE-DNS-PUBLIC',
        name: 'Primary Upstream DNS Resolver',
        hostname_or_ip: '1.1.1.1',
        type: 'service_dns',
        parent_id: 'NODE-GW-01',
        status: 'healthy',
        vendor: 'Cloudflare',
        discovery_source: 'manual',
        is_managed: 1,
        tags: 'service,dns,upstream',
        metadata: JSON.stringify({ provider: 'Cloudflare', port: 53 })
      },
      {
        id: 'NODE-WEB-HTTPS',
        name: 'Enterprise Web Application Endpoint',
        hostname_or_ip: 'google.com',
        type: 'service_http',
        parent_id: 'NODE-GW-01',
        status: 'healthy',
        vendor: 'Google LLC',
        discovery_source: 'manual',
        is_managed: 1,
        tags: 'service,http,wan',
        metadata: JSON.stringify({ protocol: 'HTTPS', port: 443 })
      }
    ];

    const insertNode = db.prepare(`
      INSERT INTO nodes (
        id, name, hostname_or_ip, type, parent_id, status, last_checked,
        vendor, os_name, discovery_source, is_managed, tags, metadata
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        node.vendor || null,
        node.os_name || null,
        node.discovery_source || 'manual',
        node.is_managed !== undefined ? node.is_managed : 1,
        node.tags || null,
        node.metadata
      );
      console.log(`✓ Registered topology node: ${node.name} (${node.hostname_or_ip})`);
    }
  }

  // Seed baseline integrations
  const defaultIntegrations = [
    {
      id: 'INT-SNMP-LOCAL',
      name: 'Local SNMP Interface Monitor',
      type: 'snmp',
      endpoint: '127.0.0.1:161',
      config: { community: 'public', version: '2c', port: 161 },
      status: 'configured'
    },
    {
      id: 'INT-WMI-HOST',
      name: 'Windows NT CIM / WMI Telemetry Integration',
      type: 'wmi',
      endpoint: 'localhost',
      config: { namespaces: ['root/cimv2'], pollingIntervalSec: 15 },
      status: 'connected'
    },
    {
      id: 'INT-SSH-GATEWAY',
      name: 'Subnet Gateway SSH Remote Administration',
      type: 'ssh',
      endpoint: `${defaultGatewayIp}:22`,
      config: { port: 22, timeoutMs: 3000 },
      status: 'configured'
    },
    {
      id: 'INT-WEBHOOK-ALERT',
      name: 'Enterprise Incident Webhook Dispatcher',
      type: 'webhook',
      endpoint: 'https://httpbin.org/status/200',
      config: { method: 'POST', format: 'json', timeoutMs: 4000 },
      status: 'configured'
    }
  ];

  const insertIntegration = db.prepare(`
    INSERT OR IGNORE INTO integrations (id, name, type, endpoint, config_json, status, last_sync, enabled, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
  `);
  const now = new Date().toISOString();
  for (const integ of defaultIntegrations) {
    insertIntegration.run(
      integ.id,
      integ.name,
      integ.type,
      integ.endpoint,
      JSON.stringify(integ.config),
      integ.status,
      now,
      now
    );
  }
  console.log('✓ Provisioned 4 baseline enterprise integrations (SNMP, WMI, SSH, Webhook).');

  // Seed baseline governance settings
  const defaultSettings = [
    { key: 'platform_name', value: 'EJI — Eldar Jamiyev’s Infrastructure Intelligence' },
    { key: 'audit_retention_days', value: '365' },
    { key: 'session_timeout_minutes', value: '60' },
    { key: 'telemetry_poll_interval_sec', value: '30' },
    { key: 'security_login_max_attempts', value: '5' },
    { key: 'security_login_lockout_min', value: '15' }
  ];
  const insertSetting = db.prepare('INSERT OR IGNORE INTO system_settings (key, value, updated_at) VALUES (?, ?, ?)');
  for (const s of defaultSettings) {
    insertSetting.run(s.key, s.value, now);
  }
  console.log('✓ Provisioned platform governance and retention settings.');

  // Create Genesis Cryptographic Audit Log
  const existingAudit = db.prepare('SELECT COUNT(*) as count FROM audit_logs').get();
  if (existingAudit.count === 0) {
    logAction({
      userId: 'SYSTEM_GENESIS',
      username: 'EJI Core Engine',
      role: 'system',
      action: 'PLATFORM_INITIALIZED',
      resource: 'EJI_DATABASE',
      details: 'Initial database schema and baseline security configuration provisioned.'
    });
    console.log('✓ Cryptographic HMAC genesis audit log established.');
  }

  console.log('--- EJI Platform Seeding Completed Successfully ---');
}

if (require.main === module) {
  seedDatabase();
}

module.exports = { seedDatabase };
