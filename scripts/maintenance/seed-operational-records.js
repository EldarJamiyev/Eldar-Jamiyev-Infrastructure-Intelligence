/**
 * EJI Operational Records Seeder & Database Sanitation Script
 * Purges duplicate test records and seeds diverse, authentic enterprise CIs, tickets, and alerts.
 */

const { db } = require('../../src/db/database');

function seedOperationalRecords() {
  console.log('--- Cleaning and Seeding EJI Operational Records ---');

  // 1. Purge duplicate test records
  const delComments = db.prepare("DELETE FROM ticket_comments WHERE ticket_id IN (SELECT id FROM helpdesk_tickets WHERE title = 'Core Switch SFP Module Intermittent Link Flapping')").run();
  const delTickets = db.prepare("DELETE FROM helpdesk_tickets WHERE title = 'Core Switch SFP Module Intermittent Link Flapping'").run();
  console.log(`Purged ${delTickets.changes} test tickets and ${delComments.changes} test comments.`);

  const delIfaces = db.prepare("DELETE FROM cmdb_interfaces WHERE ci_id IN (SELECT id FROM cmdb_hardware WHERE asset_tag LIKE 'TAG-TEST-%')").run();
  const delHw = db.prepare("DELETE FROM cmdb_hardware WHERE asset_tag LIKE 'TAG-TEST-%'").run();
  console.log(`Purged ${delHw.changes} test hardware CIs and ${delIfaces.changes} test interfaces.`);

  const delAlerts = db.prepare("DELETE FROM monitoring_alerts WHERE ci_id NOT IN (SELECT id FROM cmdb_hardware)").run();
  console.log(`Purged ${delAlerts.changes} orphaned monitoring alerts.`);

  const delBaselines = db.prepare("DELETE FROM drift_baselines WHERE name = 'Hardware Base Policy'").run();
  console.log(`Purged ${delBaselines.changes} test drift baselines.`);

  const delChaos = db.prepare("DELETE FROM chaos_executions WHERE operator_username = 'test_operator'").run();
  console.log(`Purged ${delChaos.changes} test chaos executions.`);

  // 2. Seed diverse Hardware CIs
  const existingHw = db.prepare("SELECT COUNT(*) as c FROM cmdb_hardware").get().c;
  if (existingHw === 0) {
    const insertHw = db.prepare(`
      INSERT INTO cmdb_hardware (
        id, asset_tag, serial_number, model, vendor, form_factor,
        datacenter_or_location, rack_unit, cpu_details, ram_gb, storage_gb,
        firmware_version, lifecycle_status, owner_department, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
    `);

    const insertIface = db.prepare(`
      INSERT INTO cmdb_interfaces (
        id, ci_id, interface_name, mac_address, ipv4_address, subnet_mask, speed_mbps, is_up, vlan_id
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const enterpriseHardware = [
      {
        id: 'CI-HW-RTR-01',
        assetTag: 'TAG-RTR-01',
        serialNumber: 'SN-CSCO-8500-9921',
        model: 'Catalyst 8500 Edge Router',
        vendor: 'Cisco Systems, Inc.',
        formFactor: 'router',
        location: 'Primary Datacenter',
        rackUnit: 'Rack A1 U40-U42',
        cpu: 'Intel Xeon 8-Core @ 2.5GHz',
        ram: 32,
        storage: 128,
        firmware: 'IOS-XE 17.9.3a',
        lifecycle: 'in_service',
        owner: 'NetOps Core',
        ifaces: [
          { id: 'IF-RTR-01-1', name: 'GigabitEthernet0/0/0', mac: '00:08:E3:44:11:01', ip: '10.168.195.1', mask: '255.255.255.0', speed: 1000, up: 1, vlan: 1 },
          { id: 'IF-RTR-01-2', name: 'TenGigabitEthernet0/1/0', mac: '00:08:E3:44:11:02', ip: '198.51.100.2', mask: '255.255.255.252', speed: 10000, up: 1, vlan: 100 }
        ]
      },
      {
        id: 'CI-HW-SW-01',
        assetTag: 'TAG-SW-01',
        serialNumber: 'SN-CSCO-9318-7712',
        model: 'Nexus 93180YC-FX3 Core Switch',
        vendor: 'Cisco Systems, Inc.',
        formFactor: 'switch',
        location: 'Primary Datacenter',
        rackUnit: 'Rack A1 U38',
        cpu: 'Quad-Core AMD Embedded',
        ram: 16,
        storage: 64,
        firmware: 'NX-OS 10.2(3)',
        lifecycle: 'in_service',
        owner: 'NetOps Core',
        ifaces: [
          { id: 'IF-SW-01-1', name: 'Ethernet1/1', mac: '00:01:42:88:22:01', ip: '10.168.195.2', mask: '255.255.255.0', speed: 25000, up: 1, vlan: 1 },
          { id: 'IF-SW-01-2', name: 'Ethernet1/48', mac: '00:01:42:88:22:48', ip: '10.168.195.3', mask: '255.255.255.0', speed: 100000, up: 1, vlan: 10 }
        ]
      },
      {
        id: 'CI-HW-SRV-01',
        assetTag: 'TAG-SRV-01',
        serialNumber: 'SN-DELL-R750-4410',
        model: 'PowerEdge R750 Virtualization Host',
        vendor: 'Dell Inc.',
        formFactor: 'rackmount_server',
        location: 'Primary Datacenter',
        rackUnit: 'Rack B3 U12-U14',
        cpu: 'Dual Intel Xeon Gold 6330 (56 Cores)',
        ram: 256,
        storage: 8000,
        firmware: 'iDRAC9 6.10.30.00',
        lifecycle: 'in_service',
        owner: 'SysOps Infrastructure',
        ifaces: [
          { id: 'IF-SRV-01-1', name: 'vmnic0', mac: '00:26:B9:11:88:01', ip: '10.168.195.10', mask: '255.255.255.0', speed: 10000, up: 1, vlan: 20 },
          { id: 'IF-SRV-01-2', name: 'iDRAC', mac: '00:26:B9:11:88:99', ip: '10.168.195.11', mask: '255.255.255.0', speed: 1000, up: 1, vlan: 99 }
        ]
      },
      {
        id: 'CI-HW-SRV-02',
        assetTag: 'TAG-SRV-02',
        serialNumber: 'SN-HPE-DL380-6623',
        model: 'ProLiant DL380 Gen10 DB Node',
        vendor: 'Hewlett Packard',
        formFactor: 'rackmount_server',
        location: 'Primary Datacenter',
        rackUnit: 'Rack B3 U15-U17',
        cpu: 'Dual Intel Xeon Silver 4314 (32 Cores)',
        ram: 256,
        storage: 8000,
        firmware: 'iLO 5 v2.72',
        lifecycle: 'in_service',
        owner: 'SysOps Infrastructure',
        ifaces: [
          { id: 'IF-SRV-02-1', name: 'eth0', mac: '00:1B:78:33:99:01', ip: '10.168.195.20', mask: '255.255.255.0', speed: 10000, up: 1, vlan: 30 }
        ]
      },
      {
        id: 'CI-HW-FW-01',
        assetTag: 'TAG-FW-01',
        serialNumber: 'SN-FTNT-200F-8812',
        model: 'FortiGate 200F Perimeter Firewall',
        vendor: 'Fortinet',
        formFactor: 'firewall',
        location: 'DMZ Edge',
        rackUnit: 'Rack A2 U20',
        cpu: 'FortiASIC CP9/NP6XLite',
        ram: 16,
        storage: 120,
        firmware: 'FortiOS 7.2.5',
        lifecycle: 'in_service',
        owner: 'SecOps Perimeter',
        ifaces: [
          { id: 'IF-FW-01-1', name: 'wan1', mac: 'D8:B3:70:AA:55:01', ip: '203.0.113.1', mask: '255.255.255.240', speed: 10000, up: 1, vlan: 100 },
          { id: 'IF-FW-01-2', name: 'internal', mac: 'D8:B3:70:AA:55:02', ip: '10.168.195.254', mask: '255.255.255.0', speed: 10000, up: 1, vlan: 1 }
        ]
      },
      {
        id: 'CI-HW-WS-01',
        assetTag: 'TAG-WS-01',
        serialNumber: 'SN-DELL-7090-1204',
        model: 'OptiPlex 7090 Admin Console',
        vendor: 'Dell Inc.',
        formFactor: 'desktop',
        location: 'NOC Operations Center',
        rackUnit: 'Desk 1',
        cpu: 'Intel Core i7-11700 (8 Cores)',
        ram: 32,
        storage: 512,
        firmware: 'UEFI 1.14.0',
        lifecycle: 'in_service',
        owner: 'Helpdesk Tier 1',
        ifaces: [
          { id: 'IF-WS-01-1', name: 'Ethernet', mac: '00:1E:67:CC:33:01', ip: '10.168.195.55', mask: '255.255.255.0', speed: 1000, up: 1, vlan: 50 }
        ]
      }
    ];

    for (const h of enterpriseHardware) {
      insertHw.run(
        h.id, h.assetTag, h.serialNumber, h.model, h.vendor, h.formFactor,
        h.location, h.rackUnit, h.cpu, h.ram, h.storage,
        h.firmware, h.lifecycle, h.owner
      );
      for (const iface of h.ifaces) {
        insertIface.run(
          iface.id, h.id, iface.name, iface.mac, iface.ip, iface.mask, iface.speed, iface.up, iface.vlan
        );
      }
    }
    console.log(`✓ Provisioned 6 diverse enterprise hardware CIs with network interfaces.`);
  }

  // 3. Seed realistic Helpdesk Tickets
  const existingTickets = db.prepare("SELECT COUNT(*) as c FROM helpdesk_tickets").get().c;
  if (existingTickets === 0) {
    const insertTicket = db.prepare(`
      INSERT INTO helpdesk_tickets (
        id, ticket_number, title, description, category, priority, status,
        requester_name, requester_email, assigned_team, affected_ci_id,
        sla_policy_id, sla_target_response_at, sla_target_resolve_at, sla_breached,
        created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, datetime('now'), datetime('now'))
    `);

    const tickets = [
      {
        id: 'TCK-2026-001',
        num: 1001,
        title: 'Production PostgreSQL Replication Delay Exceeding 120s',
        desc: 'Streaming replication to secondary node CI-HW-SRV-02 has fallen behind by 124 seconds during heavy write throughput.',
        category: 'incident',
        priority: 'P2_HIGH',
        status: 'in_progress',
        req: 'Elena Rostova (Lead DBA)',
        email: 'e.rostova@enterprise.internal',
        team: 'sysops',
        ciId: 'CI-HW-SRV-02',
        slaId: 'SLA-P2',
        targetResp: new Date(Date.now() + 1800000).toISOString(),
        targetResolve: new Date(Date.now() + 14400000).toISOString()
      },
      {
        id: 'TCK-2026-002',
        num: 1002,
        title: 'Internal Wildcard TLS Certificate Expiring in 14 Days',
        desc: 'Wildcard certificate *.corp.internal on edge firewall and reverse proxy requires renewal before expiry.',
        category: 'change',
        priority: 'P3_MEDIUM',
        status: 'assigned',
        req: 'Marcus Vance (SecOps)',
        email: 'm.vance@enterprise.internal',
        team: 'secops',
        ciId: 'CI-HW-FW-01',
        slaId: 'SLA-P3',
        targetResp: new Date(Date.now() + 3600000).toISOString(),
        targetResolve: new Date(Date.now() + 28800000).toISOString()
      },
      {
        id: 'TCK-2026-003',
        num: 1003,
        title: 'Core Edge BGP Route Flapping to Upstream Tier-1 Provider',
        desc: 'Catalyst 8500 Edge Router BGP session with AS64512 experienced 4 flap events in the last 60 minutes.',
        category: 'incident',
        priority: 'P1_CRITICAL',
        status: 'in_progress',
        req: 'Senior Network Architect',
        email: 'netops-oncall@enterprise.internal',
        team: 'netops',
        ciId: 'CI-HW-RTR-01',
        slaId: 'SLA-P1',
        targetResp: new Date(Date.now() + 900000).toISOString(),
        targetResolve: new Date(Date.now() + 7200000).toISOString()
      },
      {
        id: 'TCK-2026-004',
        num: 1004,
        title: 'Workstation 802.1X Dynamic VLAN Assignment Failure in Wing B',
        desc: 'New corporate laptops in Wing B are not receiving RADIUS assigned VLAN 50 and fall into quarantine VLAN.',
        category: 'service_request',
        priority: 'P4_LOW',
        status: 'resolved',
        req: 'Helpdesk Tier 1 Dispatcher',
        email: 'helpdesk@enterprise.internal',
        team: 'helpdesk',
        ciId: 'CI-HW-WS-01',
        slaId: 'SLA-P4',
        targetResp: new Date(Date.now() + 14400000).toISOString(),
        targetResolve: new Date(Date.now() + 86400000).toISOString()
      }
    ];

    for (const t of tickets) {
      insertTicket.run(
        t.id, t.num, t.title, t.desc, t.category, t.priority, t.status,
        t.req, t.email, t.team, t.ciId, t.slaId, t.targetResp, t.targetResolve
      );
    }
    console.log(`✓ Provisioned 4 realistic enterprise ITSM operational tickets.`);
  }

  // 4. Seed realistic Monitoring Alerts
  const existingAlerts = db.prepare("SELECT COUNT(*) as c FROM monitoring_alerts").get().c;
  if (existingAlerts === 0) {
    const insertAlert = db.prepare(`
      INSERT INTO monitoring_alerts (
        id, rule_id, ci_id, metric_name, observed_value, threshold_value,
        severity, status, fired_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    `);

    insertAlert.run('ALT-MEM-01', 'RULE-MEM-HIGH', 'CI-HW-SRV-01', 'memory_percent', 87.4, 85.0, 'P2_HIGH', 'firing');
    insertAlert.run('ALT-DISK-02', 'RULE-DISK-WARN', 'CI-HW-SRV-02', 'disk_used_percent', 83.1, 80.0, 'P3_MEDIUM', 'acknowledged');
    insertAlert.run('ALT-NET-03', 'RULE-PKT-LOSS', 'CI-HW-RTR-01', 'packet_loss_percent', 3.8, 2.0, 'P2_HIGH', 'firing');
    console.log(`✓ Provisioned 3 realistic enterprise monitoring alerts.`);
  }

  console.log('--- Operational Records Sanitation and Seeding Complete ---');
}

if (require.main === module) {
  seedOperationalRecords();
}

module.exports = { seedOperationalRecords };
