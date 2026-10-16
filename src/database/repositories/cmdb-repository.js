/**
 * EJI CMDB & Configuration Item Repository
 * Authoritative persistence for hardware CIs, interfaces, relationships, subnets, and discovery logs.
 */

const { db } = require('../database');
const crypto = require('crypto');

class CmdbRepository {
  static createHardwareCi({
    nodeId = null,
    assetTag,
    serialNumber = null,
    model = null,
    vendor = null,
    formFactor = 'rackmount_server',
    location = 'Main Datacenter',
    rackUnit = null,
    cpuDetails = null,
    ramGb = null,
    storageGb = null,
    ownerDepartment = 'IT Infrastructure'
  }) {
    const id = 'CI-HW-' + crypto.randomBytes(4).toString('hex').toUpperCase();
    const now = new Date().toISOString();

    db.prepare(`
      INSERT INTO cmdb_hardware (
        id, node_id, asset_tag, serial_number, model, vendor,
        form_factor, datacenter_or_location, rack_unit, cpu_details,
        ram_gb, storage_gb, owner_department, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      nodeId,
      assetTag.trim().toUpperCase(),
      serialNumber,
      model,
      vendor,
      formFactor,
      location,
      rackUnit,
      cpuDetails,
      ramGb,
      storageGb,
      ownerDepartment,
      now,
      now
    );

    return this.getHardwareCiById(id);
  }

  static getHardwareCiById(id) {
    const hw = db.prepare(`
      SELECT h.*, n.name as node_name, n.hostname_or_ip as primary_ip, n.status as health_status
      FROM cmdb_hardware h
      LEFT JOIN nodes n ON h.node_id = n.id
      WHERE h.id = ?
    `).get(id);

    if (!hw) return null;

    hw.interfaces = this.getInterfacesForCi(id);
    hw.relationships = this.getRelationshipsForCi(id);
    return hw;
  }

  static listHardwareCis({ location = null, formFactor = null, limit = 100 } = {}) {
    let query = `
      SELECT h.*, n.name as node_name, n.hostname_or_ip as primary_ip, n.status as health_status
      FROM cmdb_hardware h
      LEFT JOIN nodes n ON h.node_id = n.id
      WHERE 1=1
    `;
    const params = [];
    if (location) {
      query += ' AND h.datacenter_or_location = ?';
      params.push(location);
    }
    if (formFactor) {
      query += ' AND h.form_factor = ?';
      params.push(formFactor);
    }
    query += ' ORDER BY h.created_at DESC LIMIT ?';
    params.push(limit);

    return db.prepare(query).all(...params);
  }

  static updateHardwareCi(id, updates = {}) {
    const existing = db.prepare('SELECT * FROM cmdb_hardware WHERE id = ?').get(id);
    if (!existing) throw new Error(`Hardware CI ${id} not found`);

    const now = new Date().toISOString();
    const model = updates.model !== undefined ? updates.model : existing.model;
    const vendor = updates.vendor !== undefined ? updates.vendor : existing.vendor;
    const location = updates.location !== undefined ? updates.location : existing.datacenter_or_location;
    const rackUnit = updates.rackUnit !== undefined ? updates.rackUnit : existing.rack_unit;
    const cpuDetails = updates.cpuDetails !== undefined ? updates.cpuDetails : existing.cpu_details;
    const ramGb = updates.ramGb !== undefined ? updates.ramGb : existing.ram_gb;
    const storageGb = updates.storageGb !== undefined ? updates.storageGb : existing.storage_gb;
    const lifecycleStatus = updates.lifecycleStatus !== undefined ? updates.lifecycleStatus : existing.lifecycle_status;
    const ownerDepartment = updates.ownerDepartment !== undefined ? updates.ownerDepartment : existing.owner_department;

    db.prepare(`
      UPDATE cmdb_hardware
      SET model = ?, vendor = ?, datacenter_or_location = ?, rack_unit = ?,
          cpu_details = ?, ram_gb = ?, storage_gb = ?, lifecycle_status = ?,
          owner_department = ?, updated_at = ?
      WHERE id = ?
    `).run(model, vendor, location, rackUnit, cpuDetails, ramGb, storageGb, lifecycleStatus, ownerDepartment, now, id);

    return this.getHardwareCiById(id);
  }

  static addInterface({
    ciId,
    interfaceName,
    macAddress = null,
    ipv4Address = null,
    subnetMask = '255.255.255.0',
    speedMbps = 1000,
    isUp = 1,
    vlanId = 1
  }) {
    const id = 'IFACE-' + crypto.randomBytes(4).toString('hex').toUpperCase();

    db.prepare(`
      INSERT INTO cmdb_interfaces (
        id, ci_id, interface_name, mac_address, ipv4_address, subnet_mask, speed_mbps, is_up, vlan_id
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, ciId, interfaceName, macAddress, ipv4Address, subnetMask, speedMbps, isUp ? 1 : 0, vlanId);

    return { id, ciId, interfaceName, macAddress, ipv4Address, isUp, vlanId };
  }

  static getInterfacesForCi(ciId) {
    return db.prepare('SELECT * FROM cmdb_interfaces WHERE ci_id = ?').all(ciId);
  }

  static addRelationship({ parentCiId, childCiId, relationType = 'depends_on' }) {
    const id = 'REL-' + crypto.randomBytes(4).toString('hex').toUpperCase();
    const now = new Date().toISOString();

    db.prepare(`
      INSERT INTO cmdb_relationships (id, parent_ci_id, child_ci_id, relation_type, created_at)
      VALUES (?, ?, ?, ?, ?)
    `).run(id, parentCiId, childCiId, relationType, now);

    return { id, parentCiId, childCiId, relationType, createdAt: now };
  }

  static getRelationshipsForCi(ciId) {
    const parents = db.prepare('SELECT * FROM cmdb_relationships WHERE child_ci_id = ?').all(ciId);
    const children = db.prepare('SELECT * FROM cmdb_relationships WHERE parent_ci_id = ?').all(ciId);
    return { parents, children };
  }

  static getFullDependencyGraph() {
    const nodes = db.prepare('SELECT id, name, hostname_or_ip, type, status FROM nodes').all();
    const edges = db.prepare('SELECT parent_ci_id as from_node, child_ci_id as to_node, relation_type FROM cmdb_relationships').all();

    for (const n of nodes) {
      if (n.parent_id) {
        edges.push({ from_node: n.parent_id, to_node: n.id, relation_type: 'routes_to' });
      }
    }

    return { nodes, edges };
  }

  static listSubnets() {
    return db.prepare('SELECT * FROM cmdb_subnets ORDER BY network_cidr ASC').all();
  }

  static createSubnet({
    networkCidr,
    vlanId = 1,
    vlanName = 'Subnet',
    gatewayIp = null,
    dnsServers = '1.1.1.1',
    dhcpEnabled = 1,
    environment = 'prod',
    location = 'Main Datacenter'
  }) {
    const id = 'SUBNET-' + crypto.randomBytes(4).toString('hex').toUpperCase();

    db.prepare(`
      INSERT INTO cmdb_subnets (
        id, network_cidr, vlan_id, vlan_name, gateway_ip, dns_servers, dhcp_enabled, environment, location
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, networkCidr, vlanId, vlanName, gatewayIp, dnsServers, dhcpEnabled ? 1 : 0, environment, location);

    return db.prepare('SELECT * FROM cmdb_subnets WHERE id = ?').get(id);
  }

  static logReconciliation({ source, processed, created, updated, conflicts }) {
    const id = 'REC-' + crypto.randomBytes(4).toString('hex').toUpperCase();
    const now = new Date().toISOString();

    db.prepare(`
      INSERT INTO cmdb_reconciliation_log (id, source, records_processed, records_created, records_updated, conflicts_detected, timestamp)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(id, source, processed, created, updated, conflicts, now);

    return { id, source, processed, created, updated, conflicts, timestamp: now };
  }
}

module.exports = CmdbRepository;
module.exports.CmdbRepository = CmdbRepository;
