/**
 * EJII Persistent Office Equipment & DHCP/APIPA Lifecycle Repository (SQLite WAL)
 * Tracks all discovered office computers, printers, VoIP phones, cameras, and switches
 * across scans and passive wire captures (ARP, DHCP DORA, mDNS, LLMNR).
 * Automatically detects when a known MAC address drops from a valid LAN IP onto
 * a temporary RFC 3927 APIPA error IP (169.254.x.x).
 */

const crypto = require('crypto');
const { db } = require('./database');
const { runMigrations } = require('./migrations');

class EquipmentInventoryRepository {
  constructor() {
    try {
      runMigrations(db);
    } catch (_) {}
    this._prepareStatements();
  }

  _prepareStatements() {
    try {
      this.stmtGetById = db.prepare('SELECT * FROM office_equipment_inventory WHERE device_id = ?');
      this.stmtGetByMac = db.prepare('SELECT * FROM office_equipment_inventory WHERE mac_address = ? AND mac_address != \'Unknown\' LIMIT 1');
      this.stmtGetByIp = db.prepare('SELECT * FROM office_equipment_inventory WHERE current_ip = ? LIMIT 1');

      this.stmtUpsertDevice = db.prepare(`
        INSERT INTO office_equipment_inventory (
          device_id, mac_address, current_ip, last_known_good_ip, device_name,
          equipment_type, equipment_category, equipment_brand, icon,
          is_apipa_fault, status, open_ports_json, passive_os_fingerprint,
          discovery_source, first_seen_at, last_seen_at
        ) VALUES (
          @device_id, @mac_address, @current_ip, @last_known_good_ip, @device_name,
          @equipment_type, @equipment_category, @equipment_brand, @icon,
          @is_apipa_fault, @status, @open_ports_json, @passive_os_fingerprint,
          @discovery_source, @first_seen_at, @last_seen_at
        )
        ON CONFLICT(device_id) DO UPDATE SET
          mac_address = CASE WHEN excluded.mac_address != 'Unknown' AND excluded.mac_address != '' THEN excluded.mac_address ELSE office_equipment_inventory.mac_address END,
          current_ip = excluded.current_ip,
          last_known_good_ip = CASE WHEN excluded.is_apipa_fault = 0 AND excluded.current_ip NOT LIKE '169.254.%' THEN excluded.current_ip ELSE office_equipment_inventory.last_known_good_ip END,
          device_name = CASE WHEN excluded.device_name IS NOT NULL AND excluded.device_name != '' THEN excluded.device_name ELSE office_equipment_inventory.device_name END,
          equipment_type = excluded.equipment_type,
          equipment_category = excluded.equipment_category,
          equipment_brand = CASE WHEN excluded.equipment_brand NOT LIKE '%No MAC%' THEN excluded.equipment_brand ELSE office_equipment_inventory.equipment_brand END,
          icon = excluded.icon,
          is_apipa_fault = excluded.is_apipa_fault,
          status = excluded.status,
          open_ports_json = excluded.open_ports_json,
          passive_os_fingerprint = COALESCE(excluded.passive_os_fingerprint, office_equipment_inventory.passive_os_fingerprint),
          discovery_source = excluded.discovery_source,
          last_seen_at = excluded.last_seen_at
      `);

      this.stmtInsertDhcpEvent = db.prepare(`
        INSERT INTO dhcp_and_ip_events (
          event_id, mac_address, ip_address, previous_ip, event_type,
          dhcp_message_type, hostname, details, observed_at
        ) VALUES (
          @event_id, @mac_address, @ip_address, @previous_ip, @event_type,
          @dhcp_message_type, @hostname, @details, @observed_at
        )
      `);
    } catch (_) {}
  }

  /**
   * Upserts a discovered or passively observed office device and detects IP drift
   * or regression from a valid LAN IP into an RFC 3927 APIPA 169.254.x.x fault.
   */
  upsertEquipmentRecord(params = {}) {
    const rawIp = params.ip || params.currentIp;
    if (!rawIp || !this.stmtUpsertDevice) return null;

    const cleanIp = String(rawIp).trim();
    const macAddress = params.macAddress || params.mac || params.clientMac || 'Unknown';
    const cleanMac = macAddress && macAddress !== 'Unknown' && macAddress !== 'N/A' && !macAddress.includes('No MAC')
      ? String(macAddress).trim().toUpperCase()
      : 'Unknown';

    const isApipa = /^169\.254\./.test(cleanIp) && cleanIp !== '169.254.169.254';
    const existingByMac = cleanMac !== 'Unknown' ? this.stmtGetByMac.get(cleanMac) : null;
    const existingByIp = this.stmtGetByIp.get(cleanIp);
    const existing = existingByMac || existingByIp || null;

    const deviceName = params.deviceName || params.hostname || '';
    const equipmentProfile = params.equipmentProfile || {};
    const status = params.status || 'ONLINE';
    const openPorts = params.openPorts || [];
    const passiveOsFingerprint = params.passiveOsFingerprint || null;
    const discoverySource = params.discoverySource || params.source || 'SCANNER';
    const equipmentType = params.equipmentType || equipmentProfile.equipmentType || existing?.equipment_type || 'COMPUTER';
    const equipmentBrand = params.equipmentBrand || equipmentProfile.equipmentBrand || existing?.equipment_brand || '— (No MAC Observed)';
    const equipmentCategory = params.equipmentCategory || equipmentProfile.category || existing?.equipment_category || null;

    const deviceId = existing
      ? existing.device_id
      : (cleanMac !== 'Unknown' ? `DEV-MAC-${cleanMac.replace(/[^A-F0-9]/g, '')}` : `DEV-IP-${cleanIp.replace(/\./g, '_')}`);

    const now = new Date().toISOString();
    const prevKnownGoodIp = !isApipa
      ? cleanIp
      : (existing?.last_known_good_ip || null);

    let ipRegressionDetected = false;
    if (isApipa && existing && existing.last_known_good_ip && !existing.last_known_good_ip.startsWith('169.254.')) {
      ipRegressionDetected = true;
      this.recordDhcpOrIpEvent({
        macAddress: cleanMac,
        ipAddress: cleanIp,
        previousIp: existing.last_known_good_ip,
        eventType: 'APIPA_REGRESSION_DETECTED',
        dhcpMessageType: 'APIPA_FALLBACK',
        hostname: deviceName || existing.device_name || '',
        details: `Device (${cleanMac}) lost its office IP (${existing.last_known_good_ip}) and fell back to emergency APIPA address ${cleanIp}.`
      });
    }

    const record = {
      device_id: deviceId,
      mac_address: cleanMac,
      current_ip: cleanIp,
      last_known_good_ip: prevKnownGoodIp,
      device_name: deviceName || existing?.device_name || '',
      equipment_type: equipmentType,
      equipment_category: equipmentCategory || (isApipa ? 'apipa_unconfigured' : 'workstations'),
      equipment_brand: equipmentBrand,
      icon: equipmentProfile.icon || existing?.icon || (isApipa ? '⚠️' : (equipmentType === 'PRINTER' ? '🖨️' : '💻')),
      is_apipa_fault: isApipa ? 1 : 0,
      status: isApipa ? 'APIPA_ISOLATED' : String(status || 'ONLINE'),
      open_ports_json: JSON.stringify(Array.isArray(openPorts) ? openPorts : (typeof openPorts === 'string' ? openPorts.split(',') : [])),
      passive_os_fingerprint: passiveOsFingerprint || existing?.passive_os_fingerprint || null,
      discovery_source: discoverySource,
      first_seen_at: existing?.first_seen_at || now,
      last_seen_at: now
    };

    try {
      this.stmtUpsertDevice.run(record);
    } catch (_) {}

    return {
      ...record,
      is_apipa: record.is_apipa_fault,
      apipa_reverted_count: ipRegressionDetected ? 1 : (isApipa ? 1 : 0),
      openPorts: Array.isArray(openPorts) ? openPorts : (typeof openPorts === 'string' ? openPorts.split(',') : []),
      isApipaFault: Boolean(record.is_apipa_fault),
      ipRegressionDetected
    };
  }

  recordDhcpOrIpEvent(params = {}) {
    if (!this.stmtInsertDhcpEvent) return null;
    const macAddress = params.macAddress || params.clientMac || 'Unknown';
    const ipAddress = params.ipAddress || params.offeredIp || params.currentIp || '0.0.0.0';
    const previousIp = params.previousIp || null;
    const eventType = params.eventType || params.dhcpMessageType || 'DHCP_TRANSACTION';
    const dhcpMessageType = params.dhcpMessageType || eventType;
    const hostname = params.hostname || '';
    const details = params.details || '';

    const entry = {
      event_id: `DHCP-EVT-${Date.now()}-${crypto.randomBytes(3).toString('hex')}`,
      mac_address: String(macAddress || 'Unknown').toUpperCase(),
      ip_address: String(ipAddress || '0.0.0.0'),
      previous_ip: previousIp ? String(previousIp) : null,
      event_type: String(eventType),
      dhcp_message_type: String(dhcpMessageType || ''),
      hostname: String(hostname || ''),
      details: typeof details === 'object' ? JSON.stringify(details) : String(details || ''),
      observed_at: new Date().toISOString()
    };
    try {
      this.stmtInsertDhcpEvent.run(entry);
    } catch (_) {}
    return entry;
  }

  getInventory({ category = '', includeUnoccupied = false } = {}) {
    try {
      let rows = db.prepare('SELECT * FROM office_equipment_inventory ORDER BY is_apipa_fault DESC, last_seen_at DESC').all();
      if (!includeUnoccupied) {
        rows = rows.filter((r) => r.status !== 'NO_ICMP_RESPONSE' && r.equipment_type !== 'UNOCCUPIED_IP');
      }
      if (category && category !== 'ALL') {
        const catLower = category.toLowerCase();
        rows = rows.filter(
          (r) =>
            String(r.equipment_category || '').toLowerCase() === catLower ||
            String(r.equipment_type || '').toLowerCase() === catLower ||
            (catLower === 'apipa_unconfigured' && r.is_apipa_fault === 1)
        );
      }
      return rows.map((r) => ({
        ...r,
        openPorts: JSON.parse(r.open_ports_json || '[]'),
        isApipaFault: Boolean(r.is_apipa_fault)
      }));
    } catch (_) {
      return [];
    }
  }

  getAllEquipmentRecords(opts = {}) {
    return this.getInventory(opts);
  }

  getEquipmentSummaryCounts() {
    const all = this.getInventory({ includeUnoccupied: false });
    const summary = {
      totalActiveEquipment: all.length,
      printers: 0,
      computers: 0,
      voipPhones: 0,
      networkGear: 0,
      cameras: 0,
      apipaIssues: 0
    };
    for (const item of all) {
      if (item.isApipaFault || item.equipment_category === 'apipa_unconfigured') summary.apipaIssues++;
      if (item.equipment_type === 'PRINTER' || item.equipment_category === 'printers') summary.printers++;
      else if (item.equipment_type === 'VOIP_PHONE' || item.equipment_category === 'voip_phones') summary.voipPhones++;
      else if (item.equipment_type === 'CAMERA_NVR') summary.cameras++;
      else if (
        item.equipment_type === 'NETWORK_INFRASTRUCTURE' ||
        item.equipment_category === 'switches' ||
        item.equipment_category === 'routers_firewalls'
      ) {
        summary.networkGear++;
      } else {
        summary.computers++;
      }
    }
    summary.totalCount = summary.totalActiveEquipment;
    summary.apipaCount = summary.apipaIssues;
    summary.printersCount = summary.printers;
    summary.computersCount = summary.computers;
    summary.voipCount = summary.voipPhones;
    return summary;
  }

  getRecentDhcpEvents(limit = 30) {
    try {
      return db.prepare('SELECT * FROM dhcp_and_ip_events ORDER BY observed_at DESC LIMIT ?').all(limit);
    } catch (_) {
      return [];
    }
  }
}

const equipmentInventoryRepository = new EquipmentInventoryRepository();

module.exports = {
  EquipmentInventoryRepository,
  equipmentInventoryRepository
};
