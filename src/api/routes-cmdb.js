/**
 * EJI CMDB & Configuration Management API Routes
 */

const express = require('express');
const router = express.Router();
const os = require('os');
const { db } = require('../db/database');
const CmdbRepository = require('../database/repositories/cmdb-repository');
const IpamService = require('../network/routing/ipam-service');
const { authenticate } = require('./middleware');

router.use(authenticate);

// GET /api/cmdb/hardware - List hardware CIs
router.get('/hardware', (req, res) => {
  try {
    const { location, formFactor, limit } = req.query;
    const items = CmdbRepository.listHardwareCis({
      location: location || null,
      formFactor: formFactor || null,
      limit: limit ? parseInt(limit, 10) : 100
    });
    res.json({ success: true, count: items.length, hardware: items });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/cmdb/hardware - Create hardware CI
router.post('/hardware', (req, res) => {
  try {
    const { assetTag, model, vendor, formFactor, location, rackUnit, cpuDetails, ramGb, storageGb, ownerDepartment, nodeId } = req.body;
    if (!assetTag) {
      return res.status(400).json({ success: false, error: 'assetTag is required' });
    }

    const item = CmdbRepository.createHardwareCi({
      nodeId,
      assetTag,
      model,
      vendor,
      formFactor,
      location,
      rackUnit,
      cpuDetails,
      ramGb: ramGb ? parseFloat(ramGb) : null,
      storageGb: storageGb ? parseFloat(storageGb) : null,
      ownerDepartment
    });

    res.status(201).json({ success: true, hardware: item });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/cmdb/hardware/:id - Get hardware CI details
router.get('/hardware/:id', (req, res) => {
  try {
    const item = CmdbRepository.getHardwareCiById(req.params.id);
    if (!item) return res.status(404).json({ success: false, error: 'Hardware CI not found' });
    res.json({ success: true, hardware: item });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// PATCH /api/cmdb/hardware/:id - Update hardware CI
router.patch('/hardware/:id', (req, res) => {
  try {
    const updated = CmdbRepository.updateHardwareCi(req.params.id, req.body);
    res.json({ success: true, hardware: updated });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/cmdb/interfaces - Add interface
router.post('/interfaces', (req, res) => {
  try {
    const { ciId, interfaceName, macAddress, ipv4Address, subnetMask, speedMbps, vlanId } = req.body;
    if (!ciId || !interfaceName) {
      return res.status(400).json({ success: false, error: 'ciId and interfaceName are required' });
    }

    const iface = CmdbRepository.addInterface({
      ciId,
      interfaceName,
      macAddress,
      ipv4Address,
      subnetMask,
      speedMbps: speedMbps ? parseInt(speedMbps, 10) : 1000,
      vlanId: vlanId ? parseInt(vlanId, 10) : 1
    });

    res.status(201).json({ success: true, interface: iface });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/cmdb/subnets - List subnets
router.get('/subnets', (req, res) => {
  try {
    const subnets = CmdbRepository.listSubnets();
    res.json({ success: true, count: subnets.length, subnets });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/cmdb/subnets - Create subnet
router.post('/subnets', (req, res) => {
  try {
    const { networkCidr, vlanId, vlanName, gatewayIp, dnsServers, environment, location } = req.body;
    if (!networkCidr) return res.status(400).json({ success: false, error: 'networkCidr is required' });

    const subnet = CmdbRepository.createSubnet({
      networkCidr,
      vlanId: vlanId ? parseInt(vlanId, 10) : 1,
      vlanName,
      gatewayIp,
      dnsServers,
      environment,
      location
    });

    res.status(201).json({ success: true, subnet });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/cmdb/subnets/:cidr/next-free - Next available IP
router.get('/subnets/:cidr/next-free', (req, res) => {
  try {
    const decodedCidr = decodeURIComponent(req.params.cidr);
    const result = IpamService.findNextFreeIp(decodedCidr);
    res.json({ success: true, ...result });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/cmdb/graph - Full dependency topology graph
router.get('/graph', (req, res) => {
  try {
    const graph = CmdbRepository.getFullDependencyGraph();
    res.json({ success: true, graph });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/cmdb/scan-local-network
 * Real-world LAN sweep & OS kernel ARP discovery synced directly into authoritative CMDB
 * Zero-Fiction Standard: Restricts discovery strictly to true physical interface and subnet.
 */
router.post('/scan-local-network', async (req, res) => {
  try {
    const { getArpTable, resolveOuiVendor } = require('../tools/ip-scanner');
    const { logAction } = require('../core/audit-logger');
    const { getPhysicalNetworkInfo, isVirtualHypervisorIp } = require('../network/routing/physical-network-detector');

    // 1. Authoritative physical network introspection
    const netInfo = getPhysicalNetworkInfo();
    const localSubnet = netInfo.subnetCidr || '10.168.195.0/24';
    const subnetPrefix = netInfo.hostIp ? netInfo.hostIp.split('.').slice(0, 3).join('.') + '.' : '10.168.195.';

    // 2. Read real kernel ARP cache from operating system, filtered to physical adapter/subnet
    const arpTable = await getArpTable({
      interfaceIndex: netInfo.interfaceIndex,
      subnetPrefix: subnetPrefix
    });

    // 3. Filter valid unicast physical hardware addresses within physical subnet scope
    const validArp = arpTable.filter(e => 
      e.mac && 
      e.mac !== 'FF:FF:FF:FF:FF:FF' && 
      e.mac !== '00:00:00:00:00:00' &&
      !e.mac.startsWith('01:00:5E') && 
      !e.mac.startsWith('33:33') && 
      !e.ip.endsWith('.255') &&
      !isVirtualHypervisorIp(e.ip) &&
      e.ip.startsWith(subnetPrefix)
    );

    let syncedCount = 0;
    const syncedDevices = [];

    for (const dev of validArp.slice(0, 50)) {
      const cleanMac = dev.mac.toUpperCase();
      const vendor = resolveOuiVendor(cleanMac);

      const existingIface = db.prepare('SELECT ci_id FROM cmdb_interfaces WHERE mac_address = ? OR ipv4_address = ?').get(cleanMac, dev.ip);

      let ciId;
      if (existingIface) {
        ciId = existingIface.ci_id;
      } else {
        let formFactor = 'desktop';
        let assetTagPrefix = 'HOST';
        let modelDesc = `${vendor} Physical Endpoint`;

        if (dev.ip === netInfo.gatewayIp) {
          formFactor = 'router';
          assetTagPrefix = 'NET-GW';
          modelDesc = `${vendor} Core Gateway Router`;
        } else if (vendor.includes('MikroTik')) {
          formFactor = 'router';
          assetTagPrefix = 'NET-ROUTER';
          modelDesc = `${vendor} Device`;
        } else if (vendor.includes('Cisco') || vendor.includes('Ubiquiti') || vendor.includes('TP-Link')) {
          formFactor = vendor.includes('Ubiquiti') ? 'ap' : 'switch';
          assetTagPrefix = 'NET';
          modelDesc = `${vendor} Infrastructure Node`;
        } else if (vendor.includes('Dell') || vendor.includes('Hewlett') || vendor.includes('Intel')) {
          formFactor = 'rackmount_server';
          assetTagPrefix = 'SRV';
          modelDesc = `${vendor} Server / Appliance`;
        } else if (vendor.includes('Apple') || vendor.includes('Xiaomi') || vendor.includes('Samsung') || vendor.includes('Private / Randomized')) {
          formFactor = vendor.includes('Apple') ? 'laptop' : 'laptop';
          assetTagPrefix = 'CLT';
          modelDesc = `${vendor} Client Node`;
        } else if (vendor.includes('Lite-On') || vendor.includes('Lenovo')) {
          formFactor = 'desktop';
          assetTagPrefix = 'WS';
          modelDesc = `${vendor} Workstation`;
        }

        const ipSlug = dev.ip.replace(/\./g, '-');
        const assetTag = `${assetTagPrefix}-${ipSlug}`;

        const newCi = CmdbRepository.createHardwareCi({
          assetTag,
          model: modelDesc,
          vendor: vendor,
          formFactor,
          location: `Physical Operations Subnet (${localSubnet})`,
          ownerDepartment: 'Discovered via Physical Hardware ARP'
        });

        ciId = newCi.id;

        CmdbRepository.addInterface({
          ciId: newCi.id,
          interfaceName: 'eth0',
          macAddress: cleanMac,
          ipv4Address: dev.ip,
          subnetMask: netInfo.subnetMask || '255.255.255.0',
          speedMbps: 1000,
          isUp: 1,
          vlanId: 1
        });

        syncedCount++;
      }

      syncedDevices.push({
        ciId,
        ip: dev.ip,
        mac: cleanMac,
        vendor,
        type: dev.type
      });
    }

    logAction({
      userId: req.user ? req.user.id : 'SYSTEM',
      username: req.user ? req.user.username : 'EJI Core Engine',
      role: req.user ? req.user.role : 'network_admin',
      action: 'CMDB_LAN_DISCOVERY_SYNC',
      resource: localSubnet,
      details: `Discovered ${validArp.length} physical ARP devices on ${localSubnet}, synced ${syncedCount} new CIs into CMDB.`
    });

    res.json({
      success: true,
      subnet: localSubnet,
      totalArpDiscovered: validArp.length,
      syncedToCmdbCount: syncedCount,
      devices: syncedDevices
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;
