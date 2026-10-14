/**
 * EJII Advanced IP Scanner & Angry IP Scanner Engine
 * High-throughput asynchronous subnet sweeper, real ARP cache polling, and MAC OUI vendor resolution.
 * 100% Genuine Network Telemetry — Zero Simulated Data.
 */

const { exec } = require('child_process');
const { performance } = require('perf_hooks');
const { IS_WINDOWS } = require('../config');
const { checkPort } = require('../protocols/tcp-port');

/**
 * Built-in IEEE OUI (Organizationally Unique Identifier) Hardware Database
 */
const OUI_DATABASE = {
  '00:0C:29': 'VMware, Inc.',
  '00:50:56': 'VMware, Inc.',
  '00:05:69': 'VMware, Inc.',
  '00:1A:11': 'Google, Inc.',
  '08:00:27': 'Oracle VirtualBox',
  '52:54:00': 'QEMU / KVM Virtual NIC',
  '00:15:5D': 'Microsoft Corporation (Hyper-V)',
  '00:03:FF': 'Microsoft Corporation',
  'DC:A6:32': 'Raspberry Pi Trading Ltd',
  'B8:27:EB': 'Raspberry Pi Foundation',
  '00:1C:B3': 'Apple, Inc.',
  'AC:DE:48': 'Apple, Inc.',
  'F0:18:98': 'Apple, Inc.',
  '00:1E:67': 'Intel Corporation',
  '00:26:B9': 'Dell Inc.',
  'D4:BE:D9': 'Dell Inc.',
  '00:1B:78': 'Hewlett Packard',
  '2C:54:2D': 'Cisco Systems, Inc.',
  '00:01:42': 'Cisco Systems, Inc.',
  '00:08:E3': 'Cisco Systems, Inc.',
  'D8:B3:70': 'Ubiquiti Networks Inc.'
};

/**
 * Resolve MAC address to hardware manufacturer
 * @param {string} mac 
 */
function resolveOuiVendor(mac) {
  if (!mac) return 'Unknown Vendor';
  const cleanMac = mac.replace(/[:-]/g, '').toUpperCase();
  if (cleanMac.length < 6) return 'Invalid MAC';

  const prefix = `${cleanMac.slice(0, 2)}:${cleanMac.slice(2, 4)}:${cleanMac.slice(4, 6)}`;
  return OUI_DATABASE[prefix] || 'Unregistered / Private Vendor';
}

/**
 * Read the host's actual ARP cache table
 */
function getArpTable() {
  return new Promise((resolve) => {
    const cmd = IS_WINDOWS ? 'arp.exe -a' : 'ip neigh show || arp -n';
    exec(cmd, { timeout: 4000 }, (error, stdout) => {
      const raw = stdout || '';
      const entries = [];
      const lines = raw.split('\n');

      for (const line of lines) {
        // Windows format: "  192.168.1.1           00-11-22-33-44-55     dynamic"
        const match = line.trim().match(/([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\s+([0-9a-fA-F:-]{17})\s+(\w+)/i);
        if (match) {
          const ip = match[1];
          const mac = match[2].replace(/-/g, ':').toUpperCase();
          const type = match[3];
          entries.push({
            ip,
            mac,
            type,
            vendor: resolveOuiVendor(mac)
          });
        }
      }

      resolve(entries);
    });
  });
}

/**
 * Sweep a specific IPv4 subnet range using concurrent TCP connect probes
 * @param {string} subnetBase (e.g. '192.168.1')
 * @param {number} startHost (default: 1)
 * @param {number} endHost (default: 254)
 * @param {number} concurrency (default: 32)
 */
async function sweepSubnet(subnetBase = '192.168.1', startHost = 1, endHost = 30, concurrency = 20) {
  const startTime = performance.now();
  const cleanBase = subnetBase.trim().replace(/\.$/, '');

  // Retrieve ARP table first for MAC resolution
  const arpEntries = await getArpTable();
  const arpMap = new Map();
  for (const entry of arpEntries) {
    arpMap.set(entry.ip, entry);
  }

  const hostsToScan = [];
  const start = Math.max(1, startHost);
  const end = Math.min(254, endHost);

  for (let i = start; i <= end; i++) {
    hostsToScan.push(`${cleanBase}.${i}`);
  }

  const discoveredHosts = [];
  let index = 0;

  // Common quick-check ports (HTTP, DNS, SMB, HTTPS, SSH, RDP)
  const probePorts = [80, 443, 445, 22, 53, 3389];

  async function worker() {
    while (index < hostsToScan.length) {
      const host = hostsToScan[index++];
      if (!host) break;

      // Quick TCP probe to port 80 or 445 to test if host is alive
      let isUp = false;
      let openPort = null;
      let latency = null;

      for (const p of probePorts) {
        const res = await checkPort(host, p, 300);
        if (res.status === 'OPEN') {
          isUp = true;
          openPort = p;
          latency = res.connectLatencyMs;
          break;
        } else if (res.status === 'CLOSED') {
          // CLOSED means host is online and sent RST!
          isUp = true;
          openPort = p;
          latency = res.connectLatencyMs;
          break;
        }
      }

      const arp = arpMap.get(host);
      if (isUp || arp) {
        discoveredHosts.push({
          ip: host,
          status: isUp ? 'ONLINE' : 'CACHED_ARP',
          responsivePort: openPort,
          latencyMs: latency,
          macAddress: arp ? arp.mac : 'Unknown',
          vendor: arp ? arp.vendor : 'Unknown',
          arpType: arp ? arp.type : 'None'
        });
      }
    }
  }

  const workers = [];
  for (let w = 0; w < Math.min(concurrency, hostsToScan.length); w++) {
    workers.push(worker());
  }
  await Promise.all(workers);

  const durationMs = parseFloat((performance.now() - startTime).toFixed(2));

  return {
    subnet: `${cleanBase}.${start}-${end}`,
    totalScanned: hostsToScan.length,
    discoveredCount: discoveredHosts.length,
    durationMs,
    hosts: discoveredHosts
  };
}

module.exports = {
  resolveOuiVendor,
  getArpTable,
  sweepSubnet
};
