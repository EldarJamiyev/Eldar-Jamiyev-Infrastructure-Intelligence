/**
 * Verification script for live EJII server and physical telemetry
 */
const http = require('http');

function post(path, body, token) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(body || {});
    const headers = {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(payload)
    };
    if (token) headers['Authorization'] = 'Bearer ' + token;

    const req = http.request({
      hostname: 'localhost',
      port: 8443,
      path,
      method: 'POST',
      headers
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch (e) { resolve({ status: res.statusCode, data }); }
      });
    });
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

function get(path, token) {
  return new Promise((resolve, reject) => {
    const headers = {};
    if (token) headers['Authorization'] = 'Bearer ' + token;
    http.get({
      hostname: 'localhost',
      port: 8443,
      path,
      headers
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch (e) { resolve({ status: res.statusCode, data }); }
      });
    }).on('error', reject);
  });
}

async function run() {
  // 1. Login
  const auth = await post('/api/auth/login', { username: 'netadmin', password: 'NetadminPassword2026!' });
  const token = auth.body.token;
  console.log('Login Status:', auth.status, 'Token acquired.');

  // 2. Topology
  const topo = await get('/api/network/topology', token);
  console.log('\n--- Real Network Fleet Nodes ---');
  for (const n of topo.body.nodes) {
    console.log(`${n.id.padEnd(16)} | ${n.name.padEnd(35)} | ${n.hostname_or_ip.padEnd(16)} | Status: ${(n.status || '').padEnd(10)} | Latency: ${n.last_latency_ms}ms`);
  }

  // 3. Test on-demand dual probes
  console.log('\n--- Testing On-Demand Dual Probes ---');
  for (const id of ['NODE-GW-01', 'NODE-DNS-PUBLIC', 'NODE-WEB-HTTPS', 'NODE-LOCAL-HOST']) {
    const probe = await post('/api/network/probe/' + id, {}, token);
    const p = probe.body.probe || {};
    console.log(`Probe ${id.padEnd(16)} -> Status: ${probe.body.node.status} | Latency: ${probe.body.node.last_latency_ms}ms | Protocol: ${p.probeType} | ${p.details}`);
  }

  // 4. Test Packet Capture Status & Frames
  console.log('\n--- Testing Live Packet Capture Engine ---');
  const capStatus = await get('/api/network/capture/status', token);
  console.log('Capture Active:', capStatus.body.active, 'Total Sequenced Frames:', capStatus.body.totalSequenced);

  // 5. Test CMDB Physical LAN Scan
  console.log('\n--- Testing CMDB Physical LAN Discovery ---');
  const scan = await post('/api/cmdb/scan-local-network', {}, token);
  console.log('Subnet Scoped:', scan.body.subnet);
  console.log('Total ARP Discovered:', scan.body.totalArpDiscovered);
  console.log('Synced to CMDB:', scan.body.syncedToCmdbCount);
  if (scan.body.devices && scan.body.devices.length > 0) {
    console.log('Sample Discovered Devices:');
    for (const d of scan.body.devices.slice(0, 5)) {
      console.log(`  ${d.ip.padEnd(16)} | MAC: ${d.mac} | Vendor: ${d.vendor}`);
    }
  }

  // 6. Check Active Incidents in Database
  const incRes = await get('/api/rca/incidents?status=open', token);
  console.log('\n--- Active Incidents Count ---');
  console.log('Open Incidents:', incRes.body.count || (incRes.body.incidents ? incRes.body.incidents.length : 0));
}

run().catch(console.error);
