/**
 * EJII Test Suite: Ultra IP & Infrastructure Fleet Scanner
 * Verifies subnet range parsing, OUI database, NetBIOS query, Wake-on-LAN 102-byte packet structure, and API routes.
 * Zero-Simulation Mandate.
 */

const assert = require('assert');
const {
  parseIpTargets,
  resolveOuiVendor,
  generateWolPacket,
  queryNetBiosName,
  queryReverseDns,
  classifyDevice,
  ultraIpScanner
} = require('../src/tools/ip-scanner');

async function runIpScannerSuiteTests() {
  console.log('\n========================================================================');
  console.log('  TEST SUITE: ULTRA IP & INFRASTRUCTURE FLEET SCANNER                   ');
  console.log('========================================================================');

  // [Test 1] Subnet & Range Target Parsing
  console.log('[Test 1] Testing Subnet & IP Range Parsing (CIDR, Dash, Single IP)...');
  
  // Test CIDR /24
  const cidr24 = parseIpTargets('10.168.195.0/24');
  assert.strictEqual(cidr24.length, 254, 'CIDR /24 must parse into exactly 254 usable host IPs');
  assert.strictEqual(cidr24[0], '10.168.195.1');
  assert.strictEqual(cidr24[253], '10.168.195.254');

  // Test CIDR /29
  const cidr29 = parseIpTargets('192.168.1.0/29');
  assert.strictEqual(cidr29.length, 6, 'CIDR /29 must parse into 6 usable host IPs');

  // Test Dash Range
  const dashRange = parseIpTargets('10.168.195.1-50');
  assert.strictEqual(dashRange.length, 50, 'Dash range 1-50 must parse into 50 IPs');
  assert.strictEqual(dashRange[0], '10.168.195.1');
  assert.strictEqual(dashRange[49], '10.168.195.50');

  // Test Full Dash Range
  const fullDash = parseIpTargets('10.168.195.10 - 10.168.195.15');
  assert.strictEqual(fullDash.length, 6, 'Full dash range must parse into 6 IPs');

  // Test Single IP
  const singleIp = parseIpTargets('10.168.195.33');
  assert.strictEqual(singleIp.length, 1);
  assert.strictEqual(singleIp[0], '10.168.195.33');

  console.log('  ✓ Subnet parser accurately supports CIDR, dash ranges, and individual addresses.');

  // [Test 2] IEEE OUI Database & Vendor Resolution
  console.log('[Test 2] Testing IEEE OUI Hardware Database & Private MAC Detection...');
  
  assert.ok(resolveOuiVendor('64:12:25:AA:BB:CC').includes('MikroTik'), 'Must resolve MikroTik OUI');
  assert.ok(resolveOuiVendor('3C:52:82:11:22:33').includes('Intel'), 'Must resolve Intel OUI');
  assert.ok(resolveOuiVendor('6C:3B:E5:44:55:66').includes('Apple'), 'Must resolve Apple OUI');
  assert.ok(resolveOuiVendor('A4:AE:11:77:88:99').includes('Lite-On') || resolveOuiVendor('A4:AE:11:77:88:99').includes('Lenovo'), 'Must resolve Lenovo/Lite-On OUI');

  // Test Randomized Private Mobile MAC (locally administered bit = 1: x2, x6, xA, xE)
  const privateVendor = resolveOuiVendor('02:A1:B2:C3:D4:E5');
  assert.ok(privateVendor.includes('Private') || privateVendor.includes('Randomized') || privateVendor.includes('Local'), 'Must flag randomized private MAC');
  console.log('  ✓ IEEE OUI hardware database accurately resolves genuine and private MAC addresses.');

  // [Test 3] Wake-On-LAN (WOL) 102-Byte Magic Packet Structure
  console.log('[Test 3] Testing Wake-On-LAN Magic Packet Generation Buffer Structure...');
  
  const testMac = '38:B1:DB:45:8F:12';
  const magicPacket = generateWolPacket(testMac);
  
  // Requirement: exactly 102 bytes
  assert.strictEqual(magicPacket.length, 102, 'WOL magic packet must be exactly 102 bytes');

  // Requirement: first 6 bytes must be all 0xFF
  for (let i = 0; i < 6; i++) {
    assert.strictEqual(magicPacket[i], 0xFF, `Byte ${i} of WOL header must be 0xFF`);
  }

  // Requirement: 16 iterations of target 6-byte MAC
  const expectedMacBytes = [0x38, 0xB1, 0xDB, 0x45, 0x8F, 0x12];
  for (let iter = 0; iter < 16; iter++) {
    const offset = 6 + iter * 6;
    for (let b = 0; b < 6; b++) {
      assert.strictEqual(
        magicPacket[offset + b],
        expectedMacBytes[b],
        `Iteration ${iter} byte ${b} must match target MAC`
      );
    }
  }

  // Test invalid MAC format rejection
  assert.throws(() => generateWolPacket('invalid-mac-str'));
  assert.throws(() => generateWolPacket(''));
  console.log('  ✓ WOL Magic Packet verified: 102 bytes with 6x 0xFF header + 16x MAC sequence.');

  // [Test 4] NetBIOS & Reverse DNS Query Safety
  console.log('[Test 4] Testing NetBIOS & Reverse DNS Query Safety on Local Interfaces...');
  
  // Query loopback or local IP (should resolve or safely return null without throwing)
  const nbResult = await queryNetBiosName('127.0.0.1', 300);
  assert.ok(nbResult === null || typeof nbResult === 'object', 'NetBIOS query must return object or null');

  const dnsResult = await queryReverseDns('127.0.0.1', 300);
  assert.ok(dnsResult === null || typeof dnsResult === 'string', 'Reverse DNS must return string or null');
  console.log('  ✓ Multi-protocol queries executed safely with robust timeouts.');

  // [Test 5] Device Role Classification
  console.log('[Test 5] Testing Device Role & OS Fingerprinting Logic...');
  
  const routerHost = { ip: '10.168.195.1', vendor: 'MikroTik RouterOS', openServices: [] };
  assert.ok(classifyDevice(routerHost).includes('Gateway / Router'));

  const printerHost = { ip: '10.168.195.80', vendor: 'Hewlett-Packard', openServices: [{ port: 9100 }] };
  assert.ok(classifyDevice(printerHost).includes('Printer'));

  const camHost = { ip: '10.168.195.99', vendor: 'Hikvision Digital', openServices: [{ port: 554 }] };
  assert.ok(classifyDevice(camHost).includes('Camera') || classifyDevice(camHost).includes('IoT'));

  const workstationHost = { ip: '10.168.195.33', computerName: 'NOC-WORKSTATION', vendor: 'Intel Corporation', openServices: [{ port: 445 }] };
  assert.ok(classifyDevice(workstationHost).includes('Windows'));
  console.log('  ✓ OS & device role fingerprinting accurately categorizes network endpoints.');

  // [Test 6] API Endpoints /api/network/scanner/*
  console.log('[Test 6] Testing Express Scanner Routes (/api/network/scanner/*)...');
  const routesNetwork = require('../src/api/routes-network');
  
  const startRoute = routesNetwork.stack.find(l => l.route && l.route.path === '/scanner/start');
  assert.ok(startRoute, 'Route /scanner/start must exist');

  const statusRoute = routesNetwork.stack.find(l => l.route && l.route.path === '/scanner/status');
  assert.ok(statusRoute, 'Route /scanner/status must exist');

  const wolRoute = routesNetwork.stack.find(l => l.route && l.route.path === '/scanner/wol');
  assert.ok(wolRoute, 'Route /scanner/wol must exist');

  // Test WOL route validation
  let wolResponse = null;
  wolRoute.route.stack[0].handle({
    body: { macAddress: '38:B1:DB:45:8F:12' }
  }, {
    json: (res) => { wolResponse = res; },
    status: () => ({ json: (res) => { wolResponse = res; } })
  });
  // Wait brief tick
  await new Promise(r => setTimeout(r, 50));
  assert.ok(wolResponse, 'WOL response must be returned');
  assert.strictEqual(wolResponse.bytesSent, 102, 'WOL response must confirm 102 bytes sent');
  console.log('  ✓ Endpoint POST /api/network/scanner/wol verified with 102-byte transmission.');

  console.log('\n========================================================================');
  console.log('  ALL ULTRA IP SCANNER TESTS PASSED 100% GREEN!                         ');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runIpScannerSuiteTests().then(() => process.exit(0)).catch(err => {
    console.error('IP Scanner test suite failed:', err);
    process.exit(1);
  });
}

module.exports = { runIpScannerSuiteTests };
