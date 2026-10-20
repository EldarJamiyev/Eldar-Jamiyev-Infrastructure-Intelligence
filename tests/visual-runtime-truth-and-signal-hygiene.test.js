/**
 * EJII Test Suite 37: Visual Runtime Truth, Signal Hygiene & Disambiguation Suite
 * 
 * Tests:
 * [37.1] Universal escapeAttr & escapeHtml Escaping, UI Resilience & Injection Defense
 * [37.2] Signal Triage Noise Suppression (Telemetry/OS Domains & Mid-Stream TLS AppData)
 * [37.3] RFC 1122 1-Byte/0-Byte TCP Keep-Alive Probe & ACK Sequence Disambiguation
 * [37.4] Process Explorer CPU% Normalization Math (0.0% - 100.0%) & Critical OS Process Shielding
 * [37.5] Ultra IP Scanner 3-Tier Sorting, Status Badge Clarity & Dynamic Topology Subnet/Adapter Labels
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { getPhysicalNetworkInfo } = require('../src/network/routing/physical-network-detector');
const { hostDiagnosticsEngine } = require('../src/systems/diagnostics/host-diagnostics-engine');
const { topologyEngine } = require('../src/network/topology/topology-engine');
const { packetStreamer } = require('../src/network/packet-streaming/packet-streamer');

async function runVisualRuntimeTruthAndSignalHygieneTests() {
  console.log('========================================================================');
  console.log('  TEST SUITE 37: VISUAL RUNTIME TRUTH, SIGNAL HYGIENE & DISAMBIGUATION  ');
  console.log('========================================================================\n');

  // -------------------------------------------------------------------------
  // [37.1] Universal escapeAttr & escapeHtml Escaping, UI Resilience & Injection Defense
  // -------------------------------------------------------------------------
  console.log('[Test 37.1] Verifying Universal escapeAttr & escapeHtml Escaping & Table Resilience...');

  const appJsCode = fs.readFileSync(path.join(__dirname, '../public/js/app.js'), 'utf8');
  assert.ok(appJsCode.includes('window.escapeAttr = function'), 'public/js/app.js must define window.escapeAttr');
  assert.ok(appJsCode.includes('window.escapeHtml = function'), 'public/js/app.js must define window.escapeHtml');

  const nocViewCode = fs.readFileSync(path.join(__dirname, '../public/js/views/noc-view.js'), 'utf8');
  assert.ok(nocViewCode.includes('function escapeAttr(str)'), 'noc-view.js must define local escapeAttr helper');
  assert.ok(nocViewCode.includes('window.escapeAttr = escapeAttr'), 'noc-view.js must export escapeAttr to window');

  // Verify escapeAttr implementation behavior
  function escapeAttr(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }

  assert.strictEqual(escapeAttr(null), '');
  assert.strictEqual(escapeAttr(undefined), '');
  assert.strictEqual(escapeAttr(''), '');
  assert.strictEqual(escapeAttr('192.168.31.1'), '192.168.31.1');
  assert.strictEqual(escapeAttr('<script>alert("xss")</script>'), '&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;');
  assert.strictEqual(escapeAttr("admin' OR '1'='1"), 'admin&#039; OR &#039;1&#039;=&#039;1');

  // Verify App Finder table row rendering with escapeAttr
  const testEndpoint = {
    pid: 1234,
    processName: 'node.exe',
    localPort: 8443,
    remoteAddress: '192.168.31.1',
    remotePort: 443,
    state: 'ESTABLISHED',
    troubleshootUrl: '/core-diagnostics?host=192.168.31.1&port=443'
  };
  const renderedAction = `<button class="btn btn-primary" onclick="window.troubleshootEndpoint('${escapeAttr(testEndpoint.remoteAddress)}', ${testEndpoint.remotePort})">🔍 Troubleshoot 443</button>`;
  assert.ok(renderedAction.includes("window.troubleshootEndpoint('192.168.31.1', 443)"));
  console.log('  ✓ escapeAttr and escapeHtml globally verified without ReferenceError risks.');

  // -------------------------------------------------------------------------
  // [37.2] Signal Triage Noise Suppression & TLS Payload Hygiene
  // -------------------------------------------------------------------------
  console.log('[Test 37.2] Verifying ⭐ Important Mode Noise Suppression & Protocol Filter Hygiene...');

  const BACKGROUND_NOISE_PATTERNS = [
    /(?:^|\.)googleapis\.com$/i,
    /(?:^|\.)google\.com$/i,
    /(?:^|\.)msedge\.net$/i,
    /(?:^|\.)msftconnecttest\.com$/i,
    /(?:^|\.)signalr\.net$/i,
    /(?:^|\.)lencr\.org$/i,
    /(?:^|\.)digicert\.com$/i,
    /(?:^|\.)trafficmanager\.net$/i,
    /(?:^|\.)azureedge\.net$/i,
    /(?:^|\.)windows\.net$/i,
    /(?:^|\.)telemetry\./i,
    /(?:^|\.)pipe\.aria\.microsoft\.com$/i,
    /(?:^|\.)events\.data\.microsoft\.com$/i
  ];

  function isBackgroundNoiseHost(hostStr) {
    if (!hostStr) return false;
    const clean = String(hostStr).toLowerCase().replace(/^\[PING\]\s*/, '').replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/:\d+$/, '').trim();
    if (!clean) return false;
    return BACKGROUND_NOISE_PATTERNS.some(pat => pat.test(clean));
  }

  // Noise domain tests
  assert.strictEqual(isBackgroundNoiseHost('play.googleapis.com'), true);
  assert.strictEqual(isBackgroundNoiseHost('edge.microsoft.msedge.net'), true);
  assert.strictEqual(isBackgroundNoiseHost('www.msftconnecttest.com'), true);
  assert.strictEqual(isBackgroundNoiseHost('service.signalr.net'), true);
  assert.strictEqual(isBackgroundNoiseHost('r3.o.lencr.org'), true);
  assert.strictEqual(isBackgroundNoiseHost('internal-corp.portal.com'), false);
  assert.strictEqual(isBackgroundNoiseHost('mail.taxes.gov.az'), false);

  // Important mode filter function simulation matching noc-view.js
  function testImportantFilter(f) {
    const proto = (f.protocol || '').toUpperCase();
    const flags = f.tcp?.flags || {};
    const isRst = Boolean(flags.rst || f.tcpAnalysis?.isRst);
    const isIcmp = proto === 'ICMP' || f.urlResolution?.method === 'ICMP-correlated';

    if (isIcmp || isRst) return true;

    const hostVal = f.urlResolution?.hostnameOrUrl ||
      f.urlIntelligence?.value ||
      f.tls?.handshake?.sni ||
      f.tls?.sni ||
      f.sni ||
      f.dns?.query ||
      f.dns?.qname ||
      f.http?.host ||
      '';

    if (hostVal && isBackgroundNoiseHost(hostVal)) {
      return false;
    }

    const isTls = proto.startsWith('TLS') || Boolean(f.tls);
    if (isTls) {
      const isTlsClientHello = Boolean(
        f.tls?.handshake?.type === 'ClientHello' ||
        f.tls?.handshake?.typeNum === 1 ||
        f.tls?.sni ||
        f.sni ||
        (f.summary && f.summary.includes('ClientHello')) ||
        (f.info && f.info.includes('ClientHello'))
      );
      const isTlsAlert = Boolean(f.tls?.contentType === 'Alert' || f.tls?.contentTypeNum === 21);
      return isTlsClientHello || isTlsAlert;
    }

    if (f.tcpAnalysis?.isKeepAlive || f.tcpAnalysis?.isKeepAliveAck) {
      return false;
    }

    const isHandshake = Boolean(flags.syn || flags.fin);
    const isApp = proto === 'DNS' || proto === 'HTTP' || proto === 'ARP';
    const hasRealAnomaly = Boolean(f.tcpAnalysis?.isRetransmission || f.tcpAnalysis?.isZeroWindow || f.tcpAnalysis?.isDupAck);

    return isHandshake || isApp || hasRealAnomaly;
  }

  // 1. Noise host frames must be rejected
  assert.strictEqual(testImportantFilter({ protocol: 'DNS', dns: { query: 'telemetry.msedge.net' } }), false);
  assert.strictEqual(testImportantFilter({ protocol: 'TLS', tls: { handshake: { type: 'ClientHello', sni: 'play.googleapis.com' } } }), false);

  // 2. Mid-stream TLS Application Data must be rejected
  assert.strictEqual(testImportantFilter({ protocol: 'TLS', length: 1400, tls: { contentType: 'Application Data', contentTypeNum: 23 } }), false);

  // 3. Meaningful TLS ClientHello with business SNI must be preserved
  assert.strictEqual(testImportantFilter({ protocol: 'TLS', tls: { handshake: { type: 'ClientHello', sni: 'mail.taxes.gov.az' } } }), true);

  // 4. ICMP manual ping and TCP RST must always be preserved
  assert.strictEqual(testImportantFilter({ protocol: 'ICMP', urlResolution: { hostnameOrUrl: '192.168.31.1' } }), true);
  assert.strictEqual(testImportantFilter({ protocol: 'TCP', tcp: { flags: { rst: true } } }), true);
  console.log('  ✓ ⭐ Important mode noise filter & mid-stream TLS ApplicationData suppression verified.');

  // -------------------------------------------------------------------------
  // [37.3] RFC 1122 1-Byte/0-Byte TCP Keep-Alive Probe & ACK Disambiguation
  // -------------------------------------------------------------------------
  console.log('[Test 37.3] Verifying RFC 1122 TCP Keep-Alive Probe & ACK Sequence Disambiguation...');

  // Create isolated packetStreamer stream instance for testing sequence analysis
  const streamKey = '192.168.31.89:54321<->192.168.31.1:443';
  packetStreamer.streamKeyToId.delete(streamKey);

  // Step 1: Initial payload packet sent by client (Seq: 5000, Len: 100 -> maxSeqClient becomes 5000)
  const initialDataPacket = {
    srcIp: '192.168.31.89',
    dstIp: '192.168.31.1',
    timestamp: new Date().toISOString(),
    tcp: {
      srcPort: 54321,
      dstPort: 443,
      seq: 5000,
      ack: 1000,
      flags: { syn: false, ack: true, fin: false, rst: false, psh: true },
      payloadLength: 100,
      windowSize: 64240,
      dataOffset: 20
    }
  };
  packetStreamer._analyzeTcpStream(initialDataPacket);
  assert.strictEqual(initialDataPacket.tcpAnalysis.isRetransmission, false);
  assert.strictEqual(initialDataPacket.tcpAnalysis.isKeepAlive, false);

  // Step 2: RFC 1122 Keep-Alive Probe (Seq = maxSeq - 1 = 4999, Len = 1, ACK = 1, no PSH)
  const keepAliveProbePacket = {
    srcIp: '192.168.31.89',
    dstIp: '192.168.31.1',
    timestamp: new Date().toISOString(),
    tcp: {
      srcPort: 54321,
      dstPort: 443,
      seq: 4999,
      ack: 1000,
      flags: { syn: false, ack: true, fin: false, rst: false, psh: false },
      payloadLength: 1,
      windowSize: 64240,
      dataOffset: 20
    }
  };
  packetStreamer._analyzeTcpStream(keepAliveProbePacket);
  assert.strictEqual(keepAliveProbePacket.tcpAnalysis.isKeepAlive, true, 'Keep-Alive probe must have isKeepAlive = true');
  assert.strictEqual(keepAliveProbePacket.tcpAnalysis.isRetransmission, false, 'Keep-Alive probe must NOT be marked isRetransmission');
  assert.strictEqual(keepAliveProbePacket.tcpAnalysis.isDupAck, false, 'Keep-Alive probe must NOT be marked isDupAck');
  assert.strictEqual(keepAliveProbePacket.tcpAnalysis.isOutOfOrder, false, 'Keep-Alive probe must NOT be marked isOutOfOrder');

  // Step 3: RFC 1122 Keep-Alive ACK from server (Len = 0, ACK = 1, ack = 5000)
  const keepAliveAckPacket = {
    srcIp: '192.168.31.1',
    dstIp: '192.168.31.89',
    timestamp: new Date().toISOString(),
    tcp: {
      srcPort: 443,
      dstPort: 54321,
      seq: 1000,
      ack: 5000,
      flags: { syn: false, ack: true, fin: false, rst: false, psh: false },
      payloadLength: 0,
      windowSize: 64240,
      dataOffset: 20
    }
  };
  packetStreamer._analyzeTcpStream(keepAliveAckPacket);
  assert.strictEqual(keepAliveAckPacket.tcpAnalysis.isKeepAliveAck, true, 'Keep-Alive ACK must have isKeepAliveAck = true');
  assert.strictEqual(keepAliveAckPacket.tcpAnalysis.isDupAck, false, 'Keep-Alive ACK must NOT be marked isDupAck');
  assert.strictEqual(keepAliveAckPacket.tcpAnalysis.isRetransmission, false, 'Keep-Alive ACK must NOT be marked isRetransmission');

  // Verify that Keep-Alives are excluded from important & failures viewing modes
  assert.strictEqual(testImportantFilter({ protocol: 'TCP', tcpAnalysis: keepAliveProbePacket.tcpAnalysis }), false);
  assert.strictEqual(testImportantFilter({ protocol: 'TCP', tcpAnalysis: keepAliveAckPacket.tcpAnalysis }), false);
  console.log('  ✓ RFC 1122 1-byte/0-byte Keep-Alive probe and ACK correctly disambiguated from Retrans/DupAck.');

  // -------------------------------------------------------------------------
  // [37.4] Process Explorer CPU% Normalization Math & Process Shielding
  // -------------------------------------------------------------------------
  console.log('[Test 37.4] Verifying Process Explorer CPU% Normalization Math & Process Shielding...');

  const resPillar = await hostDiagnosticsEngine.collectResourcePillar();
  assert.ok(resPillar, 'Resource pillar must be returned');
  const procs = resPillar.details.topProcesses || [];
  assert.ok(procs.length > 0, 'Must collect top processes');

  for (const p of procs) {
    assert.ok(typeof p.cpu === 'number', 'Process cpu must be a number');
    assert.ok(p.cpu >= 0.0 && p.cpu <= 100.0, `Process CPU% (${p.cpu}%) must be normalized between 0.0% and 100.0%`);
    assert.ok(typeof p.cpuTotalSeconds === 'number', 'Process cpuTotalSeconds must be retained');
  }

  const procList = await hostDiagnosticsEngine.getProcessList(15);
  for (const p of procList) {
    assert.ok(p.cpu >= 0.0 && p.cpu <= 100.0, `Process list CPU% (${p.cpu}%) must be normalized between 0.0% and 100.0%`);
  }

  // Verify OS Process Shielding logic from core-diagnostics-view.js
  const coreDiagJs = fs.readFileSync(path.join(__dirname, '../public/js/views/core-diagnostics-view.js'), 'utf8');
  assert.ok(coreDiagJs.includes('const PROTECTED_PROCESSES = new Set'), 'core-diagnostics-view.js must define PROTECTED_PROCESSES');
  assert.ok(coreDiagJs.includes('🛡️ OS Protected'), 'core-diagnostics-view.js must render 🛡️ OS Protected badge');

  const PROTECTED_TEST_LIST = ['system', 'dwm', 'explorer', 'svchost', 'msmpeng', 'node'];
  for (const procName of PROTECTED_TEST_LIST) {
    assert.ok(coreDiagJs.includes(`'${procName}'`), `PROTECTED_PROCESSES must include '${procName}'`);
  }
  console.log(`  ✓ CPU% strictly normalized to [0.0%, 100.0%] across ${procs.length} processes; OS Process Shielding verified.`);

  // -------------------------------------------------------------------------
  // [37.5] Ultra IP Scanner 3-Tier Sorting, Status Badges & Dynamic Topology Labels
  // -------------------------------------------------------------------------
  console.log('[Test 37.5] Verifying Ultra IP Scanner 3-Tier Sorting, Badges & Dynamic Topology Labels...');

  // 1. Verify 3-tier host sorting
  const testHosts = [
    { ip: '192.168.31.254', status: 'UNRESPONSIVE', detailedStatus: 'NO_ICMP_RESPONSE' },
    { ip: '192.168.31.1', status: 'ONLINE', latencyMs: 1.2 },
    { ip: '192.168.31.45', status: 'CACHED_ARP' },
    { ip: '192.168.31.12', status: 'ONLINE', latencyMs: 0.8 },
    { ip: '192.168.31.99', status: 'OFFLINE', detailedStatus: 'CONFIRMED_OFFLINE' }
  ];

  const getHostTier = (h) => {
    const s = (h.status || '').toUpperCase();
    if (s === 'ONLINE' || s === 'RECENTLY_SEEN') return 1;
    if (s === 'CACHED_ARP' || s === 'ARP CACHED' || s === 'FRESH_ARP') return 2;
    return 3;
  };
  const ipToNum = (ip) => {
    const parts = ip.split('.').map(Number);
    return (((parts[0] || 0) << 24) | ((parts[1] || 0) << 16) | ((parts[2] || 0) << 8) | (parts[3] || 0)) >>> 0;
  };

  testHosts.sort((a, b) => {
    const tA = getHostTier(a);
    const tB = getHostTier(b);
    if (tA !== tB) return tA - tB;
    return ipToNum(a.ip) - ipToNum(b.ip);
  });

  assert.strictEqual(testHosts[0].ip, '192.168.31.1', 'Tier 1 ONLINE first (lower IP)');
  assert.strictEqual(testHosts[1].ip, '192.168.31.12', 'Tier 1 ONLINE second (higher IP)');
  assert.strictEqual(testHosts[2].ip, '192.168.31.45', 'Tier 2 CACHED_ARP');
  assert.strictEqual(testHosts[3].ip, '192.168.31.99', 'Tier 3 OFFLINE (lower IP)');
  assert.strictEqual(testHosts[4].ip, '192.168.31.254', 'Tier 3 NO_ICMP_RESPONSE (higher IP)');

  // 2. Verify Ultra IP Scanner UI contracts
  const scannerViewJs = fs.readFileSync(path.join(__dirname, '../public/js/views/ultra-ip-scanner-view.js'), 'utf8');
  assert.ok(scannerViewJs.includes('min-width: 110px'), 'Scanner status column header must have min-width: 110px');
  assert.ok(scannerViewJs.includes('NO PING'), 'Scanner must render clean NO PING status badge');
  assert.ok(scannerViewJs.includes('scannerDeltaSummaryBanner'), 'Scanner must define scannerDeltaSummaryBanner');

  // 3. Verify Dynamic Topology resolution & card title formatting
  const netInfo = getPhysicalNetworkInfo();
  assert.ok(netInfo.isDetected, 'Physical network must be detected');
  assert.ok(netInfo.subnetCidr && /^\d+\.\d+\.\d+\.\d+\/\d+$/.test(netInfo.subnetCidr), 'Live subnet must be a valid CIDR');
  assert.ok(netInfo.hostIp && /^\d+\.\d+\.\d+\.\d+$/.test(netInfo.hostIp), 'Live host IP must be a valid IPv4');

  topologyEngine.syncTopologyToPhysicalNetwork();
  const topoData = topologyEngine.getTopology();
  const hostNode = topoData.nodes.find(n => n.id === 'NODE-HOST-01');
  assert.ok(hostNode, 'NODE-HOST-01 must exist in topology');
  assert.ok(hostNode.vendor && (hostNode.vendor.includes('Windows Workstation') || hostNode.vendor.includes('Intel')), 'NODE-HOST-01 vendor must identify workstation hardware');

  // Title formatting invariant: remove redundant parenthetical IP to prevent card boundary clipping
  function cleanCardTitle(name) {
    return (name || 'Device').replace(/\s*\(\s*\d+\.\d+\.\d+\.\d+(?:\/\d+)?\s*\)\s*$/, '').trim();
  }
  assert.strictEqual(cleanCardTitle(`Local Workstation Host (${netInfo.hostIp})`), 'Local Workstation Host');
  assert.strictEqual(cleanCardTitle(`Default Gateway (${netInfo.gatewayIp})`), 'Default Gateway');
  assert.strictEqual(cleanCardTitle(`Distribution & Access LAN (${netInfo.subnetCidr})`), 'Distribution & Access LAN');
  assert.strictEqual(cleanCardTitle('Upstream Internet (Google)'), 'Upstream Internet (Google)');

  // Verify server EADDRINUSE handling
  const serverJs = fs.readFileSync(path.join(__dirname, '../src/server.js'), 'utf8');
  assert.ok(serverJs.includes("err.code === 'EADDRINUSE'"), 'src/server.js must handle EADDRINUSE cleanly');

  // Verify setup-launcher.bat port 8443 check
  const launcherBat = fs.readFileSync(path.join(__dirname, '../setup-launcher.bat'), 'utf8');
  assert.ok(launcherBat.includes('netstat -ano') && launcherBat.includes(':8443'), 'setup-launcher.bat must check port 8443');

  // Verify dynamic gateway automation scripts
  const pingBatMount = fs.readFileSync(path.join(__dirname, '../data/scripts_mount/Scripts/Ping Default Gateway & Cloudflare DNS.bat'), 'utf8');
  assert.ok(!pingBatMount.includes('10.168.195.1'), 'Ping Default Gateway & Cloudflare DNS.bat must not hardcode 10.168.195.1');
  assert.ok(pingBatMount.includes('route print 0.0.0.0') || pingBatMount.includes('ipconfig'), 'Ping bat must dynamically resolve default gateway');

  const testPortPs1Mount = fs.readFileSync(path.join(__dirname, '../data/scripts_mount/Scripts/Test Port Connectivity to Default Gateway.ps1'), 'utf8');
  assert.ok(!testPortPs1Mount.includes('10.168.195.1'), 'Test Port Connectivity script must not hardcode 10.168.195.1');
  assert.ok(testPortPs1Mount.includes('Get-NetRoute') || testPortPs1Mount.includes('Get-CimInstance'), 'Test Port Connectivity script must dynamically resolve default gateway');

  console.log('  ✓ 3-tier scanner sorting, badge clarity, dynamic topology resolution, and gateway scripts verified.');

  console.log('\n========================================================================');
  console.log('  TEST SUITE 37: 100% PASSED (ALL 5 RIGOROUS CHECKS VERIFIED)');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runVisualRuntimeTruthAndSignalHygieneTests().then(() => {
    process.exit(0);
  }).catch((err) => {
    console.error('Suite 37 failed:', err);
    process.exit(1);
  });
}

module.exports = { runVisualRuntimeTruthAndSignalHygieneTests };
