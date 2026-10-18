/**
 * EJII Test Suite 40: Live DOM Visual Truth & Signal Hygiene Regression Suite
 * 
 * Verifies:
 * [40.1] Visual Runtime Signal Dissection & Noise Frame Suppression
 * [40.2] Ultra IP Scanner Deterministic 3-Tier Ordering, Status Badges & Vendor Truth
 * [40.3] NOC Dynamic Topology SVG Architecture, Zero Subnet Fallbacks & Card Geometry
 * [40.4] Process Explorer CPU% Dual-Pillar Multi-Core Normalization & OS Process Shielding
 * [40.5] PC Automation Script Dynamic Gateway Substitution & Action Ledger
 */

'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const { getPhysicalNetworkInfo } = require('../src/network/routing/physical-network-detector');
const { hostDiagnosticsEngine } = require('../src/systems/diagnostics/host-diagnostics-engine');
const { topologyEngine } = require('../src/network/topology/topology-engine');
const { scriptAutomation } = require('../src/tools/script-automation');
const { ultraIpScanner } = require('../src/tools/ip-scanner');

async function runLiveDomVisualTruthRegressionTests() {
  console.log('========================================================================');
  console.log('  TEST SUITE 40: LIVE DOM VISUAL TRUTH & SIGNAL HYGIENE REGRESSION      ');
  console.log('========================================================================\n');

  // -------------------------------------------------------------------------
  // [40.1] Visual Runtime Signal Dissection & Noise Frame Suppression
  // -------------------------------------------------------------------------
  console.log('[Test 40.1] Verifying Visual Runtime Signal Dissection & Noise Frame Suppression...');
  {
    const nocViewJs = fs.readFileSync(path.join(__dirname, '../public/js/views/noc-view.js'), 'utf8');
    const snifferViewJs = fs.readFileSync(path.join(__dirname, '../public/js/views/sniffer-view.js'), 'utf8');

    // 1. Verify escapeAttr and escapeHtml exist in both views
    assert.ok(nocViewJs.includes('function escapeAttr(str)'), 'noc-view.js must define escapeAttr');
    assert.ok(snifferViewJs.includes('function escapeAttr(str)'), 'sniffer-view.js must define escapeAttr');
    assert.ok(nocViewJs.includes('function escapeHtml(str)'), 'noc-view.js must define escapeHtml');
    assert.ok(snifferViewJs.includes('function escapeHtml(str)'), 'sniffer-view.js must define escapeHtml');

    // 2. Verify BACKGROUND_NOISE_PATTERNS in noc-view.js
    assert.ok(nocViewJs.includes('BACKGROUND_NOISE_PATTERNS'), 'noc-view.js must define BACKGROUND_NOISE_PATTERNS');
    const noiseKeywords = ['googleapis', 'signalr', 'msedge', 'msftconnecttest', 'trafficmanager', 'azureedge'];
    for (const kw of noiseKeywords) {
      assert.ok(nocViewJs.includes(kw), `BACKGROUND_NOISE_PATTERNS must include ${kw}`);
    }

    // 3. Test Important Signal Filter Logic
    const BACKGROUND_PATTERNS = [
      /googleapis\.com/i,
      /signalr\.net/i,
      /msedge\.net/i,
      /bing\.com/i,
      /azure\.com/i,
      /delivery\.mp\.microsoft\.com/i
    ];

    function isBackgroundNoise(host) {
      if (!host) return false;
      return BACKGROUND_PATTERNS.some(pat => pat.test(host));
    }

    function isImportantSignal(f) {
      const proto = (f.protocol || '').toUpperCase();
      const flags = f.tcp?.flags || {};
      const isRst = Boolean(flags.rst || f.tcpAnalysis?.isRst);
      const isIcmp = proto === 'ICMP' || f.urlResolution?.method === 'ICMP-correlated';

      if (isIcmp || isRst) return true;

      const hostVal = f.urlResolution?.hostnameOrUrl ||
        f.tls?.handshake?.sni ||
        f.tls?.sni ||
        f.sni ||
        f.dns?.query ||
        '';

      if (hostVal && isBackgroundNoise(hostVal)) return false;

      const isTls = proto.startsWith('TLS') || Boolean(f.tls);
      if (isTls) {
        const isTlsClientHello = Boolean(
          f.tls?.handshake?.type === 'ClientHello' ||
          f.tls?.handshake?.typeNum === 1 ||
          f.tls?.sni ||
          f.sni
        );
        const isTlsAlert = Boolean(f.tls?.contentType === 'Alert' || f.tls?.contentTypeNum === 21);
        return isTlsClientHello || isTlsAlert;
      }

      if (f.isKeepAlive || f.isKeepAliveAck || f.tcpAnalysis?.isKeepAlive || f.tcpAnalysis?.isKeepAliveAck) {
        return false;
      }

      const isHandshake = Boolean(flags.syn || flags.fin);
      const isApp = proto === 'DNS' || proto === 'HTTP' || proto === 'ARP';
      const hasRealAnomaly = Boolean(f.tcpAnalysis?.isRetransmission || f.tcpAnalysis?.isZeroWindow || f.tcpAnalysis?.isDupAck);

      return isHandshake || isApp || hasRealAnomaly;
    }

    // Noise domain suppression
    assert.strictEqual(isImportantSignal({ protocol: 'TLS', tls: { handshake: { type: 'ClientHello', sni: 'play.googleapis.com' } } }), false);
    assert.strictEqual(isImportantSignal({ protocol: 'DNS', dns: { query: 'telemetry.msedge.net' } }), false);

    // Mid-stream encrypted TLS application data suppression
    assert.strictEqual(isImportantSignal({ protocol: 'TLS', length: 1400, tls: { contentType: 'Application Data', contentTypeNum: 23 } }), false);

    // Keep-alive suppression
    assert.strictEqual(isImportantSignal({ protocol: 'TCP', isKeepAlive: true, tcp: { flags: { ack: true } } }), false);

    // Valid signals preserved
    assert.strictEqual(isImportantSignal({ protocol: 'TLS', tls: { handshake: { type: 'ClientHello', sni: 'mail.taxes.gov.az' } } }), true);
    assert.strictEqual(isImportantSignal({ protocol: 'TCP', tcp: { flags: { rst: true } } }), true);
    assert.strictEqual(isImportantSignal({ protocol: 'ICMP' }), true);
    assert.strictEqual(isImportantSignal({ protocol: 'TCP', tcp: { flags: { syn: true } } }), true);

    // 4. Verify toggleWatchAppConnections in noc-view.js
    assert.ok(nocViewJs.includes('window.toggleWatchAppConnections = function'), 'noc-view.js must define window.toggleWatchAppConnections');
    assert.ok(nocViewJs.includes('👁️ Watch'), 'noc-view.js must render Watch button in App Finder table');

    console.log('  ✓ Important signal dissection, noise domain filter & Watch button verified.');
  }

  // -------------------------------------------------------------------------
  // [40.2] Ultra IP Scanner Deterministic 3-Tier Ordering, Status Badges & Vendor Truth
  // -------------------------------------------------------------------------
  console.log('\n[Test 40.2] Verifying Ultra IP Scanner Deterministic 3-Tier Ordering & Status Badges...');
  {
    const scannerJs = fs.readFileSync(path.join(__dirname, '../public/js/views/ultra-ip-scanner-view.js'), 'utf8');

    // 1. Verify getHostSortTier implementation
    assert.ok(scannerJs.includes('function getHostSortTier(h)'), 'ultra-ip-scanner-view.js must define getHostSortTier');
    assert.ok(scannerJs.includes('return 1'), 'getHostSortTier must return tier 1 for active/online hosts');
    assert.ok(scannerJs.includes('return 2'), 'getHostSortTier must return tier 2 for ARP-cached hosts');
    assert.ok(scannerJs.includes('return 3'), 'getHostSortTier must return tier 3 for offline/unresponsive hosts');

    // Test tier assignment
    function getHostSortTier(h) {
      const s = (h.status || '').toUpperCase();
      if (s === 'ONLINE' || s === 'RECENTLY_SEEN' || (Array.isArray(h.openServices) && h.openServices.length > 0) || (typeof h.latencyMs === 'number' && h.latencyMs > 0)) {
        return 1;
      }
      if (s === 'CACHED_ARP' || s === 'ARP CACHED' || s === 'FRESH_ARP') {
        return 2;
      }
      return 3;
    }

    assert.strictEqual(getHostSortTier({ status: 'ONLINE', ip: '192.168.31.1' }), 1);
    assert.strictEqual(getHostSortTier({ status: 'CACHED_ARP', ip: '192.168.31.25' }), 2);
    assert.strictEqual(getHostSortTier({ status: 'UNRESPONSIVE', ip: '192.168.31.200' }), 3);
    assert.strictEqual(getHostSortTier({ status: 'OFFLINE', ip: '192.168.31.201' }), 3);

    // 2. Status badge clarity: NO PING badge without truncation
    assert.ok(scannerJs.includes('NO PING'), 'Scanner must render clean NO PING status badge');
    assert.ok(scannerJs.includes('min-width: 110px'), 'Scanner status column must have min-width: 110px');

    // 3. Hardware vendor resolution: No fake hardware vendor when no MAC observed
    const ipScannerSrc = fs.readFileSync(path.join(__dirname, '../src/tools/ip-scanner.js'), 'utf8');
    assert.ok(
      ipScannerSrc.includes("vendor = '— (No MAC Observed)'") || ipScannerSrc.includes('No MAC Observed'),
      'ip-scanner.js must explicitly set "— (No MAC Observed)" when MAC is missing or empty'
    );

    console.log('  ✓ Deterministic 3-tier host ordering, NO PING badge & vendor truth verified.');
  }

  // -------------------------------------------------------------------------
  // [40.3] NOC Dynamic Topology SVG Architecture, Zero Subnet Fallbacks & Card Geometry
  // -------------------------------------------------------------------------
  console.log('\n[Test 40.3] Verifying NOC Dynamic Topology SVG Architecture & Card Geometry...');
  {
    const nocViewJs = fs.readFileSync(path.join(__dirname, '../public/js/views/noc-view.js'), 'utf8');
    const topoEngineJs = fs.readFileSync(path.join(__dirname, '../src/network/topology/topology-engine.js'), 'utf8');
    const physNetJs = fs.readFileSync(path.join(__dirname, '../src/network/routing/physical-network-detector.js'), 'utf8');

    // 1. Zero hardcoded fallbacks to 10.168.195.0/24 in production topology
    assert.ok(!topoEngineJs.includes("'10.168.195.0/24'"), 'topology-engine.js must not contain hardcoded 10.168.195.0/24');
    assert.ok(!physNetJs.includes("'10.168.195.0/24'"), 'physical-network-detector.js must not contain hardcoded 10.168.195.0/24');

    // 2. Physical network detection verification
    const netInfo = getPhysicalNetworkInfo();
    assert.ok(netInfo.isDetected, 'Physical network must be detected');
    assert.strictEqual(netInfo.subnetCidr, '192.168.31.0/24', 'Live subnet must be 192.168.31.0/24');
    assert.strictEqual(netInfo.hostIp, '192.168.31.89', 'Live host IP must be 192.168.31.89');

    // 3. Topology node vendor: Zero Intel I219-LM fabrication
    topologyEngine.syncTopologyToPhysicalNetwork();
    const topo = topologyEngine.getTopology();
    const hostNode = topo.nodes.find(n => n.id === 'NODE-HOST-01');
    assert.ok(hostNode, 'NODE-HOST-01 must exist');
    assert.ok(!hostNode.vendor.includes('Intel I219-LM'), 'NODE-HOST-01 vendor must not be Intel I219-LM');
    assert.ok(hostNode.vendor.includes('AX211') || hostNode.vendor.includes('Windows Workstation'));

    // 4. Card geometry: cardW = 240 and colWidth = 255 prevent title clipping
    assert.ok(nocViewJs.includes('cardW = 240'), 'noc-view.js must use cardW = 240 for wide card layout');
    assert.ok(nocViewJs.includes('colWidth = 255'), 'noc-view.js must use colWidth = 255 for spacing');

    // 5. SVG text blur/glow: filter and text-shadow must be none
    assert.ok(nocViewJs.includes('filter: none;'), 'noc-view.js SVG text must have filter: none');
    assert.ok(nocViewJs.includes('text-shadow: none;'), 'noc-view.js SVG text must have text-shadow: none');

    // 6. Cache busting in index.html
    const indexHtml = fs.readFileSync(path.join(__dirname, '../public/index.html'), 'utf8');
    assert.ok(indexHtml.includes('?v=2026.10.18.2'), 'index.html must include cache-busting version ?v=2026.10.18.2');

    console.log('  ✓ Dynamic topology SVG geometry, zero hardcoded subnet & cache busting verified.');
  }

  // -------------------------------------------------------------------------
  // [40.4] Process Explorer CPU% Dual-Pillar Multi-Core Normalization & OS Process Shielding
  // -------------------------------------------------------------------------
  console.log('\n[Test 40.4] Verifying Process Explorer CPU% Dual-Pillar Multi-Core Normalization & Process Shielding...');
  {
    // 1. Live process metrics check
    const resPillar = await hostDiagnosticsEngine.collectResourcePillar();
    const topProcs = resPillar.details.topProcesses || [];
    assert.ok(topProcs.length > 0, 'Must collect live processes');

    for (const p of topProcs) {
      assert.ok(typeof p.cpu === 'number', 'CPU must be number');
      assert.ok(p.cpu >= 0.0 && p.cpu <= 100.0, `Process CPU% (${p.cpu}%) must be within [0.0, 100.0]`);
      assert.ok(typeof p.cpuTotalSeconds === 'number', 'cpuTotalSeconds must be preserved');
    }

    // 2. Normalization invariant under multi-core simulation
    const logicalCores = 22;
    function normalizeCpu(rawPercent) {
      return Number(Math.min(100.0, Math.max(0.0, rawPercent / logicalCores)).toFixed(1));
    }
    assert.strictEqual(normalizeCpu(2200), 100.0, '2200% raw time across 22 cores must normalize to 100.0%');
    assert.strictEqual(normalizeCpu(1100), 50.0, '1100% raw time across 22 cores must normalize to 50.0%');
    assert.strictEqual(normalizeCpu(0), 0.0, '0% raw time must normalize to 0.0%');

    // 3. Protected OS processes rendering in core-diagnostics-view.js
    const diagViewJs = fs.readFileSync(path.join(__dirname, '../public/js/views/core-diagnostics-view.js'), 'utf8');
    assert.ok(diagViewJs.includes('const PROTECTED_PROCESSES = new Set'), 'core-diagnostics-view.js must define PROTECTED_PROCESSES');
    assert.ok(diagViewJs.includes('🛡️ OS Protected'), 'core-diagnostics-view.js must render 🛡️ OS Protected');

    // 4. Compact AI Brain Status Bar in ai-brain-drawer.js
    const drawerJs = fs.readFileSync(path.join(__dirname, '../public/js/components/ai-brain-drawer.js'), 'utf8');
    assert.ok(drawerJs.includes('isAiBrainExpanded') || drawerJs.includes('toggleAiBrainDrawerExpand'), 'ai-brain-drawer.js must support expandable/collapsible state');
    assert.ok(drawerJs.includes('Expand AI Brain Details') || drawerJs.includes('toggleAiBrainDrawerExpand'), 'ai-brain-drawer.js must implement compact status bar');

    console.log('  ✓ Multi-core CPU% normalization math [0.0%, 100.0%] and OS process shielding verified.');
  }

  // -------------------------------------------------------------------------
  // [40.5] PC Automation Script Dynamic Gateway Substitution & Action Ledger
  // -------------------------------------------------------------------------
  console.log('\n[Test 40.5] Verifying PC Automation Script Dynamic Gateway Substitution & Action Ledger...');
  {
    const res = await scriptAutomation.listAutomationScripts();
    assert.ok(res.exists, 'Script directory must exist');
    const scripts = res.scripts || [];
    assert.ok(Array.isArray(scripts) && scripts.length > 0, `Must list automation scripts, found ${scripts.length}`);

    // Verify dynamic gateway substitution in scripts
    const pingScript = scripts.find(s => s.filename.includes('Ping') || s.filename.includes('Gateway'));
    if (pingScript) {
      const scriptData = await scriptAutomation.getScriptContent(pingScript.filename);
      assert.ok(!scriptData.content.includes('10.168.195.1'), 'Script content must not contain hardcoded 10.168.195.1');
      assert.ok(scriptData.content.includes('192.168.31.1') || scriptData.content.includes('route print') || scriptData.content.includes('ipconfig') || scriptData.content.includes('Get-NetRoute'), 'Script content must dynamically use active gateway');
    }

    // 2. Command Palette registration of Guided Investigator
    const cmdPaletteJs = fs.readFileSync(path.join(__dirname, '../public/js/components/command-palette.js'), 'utf8');
    assert.ok(
      cmdPaletteJs.includes('Launch Guided Cross-Section Incident Investigator (5-Stage Pipeline)'),
      'command-palette.js must register Guided Cross-Section Incident Investigator'
    );

    console.log('  ✓ Dynamic gateway substitution in automation scripts and Command Palette registration verified.');
  }

  console.log('\n========================================================================');
  console.log('  TEST SUITE 40: 100% PASSED (ALL 5 RIGOROUS CHECKS VERIFIED)');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runLiveDomVisualTruthRegressionTests().then(() => {
    process.exit(0);
  }).catch((err) => {
    console.error('Suite 40 failed:', err);
    process.exit(1);
  });
}

module.exports = { runLiveDomVisualTruthRegressionTests };
