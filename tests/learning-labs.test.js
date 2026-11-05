/**
 * EJII Learning Center — Test Suite: Educational Labs Math, Logic & Simulations
 * Tests pure calculation, state transitions, and diagnostic algorithms across all 8 labs.
 * Mandate: Pure educational simulations.
 */

'use strict';

const assert = require('node:assert/strict');

// Import lab logic modules
const subnetLab = require('../public/js/learning/labs/subnetting-trainer');
const packetLab = require('../public/js/learning/labs/packet-journey');
const vlanLab = require('../public/js/learning/labs/vlan-lab');
const routingLab = require('../public/js/learning/labs/routing-explorer');
const psLab = require('../public/js/learning/labs/powershell-sandbox');
const linuxLab = require('../public/js/learning/labs/linux-sandbox');
const adLab = require('../public/js/learning/labs/active-directory-lab');
const dnsDhcpLab = require('../public/js/learning/labs/dns-dhcp-lab');

console.log('========================================================================');
console.log('  TEST: EJII LEARNING CENTER LAB SIMULATIONS & DETERMINISTIC LOGIC');
console.log('========================================================================');

// ============================================================================
// Lab 1: Subnetting Trainer
// ============================================================================
console.log('[Lab 1] Testing IPv4 Subnetting Trainer calculations...');

// Test 1.1: Standard /24
const sub24 = subnetLab.calculateSubnet('192.168.1.150', 24);
assert.equal(sub24.networkAddress, '192.168.1.0');
assert.equal(sub24.broadcastAddress, '192.168.1.255');
assert.equal(sub24.firstUsable, '192.168.1.1');
assert.equal(sub24.lastUsable, '192.168.1.254');
assert.equal(sub24.usableHosts, 254);
assert.equal(sub24.subnetMask, '255.255.255.0');
console.log('  ✓ /24 boundary verified.');

// Test 1.2: Subnetting /27
const sub27 = subnetLab.calculateSubnet('10.10.10.75', 27);
assert.equal(sub27.networkAddress, '10.10.10.64');
assert.equal(sub27.broadcastAddress, '10.10.10.95');
assert.equal(sub27.firstUsable, '10.10.10.65');
assert.equal(sub27.lastUsable, '10.10.10.94');
assert.equal(sub27.usableHosts, 30);
console.log('  ✓ /27 boundary verified (block size 32, usable 30).');

// Test 1.3: Supernet /16
const sub16 = subnetLab.calculateSubnet('172.16.55.10', 16);
assert.equal(sub16.networkAddress, '172.16.0.0');
assert.equal(sub16.broadcastAddress, '172.16.255.255');
assert.equal(sub16.usableHosts, 65534);
console.log('  ✓ /16 boundary verified (usable 65534).');

// Test 1.4: /20 Subnet Boundary
const sub20 = subnetLab.calculateSubnet('10.1.22.5', 20);
assert.equal(sub20.networkAddress, '10.1.16.0');
assert.equal(sub20.broadcastAddress, '10.1.31.255');
assert.equal(sub20.firstUsable, '10.1.16.1');
assert.equal(sub20.lastUsable, '10.1.31.254');
assert.equal(sub20.usableHosts, 4094);
console.log('  ✓ /20 boundary verified (block size 16 in 3rd octet).');

// Test 1.5: RFC 3021 /31 point-to-point
const sub31 = subnetLab.calculateSubnet('192.168.0.2', 31);
assert.equal(sub31.networkAddress, '192.168.0.2');
assert.equal(sub31.broadcastAddress, '192.168.0.3');
assert.equal(sub31.usableHosts, 2);
console.log('  ✓ RFC 3021 /31 point-to-point verified (both addresses usable).');

// Test 1.6: Boundary /32 host route and /0 default
const sub32 = subnetLab.calculateSubnet('10.0.0.1', 32);
assert.equal(sub32.usableHosts, 1);
const sub0 = subnetLab.calculateSubnet('0.0.0.0', 0);
assert.equal(sub0.totalAddresses, '4294967296');
console.log('  ✓ /32 host route and /0 default route verified.');

// Test 1.7: Error guards
assert.ok(subnetLab.calculateSubnet('invalid-ip', 24).error);
assert.ok(subnetLab.calculateSubnet('192.168.1.1', 35).error);
console.log('  ✓ Subnet trainer input validation guards verified.');

// ============================================================================
// Lab 2: L2/L3 Packet Journey
// ============================================================================
console.log('[Lab 2] Testing L2/L3 Packet Journey Visualizer...');
const sameSubnetState = packetLab.getJourneyState('same-subnet', 0);
assert.equal(sameSubnetState.mode, 'same-subnet');
assert.equal(sameSubnetState.totalSteps, 6);

const diffSubnetHop1 = packetLab.getJourneyState('different-subnet', 1);
assert.equal(diffSubnetHop1.step.l2.dstMac, '00:00:5E:00:01:01', 'Hop 1 destination MAC must be the Router MAC');
assert.equal(diffSubnetHop1.step.l3.dstIp, '172.16.2.80', 'Hop 1 destination IP must be the server IP');

const diffSubnetHop2 = packetLab.getJourneyState('different-subnet', 4);
assert.equal(diffSubnetHop2.step.l2.srcMac, '00:00:5E:00:02:01', 'Hop 2 source MAC rewritten by router');
assert.equal(diffSubnetHop2.step.l2.dstMac, 'CC:CC:CC:33:33:33', 'Hop 2 destination MAC is server MAC');
console.log('  ✓ Hop-by-hop L2 rewrite & L3 persistence verified.');

// ============================================================================
// Lab 3: VLAN Segmentation & 802.1Q
// ============================================================================
console.log('[Lab 3] Testing VLAN Segmentation & 802.1Q Trunking...');
const vlanConfig = JSON.parse(JSON.stringify(vlanLab.DEFAULT_CONFIG));

// Test 3.1: Host A and Host C on VLAN 10 across trunk
const aToC = vlanLab.evaluatePairConnectivity('hostA', 'hostC', vlanConfig);
assert.equal(aToC.connected, true);
assert.equal(aToC.vlan, 10);

// Test 3.2: Host A (VLAN 10) and Host B (VLAN 20) on same switch
const aToB = vlanLab.evaluatePairConnectivity('hostA', 'hostB', vlanConfig);
assert.equal(aToB.connected, false, 'Different VLANs must be isolated at L2');
assert.ok(aToB.reason.includes('VLAN Isolation'));

// Test 3.3: Trunk Pruning
vlanConfig.sw1.trunk.allowedVlans = [20, 30]; // Remove VLAN 10
const aToCPruned = vlanLab.evaluatePairConnectivity('hostA', 'hostC', vlanConfig);
assert.equal(aToCPruned.connected, false);
assert.ok(aToCPruned.reason.includes('Trunk Pruning'));

// Test 3.4: Native VLAN mismatch
vlanConfig.sw1.trunk.allowedVlans = [10, 20, 30];
vlanConfig.sw1.trunk.nativeVlan = 99;
vlanConfig.sw2.trunk.nativeVlan = 1;
const mismatch = vlanLab.evaluatePairConnectivity('hostA', 'hostC', vlanConfig);
assert.equal(mismatch.connected, false);
assert.ok(mismatch.reason.includes('Native VLAN Mismatch'));
console.log('  ✓ VLAN isolation, 802.1Q transport, pruning, and native mismatch verified.');

// ============================================================================
// Lab 4: Routing Explorer (LPM)
// ============================================================================
console.log('[Lab 4] Testing Longest-Prefix Match Routing Explorer...');
// Destination 10.1.20.150 matches /8, /16, /24, and /25.
const lpmResult = routingLab.evaluateLPM('10.1.20.150');
assert.ok(lpmResult.bestRoute);
assert.equal(lpmResult.bestRoute.prefix, '10.1.20.128/25', 'LPM rule: /25 must win over /24, /16, /8, /0');
assert.equal(lpmResult.bestRoute.iface, 'Gi0/3');

// Destination 8.8.8.8 matches only default route 0.0.0.0/0
const defaultResult = routingLab.evaluateLPM('8.8.8.8');
assert.equal(defaultResult.bestRoute.prefix, '0.0.0.0/0');
assert.equal(defaultResult.bestRoute.iface, 'Gi0/5');
console.log('  ✓ Longest-Prefix Match (LPM) and default route fallback verified.');

// ============================================================================
// Lab 5: PowerShell Sandbox
// ============================================================================
console.log('[Lab 5] Testing PowerShell Diagnostic Sandbox...');
const svcOutput = psLab.executePsCommand('Get-Service');
assert.ok(svcOutput.includes('Running') && svcOutput.includes('Dnscache'));

const stoppedSvcOutput = psLab.executePsCommand('Get-Service | Where-Object Status -eq Stopped');
assert.ok(stoppedSvcOutput.includes('Spooler') || stoppedSvcOutput.includes('wuauserv'));

const procOutput = psLab.executePsCommand('Get-Process');
assert.ok(procOutput.includes('explorer') && procOutput.includes('powershell'));

const netOutput = psLab.executePsCommand('Get-NetIPConfiguration');
assert.ok(netOutput.includes('192.168.10.45') && netOutput.includes('192.168.10.1'));
console.log('  ✓ PowerShell cmdlets and pipeline simulation verified.');

// ============================================================================
// Lab 6: Linux Sandbox
// ============================================================================
console.log('[Lab 6] Testing Linux Command & Filesystem Trainer...');
const pwdRes = linuxLab.executeLinuxCommand('pwd', '/home/devops');
assert.equal(pwdRes.output, '/home/devops');

const lsRes = linuxLab.executeLinuxCommand('ls', '/home/devops');
assert.ok(lsRes.output.includes('README.md'));

const cdRes = linuxLab.executeLinuxCommand('cd /etc', '/home/devops');
assert.equal(cdRes.newDir, '/etc');

const catRes = linuxLab.executeLinuxCommand('cat /etc/hosts', '/');
assert.ok(catRes.output.includes('127.0.0.1'));

const sysctlRes = linuxLab.executeLinuxCommand('systemctl status nginx', '/');
assert.ok(sysctlRes.output.includes('active (running)'));
console.log('  ✓ Linux shell traversal, cat, and systemctl verified.');

// ============================================================================
// Lab 7: Active Directory & Permissions Explorer
// ============================================================================
console.log('[Lab 7] Testing Active Directory & Permissions Explorer...');
// Alice (DevOps): Has Full Control on Share and Modify on NTFS -> Effective: Modify
const aliceAccess = adLab.calculateEffectiveAccess('alice', '\\\\fs01\\Engineering');
assert.equal(aliceAccess.effective, 'Read, Write, Modify');

// Carol (Finance): Has Deny Write in NTFS -> Deny must override!
const carolAccess = adLab.calculateEffectiveAccess('carol', '\\\\fs01\\Engineering');
assert.equal(carolAccess.hasDenyWrite, true);
assert.equal(carolAccess.effective, 'Read Only (Deny Override)');

// Eldar (Domain Admin): Has Full Control on both -> Effective: Full Control
const eldarAccess = adLab.calculateEffectiveAccess('eldar', '\\\\fs01\\Engineering');
assert.equal(eldarAccess.effective, 'Full Control (Ownership & Permissions)');

// LSDOU Chain for Engineering OU
const engGpos = adLab.getLsdouPolicyChain('Engineering');
assert.equal(engGpos.length, 4);
assert.equal(engGpos[3].id, 'gpo-eng');
console.log('  ✓ Effective permissions, Deny override, and GPO LSDOU precedence verified.');

// ============================================================================
// Lab 8: DNS & DHCP Troubleshooting Simulator
// ============================================================================
console.log('[Lab 8] Testing DNS & DHCP Simulator (All 8 Scenarios)...');
assert.equal(dnsDhcpLab.SCENARIOS.length, 8);

for (const scenario of dnsDhcpLab.SCENARIOS) {
  const correctOpt = scenario.diagnosticOptions.find(o => o.isCorrect);
  assert.ok(correctOpt, `Scenario ${scenario.id} must have a correct option`);

  // Evaluate correct diagnosis
  const verified = dnsDhcpLab.evaluateDiagnosis(scenario.id, correctOpt.id);
  assert.equal(verified.isCorrect, true);
  assert.ok(verified.explanation.includes('Remediation Protocol'));

  // Evaluate incorrect diagnosis
  const incorrectOpt = scenario.diagnosticOptions.find(o => !o.isCorrect);
  const failed = dnsDhcpLab.evaluateDiagnosis(scenario.id, incorrectOpt.id);
  assert.equal(failed.isCorrect, false);
}
console.log('  ✓ All 8 infrastructure fault scenarios, diagnoses, and remediations verified.');

console.log('========================================================================');
console.log('  SUITE PASSED: 100% EDUCATIONAL LABS MATH & LOGIC VERIFIED');
console.log('========================================================================');
