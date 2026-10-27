// tests/suite-91-zero-trust-firewall-policy-synthesizer.test.js
/**
 * EJII Test Suite 91: Zero-Trust Micro-Segmentation Firewall Policy Synthesizer
 * Verifies synthesis of Windows Defender netsh commands, Linux nftables scripts,
 * Kubernetes NetworkPolicy YAML manifests, lateral movement violation detection,
 * and the /api/network/zero-trust-policies REST API endpoint.
 */

'use strict';

const assert = require('node:assert/strict');
const { ZeroTrustPolicySynthesizer } = require('../src/security/zero-trust-policy-synthesizer');
const routesNetwork = require('../src/api/routes-network');

async function runSuite91ZeroTrustFirewallPolicySynthesizer() {
  console.log('========================================================================');
  console.log('  === [SUITE 91] ZERO-TRUST FIREWALL POLICY SYNTHESIZER ===              ');
  console.log('========================================================================\n');

  const testAssets = [
    { ip: '10.0.0.1', hostname: 'core-gw-01', role: 'GATEWAY', openPorts: [53, 443] },
    { ip: '10.0.0.50', hostname: 'k8s-ingress-app', role: 'SERVER', openPorts: [80, 443, 8443] },
    { ip: '10.0.0.100', hostname: 'dev-workstation-01', role: 'WORKSTATION', openPorts: [22] }
  ];

  // [91.1] Windows Defender netsh Rule Synthesis
  console.log('[Test 91.1] Synthesizing Windows Defender netsh rules for assets...');
  const bundle = ZeroTrustPolicySynthesizer.synthesize(testAssets, [], '10.0.0.0/24');

  assert.ok(bundle, 'Policy bundle must be returned');
  assert.strictEqual(bundle.targetSubnet, '10.0.0.0/24');
  assert.strictEqual(bundle.assetCount, 3);
  assert.ok(Array.isArray(bundle.windowsNetshRules), 'windowsNetshRules must be an array');
  assert.ok(bundle.windowsNetshRules.length > 0, 'Must produce netsh commands');

  // Verify valid netsh command structure
  assert.ok(bundle.windowsNetshRules[0].includes('netsh advfirewall set allprofiles'), 'First command must be allprofiles hardening');
  const addRule = bundle.windowsNetshRules.find(r => r.includes('netsh advfirewall firewall add rule'));
  assert.ok(addRule, 'Must contain firewall add rules');
  assert.ok(addRule.includes('dir=in') || addRule.includes('dir=out'), 'Rule must specify direction');
  assert.ok(addRule.includes('action=allow') || addRule.includes('action=block'), 'Rule must specify action');
  console.log(`  ✓ Windows netsh rules synthesized (${bundle.windowsNetshRules.length} rules). Example:\n    ${addRule}`);

  // [91.2] Linux nftables Manifest Synthesis
  console.log('[Test 91.2] Synthesizing Linux nftables configuration manifest...');
  assert.ok(typeof bundle.linuxNftablesManifest === 'string');
  assert.ok(bundle.linuxNftablesManifest.includes('table inet'), 'nftables must declare table inet');
  assert.ok(bundle.linuxNftablesManifest.includes('chain inbound'), 'nftables must declare chain inbound');
  assert.ok(bundle.linuxNftablesManifest.includes('chain outbound'), 'nftables must declare chain outbound');
  assert.ok(bundle.linuxNftablesManifest.includes('policy drop;'), 'Zero-trust default policy must be drop');
  assert.ok(bundle.linuxNftablesManifest.includes('ct state established,related accept'), 'Must accept established connections');
  console.log('  ✓ Linux nftables manifest verified with default-drop zero-trust posture.');

  // [91.3] Kubernetes NetworkPolicy YAML Synthesis
  console.log('[Test 91.3] Synthesizing Kubernetes NetworkPolicy YAML specification...');
  assert.ok(typeof bundle.kubernetesNetworkPolicyYaml === 'string');
  assert.ok(bundle.kubernetesNetworkPolicyYaml.includes('apiVersion: networking.k8s.io/v1'), 'Must use networking.k8s.io/v1');
  assert.ok(bundle.kubernetesNetworkPolicyYaml.includes('kind: NetworkPolicy'), 'Must declare kind NetworkPolicy');
  assert.ok(bundle.kubernetesNetworkPolicyYaml.includes('ingress:'), 'Must specify ingress rules');
  assert.ok(bundle.kubernetesNetworkPolicyYaml.includes('egress:'), 'Must specify egress rules');
  assert.ok(bundle.kubernetesNetworkPolicyYaml.includes('policyTypes:'), 'Must specify policyTypes');
  console.log('  ✓ Kubernetes NetworkPolicy YAML synthesized with Ingress & Egress specifications.');

  // [91.4] Lateral Movement Violation Detection (SMB / RDP on Workstation)
  console.log('[Test 91.4] Testing lateral movement detection on shadow admin ports (SMB/RDP)...');
  const rogueFlows = [
    // Authorized web flow: Workstation -> Ingress 443
    { protocol: 'TCP', localIp: '10.0.0.100', localPort: 49210, remoteIp: '10.0.0.50', remotePort: 443, processName: 'firefox.exe' },
    // Unauthorized lateral movement: Workstation -> Ingress 445 (SMB)
    { protocol: 'TCP', localIp: '10.0.0.100', localPort: 49220, remoteIp: '10.0.0.50', remotePort: 445, processName: 'cmd.exe', processId: 1048 },
    // Unauthorized shadow admin: Workstation -> Ingress 3389 (RDP)
    { protocol: 'TCP', localIp: '10.0.0.100', localPort: 49230, remoteIp: '10.0.0.50', remotePort: 3389, processName: 'mstsc.exe', processId: 1120 }
  ];

  const auditedBundle = ZeroTrustPolicySynthesizer.synthesize(testAssets, rogueFlows, '10.0.0.0/24');
  assert.ok(Array.isArray(auditedBundle.lateralMovementViolations), 'Violations must be an array');
  assert.ok(auditedBundle.lateralMovementViolations.length >= 2, 'Must flag SMB (445) and RDP (3389) violations');

  const smbViolation = auditedBundle.lateralMovementViolations.find(v => v.flow.remotePort === 445);
  assert.ok(smbViolation, 'Must flag SMB port 445 lateral movement');
  assert.strictEqual(smbViolation.severity, 'CRITICAL');
  console.log(`  ✓ Lateral movement detected: Port ${smbViolation.flow.remotePort} (${smbViolation.reason}), Severity=${smbViolation.severity}`);

  // [91.5] REST API Endpoint: GET /api/network/zero-trust-policies
  console.log('[Test 91.5] Testing GET /api/network/zero-trust-policies via router stack...');
  const policyLayer = routesNetwork.stack.find(s => s.route && (
    Array.isArray(s.route.path) ? s.route.path.includes('/zero-trust-policies') : s.route.path === '/zero-trust-policies'
  ));
  assert.ok(policyLayer, 'Route GET /zero-trust-policies must exist in routes-network.js');

  let policyJson = null;
  const mockReq = { query: {} };
  const mockRes = {
    statusCode: 200,
    status(c) { this.statusCode = c; return this; },
    json(d) { policyJson = d; return this; }
  };
  const handler = policyLayer.route.stack[policyLayer.route.stack.length - 1].handle;
  handler(mockReq, mockRes, () => {});

  assert.ok(policyJson, 'Must return JSON');
  assert.strictEqual(policyJson.success, true);
  assert.ok(Array.isArray(policyJson.windowsNetshRules));
  assert.ok(typeof policyJson.linuxNftablesManifest === 'string');
  assert.ok(typeof policyJson.kubernetesNetworkPolicyYaml === 'string');
  console.log(`  ✓ GET /api/network/zero-trust-policies returned 200 OK: ${policyJson.windowsNetshRules.length} netsh rules, Subnet=${policyJson.targetSubnet}`);

  console.log('\n========================================================================');
  console.log('  SUITE 91 PASSED: ZERO-TRUST POLICY SYNTHESIZER 100% GREEN             ');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runSuite91ZeroTrustFirewallPolicySynthesizer().catch((err) => {
    console.error('Suite 91 failed:', err);
    process.exit(1);
  });
}

module.exports = {
  runSuite91ZeroTrustFirewallPolicySynthesizer,
  runSuite91: runSuite91ZeroTrustFirewallPolicySynthesizer
};
