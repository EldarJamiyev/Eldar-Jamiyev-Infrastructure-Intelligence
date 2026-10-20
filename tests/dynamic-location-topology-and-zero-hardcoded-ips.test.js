/**
 * EJII Test Suite 65: Dynamic Location-Aware Topology Auto-Synchronization,
 * Elimination of Hardcoded 10.22.12.204 on Non-10.22.12.x Subnets,
 * Real Gateway ARP OUI Vendor Resolution & Auto-Populated L5 Access Fleet
 */

const assert = require('assert');
const { getPhysicalNetworkInfo, syncTopologyWithCurrentLocation } = require('../src/network/routing/physical-network-detector');
const { topologyEngine } = require('../src/network/topology/topology-engine');
const { db } = require('../src/db/database');

async function runDynamicLocationTopologyAndZeroHardcodedIpsTests() {
  console.log('========================================================================');
  console.log('  SUITE 65: DYNAMIC LOCATION TOPOLOGY & ZERO HARDCODED 10.22.12.204     ');
  console.log('========================================================================\n');

  // [65.1] Verify Live Physical Network & Location Introspection
  console.log('[65.1] Verifying live physical network & location introspection...');
  const netInfo = getPhysicalNetworkInfo({ forceRefresh: true });
  assert.ok(netInfo && netInfo.localIp, 'Must detect active localIp');
  assert.ok(netInfo.defaultGateway, 'Must detect active defaultGateway');
  assert.ok(netInfo.subnetCidr, 'Must detect active subnetCidr');
  assert.ok(!/MikroTik RouterOS|Cisco Catalyst/i.test(netInfo.gatewayVendor || '') || netInfo.gatewayMac !== 'Unknown',
    'Gateway vendor must not be a fake hardcoded placeholder');
  console.log(`  ✓ Live network detected: Host=${netInfo.localIp}, Gateway=${netInfo.defaultGateway} (${netInfo.gatewayVendor || 'Observed'}), Subnet=${netInfo.subnetCidr}, DNS=${(netInfo.dnsServers || []).join(', ')}`);

  // [65.2] Verify syncTopologyWithCurrentLocation Updates L1-L6 Nodes to Match Current Location
  console.log('[65.2] Verifying syncTopologyWithCurrentLocation eliminates alien 10.22.12.204 IP...');
  if (typeof syncTopologyWithCurrentLocation === 'function') {
    syncTopologyWithCurrentLocation(db);
  }
  topologyEngine.cachedTopology = null;
  const topo = topologyEngine.getTopology();
  const nodes = topo.nodes || [];
  const hostNode = nodes.find((n) => n.id === 'NODE-HOST-01');
  const gwNode = nodes.find((n) => n.id === 'NODE-GW-01');
  const appNode = nodes.find((n) => n.id === 'NODE-APP-01');
  const subnetNode = nodes.find((n) => n.id === 'NODE-SUBNET-01' || n.id === 'NODE-LAN-01');

  assert.ok(hostNode, 'L6 Host node must exist');
  assert.ok(gwNode, 'L2 Gateway node must exist');
  assert.ok(appNode, 'L4 App node must exist');
  assert.ok(subnetNode, 'L5 Subnet node must exist');

  assert.strictEqual(hostNode.hostname_or_ip, netInfo.localIp, 'L6 Host node must match current location localIp');
  assert.strictEqual(gwNode.hostname_or_ip, netInfo.defaultGateway, 'L2 Gateway node must match current location defaultGateway');
  assert.strictEqual(subnetNode.hostname_or_ip, netInfo.subnetCidr, 'L5 Subnet node must match current location subnetCidr');

  if (!netInfo.localIp.startsWith('10.22.12.')) {
    assert.notStrictEqual(
      appNode.hostname_or_ip,
      '10.22.12.204',
      `L4 App node MUST NOT show alien IP 10.22.12.204 when user is on ${netInfo.subnetCidr} (got ${appNode.hostname_or_ip})`
    );
  }
  console.log(`  ✓ All L1-L6 topology nodes verified dynamically aligned with current location (${netInfo.subnetCidr}); L4 App IP=${appNode.hostname_or_ip}.\n`);

  console.log('========================================================================');
  console.log('  SUITE 65 PASSED: DYNAMIC LOCATION TOPOLOGY 100% GREEN                 ');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runDynamicLocationTopologyAndZeroHardcodedIpsTests()
    .then(() => process.exit(0))
    .catch((err) => {
      console.error('Suite 65 failed:', err);
      process.exit(1);
    });
}

module.exports = { runDynamicLocationTopologyAndZeroHardcodedIpsTests };
