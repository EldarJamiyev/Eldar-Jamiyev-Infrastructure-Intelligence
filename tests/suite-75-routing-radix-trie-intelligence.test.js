"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.runSuite75RoutingRadixTrieIntelligence = runSuite75RoutingRadixTrieIntelligence;
// tests/suite-75-routing-radix-trie-intelligence.test.ts
const assert = __importStar(require("node:assert"));
const routing_radix_intelligence_1 = require("../src/topology/routing-radix-intelligence");
async function runSuite75RoutingRadixTrieIntelligence() {
    console.log('=== [SUITE 75] ROUTING RADIX TRIE LPM & ANOMALY AUDITOR VERIFICATION ===');
    // 1. Radix Trie LPM Resolution across Hierarchical Overlapping Masks
    console.log('[75.1] Verifying 32-bit LPM resolution across /0, /8, /16, /24, /32 prefixes...');
    const trie = new routing_radix_intelligence_1.RoutingRadixIntelligenceEngine();
    // Insert hierarchical nested routes
    trie.insertRoute('0.0.0.0/0', '192.168.1.1', 'Ethernet 1', 100);
    trie.insertRoute('10.0.0.0/8', '10.254.254.1', 'VPN Tunnel', 50);
    trie.insertRoute('10.50.0.0/16', '10.50.254.1', 'Branch Router', 30);
    trie.insertRoute('10.50.10.0/24', '10.50.10.1', 'VLAN 10 Subnet', 20);
    trie.insertRoute('10.50.10.5/32', '10.50.10.5', 'Single Host Server', 10);
    // Probe Default Route
    const lpmDefault = trie.lookupLongestPrefixMatch('8.8.8.8');
    assert.strictEqual(lpmDefault.matched, true, '8.8.8.8 must match default route');
    assert.strictEqual(lpmDefault.matchedCidr, '0.0.0.0/0', 'Must match 0.0.0.0/0');
    assert.strictEqual(lpmDefault.nextHop, '192.168.1.1');
    assert.strictEqual(lpmDefault.prefixLength, 0);
    // Probe /8
    const lpm8 = trie.lookupLongestPrefixMatch('10.1.2.3');
    assert.strictEqual(lpm8.matchedCidr, '10.0.0.0/8');
    assert.strictEqual(lpm8.prefixLength, 8);
    // Probe /16
    const lpm16 = trie.lookupLongestPrefixMatch('10.50.99.1');
    assert.strictEqual(lpm16.matchedCidr, '10.50.0.0/16');
    assert.strictEqual(lpm16.prefixLength, 16);
    // Probe /24
    const lpm24 = trie.lookupLongestPrefixMatch('10.50.10.200');
    assert.strictEqual(lpm24.matchedCidr, '10.50.10.0/24');
    assert.strictEqual(lpm24.prefixLength, 24);
    // Probe /32 exact host
    const lpm32 = trie.lookupLongestPrefixMatch('10.50.10.5');
    assert.strictEqual(lpm32.matchedCidr, '10.50.10.5/32');
    assert.strictEqual(lpm32.prefixLength, 32);
    assert.strictEqual(lpm32.nextHop, '10.50.10.5');
    // Verify Trie Stats
    const stats = trie.getStats();
    assert.ok(stats.nodeCount >= 33, `Trie node count should be at least 33, got ${stats.nodeCount}`);
    assert.strictEqual(stats.maxDepth, 32, 'Max trie depth should reach 32 for /32 host route');
    // 2. Deterministic Routing Anomaly Auditing
    console.log('[75.2] Verifying deterministic detection of 4 enterprise routing anomalies...');
    const testRoutes = [
        // 1. Equal-metric default gateway ambiguity
        { cidr: '0.0.0.0/0', destination: '0.0.0.0', netmask: '0.0.0.0', gateway: '192.168.1.1', interfaceName: 'eth0', metric: 25 },
        { cidr: '0.0.0.0/0', destination: '0.0.0.0', netmask: '0.0.0.0', gateway: '192.168.2.1', interfaceName: 'eth1', metric: 25 },
        // 2. Shadowed Route (Same prefix with higher metric)
        { cidr: '172.16.0.0/24', destination: '172.16.0.0', netmask: '255.255.255.0', gateway: '10.0.0.1', interfaceName: 'eth0', metric: 10 },
        { cidr: '172.16.0.0/24', destination: '172.16.0.0', netmask: '255.255.255.0', gateway: '10.0.0.2', interfaceName: 'eth0', metric: 50 },
        // 3. Split-Tunnel Leaks (0.0.0.0/1 and 128.0.0.0/1)
        { cidr: '0.0.0.0/1', destination: '0.0.0.0', netmask: '128.0.0.0', gateway: '10.8.0.1', interfaceName: 'tun0', metric: 5 },
        { cidr: '128.0.0.0/1', destination: '128.0.0.0', netmask: '128.0.0.0', gateway: '10.8.0.1', interfaceName: 'tun0', metric: 5 },
        // 4. CGNAT & APIPA Anomalies
        { cidr: '100.64.0.0/10', destination: '100.64.0.0', netmask: '255.192.0.0', gateway: '100.64.1.1', interfaceName: 'eth0', metric: 20 },
        { cidr: '169.254.0.0/16', destination: '169.254.0.0', netmask: '255.255.0.0', gateway: '169.254.1.1', interfaceName: 'eth0', metric: 20 }
    ];
    const auditEngine = new routing_radix_intelligence_1.RoutingRadixIntelligenceEngine();
    const anomalies = auditEngine.auditRouteTable(testRoutes);
    assert.ok(anomalies.length >= 4, `Expected at least 4 anomalies, got ${anomalies.length}`);
    const types = new Set(anomalies.map((a) => a.anomalyType));
    assert.ok(types.has('GATEWAY_METRIC_AMBIGUITY'), 'Must detect GATEWAY_METRIC_AMBIGUITY');
    assert.ok(types.has('SHADOWED_ROUTES'), 'Must detect SHADOWED_ROUTES');
    assert.ok(types.has('SPLIT_TUNNEL_LEAKS'), 'Must detect SPLIT_TUNNEL_LEAKS');
    assert.ok(types.has('CGNAT_OR_APIPA_ANOMALIES'), 'Must detect CGNAT_OR_APIPA_ANOMALIES');
    // Verify remediation advice is non-empty
    for (const anomaly of anomalies) {
        assert.ok(anomaly.remediationAdvice.length > 10, 'Remediation advice must be comprehensive');
        assert.ok(anomaly.affectedRoutes.length > 0, 'Affected routes list must not be empty');
    }
    // 3. Live Host Route Extraction & Comprehensive Audit
    console.log('[75.3] Verifying unprivileged live OS route table extraction...');
    const report = auditEngine.runComprehensiveAudit();
    assert.ok(report.totalRoutes >= 1, `Total extracted host routes must be >= 1, got ${report.totalRoutes}`);
    assert.ok(report.trieNodeCount >= 1, 'Trie node count in live report must be >= 1');
    assert.ok(report.sampleLpmProbes['8.8.8.8'] !== undefined, 'LPM probe for 8.8.8.8 must be present');
    assert.ok(Array.isArray(report.anomalies), 'Anomalies array must be present');
    assert.ok(report.timestampIso.length > 15, 'Timestamp must be valid ISO string');
    console.log(`  ✓ Extracted ${report.totalRoutes} live OS routes. Trie depth: ${report.maxTrieDepth}.`);
    console.log('✓ Suite 75 passed: Routing Radix Trie Intelligence 100% verified.\n');
}
if (require.main === module) {
    runSuite75RoutingRadixTrieIntelligence().then(() => process.exit(0)).catch(err => {
        console.error(err);
        process.exit(1);
    });
}
//# sourceMappingURL=suite-75-routing-radix-trie-intelligence.test.js.map