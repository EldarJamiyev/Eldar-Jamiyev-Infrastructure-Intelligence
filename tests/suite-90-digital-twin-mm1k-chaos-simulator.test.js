// tests/suite-90-digital-twin-mm1k-chaos-simulator.test.js
/**
 * EJII Test Suite 90: Digital Twin Chaos Simulator & M/M/1/K Finite-Buffer Queuing Engine
 * Verifies M/M/1/K queuing math (rho, P_K drop probability, Little's law waiting time),
 * What-If chaos topological degradation, Laplacian algebraic connectivity (lambda_2, Delta lambda_2),
 * and the REST API POST /api/network/digital-twin/simulate endpoint.
 */

'use strict';

const assert = require('node:assert/strict');
const { DigitalTwinChaosSimulator } = require('../src/topology/digital-twin-chaos-simulator');
const routesNetwork = require('../src/api/routes-network');

async function runSuite90DigitalTwinChaosSimulator() {
  console.log('========================================================================');
  console.log('  === [SUITE 90] DIGITAL TWIN CHAOS & M/M/1/K QUEUING SIMULATOR ===     ');
  console.log('========================================================================\n');

  // [90.1] M/M/1/K Under-saturated Regime (rho < 1.0)
  console.log('[Test 90.1] Testing M/M/1/K queuing under-saturated regime (rho = 0.5, K = 10)...');
  // lambda = 500 pps, mu = 1000 pps, K = 10
  // rho = 0.5
  // P_0 = (1 - 0.5) / (1 - 0.5^11) = 0.5 / (1 - 0.000488) = 0.500244
  // P_K = P_0 * 0.5^10 = 0.500244 / 1024 = 0.000488
  const qLow = DigitalTwinChaosSimulator.computeMM1K(500, 1000, 10);
  assert.strictEqual(qLow.utilizationRho, 0.5);
  assert.ok(qLow.dropProbability < 0.001, `Drop prob under 50% load must be < 0.1%, got ${qLow.dropProbability}`);
  assert.ok(qLow.averageQueueLength > 0 && qLow.averageQueueLength < 1.5, `Average queue length should be ~1, got ${qLow.averageQueueLength}`);
  assert.ok(qLow.queuingDelaySec > 0, `Queuing delay must be positive, got ${qLow.queuingDelaySec}`);
  console.log(`  ✓ Under-saturated M/M/1/K: rho=${qLow.utilizationRho}, dropProb=${qLow.dropProbability}, avgQueue=${qLow.averageQueueLength}, delay=${(qLow.queuingDelaySec * 1000).toFixed(2)}ms`);

  // [90.2] M/M/1/K Critical Saturation (rho = 1.0) Degenerate Case
  console.log('[Test 90.2] Testing M/M/1/K critical saturation (rho = 1.0, K = 20)...');
  // At rho = 1.0: P_k = 1 / (K + 1) for all k
  // For K = 20: P_20 = 1 / 21 = 0.047619
  // Average queue length L = K / 2 = 10.0
  const qCrit = DigitalTwinChaosSimulator.computeMM1K(1000, 1000, 20);
  assert.strictEqual(qCrit.utilizationRho, 1.0);
  assert.ok(Math.abs(qCrit.dropProbability - (1 / 21)) < 0.001, `Drop prob at rho=1 must be ~1/21, got ${qCrit.dropProbability}`);
  assert.strictEqual(qCrit.averageQueueLength, 10.0, `Average queue length at rho=1 must be K/2 = 10, got ${qCrit.averageQueueLength}`);
  console.log(`  ✓ Critical saturation M/M/1/K: rho=1.0, dropProb=${qCrit.dropProbability}, avgQueue=${qCrit.averageQueueLength}`);

  // [90.3] M/M/1/K Over-saturated Regime (rho > 1.0)
  console.log('[Test 90.3] Testing M/M/1/K over-saturated buffer overflow regime (rho = 2.0, K = 10)...');
  // lambda = 2000 pps, mu = 1000 pps, K = 10
  // System is overloaded; buffer is almost always full; drop probability ~ 1 - 1/rho = 0.50
  const qHigh = DigitalTwinChaosSimulator.computeMM1K(2000, 1000, 10);
  assert.strictEqual(qHigh.utilizationRho, 2.0);
  assert.ok(qHigh.dropProbability > 0.45 && qHigh.dropProbability <= 0.55, `Drop prob under 2x overload must be ~0.50, got ${qHigh.dropProbability}`);
  assert.ok(qHigh.averageQueueLength > 8.5, `Buffer should be mostly full (avgQueue > 8.5), got ${qHigh.averageQueueLength}`);
  console.log(`  ✓ Over-saturated M/M/1/K: rho=2.0, dropProb=${qHigh.dropProbability}, avgQueue=${qHigh.averageQueueLength}`);

  // [90.4] Digital Twin Topological Chaos Simulation & Delta Lambda_2
  console.log('[Test 90.4] Simulating link severance & traffic surge on 6-node topology...');
  const simulator = new DigitalTwinChaosSimulator();

  const testNodes = [
    { id: 'L1-WAN', role: 'GATEWAY', latencyMs: 12.0, packetLossPct: 0.1 },
    { id: 'L2-EDGE', role: 'GATEWAY', latencyMs: 2.5, packetLossPct: 0.0 },
    { id: 'L3-CORE', role: 'SWITCH', latencyMs: 0.8, packetLossPct: 0.0 },
    { id: 'L4-SERVER', role: 'SERVER', latencyMs: 0.5, packetLossPct: 0.0 },
    { id: 'L5-HOST-A', role: 'WORKSTATION', latencyMs: 0.2, packetLossPct: 0.0 },
    { id: 'L6-HOST-B', role: 'WORKSTATION', latencyMs: 0.3, packetLossPct: 0.0 }
  ];

  const testEdges = [
    { source: 'L1-WAN', target: 'L2-EDGE', rttMs: 12.0 },
    { source: 'L2-EDGE', target: 'L3-CORE', rttMs: 2.5 },
    { source: 'L3-CORE', target: 'L4-SERVER', rttMs: 0.8 },
    { source: 'L3-CORE', target: 'L5-HOST-A', rttMs: 0.5 },
    { source: 'L3-CORE', target: 'L6-HOST-B', rttMs: 0.6 }
  ];

  // Sever the core link between L2-EDGE and L3-CORE
  const chaosResult = simulator.simulate(testNodes, testEdges, 'L1-WAN', {
    severedEdgeKeys: ['L2-EDGE:L3-CORE'],
    trafficMultiplier: 2.5,
    bufferCapacityK: 20
  });

  assert.ok(chaosResult, 'Chaos simulation result must be returned');
  assert.ok(typeof chaosResult.preChaosLambda2 === 'number', 'Pre-chaos lambda2 must be numeric');
  assert.ok(typeof chaosResult.postChaosLambda2 === 'number', 'Post-chaos lambda2 must be numeric');
  assert.ok(chaosResult.deltaLambda2 <= 0, `Severing bridge must decrease or maintain algebraic connectivity (got delta = ${chaosResult.deltaLambda2})`);
  assert.ok(chaosResult.strandedNodeCount > 0, 'Stranded/partitioned nodes must be detected when cut-edge is severed');
  assert.ok(chaosResult.partitionedNodeIds.length > 0, 'partitionedNodeIds must contain stranded nodes');
  assert.ok(Array.isArray(chaosResult.nodeMetrics), 'Node queuing metrics must be populated');
  assert.ok(chaosResult.averageDropProbabilityPct >= 0);
  console.log(`  ✓ Chaos simulation verified: Pre-lambda2=${chaosResult.preChaosLambda2.toFixed(4)}, Post-lambda2=${chaosResult.postChaosLambda2.toFixed(4)}, Delta=${chaosResult.deltaLambda2}, Stranded=${chaosResult.strandedNodeCount}`);

  // [90.5] REST API POST /api/network/digital-twin/simulate
  console.log('[Test 90.5] Testing POST /api/network/digital-twin/simulate via router stack...');
  const simLayer = routesNetwork.stack.find(s => s.route && s.route.path === '/digital-twin/simulate');
  assert.ok(simLayer, 'Route POST /digital-twin/simulate must be mounted in routes-network.js');

  let simJson = null;
  const mockReq = {
    body: {
      scenario: {
        trafficMultiplier: 1.8,
        severedEdgeKeys: ['L2-EDGE_ROUTER:L3-CORE_SWITCH'],
        bufferCapacityK: 30
      }
    }
  };
  const mockRes = {
    statusCode: 200,
    status(c) { this.statusCode = c; return this; },
    json(d) { simJson = d; return this; }
  };

  const handler = simLayer.route.stack[simLayer.route.stack.length - 1].handle;
  handler(mockReq, mockRes, () => {});

  assert.ok(simJson, 'Route must respond with JSON');
  assert.strictEqual(simJson.success, true);
  assert.ok(typeof simJson.deltaLambda2 === 'number');
  assert.ok(Array.isArray(simJson.nodeMetrics));
  console.log(`  ✓ POST /api/network/digital-twin/simulate responded 200 OK: deltaLambda2=${simJson.deltaLambda2}`);

  console.log('\n========================================================================');
  console.log('  SUITE 90 PASSED: DIGITAL TWIN CHAOS & M/M/1/K SIMULATOR 100% GREEN   ');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runSuite90DigitalTwinChaosSimulator().catch((err) => {
    console.error('Suite 90 failed:', err);
    process.exit(1);
  });
}

module.exports = {
  runSuite90DigitalTwinChaosSimulator,
  runSuite90: runSuite90DigitalTwinChaosSimulator
};
