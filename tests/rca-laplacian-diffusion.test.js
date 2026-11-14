/**
 * EJII — RCA Engine Continuous Laplacian Heat Diffusion & Topology Contours Suite (Track 2)
 * Verifies integration of continuous heat diffusion probabilities into RCA propagation chains
 * and topological heatmap contour calculation.
 */

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { RCAEngine } = require('../src/core/rca-engine');
const { temporalInfrastructureGraph } = require('../src/core/topology/temporal-graph-engine');

test('EJII RCA Continuous Laplacian Heat Diffusion Suite', async (t) => {
  const rca = new RCAEngine();

  await t.test('1. verifies disambiguateUpstreamVsDownstreamSymptoms calculates continuous degradation probabilities and contours', () => {
    const nodes = [
      { id: 'switch-core-01', role: 'CORE_SWITCH', status: 'CRITICAL', location: 'DC_EAST' },
      { id: 'app-gateway-01', role: 'APP_GATEWAY', status: 'CRITICAL', location: 'DC_EAST' },
      { id: 'db-cluster-01', role: 'DATABASE', status: 'CRITICAL', location: 'DC_EAST' },
      { id: 'worker-pool-01', role: 'WORKER', status: 'CRITICAL', location: 'DC_EAST' }
    ];

    const edges = [
      { source: 'switch-core-01', target: 'app-gateway-01', weight: 0.9 },
      { source: 'app-gateway-01', target: 'db-cluster-01', weight: 0.8 },
      { source: 'app-gateway-01', target: 'worker-pool-01', weight: 0.7 }
    ];

    const telemetryMap = {
      'switch-core-01': { lossPct: 100, latencyMs: 5000, status: 'CRITICAL', timestamp: new Date(Date.now() - 5000).toISOString() },
      'app-gateway-01': { lossPct: 90, latencyMs: 4000, status: 'CRITICAL', timestamp: new Date(Date.now() - 3000).toISOString() },
      'db-cluster-01': { lossPct: 80, latencyMs: 3000, status: 'CRITICAL', timestamp: new Date(Date.now() - 1000).toISOString() },
      'worker-pool-01': { lossPct: 75, latencyMs: 2500, status: 'CRITICAL', timestamp: new Date().toISOString() }
    };

    const result = rca.disambiguateUpstreamVsDownstreamSymptoms({
      primaryIncident: { target: 'switch-core-01' },
      nodes,
      edges,
      telemetryMap
    });

    assert.ok(result);
    assert.ok(result.multiHopTraversal, 'Must return multiHopTraversal');
    assert.equal(result.multiHopTraversal.rootCauseAncestors[0], 'switch-core-01');

    const chain = result.multiHopTraversal.propagationChain;
    assert.ok(chain.length >= 4);

    const rootItem = chain.find((c) => c.nodeId === 'switch-core-01');
    assert.ok(rootItem);
    assert.equal(rootItem.hopDistanceFromRoot, 0);
    assert.ok(rootItem.continuousDegradationProbability >= 0.50, `Root probability should be high, got ${rootItem.continuousDegradationProbability}`);
    assert.ok(rootItem.contourLevel);

    const hop1Item = chain.find((c) => c.nodeId === 'app-gateway-01');
    assert.ok(hop1Item);
    assert.equal(hop1Item.hopDistanceFromRoot, 1);
    assert.ok(typeof hop1Item.continuousDegradationProbability === 'number');

    const hop2Item = chain.find((c) => c.nodeId === 'db-cluster-01');
    assert.ok(hop2Item);
    assert.equal(hop2Item.hopDistanceFromRoot, 2);

    // Continuous decay property: downstream nodes exhibit strictly non-negative continuous probabilities
    assert.ok(hop1Item.continuousDegradationProbability > 0);
    assert.ok(hop2Item.continuousDegradationProbability > 0);

    // Contours list must be populated
    assert.ok(Array.isArray(result.multiHopTraversal.laplacianDiffusionContours));
  });

  await t.test('2. verifies computeLaplacianHeatDiffusion directly on temporalInfrastructureGraph produces continuous contours', () => {
    // Seed nodes
    temporalInfrastructureGraph.nodes.set('node-a', { nodeId: 'node-a', resourceType: 'switch', label: 'Node A', status: 'critical' });
    temporalInfrastructureGraph.nodes.set('node-b', { nodeId: 'node-b', resourceType: 'host', label: 'Node B', status: 'healthy' });
    temporalInfrastructureGraph.nodes.set('node-c', { nodeId: 'node-c', resourceType: 'host', label: 'Node C', status: 'healthy' });
    temporalInfrastructureGraph.upsertEdge({ sourceId: 'node-a', targetId: 'node-b', confidence: 1.0 });
    temporalInfrastructureGraph.upsertEdge({ sourceId: 'node-b', targetId: 'node-c', confidence: 1.0 });

    const diff = temporalInfrastructureGraph.computeLaplacianHeatDiffusion('node-a', 0.5);
    assert.equal(diff.sourceNodeId, 'node-a');
    assert.ok(diff.diffusionContours.length >= 3);

    const cA = diff.diffusionContours.find((c) => c.nodeId === 'node-a');
    const cB = diff.diffusionContours.find((c) => c.nodeId === 'node-b');
    const cC = diff.diffusionContours.find((c) => c.nodeId === 'node-c');

    assert.ok(cA.degradationProbability > cB.degradationProbability, 'Heat at source node-a must exceed neighbor node-b');
    assert.ok(cB.degradationProbability > cC.degradationProbability, 'Heat at 1-hop neighbor node-b must exceed 2-hop node-c');
  });

  await t.test('3. verifies diffusion-contours route handler returns authentic Laplacian contours', () => {
    const router = require('../src/api/routes-v6-fabric');
    const mockReq = {
      params: { sourceNodeId: 'node-a' },
      query: { t: '0.5' },
      method: 'GET',
      url: '/temporal-graph/diffusion-contours/node-a'
    };
    let responseData = null;
    const mockRes = {
      json: (payload) => {
        responseData = payload;
        return mockRes;
      },
      status: () => mockRes
    };

    const routeLayer = router.stack.find((l) => l.route && l.route.path && (
      (Array.isArray(l.route.path) && l.route.path.some((p) => p.includes('diffusion-contours'))) ||
      (typeof l.route.path === 'string' && l.route.path.includes('diffusion-contours'))
    ));
    assert.ok(routeLayer, 'Must find diffusion-contours route in v6 fabric router');

    routeLayer.route.stack[0].handle(mockReq, mockRes);
    assert.ok(responseData);
    assert.equal(responseData.success, true);
    assert.equal(responseData.capabilityId, 'ejii.v6.temporal_graph.diffusion_contours');
    assert.equal(responseData.data.sourceNodeId, 'node-a');
    assert.ok(responseData.data.diffusionContours.length >= 3);
  });
});
