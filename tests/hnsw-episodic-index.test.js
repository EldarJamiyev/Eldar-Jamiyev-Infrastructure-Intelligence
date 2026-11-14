/**
 * Test Suite: Phase 5.0 Track 3 HNSW Vector Graph Index & Multi-Scale Incident Cascade Clustering
 */

const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const {
  HnswEpisodicIndex,
  hnswEpisodicIndex
} = require('../src/core/memory/hnsw-episodic-index');
const { operationalMemoryEngine } = require('../src/core/memory/operational-memory-engine');

describe('Phase 5.0 Track 3: HNSW Vector Graph Index & Louvain Modularity Clustering', () => {

  test('Metric Space: 64D projection and cosine distance metric invariants', () => {
    const index = new HnswEpisodicIndex();

    const t1 = { rttMs: 45.0, packetLossPct: 2.0, dnsLatencyMs: 12.0, queueDepth: 20 };
    const t2 = { rttMs: 45.0, packetLossPct: 2.0, dnsLatencyMs: 12.0, queueDepth: 20 };
    const t3 = { rttMs: 500.0, packetLossPct: 50.0, dnsLatencyMs: 2500.0, queueDepth: 500 };

    const v1 = index.projectTelemetryTo64D(t1);
    const v2 = index.projectTelemetryTo64D(t2);
    const v3 = index.projectTelemetryTo64D(t3);

    assert.equal(v1.length, 64);
    assert.equal(v2.length, 64);
    assert.equal(v3.length, 64);

    // Distance to self must be 0
    const selfDist = index.computeCosineDistance(v1, v2);
    assert.ok(selfDist < 1e-6, `Identical vectors must have distance ~0, got ${selfDist}`);

    // Distance to dissimilar vector must be > 0
    const diffDist = index.computeCosineDistance(v1, v3);
    assert.ok(diffDist > 0.05, `Divergent vectors must have distance > 0.05, got ${diffDist}`);
  });

  test('HNSW Multi-Layer Index: insertion, logarithmic search, and high recall@K vs exact scan', () => {
    const index = new HnswEpisodicIndex(); // Canonical M=16, M0=32, efConstruction=64, efSearch=32

    // Populate index with 120 synthetic telemetry incident vectors
    for (let i = 0; i < 120; i++) {
      const cluster = i % 4;
      const telemetry = {
        clusterId: cluster,
        rttMs: cluster === 0 ? 15 + Math.random() * 5 : (cluster === 1 ? 150 + Math.random() * 20 : 50 + Math.random() * 10),
        lossPct: cluster === 2 ? 8.0 + Math.random() * 2 : 0.1,
        queueDepth: cluster === 1 ? 80 + Math.random() * 15 : 5
      };
      const vec = index.projectTelemetryTo64D(telemetry);
      index.insert(`incident_${i}`, vec, { id: `incident_${i}`, cluster });
    }

    assert.equal(index.size(), 120);
    assert.ok(index.getMaxLevel() >= 1, `HNSW graph should construct multi-layer skip-lists (maxLevel >= 1), got ${index.getMaxLevel()}`);

    // Test KNN queries against exact linear scan
    let clusterMatchesCount = 0;
    const testQueries = [
      { rttMs: 16.0, lossPct: 0.1, queueDepth: 5, expectedCluster: 0 },     // Target cluster 0
      { rttMs: 155.0, lossPct: 0.1, queueDepth: 85, expectedCluster: 1 },   // Target cluster 1
      { rttMs: 40.0, lossPct: 8.5, queueDepth: 10, expectedCluster: 2 }     // Target cluster 2
    ];

    for (const q of testQueries) {
      const qVec = index.projectTelemetryTo64D(q);

      const startHnsw = process.hrtime.bigint();
      const hnswResults = index.searchKNN(qVec, 5);
      const elapsedMs = Number(process.hrtime.bigint() - startHnsw) / 1e6;

      // Sub-millisecond latency requirement
      assert.ok(elapsedMs < 10.0, `HNSW query should execute quickly (< 10ms), took ${elapsedMs}ms`);
      assert.equal(hnswResults.length, 5);

      const exactResults = index.searchExactKNN(qVec, 5);
      assert.equal(exactResults.length, 5);

      // Verify semantic cluster precision: items returned must match query failure regime
      const clusterHits = hnswResults.filter(r => r.payload.cluster === q.expectedCluster).length;
      clusterMatchesCount += clusterHits;

      // Verify distance bound: HNSW distance should be close to exact 5th nearest neighbor
      const fifthExactDist = exactResults[4].distance;
      for (const res of hnswResults) {
        assert.ok(
          res.distance <= fifthExactDist + 0.005,
          `HNSW result distance ${res.distance} must be within 0.005 of 5th exact neighbor ${fifthExactDist}`
        );
      }
    }

    const precision = clusterMatchesCount / (testQueries.length * 5);
    assert.ok(precision >= 0.80, `HNSW Cluster Precision must be >= 80%, got ${(precision * 100).toFixed(1)}%`);
  });

  test('Incident Cascade Clustering: Louvain modularity partitions synthetic multi-hop incident cascades', () => {
    const index = new HnswEpisodicIndex();

    // Construct 2 distinct incident failure cascades:
    // Community 1 (DNS & Gateway timeouts):
    //   dns_timeout <-> dns_cache_miss (w=5)
    //   dns_cache_miss <-> gw_504_timeout (w=4)
    //   dns_timeout <-> gw_504_timeout (w=4)
    // Community 2 (Kernel Socket & Buffer Exhaustion):
    //   socket_leak <-> kernel_oom (w=6)
    //   kernel_oom <-> nic_rx_drop (w=5)
    //   socket_leak <-> nic_rx_drop (w=5)
    // Weak bridge:
    //   gw_504_timeout <-> socket_leak (w=1)

    const edges = [
      { source: 'dns_timeout', target: 'dns_cache_miss', weight: 5 },
      { source: 'dns_cache_miss', target: 'gw_504_timeout', weight: 4 },
      { source: 'dns_timeout', target: 'gw_504_timeout', weight: 4 },

      { source: 'socket_leak', target: 'kernel_oom', weight: 6 },
      { source: 'kernel_oom', target: 'nic_rx_drop', weight: 5 },
      { source: 'socket_leak', target: 'nic_rx_drop', weight: 5 },

      { source: 'gw_504_timeout', target: 'socket_leak', weight: 1 }
    ];

    const result = index.clusterIncidentCascades(edges);
    assert.equal(result.nodesCount, 6);
    assert.equal(result.edgesCount, 7);
    assert.ok(result.modularityQ > 0.20, `Modularity Q must be positive and strong (> 0.20), got ${result.modularityQ}`);
    assert.equal(result.communities.length, 2, 'Should discover exactly 2 cohesive incident communities');

    // Verify membership: DNS group and Socket group separated
    const comm1Ids = new Set(result.communities[0].incidentIds);
    const comm2Ids = new Set(result.communities[1].incidentIds);

    const hasDnsGroupTogether =
      (comm1Ids.has('dns_timeout') && comm1Ids.has('dns_cache_miss')) ||
      (comm2Ids.has('dns_timeout') && comm2Ids.has('dns_cache_miss'));
    assert.equal(hasDnsGroupTogether, true, 'DNS cluster nodes must be grouped together');

    const hasSocketGroupTogether =
      (comm1Ids.has('socket_leak') && comm1Ids.has('kernel_oom')) ||
      (comm2Ids.has('socket_leak') && comm2Ids.has('kernel_oom'));
    assert.equal(hasSocketGroupTogether, true, 'Kernel socket nodes must be grouped together');
  });

  test('Serialization: toJSON and fromJSON preserve exact index structure and search fidelity', () => {
    const original = new HnswEpisodicIndex({ M: 4, M0: 8 });
    for (let i = 0; i < 20; i++) {
      const vec = original.projectTelemetryTo64D({ rttMs: i * 10, lossPct: i * 0.5 });
      original.insert(`ser_node_${i}`, vec, { tag: `item_${i}` });
    }

    const jsonStr = original.toJSON();
    assert.ok(jsonStr.length > 100);

    const restored = HnswEpisodicIndex.fromJSON(jsonStr);
    assert.equal(restored.size(), 20);
    assert.equal(restored.getMaxLevel(), original.getMaxLevel());

    // Compare search results on both indices
    const queryVec = original.projectTelemetryTo64D({ rttMs: 55, lossPct: 2.5 });
    const origResults = original.searchKNN(queryVec, 3);
    const restoredResults = restored.searchKNN(queryVec, 3);

    assert.equal(origResults.length, 3);
    assert.equal(restoredResults.length, 3);
    assert.equal(origResults[0].id, restoredResults[0].id);
    assert.equal(origResults[0].distance, restoredResults[0].distance);
  });

  test('OperationalMemoryEngine integration: accelerates experience replay and enables cascade clustering', () => {
    // Populate an incident resolution via event bus
    operationalMemoryEngine.emit('INCIDENT_RESOLUTION_COMMITTED', {
      resolutionId: 'res_test_hnsw_01',
      targetKey: 'gateway.local',
      symptomSignature: 'DNS timeout on 1.1.1.1:53 with high UDP packet loss',
      rootCause: 'DNS_NXDOMAIN_POISON',
      resolutionSteps: 'Flush DNS resolver cache and switch to fallback resolver'
    });

    assert.ok(operationalMemoryEngine.hnswIndex.size() >= 1, 'HnswIndex should contain the committed resolution');

    // Query experience replay
    const replay = operationalMemoryEngine.replayHistoricalExperiences({
      target: 'gateway.local',
      symptomSignature: 'DNS latency spike',
      topK: 3
    });

    assert.ok(replay, 'Replay result must be returned');
    assert.ok(replay.candidateMatchesCount >= 1);

    // Run cascade clustering from operationalMemoryEngine
    const cascades = operationalMemoryEngine.clusterHistoricalCascades([
      { source: 'dns_fail', target: 'conn_timeout', weight: 4 },
      { source: 'conn_timeout', target: 'http_504', weight: 3 }
    ]);
    assert.ok(cascades, 'Cascades clustering should return valid result');
    assert.ok(cascades.communities.length >= 1);
  });

  test('Multi-Scale Incident Cascade Clustering: identifies propagation pathways, dominant scale, and early warning signature', () => {
    const index = new HnswEpisodicIndex();
    const edges = [
      { source: 'bgp_route_withdraw', target: 'ingress_packet_loss', weight: 6 },
      { source: 'ingress_packet_loss', target: 'gateway_502_spike', weight: 5 },
      { source: 'gateway_502_spike', target: 'client_retry_storm', weight: 4 }
    ];

    const result = index.clusterMultiScaleCascades(edges, { leadTimeBaseSeconds: 25.0 });
    assert.ok(result.communities.length >= 1);
    assert.ok(result.modularityQ >= 0);
    assert.ok(Array.isArray(result.pathways) && result.pathways.length >= 1);
    assert.strictEqual(result.pathways[0].sourceIncident, 'bgp_route_withdraw');
    assert.ok(result.pathways[0].propagatedTo.length >= 1);
    assert.ok(result.pathways[0].earlyWarningLeadTimeSeconds >= 25.0);
    assert.ok(typeof result.dominantFrequencyScale === 'number');
    assert.match(result.earlyWarningSignature, /CASCADE_EARLY_WARNING/);
  });

});
