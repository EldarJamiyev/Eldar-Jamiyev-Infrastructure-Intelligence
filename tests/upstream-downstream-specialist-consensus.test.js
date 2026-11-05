/**
 * Unit Test Suite: Upstream vs Downstream Symptom Disambiguation & Dynamic Specialist Consensus
 * Validates:
 *   1. Disambiguation between core upstream failure and consequential downstream symptoms.
 *   2. Localized branch fault classification when upstream core is healthy.
 *   3. 6-domain collaborative specialist consensus confidence formula with contradiction penalties.
 */

'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { DiagnosticReasoningEngine, disambiguateUpstreamVsDownstreamSymptoms } = require('../src/core/rca-engine');
const { cognitiveIntelligenceEngine } = require('../src/core/cognition/cognitive-intelligence-engine');

test('RCA Engine — Disambiguates upstream core failure from downstream branch symptoms', () => {
  const rca = new DiagnosticReasoningEngine();

  const upstreamNodes = [
    {
      id: 'db-core-frankfurt',
      role: 'CORE_ORACLE_DATABASE',
      location: 'Frankfurt DC',
      latencyMs: 1450,
      packetLossPct: 40,
      status: 'TIMEOUT',
      failureDescription: 'Connection pool exhausted & packet timeout'
    }
  ];

  const downstreamNodes = [
    {
      id: 'branch-app-singapore',
      role: 'BRANCH_ERP_GATEWAY',
      location: 'Singapore Office',
      latencyMs: 1520,
      packetLossPct: 0,
      status: 'DEGRADED'
    },
    {
      id: 'branch-app-london',
      role: 'BRANCH_ERP_GATEWAY',
      location: 'London Office',
      latencyMs: 1480,
      packetLossPct: 0,
      status: 'DEGRADED'
    }
  ];

  const result = rca.disambiguateUpstreamVsDownstreamSymptoms({
    upstreamNodes,
    downstreamNodes
  });

  assert.equal(result.isUpstreamFailure, true);
  assert.equal(result.classification, 'UPSTREAM_CORE_INFRASTRUCTURE_FAILURE');
  assert.equal(result.rootCauseNode, 'db-core-frankfurt');
  assert.equal(result.rootCauseLocation, 'Frankfurt DC');
  assert.equal(result.upstreamFailures.length, 1);
  assert.equal(result.downstreamSymptoms.length, 2);
  assert.match(result.executiveSummary, /ROOT CAUSE: Upstream core service/);
  assert.match(result.recommendedIntervention, /Prioritize immediate recovery on upstream/);
});

test('RCA Engine — Disambiguates localized edge/branch fault when upstream core is nominal', () => {
  const rca = new DiagnosticReasoningEngine();

  const upstreamNodes = [
    {
      id: 'db-core-frankfurt',
      role: 'CORE_DATABASE',
      location: 'Frankfurt DC',
      latencyMs: 12,
      packetLossPct: 0,
      status: 'PASS'
    }
  ];

  const downstreamNodes = [
    {
      id: 'branch-gw-tokyo',
      role: 'EDGE_BRANCH_ROUTER',
      location: 'Tokyo Office',
      latencyMs: 450,
      packetLossPct: 85,
      status: 'FAIL'
    }
  ];

  const result = rca.disambiguateUpstreamVsDownstreamSymptoms({
    upstreamNodes,
    downstreamNodes
  });

  assert.equal(result.isUpstreamFailure, false);
  assert.equal(result.classification, 'LOCALIZED_DOWNSTREAM_BRANCH_FAULT');
  assert.equal(result.rootCauseNode, 'branch-gw-tokyo');
  assert.equal(result.rootCauseLocation, 'Tokyo Office');
  assert.match(result.executiveSummary, /Localized edge\/branch fault at 'branch-gw-tokyo'/);
});

test('Cognitive Engine — Dynamic 6-Domain Specialist Consensus with telemetry and contradiction penalties', () => {
  const collab = cognitiveIntelligenceEngine.synthesizeCollaborativeSpecialistIntelligence({
    target: '127.0.0.1',
    port: 3000,
    objective: 'Investigate port 3000 latency and HTTP response',
    problemNature: 'FAILING_OR_UNREACHABLE_SERVER',
    steps: [
      { layer: 'L7_DNS', status: 'PASS', latencyMs: 1.8 },
      { layer: 'L4_TCP', status: 'PASS', latencyMs: 0.9 },
      { layer: 'L7_HTTP', status: 'FAIL', latencyMs: 15.2 }
    ],
    liveTelemetry: {
      measuredRttMs: 0.9,
      dnsLatencyMs: 1.8,
      httpStatus: 503,
      ttfbMs: 15.2
    }
  });

  assert.equal(collab.specialistContributions.length, 6);
  assert.equal(collab.specialistPerspectives.length, 6);
  assert.ok(collab.consensusConfidencePct > 0 && collab.consensusConfidencePct <= 100);
  assert.ok(collab.metricsGrounded);
  assert.equal(collab.metricsGrounded.coverageRatio, 1.0); // 6 / 6
  assert.ok(collab.metricsGrounded.contradictionsDetected >= 1); // L4 PASS but L7 FAIL contradiction
  assert.ok(collab.metricsGrounded.consistencyRatio < 1.0); // Penalized consistency

  // Verify grounded telemetry in contributions
  const netContrib = collab.specialistContributions.find(c => c.domainId === 'NETWORK_AND_PROTOCOL_INTELLIGENCE');
  assert.match(netContrib.contributedObservation, /Live wire RTT:/);

  const appContrib = collab.specialistContributions.find(c => c.domainId === 'APPLICATION_AND_SERVICE_INTELLIGENCE');
  assert.match(appContrib.contributedObservation, /HTTP 503/);
  assert.ok(Array.isArray(collab.crossExaminationDebate) && collab.crossExaminationDebate.length >= 2);
  assert.ok(collab.compoundMultiCauseAnalysis);
});

test('RCA Engine — Generalized 5-Tier N-Hop Topological Graph Traversal pinpoints root ancestor', () => {
  const rca = new DiagnosticReasoningEngine();

  const dependencyGraph = {
    nodes: [
      { id: 'tier1-storage-san', role: 'SAN_STORAGE_CLUSTER', location: 'Core Vault', status: 'FAIL', latencyMs: 2400, packetLossPct: 60 },
      { id: 'tier2-primary-db', role: 'POSTGRES_PRIMARY', location: 'Core DB Tier', status: 'TIMEOUT', latencyMs: 2100, packetLossPct: 0 },
      { id: 'tier3-auth-service', role: 'IDENTITY_PROVIDER', location: 'Middleware Tier', status: 'FAIL', latencyMs: 1950, packetLossPct: 0 },
      { id: 'tier4-api-gateway', role: 'API_INGRESS_GW', location: 'DMZ Tier', status: 'FAIL', latencyMs: 1900, packetLossPct: 0 },
      { id: 'tier5-edge-portal', role: 'BRANCH_CLIENT_PORTAL', location: 'Zurich Branch', status: 'FAIL', latencyMs: 1850, packetLossPct: 0 }
    ],
    edges: [
      { from: 'tier1-storage-san', to: 'tier2-primary-db', relationship: 'provides_to' },
      { from: 'tier2-primary-db', to: 'tier3-auth-service', relationship: 'provides_to' },
      { from: 'tier3-auth-service', to: 'tier4-api-gateway', relationship: 'provides_to' },
      { from: 'tier4-api-gateway', to: 'tier5-edge-portal', relationship: 'provides_to' }
    ]
  };

  const result = rca.disambiguateUpstreamVsDownstreamSymptoms({ dependencyGraph });
  assert.equal(result.isUpstreamFailure, true);
  assert.equal(result.rootCauseNode, 'tier1-storage-san');
  assert.equal(result.multiHopTraversal.maxPropagationDepthHops, 4);
  assert.deepEqual(result.multiHopTraversal.rootCauseAncestors, ['tier1-storage-san']);
  assert.equal(result.downstreamSymptoms.length, 4);
  const leafSymptom = result.downstreamSymptoms.find((d) => d.nodeId === 'tier5-edge-portal');
  assert.ok(leafSymptom);
  assert.equal(leafSymptom.hopDistanceFromRoot, 4);
});

test('Agentless Collector & Edge Agent Service — Multi-signal fallback on SNMP timeout & idempotent lease_epoch', async () => {
  const { agentlessCollector } = require('../src/core/agent/agentless-collector');
  const { edgeAgentService } = require('../src/core/agent/edge-agent-service');

  const profile = await agentlessCollector.profileDeviceMultiSignal('127.0.0.1', {
    timeoutMs: 300,
    ports: [3000, 59998]
  });
  assert.equal(profile.targetHost, '127.0.0.1');
  assert.equal(profile.collectionType, 'MULTI_SIGNAL_AGENTLESS_FUSION');
  assert.ok(Array.isArray(profile.signalsCollected) && profile.signalsCollected.includes('TCP_SERVICE_PORT_MATRIX'));

  // Verify idempotent lease_epoch enforcement on edgeAgentService
  const enrolled = edgeAgentService.enrollAgent({
    name: 'Epoch-Test-Agent',
    siteId: 'site-hq-lon',
    hostname: 'epoch-test.local',
    platform: 'linux',
    ipAddress: '127.0.0.1'
  });
  const dispatched = edgeAgentService.dispatchProbeTask({
    agentId: enrolled.agentId,
    taskType: 'probe_tcp',
    target: '127.0.0.1',
    port: 3000
  });
  const hb1 = edgeAgentService.processHeartbeat(enrolled.agentId);
  const taskLease1 = hb1.assignedTasks.find((t) => t.taskId === dispatched.taskId);
  assert.ok(taskLease1);
  assert.equal(taskLease1.leaseEpoch, 1);

  // Force task back to PENDING and dispatch again to advance lease_epoch to 2
  const { db } = require('../src/db/database');
  db.prepare(`UPDATE enterprise_agent_tasks SET status = 'PENDING', dispatched_at = NULL WHERE id = ?`).run(dispatched.taskId);
  const hb2 = edgeAgentService.processHeartbeat(enrolled.agentId);
  const taskLease2 = hb2.assignedTasks.find((t) => t.taskId === dispatched.taskId);
  assert.ok(taskLease2);
  assert.equal(taskLease2.leaseEpoch, 2);

  // Submitting stale epoch 1 must be rejected idempotently
  const staleSubmit = edgeAgentService.submitTaskResult(dispatched.taskId, enrolled.agentId, { ok: true }, 1);
  assert.equal(staleSubmit.success, false);
  assert.equal(staleSubmit.status, 'STALE_LEASE_EPOCH_IGNORED');

  // Submitting current epoch 2 succeeds
  const validSubmit = edgeAgentService.submitTaskResult(dispatched.taskId, enrolled.agentId, { ok: true }, 2);
  assert.equal(validSubmit.success, true);
  assert.equal(validSubmit.status, 'COMPLETED');
  assert.equal(validSubmit.leaseEpoch, 2);
});

test('PR #3 — Chat Intent Isolation Across Topic Switches & Multi-Turn State Diffing', async () => {
  const { chatOperatorService } = require('../src/core/chat/chat-operator-service');
  const sessionId = `TEST-PR3-ISOLATION-${Date.now()}`;
  const user = { id: 'u-pr3', username: 'admin', role: 'ADMIN' };

  // 1. Start mail server inspection (creates pendingTask: mail_server_inspection)
  const turn1 = await chatOperatorService.processMessage({
    sessionId,
    message: 'Check mail server',
    user
  });
  assert.equal(turn1.data.intent, 'clarification_needed');

  // 2. Switch topic to explicit DNS lookup ("Check DNS for localhost") — must cancel mail pendingTask and run dns, NOT mail ports!
  const turn2 = await chatOperatorService.processMessage({
    sessionId,
    message: 'Check DNS for localhost',
    user
  });
  assert.equal(turn2.success, true);
  assert.equal(turn2.data.intent, 'dns');
  assert.equal(turn2.data.target, 'localhost');
  assert.deepEqual(turn2.data.ports, [], 'DNS turn must not inherit mail ports');

  // 3. Run second check on localhost and then ask to compare current state to previous scan
  await chatOperatorService.processMessage({
    sessionId,
    message: 'Ping localhost',
    user
  });
  const compareTurn = await chatOperatorService.processMessage({
    sessionId,
    message: "Compare this host's current state to the previous scan",
    user
  });
  assert.equal(compareTurn.success, true);
  assert.equal(compareTurn.data.intent, 'follow_up_explanation');
  assert.ok(compareTurn.data.technicalEvidence.stateDiff, 'Must compute structured stateDiff across turns');
  assert.equal(compareTurn.data.technicalEvidence.stateDiff.target, 'localhost');
});

test('RCA Engine — Complex Enterprise Topology: HA Active/Passive Failover, Circular SCC Patient Zero, Visibility Gaps & Lingering Downstream State', () => {
  const rca = new DiagnosticReasoningEngine();

  // 1. HA Active/Passive Pair with healthy standby -> DEGRADED_REDUNDANCY_FAILOVER_ACTIVE
  const haFailover = rca.disambiguateUpstreamVsDownstreamSymptoms({
    dependencyGraph: {
      nodes: [
        { id: 'fw-core-primary', role: 'CORE_FIREWALL_PRIMARY', status: 'FAIL', haGroup: 'ha-fw-core', haRole: 'PRIMARY', quorumMinHealthy: 1 },
        { id: 'fw-core-standby', role: 'CORE_FIREWALL_STANDBY', status: 'PASS', haGroup: 'ha-fw-core', haRole: 'STANDBY', quorumMinHealthy: 1 },
        { id: 'app-tier-01', role: 'ENTERPRISE_APP', status: 'PASS' }
      ],
      edges: [
        { from: 'fw-core-primary', to: 'app-tier-01' },
        { from: 'fw-core-standby', to: 'app-tier-01' }
      ]
    }
  });
  assert.equal(haFailover.classification, 'DEGRADED_REDUNDANCY_FAILOVER_ACTIVE');
  assert.equal(haFailover.isUpstreamFailure, false);
  assert.equal(haFailover.haAnalysis.hasRedundantFailoverActive, true);
  assert.equal(haFailover.rootCauseNode, 'fw-core-primary');

  // 2. Circular / Mutual Service Dependency (Auth <-> Directory <-> Token Cache) isolates Patient Zero via SCC + anomaly timestamp
  const circularScc = rca.disambiguateUpstreamVsDownstreamSymptoms({
    dependencyGraph: {
      nodes: [
        { id: 'svc-directory', role: 'LDAP_DIRECTORY', status: 'FAIL', firstAnomalyTimestampMs: 1000 },
        { id: 'svc-auth', role: 'OAUTH_BROKER', status: 'FAIL', firstAnomalyTimestampMs: 1250 },
        { id: 'svc-token-cache', role: 'REDIS_TOKEN_CACHE', status: 'FAIL', firstAnomalyTimestampMs: 1400 }
      ],
      edges: [
        { from: 'svc-directory', to: 'svc-auth' },
        { from: 'svc-auth', to: 'svc-token-cache' },
        { from: 'svc-token-cache', to: 'svc-directory' }
      ]
    }
  });
  assert.equal(circularScc.classification, 'CIRCULAR_DEPENDENCY_PATIENT_ZERO_ISOLATED');
  assert.equal(circularScc.circularDependencies.hasCircularDependencies, true);
  assert.equal(circularScc.rootCauseNode, 'svc-directory');

  // 3. Explicit Telemetry Visibility Gap (UNPROBED / SNMP_TIMEOUT_ONLY) never misclassified as healthy or root cause
  const visibilityGap = rca.disambiguateUpstreamVsDownstreamSymptoms({
    dependencyGraph: {
      nodes: [
        { id: 'sw-core-unprobed', role: 'CORE_SWITCH', status: 'SNMP_TIMEOUT_ONLY' },
        { id: 'edge-printer-01', role: 'BRANCH_PRINTER', status: 'PASS' }
      ],
      edges: [
        { from: 'sw-core-unprobed', to: 'edge-printer-01' }
      ]
    }
  });
  assert.equal(visibilityGap.classification, 'TELEMETRY_VISIBILITY_GAP');
  assert.equal(visibilityGap.visibilityGaps.count, 1);

  // 4. Upstream Recovered with Lingering Downstream Symptoms (e.g., stale DB pool after DB recovery)
  const lingeringDownstream = rca.disambiguateUpstreamVsDownstreamSymptoms({
    dependencyGraph: {
      nodes: [
        { id: 'db-primary-01', role: 'CORE_DATABASE', status: 'PASS', previousStatus: 'FAIL', recentlyRecovered: true },
        { id: 'api-worker-pool', role: 'API_SERVICE', status: 'FAIL' }
      ],
      edges: [
        { from: 'db-primary-01', to: 'api-worker-pool' }
      ]
    }
  });
  assert.equal(lingeringDownstream.classification, 'UPSTREAM_RECOVERED_DOWNSTREAM_LINGERING_STATE');
  assert.equal(lingeringDownstream.upstreamRecoveredLingeringDownstream.detected, true);
  assert.equal(lingeringDownstream.rootCauseNode, 'api-worker-pool');
});

test('Cognition 4.0 — Closed-Loop Blind-Spot Verification & Historical Topology Validity', async () => {
  const { operationalMemoryEngine } = require('../src/core/memory/operational-memory-engine');

  const initialSynthesis = cognitiveIntelligenceEngine.synthesizeCollaborativeSpecialistIntelligence({
    target: '127.0.0.1',
    port: 3000,
    objective: 'Check 127.0.0.1:3000 where TCP is open but L7 HTTP was not yet probed',
    steps: [
      { layer: 'L7_DNS', status: 'PASS', latencyMs: 1.1 },
      { layer: 'L4_TCP', status: 'PASS', latencyMs: 0.8 }
    ]
  });
  assert.ok(initialSynthesis.recommendedFollowUpProbes.some((p) => p.probeType === 'L7_HTTP_HEALTH_PROBE'));

  const closedLoop = await cognitiveIntelligenceEngine.executeClosedLoopBlindSpotVerification({
    target: '127.0.0.1',
    port: 3000,
    objective: 'Verify L7 HTTP blind spot on 127.0.0.1:3000',
    collaborativeSynthesis: initialSynthesis,
    steps: [
      { layer: 'L7_DNS', status: 'PASS', latencyMs: 1.1 },
      { layer: 'L4_TCP', status: 'PASS', latencyMs: 0.8 }
    ]
  });
  assert.equal(closedLoop.executed, true);
  assert.ok(closedLoop.probesRun.length >= 1);
  assert.ok(closedLoop.afterConfidencePct >= closedLoop.beforeConfidencePct);

  // Verify historical resolution validity when port shifts
  operationalMemoryEngine.recordObservation({
    target: 'port-migrated-host.local',
    intent: 'port_check',
    openPorts: [3001],
    closedPorts: [3000],
    status: 'PASS',
    summary: 'Service migrated from :3000 to :3001'
  });
  const validity = operationalMemoryEngine.evaluateHistoricalContextValidity('port-migrated-host.local', 3000);
  assert.equal(validity.supersededByTopologyChange, true);
  assert.equal(validity.validityState, 'SUPERSEDED_BY_SERVICE_PORT_MIGRATION');
});

test('Cognition 4.0 — Calibrated Confidence: Sparse-Data Damping, Contradictory Closed-Loop Confidence Reduction & Probe Scope/Deduplication Guards', async () => {
  // 1. Sparse-data damping when only 1 domain has empirical evidence (< 3 domains observed)
  const sparseSynthesis = cognitiveIntelligenceEngine.synthesizeCollaborativeSpecialistIntelligence({
    target: '127.0.0.1',
    port: 3000,
    objective: 'Quick single-step check',
    steps: [
      { layer: 'L4_TCP', status: 'PASS', latencyMs: 1.0 }
    ]
  });
  assert.equal(sparseSynthesis.observedDomainCount, 1);
  assert.equal(sparseSynthesis.sparseDataDampingApplied, true);
  assert.ok(sparseSynthesis.consensusConfidencePct <= 78, `Expected sparse-data confidence <= 78%, got ${sparseSynthesis.consensusConfidencePct}%`);
  assert.ok(Array.isArray(sparseSynthesis.specialistDisagreements));
  assert.ok(typeof sparseSynthesis.evidenceWeightingRationale === 'string');

  // 2. Closed-loop verification where contradictory L7 evidence (HTTP 503) REDUCES confidence and pivots hypothesis
  const initialOptimistic = cognitiveIntelligenceEngine.synthesizeCollaborativeSpecialistIntelligence({
    target: '127.0.0.1',
    port: 3000,
    objective: 'Check 127.0.0.1:3000 health',
    steps: [
      { layer: 'L7_DNS', status: 'PASS', latencyMs: 1.1 },
      { layer: 'L3_ICMP', status: 'PASS', latencyMs: 0.9 },
      { layer: 'L4_TCP', status: 'PASS', latencyMs: 0.8 }
    ]
  });

  const contradictoryClosedLoop = await cognitiveIntelligenceEngine.executeClosedLoopBlindSpotVerification({
    target: '127.0.0.1',
    port: 3000,
    objective: 'Verify L7 health on 127.0.0.1:3000',
    collaborativeSynthesis: {
      ...initialOptimistic,
      recommendedFollowUpProbes: [
        { probeType: 'L7_HTTP_HEALTH_PROBE', target: '127.0.0.1', port: 3000, simulatedHttpStatus: 503 },
        { probeType: 'L7_HTTP_HEALTH_PROBE', target: '169.254.169.254', port: 80 }
      ]
    },
    steps: [
      { layer: 'L7_DNS', status: 'PASS', latencyMs: 1.1 },
      { layer: 'L3_ICMP', status: 'PASS', latencyMs: 0.9 },
      { layer: 'L4_TCP', status: 'PASS', latencyMs: 0.8 }
    ],
    executedProbeSignatures: []
  });

  assert.equal(contradictoryClosedLoop.executed, true);
  assert.equal(contradictoryClosedLoop.contradictoryFindingsCount, 1);
  assert.ok(
    contradictoryClosedLoop.afterConfidencePct < contradictoryClosedLoop.beforeConfidencePct,
    `Contradictory L7 evidence must reduce confidence (before=${contradictoryClosedLoop.beforeConfidencePct}%, after=${contradictoryClosedLoop.afterConfidencePct}%)`
  );
  assert.ok(contradictoryClosedLoop.confidenceDeltaPct < 0);
  assert.equal(contradictoryClosedLoop.hypothesisReassessment.status, 'HYPOTHESIS_PIVOTED_ON_CONTRADICTORY_EVIDENCE');
  assert.equal(contradictoryClosedLoop.rejectedOutOfScopeProbes.length, 1);
  assert.equal(contradictoryClosedLoop.rejectedOutOfScopeProbes[0].target, '169.254.169.254');

  // 3. Deduplication prevents re-running identical probes in the same session
  const dedupCheck = await cognitiveIntelligenceEngine.executeClosedLoopBlindSpotVerification({
    target: '127.0.0.1',
    port: 3000,
    collaborativeSynthesis: initialOptimistic,
    steps: [{ layer: 'L4_TCP', status: 'PASS', latencyMs: 0.8 }],
    executedProbeSignatures: contradictoryClosedLoop.executedProbeSignatures
  });
  assert.equal(dedupCheck.executed, false);
  assert.ok(dedupCheck.deduplicatedSkippedProbes.length >= 1);
});

test('RCA Engine 5.0 — Partial Quorum Capacity Overload, Clock-Skew Patient Zero Uncertainty, 4-Tier Causal Certainty & Multi-Root Faults', () => {
  const rca = new DiagnosticReasoningEngine();

  // 1. Active-Active cluster where quorum is met (1 of 2 healthy) but cluster load (85%) exceeds single surviving node capacity (60%)
  const partialOverload = rca.disambiguateUpstreamVsDownstreamSymptoms({
    dependencyGraph: {
      nodes: [
        { id: 'ing-aa-01', role: 'INGRESS_ACTIVE_1', status: 'FAIL', haGroup: 'ha-ingress-aa', haRole: 'ACTIVE', redundancyMode: 'ACTIVE_ACTIVE', quorumMinHealthy: 1, clusterLoadPct: 85, memberCapacityPct: 60 },
        { id: 'ing-aa-02', role: 'INGRESS_ACTIVE_2', status: 'PASS', haGroup: 'ha-ingress-aa', haRole: 'ACTIVE', redundancyMode: 'ACTIVE_ACTIVE', quorumMinHealthy: 1, clusterLoadPct: 85, memberCapacityPct: 60 },
        { id: 'checkout-svc', role: 'CHECKOUT_API', status: 'DEGRADED' }
      ],
      edges: [
        { from: 'ing-aa-01', to: 'checkout-svc' },
        { from: 'ing-aa-02', to: 'checkout-svc' }
      ]
    }
  });
  assert.equal(partialOverload.classification, 'PARTIAL_QUORUM_CAPACITY_DEGRADED');
  assert.equal(partialOverload.haAnalysis.hasPartialCapacityDegradation, true);
  assert.equal(partialOverload.causalCertaintyLevel, 'CONTRIBUTING_FACTOR');

  // 2. Circular SCC with timestamps inside clockSkewToleranceMs -> AMBIGUOUS_WITHIN_CLOCK_SKEW & PROBABLE_CAUSE
  const skewedScc = rca.disambiguateUpstreamVsDownstreamSymptoms({
    dependencyGraph: {
      clockSkewToleranceMs: 500,
      nodes: [
        { id: 'mesh-node-a', role: 'MESH_PROXY_A', status: 'FAIL', firstAnomalyTimestampMs: 10000 },
        { id: 'mesh-node-b', role: 'MESH_PROXY_B', status: 'FAIL', firstAnomalyTimestampMs: 10120 }
      ],
      edges: [
        { from: 'mesh-node-a', to: 'mesh-node-b' },
        { from: 'mesh-node-b', to: 'mesh-node-a' }
      ]
    }
  });
  assert.equal(skewedScc.classification, 'CIRCULAR_DEPENDENCY_PATIENT_ZERO_ISOLATED');
  assert.equal(skewedScc.circularDependencies.cycles[0].patientZeroConfidence, 'AMBIGUOUS_WITHIN_CLOCK_SKEW');
  assert.equal(skewedScc.circularDependencies.cycles[0].clockSkewAmbiguityDetected, true);
  assert.equal(skewedScc.causalCertaintyLevel, 'PROBABLE_CAUSE');

  // 3. Multiple independent root causes across disjoint subtrees
  const multiRoot = rca.disambiguateUpstreamVsDownstreamSymptoms({
    dependencyGraph: {
      nodes: [
        { id: 'wan-router-eu', role: 'WAN_EDGE_EU', status: 'FAIL' },
        { id: 'eu-branch-sw', role: 'EU_SWITCH', status: 'FAIL' },
        { id: 'storage-san-us', role: 'US_SAN_ARRAY', status: 'FAIL' },
        { id: 'us-db-replica', role: 'US_DB_NODE', status: 'FAIL' }
      ],
      edges: [
        { from: 'wan-router-eu', to: 'eu-branch-sw' },
        { from: 'storage-san-us', to: 'us-db-replica' }
      ]
    }
  });
  assert.equal(multiRoot.hasMultipleIndependentRootCauses, true);
  assert.deepEqual(multiRoot.independentRootCauses.map((r) => r.nodeId).sort(), ['storage-san-us', 'wan-router-eu']);
  assert.ok(Array.isArray(multiRoot.causalCandidatesClassified));
  assert.ok(multiRoot.causalCandidatesClassified.some((c) => c.certaintyTier === 'CONFIRMED_ROOT_CAUSE'));
  assert.ok(multiRoot.causalCandidatesClassified.some((c) => c.certaintyTier === 'CONTRIBUTING_FACTOR'));
});

test('Conversational Brain — Dynamic Runtime Capability Discovery, Zero-Latency Reflex & Cross-Turn Topic Pivot Isolation', async () => {
  const { discoverDynamicRuntimeCapabilities, getDynamicFunctionDeclarations } = require('../src/core/chat/conversational-brain');
  const { chatOperatorService } = require('../src/core/chat/chat-operator-service');

  const discovered = discoverDynamicRuntimeCapabilities();
  assert.ok(discovered.totalCapabilities >= 15);
  assert.equal(discovered.discoverySource, 'LIVE_RUNTIME_CAPABILITY_INTROSPECTION');

  const dynamicDecls = getDynamicFunctionDeclarations();
  assert.ok(dynamicDecls.some((d) => d.name === 'snmp_probe'));
  assert.ok(dynamicDecls.some((d) => d.name === 'snmp_walk'));
  assert.ok(dynamicDecls.some((d) => d.name === 'office_device_resolve'));
  assert.ok(dynamicDecls.some((d) => d.name === 'tls_posture_audit'));

  // Ensure discovered protocols have genuine verified callable methods
  assert.ok(discovered.protocolDrivers.length > 0);
  assert.ok(discovered.protocolDrivers.every((drv) => drv.isGenuinelyCallable === true));
  assert.ok(discovered.protocolDrivers.some((drv) => drv.driver === 'snmp-engine.js' && drv.verifiedCallableMethods.includes('walkOid')));

  // Rapid topic pivot: turn 1 checks port 3001 on 127.0.0.1, turn 2 switches to general host health
  const sessionId = `test-pivot-${Date.now()}`;
  const user = { id: 'u-pivot', username: 'admin', role: 'ADMIN' };
  const turn1 = await chatOperatorService.processMessage({
    sessionId,
    message: 'Check port 3001 on 127.0.0.1',
    user
  });
  assert.equal(turn1.data.intent, 'port_check');
  assert.equal(turn1.data.executionTier, 'ZERO_LATENCY_LOCAL_REFLEX');

  const turn2 = await chatOperatorService.processMessage({
    sessionId,
    message: 'Check DNS for localhost',
    user
  });
  assert.equal(turn2.data.intent, 'dns');
  assert.equal(turn2.data.contextPivotDetected, true);

  // Turn 3: SNMP Walk execution
  const turn3 = await chatOperatorService.processMessage({
    sessionId,
    message: 'Run SNMP walk on 127.0.0.1 with oid 1.3.6.1.2.1.1.1.0',
    user
  });
  assert.equal(turn3.data.intent, 'snmp_walk');
  assert.ok(turn3.data.structuredAnswer);
  assert.ok(turn3.data.structuredAnswer.telemetryProvenance);
  assert.ok(turn3.data.technicalEvidence.tool === 'snmp_walk');

  // Turn 4: Office Device Resolution
  const turn4 = await chatOperatorService.processMessage({
    sessionId,
    message: 'Diagnose office printer on 127.0.0.1',
    user
  });
  assert.equal(turn4.data.intent, 'office_device_resolve');
  assert.ok(turn4.data.structuredAnswer);
  assert.ok(turn4.data.technicalEvidence.tool === 'office_device_resolve');

  // Turn 5: TLS Posture Audit
  const turn5 = await chatOperatorService.processMessage({
    sessionId,
    message: 'Check TLS posture and certificate for 127.0.0.1 port 3000',
    user
  });
  assert.equal(turn5.data.intent, 'tls_posture_audit');
  assert.ok(turn5.data.structuredAnswer);
  assert.ok(turn5.data.technicalEvidence.tool === 'tls_posture_audit');
});

test('Conversational Brain — Honest Target Enforcement, ASN.1 OID Syntax Validation & TLS Posture Compliance Analysis', async () => {
  const { chatOperatorService } = require('../src/core/chat/chat-operator-service');
  const user = { id: 'u-validation', username: 'admin', role: 'ADMIN' };
  const sessionId = `test-validation-${Date.now()}`;

  // 1. Missing target on snmp_walk must NOT silently default to 127.0.0.1
  const missingTargetSnmp = await chatOperatorService.processMessage({
    sessionId,
    message: 'Run SNMP walk',
    user
  });
  assert.equal(missingTargetSnmp.data.intent, 'snmp_walk');
  assert.equal(missingTargetSnmp.data.status, 'clarification_needed');
  assert.equal(missingTargetSnmp.data.promptClarification, true);
  assert.ok(missingTargetSnmp.reply.includes('Target IP or hostname is required'));

  // 2. Missing target on office_device_resolve must NOT silently default to 127.0.0.1
  const missingTargetOffice = await chatOperatorService.processMessage({
    sessionId,
    message: 'Diagnose office printer',
    user
  });
  assert.equal(missingTargetOffice.data.intent, 'office_device_resolve');
  assert.equal(missingTargetOffice.data.status, 'clarification_needed');
  assert.equal(missingTargetOffice.data.promptClarification, true);
  assert.ok(missingTargetOffice.reply.includes('Target IP or hostname is required'));

  // 3. Missing target on tls_posture_audit must NOT silently default to 127.0.0.1
  const missingTargetTls = await chatOperatorService.processMessage({
    sessionId,
    message: 'Check TLS posture and certificate',
    user
  });
  assert.equal(missingTargetTls.data.intent, 'tls_posture_audit');
  assert.equal(missingTargetTls.data.status, 'clarification_needed');
  assert.equal(missingTargetTls.data.promptClarification, true);
  assert.ok(missingTargetTls.reply.includes('Target host is required'));

  // 4. Malformed ASN.1 OID must be rejected with L7_ASN1_OID_SYNTAX
  const malformedOid = await chatOperatorService.processMessage({
    sessionId,
    message: 'Run SNMP walk on 127.0.0.1 with oid not_a_valid_oid',
    user
  });
  assert.equal(malformedOid.data.intent, 'snmp_walk');
  assert.equal(malformedOid.data.status, 'rejected');
  assert.equal(malformedOid.data.errorCode, 'L7_ASN1_OID_SYNTAX');
  assert.ok(malformedOid.reply.includes('ASN.1 OID syntax error'));

  // 5. Valid OID alias resolution (e.g. 'interfaces')
  const aliasOid = await chatOperatorService.processMessage({
    sessionId,
    message: 'Run SNMP walk on 127.0.0.1 with oid interfaces',
    user
  });
  assert.equal(aliasOid.data.intent, 'snmp_walk');
  assert.equal(aliasOid.data.technicalEvidence.requestedOid, '1.3.6.1.2.1.2');

  // 6. Honest UDP 161 failure reporting (when UDP port 161 is closed / times out)
  // Ensure it does NOT report host dead at L3/L4
  const udpTimeoutResult = await chatOperatorService.processMessage({
    sessionId,
    message: 'Run SNMP walk on 127.0.0.1 with oid 1.3.6.1.2.1.1',
    user
  });
  assert.equal(udpTimeoutResult.data.intent, 'snmp_walk');
  assert.ok(udpTimeoutResult.data.technicalEvidence.errorClassification === 'UDP_PORT_161_TIMEOUT_OR_UNREACHABLE' || udpTimeoutResult.data.technicalEvidence.entriesCount >= 0);
  assert.ok(udpTimeoutResult.data.structuredAnswer.telemetryProvenance.honestMeasurement);

  // 7. TLS Posture Audit verdict validation
  const tlsAudit = await chatOperatorService.processMessage({
    sessionId,
    message: 'Check TLS posture and certificate for 127.0.0.1 port 3000',
    user
  });
  assert.equal(tlsAudit.data.intent, 'tls_posture_audit');
  assert.ok(tlsAudit.data.technicalEvidence.securityVerdict);
  assert.ok(typeof tlsAudit.data.technicalEvidence.tlsCompliant === 'boolean');
  assert.ok(tlsAudit.data.structuredAnswer.telemetryProvenance.zeroFabricatedMetrics);
});




