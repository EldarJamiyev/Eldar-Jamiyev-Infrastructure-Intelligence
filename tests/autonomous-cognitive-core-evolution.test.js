/**
 * EJII Autonomous Cognitive Core Evolution Test Suite
 *
 * Validates:
 *   1. Dynamic DAG Causal Discovery (EpisodicCausalMemoryEngine.discoverDynamicCausalGraph)
 *   2. Multi-Dimensional Shannon Entropy Index (/api/enterprise/ai/entropy-index)
 *   3. Operator Reinforcement Feedback Ledger (RLHF /api/enterprise/ai/operator-feedback)
 *   4. Time-to-Failure (TTCF) Capacity Horizon (/api/enterprise/ai/predictive-horizon)
 *   5. 5-Agent SRE War Room Adversarial Debate Protocol & Active Probes
 *   6. Multi-Session Concurrency Isolation & Operator Steering Re-evaluation (/api/rca/war-room/reevaluate)
 *   7. Socratic Pedagogical Mentor for Interactive Labs (/api/enterprise/socratic-mentor)
 */

'use strict';

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const { app } = require('../src/server');
const { EpisodicCausalMemoryEngine } = require('../src/ai/episodic-causal-memory-engine');
const { AutonomousWarRoomOrchestrator } = require('../src/ai/autonomous-war-room');

describe('EJII Autonomous Cognitive Core Evolution Suite', () => {
  let testServer = null;
  const baseUrl = 'http://127.0.0.1:3000';

  before(async () => {
    await new Promise((resolve) => {
      testServer = http.createServer(app);
      testServer.listen(3000, '127.0.0.1', () => {
        resolve();
      });
      testServer.on('error', (err) => {
        if (err.code === 'EADDRINUSE') {
          testServer = null;
          resolve();
        }
      });
    });
  });

  after(async () => {
    if (testServer) {
      await new Promise((resolve) => testServer.close(resolve));
    }
  });

  describe('1. Dynamic DAG Causal Discovery & Unsupervised Topology Reasoning', () => {
    it('should discover causal propagation DAG and pinpoint patient zero across arbitrary anomalies', async () => {
      const now = Date.now();
      const observations = [
        {
          anomalyType: 'CARRIER_TRANSIT_DROP',
          layer: 'L1_PHYSICAL',
          timestampMs: now - 1500,
          description: 'Physical link carrier loss on WAN perimeter',
          metrics: { severity: 9.2 }
        },
        {
          anomalyType: 'TCP_RETRANSMISSION_STALL',
          layer: 'L4_TRANSPORT',
          timestampMs: now - 900,
          description: 'SYN-ACK timeouts and unacknowledged flights',
          metrics: { severity: 7.8 }
        },
        {
          anomalyType: 'DNS_RECURSIVE_SERVFAIL',
          layer: 'L7_APPLICATION',
          timestampMs: now - 300,
          description: 'Split-horizon resolver query timeouts',
          metrics: { severity: 6.5 }
        }
      ];

      const topoNodes = [
        { id: 'WAN-GW-01', ip: '10.168.195.1' },
        { id: 'CORE-SW-01', ip: '10.168.195.2' },
        { id: 'DNS-SRV-01', ip: '10.168.195.10' }
      ];

      const res = await fetch(`${baseUrl}/api/enterprise/ai/causal-graph`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ observations, topologyNodes: topoNodes })
      });
      const data = await res.json();

      assert.strictEqual(data.success, true);
      assert.ok(data.causalGraph);
      assert.ok(data.causalGraph.nodes.length === 3);
      assert.ok(data.causalGraph.edges.length >= 2, 'Must build causal propagation edges');
      assert.strictEqual(data.causalGraph.patientZeroLayer, 'L1_PHYSICAL', 'Must isolate L1 physical carrier loss as patient zero');
      assert.ok(data.causalGraph.rootCauseCertaintyPct >= 75);
      assert.ok(data.causalGraph.synthesizedRootCause.includes('Autonomous Causal Graph pinpointed'));
    });
  });

  describe('2. Multi-Dimensional Infrastructure Shannon Entropy Index', () => {
    it('should evaluate entropy index, stability regime, and adaptive CUSUM sensitivity', async () => {
      const metrics = {
        rttMs: 65.0,
        packetLossPct: 3.5,
        dnsLatencyMs: 38.0,
        cpuSaturationPct: 78.0,
        tcpRetransmitRate: 0.08,
        cusumSigma: 4.2
      };

      const res = await fetch(`${baseUrl}/api/enterprise/ai/entropy-index`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(metrics)
      });
      const data = await res.json();

      assert.strictEqual(data.success, true);
      assert.ok(data.entropyIndex);
      assert.ok(typeof data.entropyIndex.shannonEntropy === 'number');
      assert.ok(data.entropyIndex.shannonEntropy >= 0.0 && data.entropyIndex.shannonEntropy <= 1.0);
      assert.ok(['STABLE_EQUILIBRIUM', 'ELEVATED_DRIFT', 'CRITICAL_ENTROPY_COLLAPSE'].includes(data.entropyIndex.stabilityRegime));
      assert.ok(data.entropyIndex.adaptiveCusumSensitivityMultiplier > 0);
      assert.ok(typeof data.entropyIndex.diagnosticSummary === 'string');
    });
  });

  describe('3. Operator Reinforcement Feedback Ledger (RLHF Learning)', () => {
    it('should record operator feedback and update learned prior weights', async () => {
      const feedbackPayload = {
        incidentId: 'INC-RLHF-2026-TEST',
        hypothesisId: 'hypo-mtu-blackhole',
        feedback: 'CONFIRMED',
        operatorNotes: 'Verified MTU clamp resolved intermediate packet drops',
        overrideRootCause: 'PATH_MTU_BLACKHOLE'
      };

      const postRes = await fetch(`${baseUrl}/api/enterprise/ai/operator-feedback`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(feedbackPayload)
      });
      const postData = await postRes.json();

      assert.strictEqual(postData.success, true);
      assert.strictEqual(postData.feedback.incidentId, 'INC-RLHF-2026-TEST');
      assert.strictEqual(postData.feedback.feedback, 'CONFIRMED');

      const getRes = await fetch(`${baseUrl}/api/enterprise/ai/learning-ledger`);
      const getData = await getRes.json();

      assert.strictEqual(getData.success, true);
      assert.ok(Array.isArray(getData.ledger));
      const found = getData.ledger.find(e => e.incidentId === 'INC-RLHF-2026-TEST');
      assert.ok(found, 'Recorded feedback must persist in feedback ledger');
    });
  });

  describe('4. Pre-Outage Time-To-Failure (TTCF) Capacity Horizon', () => {
    it('should project time to exhaustion and proactive remediation advice', async () => {
      const resources = [
        { resourceType: 'DHCP_SCOPE_POOL_VLAN100', currentUsagePct: 88, burnRatePerMinute: 0.8 },
        { resourceType: 'DISK_SPACE_VAR_LOG', currentUsagePct: 92, burnRatePerMinute: 0.2 },
        { resourceType: 'TLS_CERT_EXPIRE_WILDCARD', currentUsagePct: 70, burnRatePerMinute: 0.05 }
      ];

      const res = await fetch(`${baseUrl}/api/enterprise/ai/predictive-horizon`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ resources })
      });
      const data = await res.json();

      assert.strictEqual(data.success, true);
      assert.strictEqual(data.count, 3);
      assert.ok(data.predictions.length === 3);

      const dhcpPred = data.predictions.find(p => p.resourceType.includes('DHCP'));
      assert.ok(dhcpPred);
      assert.ok(dhcpPred.timeToCriticalFailureSeconds > 0);
      assert.ok(dhcpPred.proactiveRemediationAdvice.includes('DHCP lease scope'));
      assert.ok(['STABLE', 'WARNING', 'IMMINENT_OUTAGE'].includes(dhcpPred.urgency));
    });
  });

  describe('5. 5-Agent SRE War Room Multi-Incident Isolation & Adversarial Debates', () => {
    it('should execute full consensus pipeline with adversarial debates and active probe dispatch metadata', async () => {
      const res = await fetch(`${baseUrl}/api/rca/war-room/execute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          operatorRole: 'ADMIN',
          rawMetricValues: [22, 24, 25, 48, 52, 60]
        })
      });
      const data = await res.json();

      assert.strictEqual(data.success, true);
      assert.ok(data.warRoomSessionId.startsWith('sre-warroom-'));
      assert.ok(Array.isArray(data.adversarialDebates), 'Must produce adversarial debate exchange');
      assert.ok(data.adversarialDebates.length >= 3, 'Must complete at least 3 debate rounds');
      assert.strictEqual(data.adversarialDebates[0].challengerAgent, 'Agent 3 — Deep Wire Forensics');

      assert.ok(Array.isArray(data.autonomousActiveProbes), 'Must produce active probe proposals');
      assert.ok(data.autonomousActiveProbes.length >= 3);
      const pmtuProbe = data.autonomousActiveProbes.find(p => p.probeType === 'ICMP_PMTU_DISCOVERY');
      assert.ok(pmtuProbe, 'Must include ICMP PMTU discovery proposal');
      assert.strictEqual(pmtuProbe.safetyGuardClassification, 'READ_ONLY_SAFE_POL_01');
    });

    it('should isolate sessions in concurrent session map and support operator constraint re-evaluation', async () => {
      // 1. Get initial session
      const execRes = await fetch(`${baseUrl}/api/rca/war-room/execute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ operatorRole: 'ADMIN' })
      });
      const execData = await execRes.json();
      const originalSessionId = execData.warRoomSessionId;

      // 2. Query sessions list
      const listRes = await fetch(`${baseUrl}/api/rca/war-room/sessions`);
      const listData = await listRes.json();
      assert.strictEqual(listData.success, true);
      assert.ok(listData.count >= 1);
      const foundSession = listData.sessions.find(s => s.warRoomSessionId === originalSessionId);
      assert.ok(foundSession, 'Original session must be indexed in session store');

      // 3. Re-evaluate with operator steering constraint forbidding current remediation
      const currentAction = execData.agent4.proposedRemediationAction;
      const reevalRes = await fetch(`${baseUrl}/api/rca/war-room/reevaluate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          sessionId: originalSessionId,
          forbiddenRemediations: [currentAction],
          requireDualApproval: true
        })
      });
      const reevalData = await reevalRes.json();

      assert.strictEqual(reevalData.success, true);
      assert.strictEqual(reevalData.status, 'RE_EVALUATED_WITH_CONSTRAINTS');
      assert.strictEqual(reevalData.parentSessionId, originalSessionId);
      assert.notStrictEqual(reevalData.agent4.proposedRemediationAction, currentAction, 'Must choose alternative action avoiding forbidden action');
      assert.ok(reevalData.agent5.proofChain.startsWith('EJII-PROOF-STEERED-V5:'));
    });
  });

  describe('6. Socratic Pedagogical Mentor API', () => {
    it('should generate Socratic inquiry, conceptual insights, and progressive hints for labs', async () => {
      const res = await fetch(`${baseUrl}/api/enterprise/socratic-mentor`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          labId: 'vlan-lab',
          commandOrAnswer: 'switchport trunk allowed vlan 10,20',
          currentMission: 'Troubleshoot Inter-VLAN Routing Drop'
        })
      });
      const data = await res.json();

      assert.strictEqual(data.success, true);
      assert.strictEqual(data.labId, 'vlan-lab');
      assert.ok(data.socraticQuestion.includes('802.1Q') || data.socraticQuestion.includes('frame') || data.socraticQuestion.includes('broadcast domain'));
      assert.ok(data.conceptualInsight.length > 20);
      assert.ok(data.progressiveHint.length > 10);
      assert.ok(data.suggestedNextCommand.includes('trunk'));
    });
  });

  describe('7. Unified Quad-Quadrant Native Telemetry (TCPView, NetworkTrafficView, Advanced Port Scanner, Daily_Automation)', () => {
    it('should serve native Sysinternals TCPView process-to-socket table with LMS.exe (PID 5428 :623) and vmms.exe (PID 10336 :2179)', async () => {
      const res = await fetch(`${baseUrl}/api/enterprise/tcpview-sockets`);
      const data = await res.json();

      assert.strictEqual(data.success, true);
      assert.ok(Array.isArray(data.sockets));
      assert.ok(data.sockets.length >= 15);
      assert.strictEqual(data.footerSummary.endpoints, 349);
      assert.strictEqual(data.footerSummary.established, 120);
      assert.strictEqual(data.footerSummary.listening, 55);
      assert.strictEqual(data.footerSummary.timeWait, 11);
      assert.strictEqual(data.footerSummary.closeWait, 1);

      const lms = data.sockets.find(s => s.processName === 'LMS.exe' && s.pid === 5428 && s.localPort === 623);
      assert.ok(lms, 'Must include LMS.exe PID 5428 listening on TCP 623');
      const vmms = data.sockets.find(s => s.processName === 'vmms.exe' && s.localPort === 2179);
      assert.ok(vmms, 'Must include vmms.exe listening on TCP 2179');
    });

    it('should serve native NirSoft NetworkTrafficView 5-tuple conversation matrix on Intel I219-LM (10.168.195.33)', async () => {
      const res = await fetch(`${baseUrl}/api/enterprise/network-traffic-flows`);
      const data = await res.json();

      assert.strictEqual(data.success, true);
      assert.ok(data.selectedAdapter.includes('10.168.195.33'));
      assert.ok(data.selectedAdapter.includes('I219-LM'));
      assert.ok(Array.isArray(data.flows));
      assert.strictEqual(data.flows.length, 14);

      const httpFlow = data.flows.find(f => f.destinationAddress === '10.22.10.153' && f.destinationPort === 80);
      assert.ok(httpFlow, 'Must include cleartext HTTP flow to 10.22.10.153:80');
      assert.ok(httpFlow.totalBytes >= 1179);
      assert.ok(data.aiDiagnosis.broadcastStormDetected === true);
    });

    it('should execute multi-subnet Advanced Port Scanner sweep across 10.168.195.0/24, 172.29.192.0/20, and 172.29.224.0/20', async () => {
      const res = await fetch(`${baseUrl}/api/enterprise/multi-subnet-scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          rangeExpression: '10.168.195.1-254, 172.29.192.1-172.29.207.254, 172.29.224.1-172.29.239.254',
          portProfile: 'all_enterprise'
        })
      });
      const data = await res.json();

      assert.strictEqual(data.success, true);
      assert.strictEqual(data.progress.percentComplete, 100);
      const hv1 = data.hosts.find(h => h.ip === '172.29.192.1');
      assert.ok(hv1, 'Must discover 172.29.192.1 Hyper-V virtual switch');
      assert.strictEqual(hv1.mac, '00:15:5D:DF:E5:56');
      assert.strictEqual(hv1.manufacturer, 'Microsoft Corporation');
      assert.ok(hv1.sharedFolders.some(f => f.name === 'Users'));
      assert.ok(hv1.services.some(s => s.port === 623 && s.serviceBanner.includes('Intel Active Management Technology')));
      assert.ok(hv1.services.some(s => s.port === 2179));
    });
  });

  describe('8. Neuro-Symbolic Brain 2.0, Round 4 War Room Empirical Settlement, & Quick-NOC Auth', () => {
    it('should compute Bidirectional Causal Graph with 3 Competing Hypotheses and Round 4 Empirical Settlement', async () => {
      const warRes = await fetch(`${baseUrl}/api/enterprise/war-room/convene`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          targetIp: '10.168.195.33',
          operatorQuestion: 'Why is port 623 open on Hyper-V switch 172.29.192.1?'
        })
      });
      const warData = await warRes.json();

      assert.strictEqual(warData.success, true);
      assert.ok(warData.round4EmpiricalSettlement, 'Must include Round 4 Empirical Probe Settlement');
      assert.strictEqual(warData.round4EmpiricalSettlement.verdictStatus, 'EMPIRICALLY_CONFIRMED');
      assert.ok(warData.round4EmpiricalSettlement.settledPosteriorConfidence > warData.round4EmpiricalSettlement.priorConfidence);
      assert.ok(typeof warData.operatorCrossExaminationResponse === 'string' && warData.operatorCrossExaminationResponse.length > 20);
    });

    it('should authenticate POST /api/auth/quick-noc with empty body without ROLE_ELEVATION_PROHIBITED error', async () => {
      const authRes = await fetch(`${baseUrl}/api/auth/quick-noc`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({})
      });
      const authData = await authRes.json();
      assert.strictEqual(authRes.status, 200);
      assert.ok(authData.token, 'Must issue JWT token on empty quick-noc payload');
    });
  });
});
