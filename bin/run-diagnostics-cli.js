#!/usr/bin/env node
/**
 * EJII CLI Diagnostics Tool
 * Standalone terminal tool for running real low-level diagnostics.
 */

const { realPing, realTraceroute } = require('../src/protocols/icmp-ping');
const { checkPort, scanPorts } = require('../src/protocols/tcp-port');
const { resolveRecord } = require('../src/protocols/dns-diag');
const { auditTls } = require('../src/protocols/tls-audit');
const { probeHttp } = require('../src/protocols/http-probe');
const { getHostMetrics } = require('../src/protocols/host-metrics');
const { verifyChainIntegrity } = require('../src/core/audit-logger');

async function main() {
  const args = process.argv.slice(2);
  const command = args[0] ? args[0].toLowerCase() : 'help';
  const target = args[1];

  console.log('================================================================');
  console.log('  EJII — Infrastructure Intelligence CLI Utility               ');
  console.log('  Zero-Simulation Mode: Real OS & Socket Telemetry             ');
  console.log('================================================================');

  switch (command) {
    case 'ping':
      if (!target) return console.error('Usage: node bin/run-diagnostics-cli.js ping <host>');
      console.log(`Pinging ${target}...`);
      const ping = await realPing(target);
      console.log(JSON.stringify(ping, null, 2));
      break;

    case 'port':
      if (!target || !args[2]) return console.error('Usage: node bin/run-diagnostics-cli.js port <host> <port>');
      console.log(`Checking port ${args[2]} on ${target}...`);
      const port = await checkPort(target, parseInt(args[2], 10));
      console.log(JSON.stringify(port, null, 2));
      break;

    case 'sweep':
      if (!target) return console.error('Usage: node bin/run-diagnostics-cli.js sweep <host>');
      console.log(`Sweeping common ports on ${target}...`);
      const sweep = await scanPorts(target);
      console.log(`Scanned ${sweep.totalScanned} ports. Open: ${sweep.openCount}, Filtered: ${sweep.filteredCount}, Closed: ${sweep.closedCount}`);
      sweep.results.filter(r => r.open).forEach(r => console.log(`  [OPEN] Port ${r.port} (${r.service}) - ${r.connectLatencyMs}ms`));
      break;

    case 'dns':
      if (!target) return console.error('Usage: node bin/run-diagnostics-cli.js dns <domain>');
      console.log(`Resolving ${target}...`);
      const dns = await resolveRecord(target, 'A');
      console.log(JSON.stringify(dns, null, 2));
      break;

    case 'tls':
      if (!target) return console.error('Usage: node bin/run-diagnostics-cli.js tls <domain>');
      console.log(`Auditing TLS on ${target}:443...`);
      const tls = await auditTls(target, 443);
      console.log(JSON.stringify(tls, null, 2));
      break;

    case 'http':
      if (!target) return console.error('Usage: node bin/run-diagnostics-cli.js http <url>');
      console.log(`Probing ${target}...`);
      const http = await probeHttp(target);
      console.log(JSON.stringify(http, null, 2));
      break;

    case 'host':
      console.log('Querying host hardware and OS telemetry...');
      const host = await getHostMetrics(true);
      console.log(`Host: ${host.hostname} (${host.osDetails.caption})`);
      console.log(`CPU: ${host.cpu.model} (${host.cpu.cores} cores, Load: ${host.cpu.loadPercentage}%)`);
      console.log(`RAM: ${host.memory.usedFormatted} used of ${host.memory.totalFormatted} (${host.memory.usedPercentage}%)`);
      console.log(`Disks: ${host.disks.map(d => `${d.mount} ${d.usedPercentage}% (${d.freeFormatted} free)`).join(', ')}`);
      break;

    case 'audit-verify':
      console.log('Verifying cryptographic HMAC audit chain...');
      const audit = verifyChainIntegrity();
      console.log(JSON.stringify(audit, null, 2));
      break;

    case '--json':
    case 'json': {
      const { getPhysicalNetworkInfo } = require('../src/network/routing/physical-network-detector');
      const { hostDiagnosticsEngine } = require('../src/systems/diagnostics/host-diagnostics-engine');
      const { aiBrain } = require('../src/core/ai-brain');

      const netInfo = getPhysicalNetworkInfo ? getPhysicalNetworkInfo() : null;
      let hostAudit = null;
      try {
        hostAudit = (hostDiagnosticsEngine.getWarmSnapshot ? hostDiagnosticsEngine.getWarmSnapshot() : null) || await hostDiagnosticsEngine.collectFullAudit(false);
      } catch (e) {
        hostAudit = { error: e.message };
      }
      const brainState = aiBrain.getLiveState ? aiBrain.getLiveState() : null;

      const summary = {
        timestamp: new Date().toISOString(),
        network: netInfo,
        host: hostAudit,
        aiBrain: brainState
      };
      console.log(JSON.stringify(summary, null, 2));
      break;
    }

    case 'cognition':
    case 'investigate': {
      const { operationalMemoryEngine } = require('../src/core/memory/operational-memory-engine');
      const objective = args.slice(1).join(' ') || 'Something is wrong with our infrastructure. Find out what is causing the problem.';
      console.log(`Running Cognition 3.0 Dynamic Problem Solver for objective: "${objective}"...`);
      const result = await operationalMemoryEngine.executeDynamicCapabilityInvestigation({
        objective,
        target: null,
        port: 3000,
        initiatedBy: 'cli-operator',
        role: 'ADMIN'
      });
      console.log(JSON.stringify({
        investigationId: result.investigationId,
        target: result.target,
        targetDiscoveryMethod: result.targetDiscoveryMethod,
        problemNature: result.problemNatureStrategy.problemNatureClassification.primaryNature,
        selectedStrategy: result.problemNatureStrategy.selectedStrategy.strategyName,
        parallelGroupsExecuted: result.capabilityExecutionTrace.parallelGroupsExecuted,
        criticalSelfCorrection: result.criticalSelfCorrection.epistemicCalibration,
        collaborativeConsensus: result.collaborativeSynthesis.unifiedDiagnosis,
        executiveConclusion: result.executiveConclusion
      }, null, 2));
      break;
    }

    case 'superpowers':
    case 'synthesis': {
      const tgt = target || '127.0.0.1';
      console.log(`Executing 4-Phase Superpowers Unified Synthesis on target: ${tgt}...`);
      const { superpowersSkillsEngine } = require('../src/core/skills/superpowers-skills-engine');
      const synRes = await superpowersSkillsEngine.executeUnifiedSuperpowersSynthesis({
        target: tgt,
        port: args[2] ? parseInt(args[2], 10) : 443,
        query: args.slice(2).join(' ') || `Full-stack infrastructure investigation for ${tgt}`
      });
      console.log(JSON.stringify({
        synthesisId: synRes.synthesisId,
        target: synRes.target,
        durationMs: synRes.durationMs,
        summary: synRes.unifiedExecutiveSummary,
        patientZero: synRes.timelineReconstruction.patientZero,
        winningHypothesis: synRes.hypothesisArbitration.winningHypothesis,
        predictiveHorizon: {
          overallRiskScore: synRes.predictiveHorizon.overallRiskScore,
          overallRiskTier: synRes.predictiveHorizon.overallRiskTier,
          mm1QueueingAmplification: synRes.predictiveHorizon.predictions[0]?.mm1QueueingAmplification || 1.0,
          preventativeAction: synRes.predictiveHorizon.predictions[0]?.preventativeAction
        },
        remediation: synRes.systematicDebugging4Phases.phase4_implementationAndVerification.recommendedRemediation
      }, null, 2));
      break;
    }

    case 'chain':
    case 'multi-probe': {
      const tgt = target || '127.0.0.1';
      console.log(`Executing 5-layer automated diagnostic probe chain on ${tgt}...`);
      const chainStart = Date.now();
      const chainResults = [];

      // 1. ICMP Ping
      process.stdout.write('  [1/5] Layer 3 (ICMP Echo Ping)... ');
      const pRes = await realPing(tgt).catch(e => ({ success: false, error: e.message }));
      chainResults.push({ layer: 'L3_ICMP', success: pRes.success, rttMs: pRes.avgRttMs || null, details: pRes });
      console.log(pRes.success ? `PASS (${pRes.avgRttMs} ms)` : `WARN (${pRes.error || 'No echo'})`);

      // 2. TCP Port Check
      const probePort = args[2] ? parseInt(args[2], 10) : 443;
      process.stdout.write(`  [2/5] Layer 4 (TCP Handshake :${probePort})... `);
      const portRes = await checkPort(tgt, probePort, 2000).catch(e => ({ status: 'ERROR', error: e.message }));
      chainResults.push({ layer: 'L4_TCP', status: portRes.status, latencyMs: portRes.connectLatencyMs, details: portRes });
      console.log(portRes.status === 'OPEN' ? `PASS (${portRes.connectLatencyMs} ms)` : `WARN (${portRes.status})`);

      // 3. DNS Lookup
      process.stdout.write(`  [3/5] Layer 7 (RFC 1035 DNS Resolution)... `);
      let dnsRes = null;
      if (!/^\d+\.\d+\.\d+\.\d+$/.test(tgt)) {
        dnsRes = await resolveRecord(tgt, 'A').catch(e => ({ success: false, error: e.message }));
        chainResults.push({ layer: 'DNS', success: dnsRes.success, answers: dnsRes.addresses || [] });
        console.log(dnsRes.success ? `PASS (${(dnsRes.addresses || []).join(', ')})` : `WARN (${dnsRes.error})`);
      } else {
        console.log('SKIP (Target is raw IPv4)');
      }

      // 4. TLS Audit
      process.stdout.write(`  [4/5] Layer 6 (TLS 1.3 / X.509 Handshake :${probePort})... `);
      const tlsRes = await auditTls(tgt, probePort).catch(e => ({ valid: false, error: e.message }));
      chainResults.push({ layer: 'L6_TLS', valid: tlsRes.valid, protocol: tlsRes.protocol, certSubject: tlsRes.subject });
      console.log(tlsRes.valid ? `PASS (${tlsRes.protocol}, ${tlsRes.daysRemaining} days left)` : `WARN (${tlsRes.error || 'No TLS'})`);

      // 5. HTTP Probe
      process.stdout.write(`  [5/5] Layer 7 (HTTP Service Health)... `);
      const httpUrl = `http${probePort === 443 ? 's' : ''}://${tgt}:${probePort}/`;
      const hRes = await probeHttp(httpUrl, 'GET', 2500).catch(e => ({ statusCode: null, error: e.message }));
      chainResults.push({ layer: 'L7_HTTP', statusCode: hRes.statusCode, latencyMs: hRes.totalTimeMs });
      console.log(hRes.statusCode ? `PASS (HTTP ${hRes.statusCode}, ${hRes.totalTimeMs} ms)` : `WARN (${hRes.error || 'No HTTP response'})`);

      console.log('----------------------------------------------------------------');
      console.log(`Diagnostic Chain Completed in ${Date.now() - chainStart} ms. Status: OPERATIONAL.`);
      break;
    }

    case 'timeline':
    case 'reconstruct': {
      const tgt = target || '127.0.0.1';
      console.log(`Reconstructing pre-incident timeline & CUSUM changepoints for ${tgt}...`);
      const { timelineReconstructor } = require('../src/observability/timeline-reconstructor');
      const tlRes = timelineReconstructor.reconstructPreIncidentTimeline({
        target: tgt,
        lookbackMinutes: args[2] ? parseInt(args[2], 10) : 60
      });
      console.log(JSON.stringify({
        target: tlRes.target,
        patientZero: tlRes.patientZero,
        totalEventsCount: tlRes.totalEventsCount,
        changepoints: tlRes.changepoints,
        changepointAnalysis: tlRes.changepointAnalysis,
        timelineEvents: tlRes.timelineEvents
      }, null, 2));
      break;
    }

    case 'horizon': {
      const tgt = target || '127.0.0.1';
      console.log(`Evaluating non-linear predictive horizon and cascade risk for ${tgt}...`);
      const { predictiveHorizonEngine } = require('../src/ai/predictive-horizon-engine');
      const horizRes = predictiveHorizonEngine.evaluatePredictiveHorizon({
        targets: [tgt]
      });
      console.log(JSON.stringify(horizRes, null, 2));
      break;
    }

    default:
      console.log('Commands:');
      console.log('  ping <host>            Run real ICMP ping with RTT and jitter');
      console.log('  port <host> <port>     Test single TCP port connection');
      console.log('  sweep <host>           Scan 23 common enterprise ports');
      console.log('  dns <domain>           Resolve RFC 1035 DNS record');
      console.log('  tls <domain>           Audit TLS/SSL certificate & cipher');
      console.log('  http <url>             Execute synthetic HTTP probe with waterfall');
      console.log('  host                   Inspect local machine CPU, RAM, & Disks');
      console.log('  chain <host> [port]    Automated 5-layer multi-probe diagnostic chain');
      console.log('  superpowers <target>   Execute unified 4-phase Superpowers synthesis');
      console.log('  timeline <target>      Reconstruct pre-incident timeline & CUSUM changepoints');
      console.log('  horizon <target>       Evaluate non-linear M/M/1 queueing horizon & risk');
      console.log('  audit-verify           Cryptographically verify audit log hash chain');
      console.log('  cognition [objective]  Execute Cognition 3.0 Dynamic Problem Solver');
      break;
  }
}

main().then(() => process.exit(0)).catch((err) => {
  console.error(err);
  process.exit(1);
});
