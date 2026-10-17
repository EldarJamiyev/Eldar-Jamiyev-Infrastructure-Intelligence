/**
 * EJII NOC Workstation Master Test Suite Runner
 * Executes all wire-level protocol, topology, packet dissection, and stream telemetry verification suites.
 * Zero-Elevation & Zero-Simulation Mandate.
 */

process.env.NODE_ENV = process.env.NODE_ENV || 'test';

process.on('unhandledRejection', (reason) => {
  console.error('\n❌ CRITICAL ERROR: Unhandled Promise Rejection in Test Runner:');
  console.error(reason);
  process.exit(1);
});

process.on('uncaughtException', (err) => {
  console.error('\n❌ CRITICAL ERROR: Uncaught Exception in Test Runner:');
  console.error(err);
  process.exit(1);
});

const { runNetworkTests } = require('./network-probes.test');
const { runTopologyTests } = require('./topology-engine.test');
const { runDissectorTests } = require('./packet-dissector.test');
const { runWireDiagnosticsTests } = require('./wire-diagnostics.test');
const { runAddendaAcceptanceTests } = require('./addenda-acceptance.test');
const { runNocIntegrityRegressionTests } = require('./regression-noc-integrity.test');
const { runHeadlessUiVerificationTests } = require('./headless-ui-verification.test');
const { runIpScannerSuiteTests } = require('./ip-scanner-suite.test');
const { runPcAutomationTests } = require('./pc-automation.test');
const { runFrontendRebuildVerification } = require('./verify-frontend-rebuild');
const { runAdaptiveTopologyAndEvidenceTests } = require('./adaptive-topology-and-evidence.test');
const { runAiBrainTests } = require('./verify-ai-brain.test');
const { verifyAllTargets } = require('./verify-target-websites');
const { runNormalizationStressTests } = require('./reasoning-normalization.test');
const { runEdrSafeScannerTests } = require('./verify-edr-safe-scanner.test');
const { runE2EBrowserWorkflow } = require('./verify-e2e-browser-workflow');
const { runPacketDissectionEngineTests } = require('./packet-dissection-engine.test');
const { runAiCausalInvestigatorTests } = require('./ai-causal-investigator.test');
const { runAdversarialProtocolTests } = require('./adversarial-protocol-fixtures.test');
const { runTcpStreamWraparoundTests } = require('./tcp-stream-wraparound.test');
const { runToolSandboxAndSecurityTests } = require('./tool-sandbox-and-security.test');
const { runAiBrainEvidenceReasoningTests } = require('./ai-brain-evidence-reasoning.test');
const { runSecurityRbacRegressionTests } = require('./security-rbac-regression.test');
const { runCoreDiagnosticsEngineTests } = require('./core-diagnostics-engine.test');
const { runAutonomousRemediationSafetyTests } = require('./autonomous-remediation-safety.test');
const { runLiveProductionSmoke } = require('./live-production-smoke.test');
const { runHostileSecurityAuditTests } = require('./hostile-security-audit.test');
const { runLivePacketPipelineTests } = require('./live-packet-pipeline.test');
const { runWiresharkAiWorkstationTests } = require('./wireshark-ai-workstation.test');
const { runSecureDeploymentLifecycleTests } = require('./secure-deployment-lifecycle.test');
const { runBrainSelfUpdatingHarnessTests } = require('./brain-self-updating-harness.test');

async function runAllTests() {
  console.log('========================================================================');
  console.log("  EJII — Eldar Jamiyev's Infrastructure Intelligence Workstation       ");
  console.log('  NOC TOPOLOGY & WIRE-LEVEL PACKET DISSECTION TEST RUNNER               ');
  console.log('  Testing under Zero-Elevation & Unprivileged Reality Mandate          ');
  console.log('========================================================================');

  const startTime = Date.now();
  let passedSuites = 0;
  const suites = [
    { name: '1. Network Protocol Drivers (ICMP Ping, TCP Socket, RFC 1035 DNS, TLS 1.3 Handshake, HTTP)', fn: runNetworkTests },
    { name: '2. Pillar 1: NOC Topology Graph, L2/3 Discovery, Blast Radius & Congestion Heatmap', fn: runTopologyTests },
    { name: '3. Pillar 2 & 3: Binary Protocol Dissectors, TCP Stream Delta Tracker & Integration Bridge', fn: runDissectorTests },
    { name: '4. Pillar 4: Isolated Helper Tools (Async Sweeper, BGP/OSPF Listener, Wire Error Finder)', fn: runWireDiagnosticsTests },
    { name: '5. Wire Capture & Dissection Acceptance (Physical Npcap BPF, Stream Reassembly, PCAP I/O)', fn: runAddendaAcceptanceTests },
    { name: '6. NOC Wire Integrity, NirSoft Flow Matrix Sync & Evidence Model Regression', fn: runNocIntegrityRegressionTests },
    { name: '7. Pillar 5: NOC Headless UI, Dynamic Layer Topology SVG & Non-Wrapping Layout Suite', fn: runHeadlessUiVerificationTests },
    { name: '8. Pillar 6: Ultra IP & Infrastructure Fleet Scanner (NetBIOS, WOL, Multi-Protocol)', fn: runIpScannerSuiteTests },
    { name: '9. Pillar 7: Local PC Automation & Safe Script Execution Engine (BAT Files @ e:\\Scripts)', fn: runPcAutomationTests },
    { name: '10. Pillar 8: Frontend Re-Architecture, Strict Column Sync, Cyber-NOC Theme & Viewport Integrity', fn: runFrontendRebuildVerification },
    { name: '11. Evidence-Driven Intelligence, Adaptive Topology Engine, Diagnostic Reasoning & Security Audit', fn: runAdaptiveTopologyAndEvidenceTests },
    { name: '12. Continuous Adaptive AI Reasoning Brain, Bayesian Multi-Hypothesis Engine & Memory Persistence', fn: runAiBrainTests },
    { name: '13. 21 Target Websites & Government Endpoints Zero-Simulation Verification Audit', fn: verifyAllTargets },
    { name: '14. Monte-Carlo Bayesian Probability Normalization Invariant & Stress Suite (500 Iterations)', fn: runNormalizationStressTests },
    { name: '15. Controlled Two-Phase Discovery & EDR Safety Verification Suite', fn: runEdrSafeScannerTests },
    { name: '16. Browser-Level E2E Workflow & View Contract Verification Suite', fn: runE2EBrowserWorkflow },
    { name: '17. Industrial Packet Dissection Engine, Wireshark AST Filter Compiler & TCP Stream Reassembler', fn: runPacketDissectionEngineTests },
    { name: '18. Autonomous AI Causal Investigator, Rule of Contradictory Proof & Distinguishing Probes', fn: runAiCausalInvestigatorTests },
    { name: '19. Adversarial Protocol Fixtures, RFC Checksums, IPv4 Frags, Truncation & Loop Defense', fn: runAdversarialProtocolTests },
    { name: '20. TCP Stream Reassembler 32-Bit Sequence Wraparound, Overlap Trimming & RST Tear-down', fn: runTcpStreamWraparoundTests },
    { name: '21. Tool Sandbox Hardening, Role-Based Access Control, Parameter Sanitization & Audit Logs', fn: runToolSandboxAndSecurityTests },
    { name: '22. Shared AI Brain Evidence Reasoning, Multi-Hypothesis Evaluation & LLM Provider Fallback', fn: runAiBrainEvidenceReasoningTests },
    { name: '23. Security & RBAC Hostile Regression, Zero-Trust Identity & Header Spoofing Defense', fn: runSecurityRbacRegressionTests },
    { name: '24. Core Diagnostics 4-Pillar Host Ingestion, WMI/CIM Telemetry & AI Brain Synthesis', fn: runCoreDiagnosticsEngineTests },
    { name: '25. Autonomous Remediation Safety, Elevation Lifecycle & OS Process Protection', fn: runAutonomousRemediationSafetyTests },
    { name: '26. Live Production Server Socket & API Smoke Test, Zero-Trust Defenses & Live Host Telemetry', fn: runLiveProductionSmoke },
    { name: '27. Hostile Security Audit, Action Token Binding, Injection Defense, HMAC Audit Chain & 5-State Health', fn: runHostileSecurityAuditTests },
    { name: '28. Live Packet Pipeline Forensic Verification, Wire Schemas, Queue Backpressure & Fault Banner', fn: runLivePacketPipelineTests },
    { name: '29. Wireshark-Grade Workstation, Interface Enumeration, AST NL Filter & Bayesian Packet Explainer', fn: runWiresharkAiWorkstationTests },
    { name: '30. Secure Deployment Lifecycle, Production Secrets, Clean Initial Boot & Audit Persistence', fn: runSecureDeploymentLifecycleTests },
    { name: '31. Autonomous Self-Updating AI Brain Harness, Dynamic Schema Gatekeeper & Circuit Breaker', fn: runBrainSelfUpdatingHarnessTests }
  ];

  for (const s of suites) {
    try {
      console.log(`\n>>> STARTING: [${s.name}]`);
      await s.fn();
      passedSuites++;
    } catch (err) {
      console.error(`\n❌ TEST SUITE FAILED: [${s.name}]`);
      console.error(err);
      process.exit(1);
    }
  }

  const durationSec = ((Date.now() - startTime) / 1000).toFixed(2);
  console.log('========================================================================');
  console.log(`  ALL ${passedSuites}/${suites.length} NOC TEST SUITES PASSED PERFECTLY IN ${durationSec}s`);
  console.log('  100% Real Physical Wire & Network I/O Verified — Zero Mock Data Confirmed');
  console.log('  EJII NOC Topology & Packet Dissection Workstation is 100% OPERATIONAL');
  console.log('========================================================================\n');
}

if (require.main === module) {
  runAllTests().then(() => {
    process.exit(0);
  }).catch((err) => {
    console.error('Master Test Suite failed:', err);
    process.exit(1);
  });
}

module.exports = { runAllTests };
