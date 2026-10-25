

/**
 * EJII NOC Workstation Master Test Suite Runner
 * Executes all wire-level protocol, topology, packet dissection, and stream telemetry verification suites.
 * Zero-Elevation & Zero-Simulation Mandate.
 */

process.env.NODE_ENV = 'test';
process.env.EJII_SAFE_TEST_MODE = '1';
const fs = require('fs');
const path = require('path');
const os = require('os');
const testTmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ejii-test-run-'));
process.env.EJII_TEST_DATA_DIR = testTmpDir;
process.env.EJII_AUDIT_FILE_PATH = path.join(testTmpDir, 'audit-trail.jsonl');
process.env.EJII_AUDIT_ANCHOR_PATH = path.join(testTmpDir, '.chain_head');

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
const { runWireProbeAndAiBrainTruthTests } = require('./wire-probe-and-ai-brain-truth.test');
const { runFullSystemE2eAndFeedbackLoopTests } = require('./full-system-e2e-and-feedback-loop.test');
const { runUtf8IntrospectionIpPinningAndIsolationTests } = require('./utf8-introspection-ip-pinning-and-isolation.test');
const { runCrossLayerRcaWsSyncAndToolSsrfTests } = require('./cross-layer-rca-ws-sync-and-tool-ssrf.test');
const { runSignalTriageAndOrchestratorTests } = require('./signal-triage-endpoint-discovery-and-orchestrator.test');
const { runVisualRuntimeTruthAndSignalHygieneTests } = require('./visual-runtime-truth-and-signal-hygiene.test');
const { runZeroPhantomGovTrafficAndDeepBackendTests } = require('./zero-phantom-gov-traffic-and-deep-backend.test');
const { runUnifiedInvestigationRagAndMultiModelTests } = require('./unified-investigation-rag-and-multimodel.test');
const { runInvestigationIntegrityTests } = require('./investigation-integrity.test');
const { runDeepCodeVerificationGate } = require('./verify-deep-code-implementation.test');
const { runLiveDomVisualTruthRegressionTests } = require('./live-dom-visual-truth-regression.test');
const { runZeroZombieDebtAndEnterpriseUpgradeTests } = require('./zero-zombie-debt-sqlite-brain-and-ui-restraint.test');
const { runAutomationScriptAudit } = require('./audit-all-automation-scripts');
const { runAuthTests } = require('./auth-rbac.test');
const { runAutomationTests } = require('./automation-safety.test');
const { runRcaTests } = require('./rca-engine.test');
const { runServiceVerifierMatrixTests } = require('./service-verifier-matrix.test');
const { runSystemTests } = require('./system-probes.test');
const { runToolsTestSuite } = require('./tools-engines.test');
const { runLiveServerVerification } = require('./verify-live-server.e2e');
const { runFullRepositoryCohesionAndProductionTruthTests } = require('./full-repository-cohesion-and-production-truth.test');
const { runSuite51 } = require('./ai-brain-epistemic-validator-and-dag-planner.test');
const { runSuite52 } = require('./enterprise-api-contracts-concurrency-and-hygiene.test');
const { runPortableScriptsMountAndUtf8LauncherTests } = require('./portable-scripts-mount-and-utf8-launcher.test');
const { runOfficeEquipmentApipaSmartMapAndPlainDiagnosticsTests } = require('./office-equipment-apipa-smart-map-and-plain-diagnostics.test');
const { runWebSocketEaddrinuseAndServerLifecycleTests } = require('./websocket-eaddrinuse-and-server-lifecycle.test');
const { runDhcpMdnsDissectorAndOfficeLanIntelligenceTests } = require('./dhcp-mdns-dissector-and-office-lan-intelligence.test');
const { runPersistentEquipmentInventoryAndDhcpDoraTrackerTests } = require('./persistent-equipment-inventory-and-dhcp-dora-tracker.test');
const { runAiContextWindowSharedOutageAndRecoveryLoopTests } = require('./ai-context-window-shared-outage-and-recovery-loop.test');
const { runWebSocketBackpressureSchemaMigrationsAndApiContractsTests } = require('./websocket-backpressure-schema-migrations-and-api-contracts.test');
const { runEnterpriseDesignSystemAndCrossViewStateTests } = require('./enterprise-design-system-and-cross-view-state.test');
const { runAutonomousGoalWorkflowAndEndpointMemoryTests } = require('./autonomous-goal-workflow-and-endpoint-memory.test');
const { runOfficeProtocolBannersAndReverificationDiffTests } = require('./office-protocol-banners-and-reverification-diff.test');
const { runFiveViewFrontendBackendWiringTests } = require('./five-view-frontend-backend-wiring.test');
const { runReportConsistencyAndZeroStaleCountsTests } = require('./report-consistency-and-zero-stale-counts.test');
const { runDynamicLocationTopologyAndZeroHardcodedIpsTests } = require('./dynamic-location-topology-and-zero-hardcoded-ips.test');
const { runWorkerPoolTypesAndTimeseriesAdapterTests } = require('./worker-pool-types-and-timeseries-adapter.test');
const { runCncfPrometheusOtelAndLinuxParityTests } = require('./cncf-prometheus-otel-and-linux-parity.test');
const { runGitopsDriftReconciliationLoopTests } = require('./gitops-drift-reconciliation-loop.test');
const { runZeroTimeoutUnprivilegedScriptsAndHygieneTests } = require('./zero-timeout-unprivileged-scripts-and-hygiene.test');
const { runKlDivergenceBayesFactorAndCriticReflectionTests } = require('./kl-divergence-bayes-factor-and-critic-reflection.test');
const { runW3cTraceparentPipelineAndMultiEnvLocationTests } = require('./w3c-traceparent-pipeline-and-multi-env-location.test');
const { runControlPlaneUiGitopsObservabilityWiringTests } = require('./control-plane-ui-gitops-observability-wiring.test');

async function runAllTests() {
  const fs = require('fs');
  const path = require('path');
  // Isolated test environment configured in testTmpDir

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
    { name: '31. Autonomous Self-Updating AI Brain Harness, Dynamic Schema Gatekeeper & Circuit Breaker', fn: runBrainSelfUpdatingHarnessTests },
    { name: '32. AI Brain, Wire Probe Semantics, Kernel Socket Error Codes & SSRF Truth Audit', fn: runWireProbeAndAiBrainTruthTests },
    { name: '33. Full System E2E, SSRF Defense, Feedback Calibration & Architecture Integrity', fn: runFullSystemE2eAndFeedbackLoopTests },
    { name: '34. UTF-8 Adapter Introspection, DNS-Rebinding IP Pinning, Singleton Isolation & Launcher Gate', fn: runUtf8IntrospectionIpPinningAndIsolationTests },
    { name: '35. Cross-Layer Host+Wire Causal RCA, Universal Protocol Driver & Redirect SSRF Guard, WS Brain Sync, and Graceful WAL Shutdown', fn: runCrossLayerRcaWsSyncAndToolSsrfTests },
    { name: '36. Signal Triage, Process-to-Server Port Finder, Vectorized Bayesian Matrix & Multi-Model AI Brain Orchestrator', fn: runSignalTriageAndOrchestratorTests },
    { name: '37. Visual Runtime Truth, Signal Hygiene, RFC 1122 Keep-Alives & Dynamic Labels', fn: runVisualRuntimeTruthAndSignalHygieneTests },
    { name: '38. Zero Phantom Gov Traffic, RFC 1122 Keep-Alive Disambiguation & Deep 5-Section Backend Suite', fn: runZeroPhantomGovTrafficAndDeepBackendTests },
    { name: '39. Unified Guided Investigation, RAG Infrastructure Knowledge Engine & Multi-Model Second-Opinion Verification', fn: async () => {
      await runDeepCodeVerificationGate();
      await runInvestigationIntegrityTests();
      await runUnifiedInvestigationRagAndMultiModelTests();
    } },
    { name: '40. Live DOM Visual Truth, 3-Tier IP Scanner Ordering, Multi-Core CPU% Normalization & Signal Hygiene Regression', fn: runLiveDomVisualTruthRegressionTests },
    { name: '41. Zero Zombie Debt, SQLite WAL Brain Persistence, 17-Tool Sandbox & UI Restraint Audit', fn: runZeroZombieDebtAndEnterpriseUpgradeTests },
    { name: '42. Real Host Automation Script Audit & Process Tree Safety Matrix (27 Scripts)', fn: runAutomationScriptAudit },
    { name: '43. Authentication, Cryptographic HMAC Audit Trail Chain & RBAC Matrix', fn: runAuthTests },
    { name: '44. Automation Safety, Elevation Lifecycle & Dual-Custody Approval Gate', fn: runAutomationTests },
    { name: '45. Root Cause Analysis (RCA) Dependency DAG & Downstream Alert Suppression', fn: runRcaTests },
    { name: '46. Enterprise Web & Mail Verifier, 5-Layer Stepper & Connectivity Matrix', fn: runServiceVerifierMatrixTests },
    { name: '47. Real Host & Bare-Metal System Metrics, Services & Process DAG Audit', fn: runSystemTests },
    { name: '48. 14-Tool Diagnostic Subsystems (Wireshark, Nmap, Sysinternals, iPerf, Netcat, BleachBit)', fn: runToolsTestSuite },
    { name: '49. Live Running Server Socket, HTTP & WebSocket Telemetry E2E Verification', fn: runLiveServerVerification },
    { name: '50. Full-Repository Cohesion, 100% Reachability, Physical RAG Runbooks/Policies, 20-Tool Sandbox & CLI/Desktop/Mobile Truth', fn: runFullRepositoryCohesionAndProductionTruthTests },
    { name: '51. AI Brain Epistemic Entropy, Self-Validator & Causal DAG Planner', fn: runSuite51 },
    { name: '52. Enterprise API Contracts, Concurrency & Hygiene Suite', fn: runSuite52 },
    { name: '53. Portable 4-Tier Script Directory Virtualization, Self-Healing Mount & UTF-8 Console Title Integrity', fn: runPortableScriptsMountAndUtf8LauncherTests },
    { name: '54. Automatic Office Equipment Classification, Visual Smart Map, Plain-Language APIPA Resolver, Hybrid BM25/N-Gram RAG & Counterfactual Causal Simulator', fn: runOfficeEquipmentApipaSmartMapAndPlainDiagnosticsTests },
    { name: '55. Node.js v24 WebSocketServer EADDRINUSE Crash Defense & Server Lifecycle', fn: runWebSocketEaddrinuseAndServerLifecycleTests },
    { name: '56. Binary RFC 2131 DHCP (DORA) Dissector, RFC 6762 mDNS/LLMNR & Office LAN Intelligence', fn: runDhcpMdnsDissectorAndOfficeLanIntelligenceTests },
    { name: '57. Persistent Office Equipment Inventory, DHCP DORA Wire Tracker & Local Print Spooler', fn: runPersistentEquipmentInventoryAndDhcpDoraTrackerTests },
    { name: '58. AI Episodic Context Window Manager, Shared Outage Correlator & Multi-Turn Recovery Loop', fn: runAiContextWindowSharedOutageAndRecoveryLoopTests },
    { name: '59. WebSocket Backpressure, Transactional Schema Migrations & Enterprise API Contracts', fn: runWebSocketBackpressureSchemaMigrationsAndApiContractsTests },
    { name: '60. Enterprise Design System, Cross-View State Routing & 5-Pillar Architectural Restraint', fn: runEnterpriseDesignSystemAndCrossViewStateTests },
    { name: '61. Autonomous Goal Workflow DAG, 8-Invariant Self-Validation & SQLite WAL v4 Endpoint Behavioral Memory', fn: runAutonomousGoalWorkflowAndEndpointMemoryTests },
    { name: '62. Office Protocol Banners (IPP/JetDirect), Safe 650ms Short-Circuit & Closed-Loop Re-Verification Diff', fn: runOfficeProtocolBannersAndReverificationDiffTests },
    { name: '63. Full 5-View Frontend-to-Backend Wiring, Real Wire Filters, Banners & Do-Calculus DOM', fn: runFiveViewFrontendBackendWiringTests },
    { name: '64. Master Report Consistency, Zero Zombie Files, Test Integrity & 68-Suite Milestone Alignment', fn: runReportConsistencyAndZeroStaleCountsTests },
    { name: '65. Dynamic Location Topology Auto-Sync, Zero Hardcoded Alien IPs & Real Gateway OUI', fn: runDynamicLocationTopologyAndZeroHardcodedIpsTests },
    { name: '66. Worker-Thread Multi-Core Pool, TS Contracts & Pluggable Time-Series TSDB Adapter', fn: runWorkerPoolTypesAndTimeseriesAdapterTests },
    { name: '67. CNCF Prometheus Exposition, OpenTelemetry OTLP Spans, Grafana Dashboard & Linux /proc Parity', fn: runCncfPrometheusOtelAndLinuxParityTests },
    { name: '68. Continuous GitOps IaC Drift Detection & Autonomous Reconciliation Loop', fn: runGitopsDriftReconciliationLoopTests },
    { name: '69. Zero-Timeout Unprivileged Host Automation Scripts, Pre-Boot Scratch Sanitizer & Windows Loopback Resilience', fn: runZeroTimeoutUnprivilegedScriptsAndHygieneTests },
    { name: '70. Kullback-Leibler Information Gain, Harold Jeffreys Evidence Scale & Planner-Executor-Critic AI Brain', fn: runKlDivergenceBayesFactorAndCriticReflectionTests },
    { name: '71. W3C traceparent Telemetry Pipeline, CNCF OpenTelemetry Spans, 50:64:2B OUI & Multi-Environment Profiles', fn: runW3cTraceparentPipelineAndMultiEnvLocationTests },
    { name: '72. View 5 Control Plane UI Wiring, Command Palette Quick Actions & 72-Suite Verification Alignment', fn: runControlPlaneUiGitopsObservabilityWiringTests }
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
  console.log('  Evidence-Grounded Suite Verification Completed — Local OS Telemetry & Isolated Test Sandboxes');
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
