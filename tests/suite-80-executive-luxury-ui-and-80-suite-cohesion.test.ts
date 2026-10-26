// tests/suite-80-executive-luxury-ui-and-80-suite-cohesion.test.ts
import * as assert from 'node:assert';
import * as fs from 'node:fs';
import * as path from 'node:path';

export async function runSuite80ExecutiveLuxuryUiAnd80SuiteCohesion(): Promise<void> {
  console.log('=== [SUITE 80] EXECUTIVE LUXURY UI & 80-SUITE COHESION VERIFICATION ===');

  const rootDir = path.resolve(__dirname, '..');

  // 1. Executive Luxury UI Tokens & Design System Verification
  console.log('[80.1] Verifying Architectural Cashmere & Velvet Graphite tokens in stylesheets...');
  const premiumCssPath = path.join(rootDir, 'public', 'css', 'eji-premium.css');
  const styleCssPath = path.join(rootDir, 'public', 'css', 'style.css');

  assert.ok(fs.existsSync(premiumCssPath), 'eji-premium.css must exist');
  assert.ok(fs.existsSync(styleCssPath), 'style.css must exist');

  const premiumCss = fs.readFileSync(premiumCssPath, 'utf-8');
  const styleCss = fs.readFileSync(styleCssPath, 'utf-8');
  const combinedCss = premiumCss + '\n' + styleCss;

  // Verify Architectural Cashmere & Velvet Graphite palette tokens
  assert.ok(combinedCss.includes('#F4F3EF') || combinedCss.includes('#f4f3ef'), 'Must contain Warm Alabaster canvas token (#F4F3EF)');
  assert.ok(combinedCss.includes('#141413'), 'Must contain Deep Editorial Ink typography token (#141413)');
  assert.ok(combinedCss.includes('#2B44B8') || combinedCss.includes('#2b44b8'), 'Must contain Royal Executive Indigo accent token (#2B44B8)');

  // Verify Executive Component Utility Classes
  assert.ok(combinedCss.includes('.exec-card'), 'Must define .exec-card luxury card container');
  assert.ok(combinedCss.includes('.exec-toolbar'), 'Must define .exec-toolbar header bar');
  assert.ok(combinedCss.includes('.exec-btn-primary'), 'Must define .exec-btn-primary luxury button');
  assert.ok(combinedCss.includes('.exec-badge'), 'Must define .exec-badge refined chip');
  assert.ok(combinedCss.includes('.exec-table'), 'Must define .exec-table data grid');

  // 2. Interactive Engine Workbenches in Views
  console.log('[80.2] Verifying 6 new engine workbenches across all frontend views...');
  const viewsDir = path.join(rootDir, 'public', 'js', 'views');

  // Engine 1: PCAPNG in sniffer-view.js and noc-view.js
  const snifferView = fs.readFileSync(path.join(viewsDir, 'sniffer-view.js'), 'utf-8');
  const nocView = fs.readFileSync(path.join(viewsDir, 'noc-view.js'), 'utf-8');
  assert.ok(
    snifferView.includes('downloadPcapngExport') || nocView.includes('downloadPcapngExport'),
    'PCAPNG binary export workbench must be wired into sniffer or noc view'
  );
  assert.ok(
    snifferView.includes('triggerImportPcapng') || snifferView.includes('pcapngFilePicker'),
    'PCAPNG binary replay workbench must be wired into sniffer view'
  );

  // Engine 2: Radix LPM in topology-view.js and noc-view.js
  const topologyView = fs.readFileSync(path.join(viewsDir, 'topology-view.js'), 'utf-8');
  assert.ok(
    topologyView.includes('openRoutingRadixModal') || nocView.includes('openRoutingRadixModal'),
    'Routing Radix / LPM modal workbench must be wired into topology/noc view'
  );

  // Engine 3, 5, 6: Socket Process Matrix, CUSUM Forensics, and Incident Dossier in core-diagnostics-view.js
  const diagView = fs.readFileSync(path.join(viewsDir, 'core-diagnostics-view.js'), 'utf-8');
  assert.ok(
    diagView.includes('openSocketProcessMatrixModal'),
    'Process Socket Matrix workbench must be wired in core-diagnostics-view.js'
  );
  assert.ok(
    diagView.includes('openCusumChangepointModal'),
    'CUSUM Changepoint Forensics workbench must be wired in core-diagnostics-view.js'
  );
  assert.ok(
    diagView.includes('exportSignedIncidentDossier'),
    'Signed Incident Flight Dossier exporter must be wired in core-diagnostics-view.js'
  );

  // Engine 4: TLS Posture Audit in ultra-ip-scanner-view.js
  const ipScannerView = fs.readFileSync(path.join(viewsDir, 'ultra-ip-scanner-view.js'), 'utf-8');
  assert.ok(
    ipScannerView.includes('runHostTlsPostureAudit'),
    'TLS Posture Auditor action must be wired in ultra-ip-scanner-view.js'
  );

  // 3. Server Locals & Engine Registration
  console.log('[80.3] Verifying server.js app.locals registration for all 6 v3 engines...');
  const serverJs = fs.readFileSync(path.join(rootDir, 'src', 'server.js'), 'utf-8');
  assert.ok(serverJs.includes('app.locals.pcapngEngine'), 'app.locals.pcapngEngine must be registered');
  assert.ok(serverJs.includes('app.locals.routingRadixIntelligence'), 'app.locals.routingRadixIntelligence must be registered');
  assert.ok(serverJs.includes('app.locals.processSocketCorrelator'), 'app.locals.processSocketCorrelator must be registered');
  assert.ok(serverJs.includes('app.locals.tlsPostureAuditor'), 'app.locals.tlsPostureAuditor must be registered');
  assert.ok(serverJs.includes('app.locals.cusumChangepointEngine'), 'app.locals.cusumChangepointEngine must be registered');
  assert.ok(serverJs.includes('app.locals.incidentFlightRecorder'), 'app.locals.incidentFlightRecorder must be registered');

  // 4. Exact 80 Registered Test Suites Cohesion
  console.log('[80.4] Verifying canonical master test runner registration of exactly 80 suites...');
  const runnerJs = fs.readFileSync(path.join(rootDir, 'tests', 'run-all-tests.js'), 'utf-8');

  // Verify imports of Suites 74-80
  assert.ok(runnerJs.includes('suite-74-pcapng-binary-engine.test'), 'Runner must import Suite 74');
  assert.ok(runnerJs.includes('suite-75-routing-radix-trie-intelligence.test'), 'Runner must import Suite 75');
  assert.ok(runnerJs.includes('suite-76-process-socket-behavioral-matrix.test'), 'Runner must import Suite 76');
  assert.ok(runnerJs.includes('suite-77-tls-x509-posture-auditor.test'), 'Runner must import Suite 77');
  assert.ok(runnerJs.includes('suite-78-cusum-changepoint-forensics.test'), 'Runner must import Suite 78');
  assert.ok(runnerJs.includes('suite-79-incident-flight-recorder-dossier.test'), 'Runner must import Suite 79');
  assert.ok(runnerJs.includes('suite-80-executive-luxury-ui-and-80-suite-cohesion.test'), 'Runner must import Suite 80');

  // Count registered suites
  const suiteMatches = runnerJs.match(/\{\s*name:\s*['"]\d+\./g) || [];
  assert.strictEqual(
    suiteMatches.length,
    80,
    `Expected exactly 80 registered test suites in run-all-tests.js, found ${suiteMatches.length}`
  );

  // 5. Zero-Simulation Topology Graph Truth & SVG Edge Path Verification
  console.log('[80.5] Verifying Topology Engine zero-duplicate IP guarantee, edge connectivity & SVG fill="none"...');
  const { TopologyEngine } = require('../src/network/topology/topology-engine');
  const topoEngine = new TopologyEngine();
  const topo = topoEngine.getTopology();

  assert.ok(Array.isArray(topo.nodes) && topo.nodes.length >= 4, 'Topology must discover at least 4 hierarchical nodes');
  assert.ok(Array.isArray(topo.edges) && topo.edges.length >= 3, 'Topology must have active connecting edges');

  // Verify zero duplicate IP addresses in the same hierarchy layer
  const layerIpTracker = new Set<string>();
  for (const node of topo.nodes) {
    const key = `${node.layer_level || node.layer}:${node.hostname_or_ip}`;
    assert.strictEqual(
      layerIpTracker.has(key),
      false,
      `Duplicate node IP/CIDR found in layer: ${key}`
    );
    layerIpTracker.add(key);
  }

  // Verify every active node is connected by at least one edge
  const incidentNodes = new Set<string>();
  for (const edge of topo.edges) {
    incidentNodes.add(edge.source_id);
    incidentNodes.add(edge.target_id);
  }
  for (const node of topo.nodes) {
    assert.ok(
      incidentNodes.has(node.id),
      `Node ${node.id} (${node.name}) must be connected by at least one edge in the graph`
    );
  }

  // Verify Fiedler eigenvalue lambda_2 is strictly positive on connected topology
  assert.ok(
    topo.algebraicConnectivityLambda2 > 0,
    `Fiedler eigenvalue lambda_2 must be > 0 on connected topology, received ${topo.algebraicConnectivityLambda2}`
  );

  // Verify SVG edge paths explicitly include fill="none"
  assert.ok(
    nocView.includes('fill="none" d="${d}"') || nocView.includes('fill="none"'),
    'noc-view.js SVG edge path must explicitly specify fill="none"'
  );
  assert.ok(
    premiumCss.includes('.topology-light-canvas svg path') && premiumCss.includes('fill: none !important;'),
    'eji-premium.css must enforce fill: none !important for all topology SVG paths'
  );

  console.log('✓ Suite 80 passed: Executive Luxury UI, Topology Graph Truth & 80-Suite Cohesion 100% verified.\n');
}

if (require.main === module) {
  runSuite80ExecutiveLuxuryUiAnd80SuiteCohesion().then(() => process.exit(0)).catch(err => {
    console.error(err);
    process.exit(1);
  });
}
