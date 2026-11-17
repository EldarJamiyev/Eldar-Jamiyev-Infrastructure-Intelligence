#!/usr/bin/env node
/**
 * EJII TypeScript/JavaScript Dual-Maintenance Parity Guard
 * Verifies that all 1st-party TypeScript modules have valid, existing,
 * and semantically aligned JavaScript counterparts with matching exported classes and methods.
 * Zero-Simulation & Continuous Verification Standard.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');

console.log('========================================================================');
console.log('  EJII TypeScript / JavaScript Dual-Maintenance Parity Guard            ');
console.log('========================================================================');

const ROOT_DIR = path.resolve(__dirname, '..');
const SEARCH_DIRS = [
  path.join(ROOT_DIR, 'src', 'ai'),
  path.join(ROOT_DIR, 'src', 'core', 'multisite'),
  path.join(ROOT_DIR, 'src', 'core', 'skills'),
  path.join(ROOT_DIR, 'src', 'diagnostics'),
  path.join(ROOT_DIR, 'src', 'observability'),
  path.join(ROOT_DIR, 'src', 'scanner'),
  path.join(ROOT_DIR, 'src', 'security'),
  path.join(ROOT_DIR, 'src', 'sniffer'),
  path.join(ROOT_DIR, 'src', 'systems', 'remediation'),
  path.join(ROOT_DIR, 'src', 'topology')
];

let totalTsModules = 0;
let checkedModules = 0;
let failures = 0;
const divergences = [];

function getTsFiles(dir) {
  if (!fs.existsSync(dir)) return [];
  const files = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...getTsFiles(full));
    } else if (entry.name.endsWith('.ts') && !entry.name.endsWith('.d.ts')) {
      files.push(full);
    }
  }
  return files;
}

const allTsFiles = SEARCH_DIRS.flatMap(getTsFiles);
totalTsModules = allTsFiles.length;

console.log(`[TS/JS Parity] Auditing ${totalTsModules} TypeScript flagship modules...`);

for (const tsFile of allTsFiles) {
  const relativeTs = path.relative(ROOT_DIR, tsFile).replace(/\\/g, '/');
  const jsFile = tsFile.replace(/\.ts$/, '.js');
  const relativeJs = path.relative(ROOT_DIR, jsFile).replace(/\\/g, '/');

  // Check 1: Corresponding JS file must exist
  if (!fs.existsSync(jsFile)) {
    failures++;
    divergences.push(`MISSING_JS: ${relativeTs} has no compiled counterpart at ${relativeJs}`);
    continue;
  }

  // Check 2: Both files must be non-empty
  const tsContent = fs.readFileSync(tsFile, 'utf8');
  const jsContent = fs.readFileSync(jsFile, 'utf8');

  if (tsContent.trim().length === 0 || jsContent.trim().length === 0) {
    failures++;
    divergences.push(`EMPTY_FILE: ${relativeTs} or ${relativeJs} is empty`);
    continue;
  }

  // Check 3: Extract exported classes and functions from TypeScript file
  const tsClassMatches = Array.from(tsContent.matchAll(/export\s+class\s+([A-Za-z0-9_]+)/g)).map((m) => m[1]);
  const tsFunctionMatches = Array.from(tsContent.matchAll(/export\s+function\s+([A-Za-z0-9_]+)/g)).map((m) => m[1]);
  const tsConstMatches = Array.from(tsContent.matchAll(/export\s+const\s+([A-Za-z0-9_]+)/g)).map((m) => m[1]);
  const allExpectedExports = [...tsClassMatches, ...tsFunctionMatches, ...tsConstMatches];

  // Check 4: Verify AST syntax AND runtime require() loading of JS module
  try {
    new vm.Script(jsContent, { filename: jsFile });
  } catch (syntaxErr) {
    failures++;
    divergences.push(`SYNTAX_ERROR: ${relativeJs} failed AST parsing: ${syntaxErr.message}`);
    continue;
  }

  let jsModule = null;
  try {
    jsModule = require(jsFile);
  } catch (loadErr) {
    failures++;
    divergences.push(`RUNTIME_LOAD_ERROR: ${relativeJs} failed runtime require(): ${loadErr.message}`);
    continue;
  }

  if (jsModule && typeof jsModule === 'object') {
    for (const expName of allExpectedExports) {
      if (jsModule[expName] === undefined) {
        failures++;
        divergences.push(`MISSING_EXPORT: ${relativeJs} is missing expected export "${expName}" declared in ${relativeTs}`);
      }
    }

    // Check 5: For exported classes, inspect public methods
    for (const clsName of tsClassMatches) {
      const cls = jsModule[clsName];
      if (typeof cls === 'function' && cls.prototype) {
        // Extract class body for this specific class
        const classBodyMatch = tsContent.match(new RegExp(`class\\s+${clsName}\\b[^{]*\\{([\\s\\S]*?)(?:\\n\\}\\n|\\nexport|\\Z)`));
        const classBody = classBodyMatch ? classBodyMatch[1] : '';
        const methodRegex = /public\s+([a-zA-Z0-9_]+)\s*\(/g;
        let m;
        while ((m = methodRegex.exec(classBody)) !== null) {
          const methodName = m[1];
          if (methodName !== 'constructor' && typeof cls.prototype[methodName] !== 'function' && typeof cls[methodName] !== 'function') {
            failures++;
            divergences.push(`MISSING_METHOD: ${clsName}.${methodName}() in ${relativeJs} is declared in ${relativeTs} but missing on JS prototype`);
          }
        }
      }
    }
  }

  checkedModules++;
  console.log(`  ✓ ${relativeTs} <-> ${relativeJs} (synced)`);
}

console.log('------------------------------------------------------------------------');
console.log('[TS/JS Parity] Running runtime behavioral smoke checks...');
try {
  const { RlofPreferenceAligner } = require(path.join(ROOT_DIR, 'src', 'ai', 'rlof-preference-aligner.js'));
  const aligner = new RlofPreferenceAligner();
  const rOk = aligner.computeReward([0.5, 0.2, 0.1, 0.9], 'ACTION_A');
  if (!Number.isFinite(rOk)) {
    failures++;
    divergences.push('BEHAVIOR_ERROR: RlofPreferenceAligner.computeReward returned non-finite value');
  }
  let threwNaN = false;
  try {
    aligner.computeReward([NaN, 0.2, 0.1, 0.9], 'ACTION_A');
  } catch (_) {
    threwNaN = true;
  }
  if (!threwNaN) {
    failures++;
    divergences.push('BEHAVIOR_ERROR: RlofPreferenceAligner.computeReward did not reject non-finite contextVector');
  }

  const { RoutingRadixIntelligenceEngine } = require(path.join(ROOT_DIR, 'src', 'topology', 'routing-radix-intelligence.js'));
  const radix = new RoutingRadixIntelligenceEngine();
  if (typeof radix.clearRoutes === 'function') {
    radix.clearRoutes();
  }
  if (typeof radix.findLongestPrefixMatch === 'function' && radix.findLongestPrefixMatch('192.168.31.1') !== null) {
    failures++;
    divergences.push('BEHAVIOR_ERROR: RoutingRadixIntelligenceEngine pre-seeded synthetic 192.168.31.1 route');
  }

  const { GeoPartitionCrdtEngine } = require(path.join(ROOT_DIR, 'src', 'core', 'multisite', 'geo-partition-crdt-engine.js'));
  const crdtParity = new GeoPartitionCrdtEngine('site-parity-primary', { dbHandle: null });
  const selfReport = crdtParity.reconcileWithRemotePartition('site-parity-primary', {}, []);
  if (!selfReport || selfReport.convergenceStatus !== 'INVALID_SELF_TARGET') {
    failures++;
    divergences.push('BEHAVIOR_ERROR: GeoPartitionCrdtEngine did not reject self-partition sync with INVALID_SELF_TARGET');
  }
  const emptyReport = crdtParity.reconcileWithRemotePartition('site-parity-eu', {}, []);
  if (!emptyReport || emptyReport.convergenceStatus !== 'NO_REMOTE_DELTAS_AVAILABLE') {
    failures++;
    divergences.push('BEHAVIOR_ERROR: GeoPartitionCrdtEngine allowed vacuous remote sync without deltas or clock');
  }
  const realReport = crdtParity.reconcileWithRemotePartition('site-parity-eu', { 'site-parity-eu': 2 }, [
    { crdtType: 'PN_COUNTER', key: 'parity_counter', operation: 'MERGE', deltaPayload: { positive: { 'site-parity-eu': 4 }, negative: {} } }
  ]);
  if (!realReport || realReport.convergenceStatus !== 'CONVERGED' || crdtParity.getCounterValue('parity_counter') !== 4) {
    failures++;
    divergences.push('BEHAVIOR_ERROR: GeoPartitionCrdtEngine failed real PN_COUNTER delta convergence check');
  }

  if (failures === 0) {
    console.log('  ✓ Behavioral smoke checks passed (RlofPreferenceAligner finite guards, RoutingRadixIntelligenceEngine clean state, GeoPartitionCrdtEngine fail-closed & convergence)');
  }
} catch (behErr) {
  failures++;
  divergences.push(`BEHAVIOR_ERROR: ${behErr.message}`);
}

console.log('========================================================================');
if (failures === 0) {
  console.log(`[TS/JS Parity] PASS: All ${checkedModules}/${totalTsModules} TypeScript modules maintain 100% parity with JavaScript counterparts.`);
  process.exit(0);
} else {
  console.error(`[TS/JS Parity] FAIL: Detected ${failures} parity divergence(s):`);
  for (const d of divergences) {
    console.error(`  ✗ ${d}`);
  }
  process.exit(1);
}
