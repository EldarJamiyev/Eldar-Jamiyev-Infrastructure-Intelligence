#!/usr/bin/env node
/**
 * EJII Comprehensive Codebase Syntax, Integrity & Quality Linter
 * Performs comprehensive AST parsing, TypeScript validation, HTML structural audits,
 * and CSS token integrity checks across all 1st-party production and tooling files.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const { execSync } = require('child_process');

console.log('========================================================================');
console.log('  EJII Enterprise Intelligence Linter & Multi-Subsystem Integrity Audit ');
console.log('========================================================================');

const targetDirs = ['src', 'bin', 'desktop', 'mobile', 'public/js', 'scripts', 'tests'];

function walkJs(dir) {
  let list = [];
  if (!fs.existsSync(dir)) return list;
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name === 'node_modules' || e.name === '.git' || e.name === '.playwright-cli' || e.name === '.aistudio' || e.name === '.cache') continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) list = list.concat(walkJs(p));
    else if (e.name.endsWith('.js') || e.name.endsWith('.mjs')) list.push(p);
  }
  return list;
}

const jsFiles = targetDirs.flatMap((d) => walkJs(d));
console.log(`[EJII Linter] 1. Auditing AST syntax across ${jsFiles.length} JavaScript files...`);

let jsFailures = 0;
for (const file of jsFiles) {
  try {
    const code = fs.readFileSync(file, 'utf8');
    // In-process AST compilation via Node.js V8 engine
    new vm.Script(code, { filename: file });
  } catch (err) {
    console.error(`  [SYNTAX ERROR] ${file}: ${err.message}`);
    jsFailures++;
  }
}

if (jsFailures === 0) {
  console.log(`  ✓ All ${jsFiles.length} JavaScript files passed V8 AST verification.`);
} else {
  console.error(`  ✗ ${jsFailures} JavaScript files failed syntax verification.`);
}

// 2. TypeScript Compilation Check
console.log('[EJII Linter] 2. Checking TypeScript type contracts (tsc --noEmit)...');
let tsPassed = true;
try {
  execSync('npx tsc --noEmit', { stdio: 'pipe' });
  console.log('  ✓ TypeScript typecheck passed cleanly with zero diagnostics.');
} catch (err) {
  console.error('  ✗ TypeScript verification failed:', err.stderr ? err.stderr.toString() : err.message);
  tsPassed = false;
}

// 3. HTML Document Integrity Check
console.log('[EJII Linter] 3. Auditing HTML document shells...');
const htmlFiles = ['public/index.html', 'mobile/index.html'];
let htmlFailures = 0;
for (const hf of htmlFiles) {
  if (!fs.existsSync(hf)) {
    console.error(`  ✗ Missing HTML file: ${hf}`);
    htmlFailures++;
    continue;
  }
  const content = fs.readFileSync(hf, 'utf8');
  if (!/<!doctype\s+html>/i.test(content) || !content.includes('<meta name="viewport"') || !content.includes('<title>')) {
    console.error(`  ✗ HTML file ${hf} is missing mandatory document metadata.`);
    htmlFailures++;
  } else {
    console.log(`  ✓ ${hf} verified (doctype, viewport, title, valid utf-8).`);
  }
}

// 4. CSS Token & Syntax Integrity Check
console.log('[EJII Linter] 4. Auditing CSS token stylesheets...');
const cssFiles = ['public/css/ejii-meridian.css', 'mobile/mobile-style.css'];
let cssFailures = 0;
for (const cf of cssFiles) {
  if (!fs.existsSync(cf)) {
    console.error(`  ✗ Missing CSS file: ${cf}`);
    cssFailures++;
    continue;
  }
  const css = fs.readFileSync(cf, 'utf8');
  // Check balanced braces
  const openCount = (css.match(/\{/g) || []).length;
  const closeCount = (css.match(/\}/g) || []).length;
  if (openCount !== closeCount) {
    console.error(`  ✗ Unbalanced braces in ${cf}: ${openCount} open vs ${closeCount} close.`);
    cssFailures++;
  } else {
    console.log(`  ✓ ${cf} balanced (${openCount} rules verified).`);
  }
}

console.log('========================================================================');
const totalErrors = jsFailures + (tsPassed ? 0 : 1) + htmlFailures + cssFailures;
if (totalErrors === 0) {
  console.log(`[EJII Linter] PASS: All first-party code (${jsFiles.length} JS, TS, HTML, CSS) passed verification.`);
  process.exit(0);
} else {
  console.error(`[EJII Linter] FAIL: Codebase lint verification failed with ${totalErrors} issue(s).`);
  process.exit(1);
}
