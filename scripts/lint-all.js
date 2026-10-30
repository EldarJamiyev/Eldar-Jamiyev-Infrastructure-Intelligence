#!/usr/bin/env node
/**
 * EJII Comprehensive Codebase Syntax & Integrity Linter
 * Performs AST syntax validation across all production JavaScript files.
 */

'use strict';

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

function walkJs(dir) {
  let list = [];
  if (!fs.existsSync(dir)) return list;
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name === 'node_modules' || e.name === '.git' || e.name === '.playwright-cli') continue;
    const p = path.join(dir, e.name);
    if (e.isDirectory()) list = list.concat(walkJs(p));
    else if (e.name.endsWith('.js')) list.push(p);
  }
  return list;
}

const targetDirs = ['src', 'bin', 'desktop', 'mobile'];
const jsFiles = targetDirs.flatMap((d) => walkJs(d));

console.log(`[EJII Linter] Validating syntax across ${jsFiles.length} JavaScript source files...`);

let failed = 0;
for (const f of jsFiles) {
  try {
    execSync(`node --check "${f}"`, { stdio: 'pipe' });
  } catch (err) {
    console.error(`[SYNTAX ERROR] in ${f}:`, err.stderr ? err.stderr.toString().trim() : err.message);
    failed++;
  }
}

if (failed === 0) {
  console.log(`[EJII Linter] PASS: All ${jsFiles.length} production JavaScript files passed syntax verification.`);
  process.exit(0);
} else {
  console.error(`[EJII Linter] FAIL: ${failed} files failed syntax verification.`);
  process.exit(1);
}
