#!/usr/bin/env node
// Opens a rendered page in a browser and reports what a reader would hit: errors, sideways scrolling,
// diagram labels under 12 px, and whether the kit's script ran. Exit 0 when clean, 1 on a problem, 2 when it cannot check.
// playwright-core is an optional peer, as for videos.
import { createRequire } from "node:module";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const WIDTHS = [390, 1280];
const MIN_LABEL = 12;

async function launch() {
  let chromium;
  try {
    ({ chromium } = await import("playwright-core"));
  } catch (e) {
    if (e.code !== "ERR_MODULE_NOT_FOUND") throw e;
    // import() never looks in global installs, so it goes beside the plugin
    const plugin = dirname(dirname(fileURLToPath(import.meta.url)));
    console.error(`kit/check.mjs needs playwright-core. Run: npm install --no-save --prefix "${plugin}" playwright-core (in a repository checkout, npm install is enough).`);
    process.exit(2);
  }
  try {
    return await chromium.launch();
  } catch (e) {
    if (!/Executable doesn't exist/.test(e.message)) throw e;
    try {
      return await chromium.launch({ channel: "chrome" });
    } catch {
      const { version } = createRequire(import.meta.url)("playwright-core/package.json");
      console.error(`No browser found. Install Google Chrome, or run: npx playwright-core@${version} install chromium-headless-shell`);
      process.exit(2);
    }
  }
}

// Runs in the page: the smallest rendered SVG label, overflow, figure and prose counts, and the kit flag.
function measure(minLabel) {
  let smallest = null;
  for (const t of document.querySelectorAll("svg text")) {
    if (!t.textContent.trim() || !t.checkVisibility({ visibilityProperty: true })) continue;
    const m = t.getScreenCTM();
    if (!m) continue;
    const px = parseFloat(getComputedStyle(t).fontSize) * Math.hypot(m.a, m.b);
    if (!smallest || px < smallest.px) smallest = { px: Math.round(px * 100) / 100, text: t.textContent.trim().slice(0, 40) };
  }
  let prose = 0;
  for (const p of document.querySelectorAll("p, li")) if (!p.closest("figure") && !p.parentElement.closest("p, li")) prose += p.textContent.trim().split(/\s+/).filter(Boolean).length;
  return {
    overflow: document.documentElement.scrollWidth > window.innerWidth,
    smallest,
    small: smallest !== null && smallest.px < minLabel,
    figures: document.querySelectorAll("figure").length,
    prose,
    kit: document.documentElement.dataset.veKit === "ready",
  };
}

async function main() {
  const argv = process.argv.slice(2);
  const file = argv.find((a) => !a.startsWith("-"));
  if (!file || !existsSync(file)) {
    console.error("usage: node check.mjs page.html [--json]");
    process.exit(2);
  }
  const browser = await launch();
  const result = { file: resolve(file), errors: [], widths: {} };
  try {
    for (const width of WIDTHS) {
      const page = await browser.newPage({ viewport: { width, height: 900 } });
      page.on("console", (m) => { if (m.type() === "error") result.errors.push(`console at ${width}px: ${m.text()}`); });
      page.on("pageerror", (e) => result.errors.push(`page error at ${width}px: ${e.message}`));
      await page.goto(pathToFileURL(resolve(file)).href, { waitUntil: "load" });
      await page.evaluate(() => document.fonts.ready);
      await page.waitForTimeout(300);
      result.widths[width] = await page.evaluate(measure, MIN_LABEL);
      await page.close();
    }
  } finally {
    await browser.close();
  }
  const at = result.widths[1280];
  const problems = [
    ...result.errors,
    ...WIDTHS.filter((w) => result.widths[w].overflow).map((w) => `the page scrolls sideways at ${w}px`),
    ...WIDTHS.filter((w) => result.widths[w].small).map((w) => `a diagram label renders at ${result.widths[w].smallest.px}px at ${w}px ("${result.widths[w].smallest.text}"); keep labels at ${MIN_LABEL}px or more`),
  ];
  result.problems = problems;
  if (argv.includes("--json")) console.log(JSON.stringify(result, null, 2));
  else {
    const smallest = WIDTHS.map((w) => `${result.widths[w].smallest?.px ?? "—"}px at ${w}`).join(", ");
    console.log(`${problems.length ? "✗" : "✓"} ${result.file}`);
    console.log(`  ${at.figures} figure${at.figures === 1 ? "" : "s"} · ${at.prose} prose words outside figures · smallest label ${smallest} · kit: ${at.kit ? "ran" : "not found"}`);
    for (const p of problems) console.log(`  ✗ ${p}`);
  }
  process.exit(problems.length ? 1 : 0);
}

main();
