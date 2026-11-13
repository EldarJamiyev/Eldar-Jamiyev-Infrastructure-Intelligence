# EJII Universal AI Agent Skills Ecosystem

Welcome to the **Eldar Jamiyev Infrastructure Intelligence (EJII)** Universal Agent Skills Ecosystem — a comprehensive, cryptographic-locked, multi-agent-compatible catalog of **986 specialized AI Agent Skills**.

---

## 1. Inventory & Ecosystem Architecture

| Metric | Count | Description |
| :--- | :---: | :--- |
| **Total Cataloged Packages** | **986** | Total indexed skill packages across all domains |
| **Newly Imported Packages** | **861** | Verified and safely migrated from upstream (`shahinkarimov/claude-skills`) |
| **Preserved Overlapping Suites** | **38** | Retained richer local packages (`gstack`, `gravitas`, `obra-superpowers`, etc.) |
| **EJII Sovereign Exclusives** | **73** | Project-specific infrastructure skills (`always-verify-gcp`, `data-throughput-accelerator`) |
| **Security Quarantined** | **14** | Metadata-only indexed; blocked from active unprivileged execution |
| **Pinned Upstream Commit** | `546f9c2d` | Locked in [`.agents/skills/upstream-skills-lock.json`](upstream-skills-lock.json) |

---

## 2. Infrastructure Intelligence Core Stack

The prioritized core skills governing EJII operations and SRE incident response:

| Skill Package | Category | Routing Tier | License | Focus & Capability |
| :--- | :--- | :---: | :--- | :--- |
| [gravitas](gravitas/SKILL.md) | `SPECIALIZED_AND_CREATIVE` | `TIER_0_CORE_GOVERNANCE` | EJII Sovereign License | > |
| [gravitas-highstakes](gravitas-highstakes/SKILL.md) | `SPECIALIZED_AND_CREATIVE` | `TIER_0_CORE_GOVERNANCE` | EJII Sovereign License | > |
| [gravitas-typescript](gravitas-typescript/SKILL.md) | `SPECIALIZED_AND_CREATIVE` | `TIER_0_CORE_GOVERNANCE` | EJII Sovereign License | > |
| [always-verify-gcp](always-verify-gcp/SKILL.md) | `GOOGLE_CLOUD_AND_DATA_PLATFORMS` | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License | A workflow skill for all Google Cloud resource management tasks (create, delete, modify). This skill ensures that the correct CLI tool (`gcloud`, `bq`, `gsutil`) is chosen and that its commands are verified against the latest official documentation before execution. |
| [gstack](gstack/SKILL.md) | `SPECIALIZED_AND_CREATIVE` | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard | Router for the gstack skill suite. (gstack) |
| [doubt-driven-development](doubt-driven-development/SKILL.md) | `CYBERSECURITY_AND_DEVSECOPS` | `TIER_0_CORE_GOVERNANCE` | EJII Sovereign License | Subjects every non-trivial decision to a fresh-context adversarial review before it stands. Use when you want every assumption cross-examined before proceeding, when stress-testing a plan for hidden failure modes, when correctness matters more than speed, when working in unfamiliar code, when stakes are high (production auth, security-sensitive logic, a high-stakes migration, irreversible operations), or any time a confident output would be cheaper to verify now than to debug later. |
| [constraint-driven-development](constraint-driven-development/SKILL.md) | `INFRASTRUCTURE_NETWORKING_SRE` | `TIER_0_CORE_GOVERNANCE` | EJII Sovereign License | Establishes a project's quality bar as a written contract and stops agents quietly lowering it. Interviews the user on which dimensions matter, supplies sane default thresholds when they have no number in mind, records everything in CONSTRAINTS.md, and watches the diff for a weakened bar — new @ts-ignore or eslint-disable suppressions, skipped or deleted tests, assertions stripped out, unimplemented stubs, thresholds edited down. Use when no quality bar is written down, when the user says "set up constraints" or "define our standards", when the user wants dimensions they care about — accessibility, web performance, coverage — set up as enforced constraints, when an agent keeps silencing checks or skipping tests to get to green, when you need a coverage or performance threshold and don't know what number to pick, or when an agent writes more code than anyone will read. |
| [source-driven-development](source-driven-development/SKILL.md) | `FRONTEND_AND_DESIGN_SYSTEMS` | `TIER_0_CORE_GOVERNANCE` | EJII Sovereign License | Grounds every implementation decision in official documentation. Use when you want to verify an approach against the official docs before implementing it, or when you want authoritative, source-cited code free from outdated patterns. Use when building with any framework or library where correctness matters. |
| [security-review](security-review/SKILL.md) | `CYBERSECURITY_AND_DEVSECOPS` | `TIER_0_CORE_GOVERNANCE` | EJII Sovereign License | Use this skill when adding authentication, handling user input, working with secrets, creating API endpoints, or implementing payment/sensitive features. Provides comprehensive security checklist and patterns. |
| [verification-before-completion](verification-before-completion/SKILL.md) | `HARNESS_AND_AGENTIC_SYSTEMS` | `TIER_0_CORE_GOVERNANCE` | Open Agent Skills Standard | Use when about to claim work is complete, fixed, or passing, before committing or creating PRs - requires running verification commands and confirming output before making any success claims; evidence before assertions always |
| [data-throughput-accelerator](data-throughput-accelerator/SKILL.md) | `MOBILE_DEVELOPMENT` | `TIER_2_ON_DEMAND` | EJII Sovereign License | Diagnose and accelerate large data movement — ingestion, backfill, export, ETL, warehouse loading, manifest catch-up, and table synchronization — by isolating the true bottleneck, benchmarking variants, and codifying the fastest path with a hard accounting block proving rows and timestamps cohere. Use when a pipeline or backfill is too slow and must get faster without losing data correctness. |
| [database-schema-validator](database-schema-validator/SKILL.md) | `BACKEND_AND_CLOUD_NATIVE` | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License | Validates SQL schema files for compliance with internal safety and naming policies. |
| [systematic-debugging](systematic-debugging/SKILL.md) | `HARNESS_AND_AGENTIC_SYSTEMS` | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard | Use when encountering any bug, test failure, or unexpected behavior, before proposing fixes |
| [observability-and-instrumentation](observability-and-instrumentation/SKILL.md) | `INFRASTRUCTURE_NETWORKING_SRE` | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License | Instruments code so production behavior is visible and diagnosable. Use when adding logging, metrics, tracing, or alerting. Use when shipping any feature that runs in production and you need evidence it works. Use when production issues are reported but you can't tell what happened from the available data. |
| [ci-cd-and-automation](ci-cd-and-automation/SKILL.md) | `FRONTEND_AND_DESIGN_SYSTEMS` | `TIER_2_ON_DEMAND` | EJII Sovereign License | Automates CI/CD pipeline setup. Use when setting up or modifying build and deployment pipelines. Use when you need to automate quality gates, configure test runners in CI, or establish deployment strategies. |
| [mcp-builder](mcp-builder/SKILL.md) | `FRONTEND_AND_DESIGN_SYSTEMS` | `TIER_2_ON_DEMAND` | Open Agent Skills Standard | Guide for creating high-quality MCP (Model Context Protocol) servers that enable LLMs to interact with external services through well-designed tools. Use when building MCP servers to integrate external APIs or services, whether in Python (FastMCP) or Node/TypeScript (MCP SDK). |
| [codebase-design](codebase-design/SKILL.md) | `FRONTEND_AND_DESIGN_SYSTEMS` | `TIER_2_ON_DEMAND` | Open Agent Skills Standard | Shared vocabulary for designing deep modules. Use when the user wants to design or improve a module's interface, find deepening opportunities, decide where a seam goes, make code more testable or AI-navigable, or when another skill needs the deep-module vocabulary. |
| [kubernetes](kubernetes/SKILL.md) | `CYBERSECURITY_AND_DEVSECOPS` | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard | K8s manifests, Helm charts, pod autoscaling, ingress, secrets, deployment strategies |
| [gcp-composer-troubleshooting](gcp-composer-troubleshooting/SKILL.md) | `GOOGLE_CLOUD_AND_DATA_PLATFORMS` | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 | Provides expert guidance for troubleshooting Cloud Composer (Apache |
| [google-cloud-storage-basics](google-cloud-storage-basics/SKILL.md) | `GOOGLE_CLOUD_AND_DATA_PLATFORMS` | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 | >- |

---

## 3. Tiered Context Profiles

EJII avoids context-window saturation through a 4-tier loading strategy defined in [`.agents/skill-profiles.json`](../skill-profiles.json):

- **Tier 0: Core Governance & Invariant Enforcement** (Always Active)
  - `gravitas`, `gravitas-highstakes`, `doubt-driven-development`, `security-review`, `verification-before-completion`.
- **Tier 1: Infrastructure, SRE & Cloud Core** (Active for Engineering Tasks)
  - SRE incident response, Google Cloud, BigQuery, Kubernetes, Docker, and backend architecture.
- **Tier 2: On-Demand Workflows** (Loaded Dynamically)
  - Frontend, mobile, design systems, browser automation, and computational biology.
- **Tier 3: Dormant Catalog** (Explicit Invocation Only)
  - Creative engineering, game dev, 3D graphics, media, and marketing tools.

---

## 4. Multi-Agent Setup & Tooling

Connect the skill ecosystem to your preferred AI coding harness:

### PowerShell (Windows):
```powershell
# Setup all harnesses (Claude, Cursor, Codex, Antigravity)
.\scripts\setup-agent-skills.ps1 -Agent all

# Target specific harness in dry-run mode
.\scripts\setup-agent-skills.ps1 -Agent claude -DryRun
```

### Bash (macOS / Linux / WSL):
```bash
# Setup all harnesses
./scripts/setup-agent-skills.sh --agent all

# Target Cursor IDE only
./scripts/setup-agent-skills.sh --agent cursor
```

---

## 5. Categorized Skill Directory

### Networking, Infrastructure Diagnostics & SRE (39 skills)

| Skill Name | Description | Routing Tier | License |
| :--- | :--- | :---: | :--- |
| [ads-microsoft](ads-microsoft/SKILL.md) | Microsoft/Bing Ads deep analysis covering search, Performance Max, Audience Network, and Copilot integration. Evaluates 24 checks with focus | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [ads-youtube](ads-youtube/SKILL.md) | YouTube Ads specific analysis covering campaign types, creative quality, audience targeting, and measurement. Evaluates video ad performance | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [ai-memory-handoff](ai-memory-handoff/SKILL.md) | Use this skill for any request whose goal is session continuity across agents or time: finding a pending handoff, resuming previous work, re | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [ai-memory-messaging](ai-memory-messaging/SKILL.md) | Use this skill for cross-project agent-to-agent messaging: sending a request to another project's inbox, checking or popping this project's  | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [anthropics-agent-toolkits](anthropics-agent-toolkits/SKILL.md) | Official agentic runtime toolkits for low-level OS environments, bash/powershell controls, POSIX filesystem operations, and sub-process stre | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License |
| [anthropics-skills](anthropics-skills/SKILL.md) | Official agentic runtime toolkits for low-level OS environments, bash/powershell controls, POSIX filesystem operations, and sub-process stre | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License |
| [anti-ui-slop](anti-ui-slop/SKILL.md) | Stop coding agents from shipping generic UI. Extend the product's design system, use UIZZE evidence only when useful, cover required states, | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License |
| [architecture-review](architecture-review/SKILL.md) | Traceability matrix mapping GDD requirements to ADRs. Finds gaps, cross-ADR conflicts, engine compatibility. PASS/CONCERNS/NOT ASSESSED/FAIL | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [bigquery-observability](bigquery-observability/SKILL.md) | >- | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 |
| [brainstorm](brainstorm/SKILL.md) | Guides the user through finding and choosing a game concept. Use when the user wants game ideas, a new concept, a game jam idea, or to explo | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [browser-testing-with-devtools](browser-testing-with-devtools/SKILL.md) | Tests in real browsers via Chrome DevTools MCP. Use when building or debugging anything that runs in a browser. Use when you need to inspect | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License |
| [browser-use](browser-use/SKILL.md) | AI browser automation and stealth DOM interaction. Drives headless and headed browser workflows, interactive verification suites, and access | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [canvas-ui](canvas-ui/SKILL.md) | Creative Canvas UI component library with real HTML and WebGL/WebGPU effects running over it. Includes 35+ components (AsciiObject, GlassObj | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [career-ops](career-ops/SKILL.md) | Profile ingestion, CV analysis, and competency mapping. Maps technical backgrounds and skill proficiencies against SRE and network engineeri | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License |
| [chrome-devtools](chrome-devtools/SKILL.md) | Uses Chrome DevTools via MCP for efficient debugging, troubleshooting and browser automation. Use when debugging web pages, automating brows | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [constraint-driven-development](constraint-driven-development/SKILL.md) | Establishes a project's quality bar as a written contract and stops agents quietly lowering it. Interviews the user on which dimensions matt | `TIER_0_CORE_GOVERNANCE` | EJII Sovereign License |
| [craft-anything](craft-anything/SKILL.md) | Investigate how shipped software works (programs, apps, packages, firmware, web bundles) with evidence-backed answers through the Craft Anyt | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [dart-setup-ffi-assets](dart-setup-ffi-assets/SKILL.md) | Guides agents in compiling and packaging C/C++ source code into dynamic or static libraries (Code Assets) using Dart's Native Assets hook sy | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [deprecation-and-migration](deprecation-and-migration/SKILL.md) | Manages deprecation and migration. Use when removing old systems, APIs, or features. Use when migrating users from one implementation to ano | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License |
| [documentation-and-adrs](documentation-and-adrs/SKILL.md) | Records decisions and documentation. Use when you need to document an architecture decision (ADR) or the reasoning behind a design choice, w | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License |
| [drawio-skill](drawio-skill/SKILL.md) | Create and edit draw.io/diagrams.net diagrams as editable `.drawio` files. Covers architecture, UML/ERD/sequence, BPMN, network, and swimlan | `TIER_1_INFRASTRUCTURE_CORE` | MIT |
| [flutter-add-widget-test](flutter-add-widget-test/SKILL.md) | Implement a component-level test using `WidgetTester` to verify UI rendering and user interactions (tapping, scrolling, entering text). Use  | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [flutter-implement-json-serialization](flutter-implement-json-serialization/SKILL.md) | Create model classes with `fromJson` and `toJson` methods using `dart:convert`. Use when manually mapping JSON keys to class properties for  | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [flutter-setup-declarative-routing](flutter-setup-declarative-routing/SKILL.md) | Configure `MaterialApp.router` using a package like `go_router` for advanced URL-based navigation. Use when developing web applications or m | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [gcp-spark-observability](gcp-spark-observability/SKILL.md) | >- | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 |
| [gemini-omni-flash-api](gemini-omni-flash-api/SKILL.md) | Use this skill for generative video editing, text-to-video, image- and video-referenced video generation, first-frame-to-video, first-and-la | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 (Google Cloud Open Source) |
| [google-maps-platform](google-maps-platform/SKILL.md) | A collection of skills for architecting and implementing production-ready code using Google Maps Platform APIs and SDKs for any map, place,  | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 |
| [gsap-frameworks](gsap-frameworks/SKILL.md) | Official GSAP skill for Vue, Svelte, and other non-React frameworks — lifecycle, scoping selectors, cleanup on unmount. Use when the user wa | `TIER_1_INFRASTRUCTURE_CORE` | MIT |
| [jev-ultrafast](jev-ultrafast/SKILL.md) | Ultra-fast browser automation agent built on browser-use. Operates on numbered page elements for rapid web scraping, testing, and UI navigat | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [lean-web-search](lean-web-search/SKILL.md) | Token-efficient web search/extraction via Brave, Tavily, DuckDuckGo (keyless) or SearXNG, keeping raw pages out of context. Use when fresh w | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [linkedin-hook](linkedin-hook/SKILL.md) | Write scroll-stopping LinkedIn post hooks (first 1-2 lines before "see more"). Use when the user wants a LinkedIn post, opening line, or hoo | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [observability](observability/SKILL.md) | OpenTelemetry, Grafana, Prometheus, structured logging, error tracking, distributed tracing | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [observability-and-instrumentation](observability-and-instrumentation/SKILL.md) | Instruments code so production behavior is visible and diagnosable. Use when adding logging, metrics, tracing, or alerting. Use when shippin | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License |
| [opendlss-nr](opendlss-nr/SKILL.md) | Vulkan & WebGPU reimplementation of NVIDIA DLSS 5 Neural Rendering network. Neural supersampling, temporal anti-aliasing, and real-time ray  | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [roblox-networking](roblox-networking/SKILL.md) | > | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [ruflo](ruflo/SKILL.md) | Multi-agent swarm orchestration & distributed workflow intelligence. Use when coordinating autonomous agent clusters, parallel task dispatch | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License |
| [schema-mapping](schema-mapping/SKILL.md) | >- | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 |
| [shipping-and-launch](shipping-and-launch/SKILL.md) | Prepares production launches. Use when preparing to deploy to production, or when asking what needs to be in place before shipping. Use when | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License |
| [uv-workflow](uv-workflow/SKILL.md) | Production UV unwrapping for seam placement, UV packing, texel density, UDIM, lightmap UVs, and modular UV layouts. Use when preparing meshe | `TIER_1_INFRASTRUCTURE_CORE` | MIT |

### Cybersecurity, DevSecOps & Security Auditing (79 skills)

| Skill Name | Description | Routing Tier | License |
| :--- | :--- | :---: | :--- |
| [a11y-debugging](a11y-debugging/SKILL.md) | Uses Chrome DevTools MCP for accessibility (a11y) debugging and auditing based on web.dev guidelines. Use when testing semantic HTML, ARIA l | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [accessibility](accessibility/SKILL.md) | Design, implement, and audit accessible UI to WCAG 2.2 Level AA across Web, iOS, and Android — semantic ARIA roles and labels, accessibility | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License |
| [addyosmani-agent-skills](addyosmani-agent-skills/SKILL.md) | Production engineering runtimes, enterprise security boundaries, and task-isolation pipelines for autonomous coding agents. Hardens EJII's l | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License |
| [adopt](adopt/SKILL.md) | Brownfield audit — do existing artifacts actually work? Numbered migration plan. Unlike /project-stage-detect, checks compliance not existen | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [ads](ads/SKILL.md) | Multi-platform paid advertising audit and optimization skill. Analyzes Google, Meta, YouTube, LinkedIn, TikTok, Microsoft, Apple, and Amazon | `TIER_1_INFRASTRUCTURE_CORE` | MIT |
| [ads-amazon](ads-amazon/SKILL.md) | Amazon Ads deep analysis covering Sponsored Products, Sponsored Brands (incl. Sponsored Brands Video), Sponsored Display (audiences + contex | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [ads-attribution](ads-attribution/SKILL.md) | Cross-platform attribution health audit covering AdAttributionKit (iOS view-through 24h post-impression, WWDC 2025 configurable windows), GA | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [ads-audit](ads-audit/SKILL.md) | Full multi-platform paid advertising audit with parallel subagent delegation. Analyzes Google Ads, Meta Ads, LinkedIn Ads, TikTok Ads, Micro | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [ads-create](ads-create/SKILL.md) | Campaign concept and copy brief generator for paid advertising. Reads brand-profile.json and optional audit results to produce structured ca | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [ads-creative](ads-creative/SKILL.md) | Cross-platform creative quality audit covering ad copy, video, image, and format diversity across all platforms. Detects creative fatigue, e | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [ads-google](ads-google/SKILL.md) | Google Ads deep analysis covering Search, Performance Max, AI Max, Display, YouTube, and Demand Gen campaigns. Evaluates 80 checks across co | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [ads-landing](ads-landing/SKILL.md) | Landing page quality assessment for paid advertising campaigns. Evaluates message match, page speed, mobile experience, trust signals, form  | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [ads-server-side-tracking](ads-server-side-tracking/SKILL.md) | Server-side tracking pipeline audit covering server-side Google Tag Manager (sGTM), Meta CAPI Gateway, Conversions API health, event dedupli | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| `agent-design` *(Quarantined Metadata)* | Design, audit and govern AI agents: architecture discovery, failure diagnosis, governance/permissions, evaluation loops, pre-execution actio | `TIER_1_INFRASTRUCTURE_CORE` | MIT |
| [agent-reach](agent-reach/SKILL.md) | Zero-fee local web research and threat intelligence scraper. Extracts and parses public security advisories, CVE databases, and IETF protoco | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License |
| [agentplay](agentplay/SKILL.md) | Visual session replay and debugging for AI coding agents. Replays every agent session as an interactive timeline map (files read/edited, too | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [ai-memory-learning-maintenance](ai-memory-learning-maintenance/SKILL.md) | Use this skill for any ai-memory knowledge-base maintenance request: consolidating observations, reviewing session lessons, proposing durabl | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [animate](animate/SKILL.md) | Build purposeful web animations with appropriate tools, easing, duration, interruption, exits, and reduced-motion support. | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [anthropic-cybersecurity](anthropic-cybersecurity/SKILL.md) | Comprehensive cybersecurity skills library mapped to 6 major frameworks: MITRE ATT&CK, NIST CSF 2.0, MITRE ATLAS, MITRE D3FEND, NIST AI RMF, | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [asset-audit](asset-audit/SKILL.md) | Audit assets against naming conventions, file size budgets, format standards. Finds orphaned assets, missing references. | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [atelier-web](atelier-web/SKILL.md) | Measured web checks via local CLI (axe-core + Chromium): WCAG accessibility audit, runtime UX audit, responsive AVIF/WebP image pipeline. Us | `TIER_1_INFRASTRUCTURE_CORE` | MIT |
| [auth-patterns](auth-patterns/SKILL.md) | JWT, OAuth2/OIDC, session management, refresh token rotation, PKCE, NextAuth/Auth.js | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| `careful` *(Quarantined Metadata)* | Safety guardrails for destructive commands. (gstack) | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [caveman-token-reduction](caveman-token-reduction/SKILL.md) | Token reduction proxy and linguistic root compression. Use when compressing massive raw multi-engine wire traces, PCAP streams, and telemetr | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License |
| [claude-config-hygiene](claude-config-hygiene/SKILL.md) | Keep the Claude setup lean and safe: clean stale skills/memory/hooks (confirm each), audit skills, review MCP configs, lint skills for porta | `TIER_1_INFRASTRUCTURE_CORE` | MIT |
| `cloudflare-security-audit` *(Quarantined Metadata)* | Security guidance and vulnerability review for codebases, APIs, services, CLI tools, libraries, and daemons. Use for security questions, foc | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [composio](composio/SKILL.md) | Route and complete Composio work across Composio For You and Composio Platform. Use when the user mentions Composio; wants an agent to use a | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [context-budget](context-budget/SKILL.md) | Routes live context checks to the native Codex or Claude Code meter without scanning files, and performs a bounded static component audit on | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License |
| [context-engineering](context-engineering/SKILL.md) | Optimizes agent context setup. Use when starting a new session, when agent output quality degrades, when switching between tasks, or when yo | `TIER_1_INFRASTRUCTURE_CORE` | MIT |
| [content-audit](content-audit/SKILL.md) | Audit GDD content counts against what's implemented — planned vs built. | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| `cso` *(Quarantined Metadata)* | Chief Security Officer mode. (gstack) | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [design-tokens](design-tokens/SKILL.md) | W3C design token format, CSS custom property system, Figma Token sync, theme generation | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [devex-review](devex-review/SKILL.md) | Live developer experience audit. (gstack) | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [diagram-design](diagram-design/SKILL.md) | Slop-free technical diagramming and layout engineering using native HTML, CSS, and clean SVG vectors without bulky dependencies or unstyled  | `TIER_1_INFRASTRUCTURE_CORE` | MIT |
| [doc-to-markdown](doc-to-markdown/SKILL.md) | Convert PDF, Word and Excel files to clean Markdown (uv + markitdown) before analysing or summarising them, saving tokens. Use when asked to | `TIER_1_INFRASTRUCTURE_CORE` | MIT |
| [doubt-driven-development](doubt-driven-development/SKILL.md) | Subjects every non-trivial decision to a fresh-context adversarial review before it stands. Use when you want every assumption cross-examine | `TIER_0_CORE_GOVERNANCE` | EJII Sovereign License |
| [extension-to-functions-codebase](extension-to-functions-codebase/SKILL.md) | Skill for converting an installed Firebase Extension (or extension source) into a standalone Cloud Functions for Firebase codebase or publis | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [firebase-ai-logic-basics](firebase-ai-logic-basics/SKILL.md) | Official skill for integrating Firebase AI Logic (Gemini API) into web applications. Covers setup, multimodal inference, structured output,  | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 (Google Cloud Open Source) |
| [firebase-security-rules-auditor](firebase-security-rules-auditor/SKILL.md) | >- | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 (Google Cloud Open Source) |
| `gcs-security-assessment` *(Quarantined Metadata)* | >- | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 |
| [gemini-live-api-dev](gemini-live-api-dev/SKILL.md) | Use this skill when building real-time, bidirectional streaming applications with the Gemini Live API, or migrating legacy Live models (2.0/ | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 (Google Cloud Open Source) |
| [git-guardrails-claude-code](git-guardrails-claude-code/SKILL.md) | Set up Claude Code hooks to block dangerous git commands (push, reset --hard, clean, branch -D, etc.) before they execute. Use when user wan | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [guard](guard/SKILL.md) | Full safety mode: destructive command warnings + directory-scoped edits. (gstack) | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [hotfix](hotfix/SKILL.md) | Emergency fix bypassing normal sprint process — hotfix branch, approvals tracked, backport verified, full audit trail. | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [impeccable](impeccable/SKILL.md) | Use when the user wants to design, redesign, shape, critique, audit, polish, simplify, harden, animate, or otherwise improve a frontend inte | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 |
| [improve-animations](improve-animations/SKILL.md) | Survey a codebase's animation and motion code as a senior motion advisor, then produce a prioritized audit and self-contained implementation | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [ios-design-review](ios-design-review/SKILL.md) | Visual design audit for iOS apps on real hardware. (gstack) | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [kubernetes](kubernetes/SKILL.md) | K8s manifests, Helm charts, pod autoscaling, ingress, secrets, deployment strategies | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [qa-review](qa-review/SKILL.md) | Production QA gate for Blender assets using viewport screenshots, validation checklists, naming audits, and ship/no-ship verdicts via MCP. | `TIER_1_INFRASTRUCTURE_CORE` | MIT |
| `mcp-security` *(Quarantined Metadata)* | Security-review MCP setups: audit .mcp.json for secrets/injection/unpinned packages, review MCP server source, QA a server before release. U | `TIER_1_INFRASTRUCTURE_CORE` | MIT |
| [nextlevelbuilder-ui-ux-pro-max](nextlevelbuilder-ui-ux-pro-max/SKILL.md) | Production UI refinement and quiet luxury styling. Strips visual clutter, ensures 60fps rendering, and enforces EJII's Quiet Luxury Meridian | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License |
| [owasp-top10](owasp-top10/SKILL.md) | OWASP Top 10 vulnerability fixes — SQLi, XSS, CSRF, SSRF, path traversal, broken auth | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [pentest-web](pentest-web/SKILL.md) | Web application penetration testing methodology — recon, IDOR, auth bypass, authorized testing | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [ponytail-audit](ponytail-audit/SKILL.md) | > | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [pptx-html-fidelity-audit](pptx-html-fidelity-audit/SKILL.md) | Audit a python-pptx export against its source HTML deck, identify layout/content drift (footer overflow, cropped content, missing italic/em, | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [refero-styles](refero-styles/SKILL.md) | Curated collection of 30+ production DESIGN.md specifications, design tokens, and Tailwind v4 themes extracted from real premier brands (Ant | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [secrets-management](secrets-management/SKILL.md) | .env audit, secret rotation, leaked key detection + revoke, CI/CD secrets | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [security-and-hardening](security-and-hardening/SKILL.md) | Hardens code against vulnerabilities. Use when auditing an input handler for vulnerabilities, when handling user input, authentication, data | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License |
| `security-audit` *(Quarantined Metadata)* | Security guidance and vulnerability review for codebases, APIs, services, CLI tools, libraries, and daemons. Use for security questions, foc | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [security-bounty-hunter](security-bounty-hunter/SKILL.md) | Hunt for exploitable, bounty-worthy security issues in repositories. Focuses on remotely reachable vulnerabilities that qualify for real rep | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License |
| [security-review](security-review/SKILL.md) | Use this skill when adding authentication, handling user input, working with secrets, creating API endpoints, or implementing payment/sensit | `TIER_0_CORE_GOVERNANCE` | EJII Sovereign License |
| `security-threat-model` *(Quarantined Metadata)* | Repository-grounded threat modeling that enumerates trust boundaries, assets, attacker capabilities, abuse paths, and mitigations, and write | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 |
| [seo-technical-audit](seo-technical-audit/SKILL.md) | \| | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [skill-test](skill-test/SKILL.md) | Validate skill files for structural compliance and behavioral correctness. Four modes: static linter, spec, category rubric, audit. | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [test-flakiness](test-flakiness/SKILL.md) | Find flaky tests from CI logs — aggregates pass rates, spots intermittent failures, recommends quarantine. After multiple runs. | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| `tob-code-audit` *(Quarantined Metadata)* | Trail of Bits audit methods: understand code first, security differential review of diffs/PRs, false-positive verification, GitHub Actions A | `TIER_1_INFRASTRUCTURE_CORE` | CUSTOM_PERMISSIVE |
| [token-budget-advisor](token-budget-advisor/SKILL.md) | Offer a choice of response depth (25%/50%/75%/100%) with token estimates before answering, then answer at that level. Use when the user asks | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License |
| [token-card](token-card/SKILL.md) | Render a token-usage stat card from local Claude Code, Codex, Gemini CLI, and OpenCode session logs and commit it into the repository as a f | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License |
| [token-economizer-config](token-economizer-config/SKILL.md) | > | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [token-economizer-microskills](token-economizer-microskills/SKILL.md) | > | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [token-economizer-repos](token-economizer-repos/SKILL.md) | > | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [token-economizer-status](token-economizer-status/SKILL.md) | > | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [token-economizer-toolprune](token-economizer-toolprune/SKILL.md) | > | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [vercel-cli-with-tokens](vercel-cli-with-tokens/SKILL.md) | Deploy and manage projects on Vercel using token-based authentication. Use when working with Vercel CLI using access tokens rather than inte | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [verification-loop](verification-loop/SKILL.md) | Run a six-phase verification of a Claude Code session's work — build, type check, lint, tests with coverage, security grep, and diff review  | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License |
| [web-design-guidelines](web-design-guidelines/SKILL.md) | Review UI code for Web Interface Guidelines compliance. Use when asked to "review my UI", "check accessibility", "audit design", "review UX" | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [web-quality](web-quality/SKILL.md) | Audit websites for performance, Core Web Vitals, accessibility, SEO and best practices, with a read-only HTML analyzer. Use to speed up a si | `TIER_1_INFRASTRUCTURE_CORE` | MIT |
| [wizard](wizard/SKILL.md) | Generate an interactive bash wizard that walks a human through steps only they can perform. Use when provisioning infrastructure, setting up | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [writing-guidelines](writing-guidelines/SKILL.md) | Review docs/prose for Writing Guidelines compliance. Use when asked to "review my docs", "check writing style", "audit prose", "review docs  | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |

### Google Cloud, BigQuery & Data Intelligence (42 skills)

| Skill Name | Description | Routing Tier | License |
| :--- | :--- | :---: | :--- |
| [always-verify-gcp](always-verify-gcp/SKILL.md) | A workflow skill for all Google Cloud resource management tasks (create, delete, modify). This skill ensures that the correct CLI tool (`gcl | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License |
| [antigravity-cli](antigravity-cli/SKILL.md) | Operate/delegate to the Google Antigravity CLI (agy): one-shot -p prompts for a Gemini second opinion, models, permissions, plugins, auth. U | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [bigquery-ai-ml](bigquery-ai-ml/SKILL.md) | >- | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 |
| [bigquery-bigframes](bigquery-bigframes/SKILL.md) | >- | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 |
| [bigquery-data-transfer-service](bigquery-data-transfer-service/SKILL.md) | Discovers and inspects BigQuery Data Transfer Service (DTS) configurations. | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 |
| [bigquery-graph-author](bigquery-graph-author/SKILL.md) | >- | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 |
| [bigquery-graph-query](bigquery-graph-query/SKILL.md) | >- | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 |
| [bigquery-optimization](bigquery-optimization/SKILL.md) | >- | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 |
| [bigquery-troubleshooting](bigquery-troubleshooting/SKILL.md) | >- | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 |
| [bigtable-basics](bigtable-basics/SKILL.md) | >- | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 |
| [dak-setup](dak-setup/SKILL.md) | Configures (or reconfigures) the Google Cloud Data Agent Kit (DAK) plugin by checking gcloud and ADC credentials, collecting the GCP project | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 |
| [data-autocleaning](data-autocleaning/SKILL.md) | Automated data quality and transformation capabilities for Dataform/dbt/BigQuery | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 |
| [dataform-bigquery](dataform-bigquery/SKILL.md) | Expertise in generating clean, correct, and efficient Dataform pipeline | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 |
| [dbt-bigquery](dbt-bigquery/SKILL.md) | Expert guidance for creating, modifying, and optimizing dbt pipelines | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 |
| [discovering-gcp-data-assets](discovering-gcp-data-assets/SKILL.md) | \| | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 |
| [firebase-app-hosting-basics](firebase-app-hosting-basics/SKILL.md) | >- | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 (Google Cloud Open Source) |
| [firebase-auth-basics](firebase-auth-basics/SKILL.md) | Guide for setting up and using Firebase Authentication. Use this skill when the user's app requires user sign-in, user management, or secure | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 (Google Cloud Open Source) |
| [firebase-basics](firebase-basics/SKILL.md) | >- | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 (Google Cloud Open Source) |
| [firebase-crashlytics](firebase-crashlytics/SKILL.md) | Comprehensive guide for Firebase Crashlytics, including provisioning and SDK usage. Use this skill when the user needs help setting up Crash | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 (Google Cloud Open Source) |
| [firebase-data-connect](firebase-data-connect/SKILL.md) | Builds and deploys Firebase SQL Connect (aka Firebase Data Connect) backends with PostgreSQL securely. Use when designing schemas with table | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 (Google Cloud Open Source) |
| [firebase-firestore](firebase-firestore/SKILL.md) | >- | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 (Google Cloud Open Source) |
| [firebase-hosting-basics](firebase-hosting-basics/SKILL.md) | >- | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 (Google Cloud Open Source) |
| [firebase-remote-config-basics](firebase-remote-config-basics/SKILL.md) | >- | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 (Google Cloud Open Source) |
| [gcp-composer-troubleshooting](gcp-composer-troubleshooting/SKILL.md) | Provides expert guidance for troubleshooting Cloud Composer (Apache | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 |
| [gcp-data-pipelines](gcp-data-pipelines/SKILL.md) | Primary entry point for building, managing, and orchestrating data pipelines | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 |
| [gcp-dataflow](gcp-dataflow/SKILL.md) | > | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 |
| [gcp-managed-airflow-dag-authoring](gcp-managed-airflow-dag-authoring/SKILL.md) | Guides the authoring and validation of Apache Airflow DAGs for Managed Service for Apache Airflow (MSAA; formerly Cloud Composer). Covers en | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 |
| [gcp-managed-airflow-migrations](gcp-managed-airflow-migrations/SKILL.md) | Provides guidance for migrating Apache Airflow DAGs in Managed Service for Apache Airflow (MSAA; formerly Cloud Composer). Covers migration  | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 |
| [gcp-managed-airflow-recommendations](gcp-managed-airflow-recommendations/SKILL.md) | Provides recommendations and best practices for creating, configuring, tuning and optimizing Managed Service for Apache Airflow (MSAA, Cloud | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 |
| [gcp-managed-spark-upgrades](gcp-managed-spark-upgrades/SKILL.md) | \| | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 |
| [gcp-pipeline-orchestration](gcp-pipeline-orchestration/SKILL.md) | This skill helps the agent generate or update orchestration pipeline | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 |
| [gcp-pipeline-resource-provisioning](gcp-pipeline-resource-provisioning/SKILL.md) | \| | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 |
| [gcp-spark](gcp-spark/SKILL.md) | \| | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 |
| [gcp-spark-troubleshooting](gcp-spark-troubleshooting/SKILL.md) | Provides expert guidance for troubleshooting Google Cloud Spark and Dataproc workloads (Dataproc Serverless batches and standard Dataproc cl | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 |
| [gemini-api](gemini-api/SKILL.md) | Build with the Google Gemini API: text, chat, multimodal, tools, structured output, Live API voice/video, Omni Flash video. Use when code ca | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 (Google Cloud Open Source) |
| [gemini-api-dev](gemini-api-dev/SKILL.md) | Use this skill when writing code that calls the Gemini API for text generation, multi-turn chat, multimodal understanding, image generation, | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 (Google Cloud Open Source) |
| `google-cloud-storage-basics` *(Quarantined Metadata)* | >- | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 |
| `google-cloud-storage-bucket-architect` *(Quarantined Metadata)* | >- | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 |
| [google-cloud-storage-fuse](google-cloud-storage-fuse/SKILL.md) | >- | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 |
| [xcode-project-setup](xcode-project-setup/SKILL.md) | Safely modifies Xcode projects (.pbxproj) to add Swift Packages and link files. Use this skill whenever an iOS project needs dependencies in | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [real-sound](real-sound/SKILL.md) | Build premium, realistic soundtracks for code-made videos and animations from real licensed recordings - launch films, product and feature v | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [terraform-iac](terraform-iac/SKILL.md) | Terraform HCL patterns, state management, modules, AWS/GCP resource provisioning | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |

### Backend Architecture, Cloud-Native & Databases (75 skills)

| Skill Name | Description | Routing Tier | License |
| :--- | :--- | :---: | :--- |
| [ads-apple](ads-apple/SKILL.md) | Apple Ads (formerly Apple Search Ads) deep analysis for mobile app advertisers. Evaluates campaign structure, bid health, Custom Product Pag | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [ads-plan](ads-plan/SKILL.md) | Strategic paid advertising planning with industry-specific templates. Covers platform selection, campaign architecture, budget planning, cre | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [ai-evals](ai-evals/SKILL.md) | LLM evaluation — RAGAS, LLM-as-judge, benchmark creation, regression tracking | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [alphafold-database-fetch-and-analyze](alphafold-database-fetch-and-analyze/SKILL.md) | > | `TIER_1_INFRASTRUCTURE_CORE` | Open Science Permissive (DeepMind/NCBI) |
| [api-and-interface-design](api-and-interface-design/SKILL.md) | Guides stable API and interface design. Use when designing APIs, module boundaries, or any public interface. Use when creating REST or Graph | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License |
| [api-design](api-design/SKILL.md) | REST API design patterns including resource naming, status codes, pagination, filtering, error responses, versioning, and rate limiting for  | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License |
| [apple-design](apple-design/SKILL.md) | Apple's approach to interface design and fluid, physical motion, translated for the web. Use when building or reviewing gesture-driven UI, s | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [architecture-decision](architecture-decision/SKILL.md) | Create an ADR documenting a technical decision: context, alternatives considered, consequences. | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [awesome-llm-apps](awesome-llm-apps/SKILL.md) | Agent & RAG playbooks and multi-step orchestration workflows. Provides battle-tested patterns for hybrid retrieval, episodic memory indexing | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License |
| [backend-patterns](backend-patterns/SKILL.md) | Backend architecture patterns, API design, database optimization, and server-side best practices for Node.js, Express, and Next.js API route | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License |
| [brag](brag/SKILL.md) | Turn the current project website into a short, polished, shareable launch video using Hyperframes. Use when someone says "/brag", "let's bra | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [brag-slim](brag-slim/SKILL.md) | Turn a project directory or a website URL into a short, shareable launch video with music, motion, and share copy. One file, no bundled asse | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [brutalist-mood](brutalist-mood/SKILL.md) | Brutalist and concrete-monument mood direction for Blender architecture and scenes with raw concrete, monumental scale, and austere composit | `TIER_1_INFRASTRUCTURE_CORE` | MIT |
| [chembl-database](chembl-database/SKILL.md) | > | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [clinical-trials-database](clinical-trials-database/SKILL.md) | > | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [clinvar-database](clinvar-database/SKILL.md) | > | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [cloud-databases-onboarding](cloud-databases-onboarding/SKILL.md) | >- | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 |
| [create-architecture](create-architecture/SKILL.md) | Author the architecture blueprint before code is written. Validates decisions against the pinned engine, flags knowledge gaps. | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [create-epics](create-epics/SKILL.md) | Turns the GDDs and architecture into epics, one per architectural module. Use when the user wants to break the game into epics or plan the w | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [dart-collect-coverage](dart-collect-coverage/SKILL.md) | Collect coverage using the coverage packge and create an LCOV report | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [dart-generate-test-mocks](dart-generate-test-mocks/SKILL.md) | Define and generate mock objects for external dependencies using `package:mockito` and `build_runner`. Use when unit testing classes that de | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [database-design](database-design/SKILL.md) | PostgreSQL/MySQL schema design, Prisma migrations, index strategy, query optimization, N+1 fix | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [database-schema-validator](database-schema-validator/SKILL.md) | Validates SQL schema files for compliance with internal safety and naming policies. | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License |
| [dbsnp-database](dbsnp-database/SKILL.md) | > | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [docker-patterns](docker-patterns/SKILL.md) | Dockerfile best-practices, multi-stage builds, docker-compose, production hardening | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [encode-ccres-database](encode-ccres-database/SKILL.md) | > | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [ensembl-database](ensembl-database/SKILL.md) | > | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [environment-artist](environment-artist/SKILL.md) | AAA environment art for modular kits, buildings, terrain, vegetation, architecture, and scene composition. Use for game-optimized environmen | `TIER_1_INFRASTRUCTURE_CORE` | MIT |
| [fastapi-patterns](fastapi-patterns/SKILL.md) | FastAPI best practices covering project structure, Pydantic v2 schemas, dependency injection, async handlers, authentication, authorization, | `TIER_1_INFRASTRUCTURE_CORE` | MIT |
| [floorplan](floorplan/SKILL.md) | Draw a floorplan of an app's codebase (one repo or several side by side), an interactive node-graph map where every subsystem, module, file  | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [flutter-apply-architecture-best-practices](flutter-apply-architecture-best-practices/SKILL.md) | Architects a Flutter application using the recommended layered approach (UI, Logic, Data). Use when structuring a new project or refactoring | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [flutter-dart](flutter-dart/SKILL.md) | Official Flutter/Dart guidance: architecture, responsive layouts, go_router, localization, JSON, testing, layout fixes, static analysis, Dar | `TIER_1_INFRASTRUCTURE_CORE` | CUSTOM_PERMISSIVE |
| [gnomad-database](gnomad-database/SKILL.md) | > | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [graphify](graphify/SKILL.md) | Use for any question about a codebase, its architecture, file relationships, or project content — especially when graphify-out/ exists, wher | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [graphify-windows](graphify-windows/SKILL.md) | Use for any question about a codebase, its architecture, file relationships, or project content — especially when graphify-out/ exists, wher | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [graphql-api](graphql-api/SKILL.md) | GraphQL schema design, resolver patterns, N+1 DataLoader, subscriptions, type safety | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [gsap-plugins](gsap-plugins/SKILL.md) | Official GSAP skill for GSAP plugins — registration, ScrollToPlugin, ScrollSmoother, Flip, Draggable, Inertia, Observer, SplitText, Scramble | `TIER_1_INFRASTRUCTURE_CORE` | MIT |
| [gtex-database](gtex-database/SKILL.md) | > | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [human-protein-atlas-database](human-protein-atlas-database/SKILL.md) | > | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [improve-codebase-architecture](improve-codebase-architecture/SKILL.md) | Scan a codebase for deepening opportunities, present them as a visual HTML report, then grill through whichever one you pick. | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [interpro-database](interpro-database/SKILL.md) | > | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [jaspar-database](jaspar-database/SKILL.md) | > | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [queue-workers](queue-workers/SKILL.md) | BullMQ/RabbitMQ job queues, worker pools, retry logic, dead letter queue, priority jobs | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [quickgo-database](quickgo-database/SKILL.md) | > | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [landing-report](landing-report/SKILL.md) | Read-only queue dashboard for workspace-aware ship. (gstack) | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [langchain-agents](langchain-agents/SKILL.md) | Build agents and RAG with LangChain/LangGraph/Deep Agents: tools, middleware, persistence, human-in-the-loop, quickstarts. Use when designin | `TIER_1_INFRASTRUCTURE_CORE` | MIT |
| [liminal-space-style](liminal-space-style/SKILL.md) | Liminal space and Backrooms art direction for Blender with empty transitional architecture, wrong familiarity, and endless repetition. | `TIER_1_INFRASTRUCTURE_CORE` | MIT |
| [manim-video](manim-video/SKILL.md) | Production pipeline for mathematical and technical animations using Manim Community Edition. Creates 3Blue1Brown-style explainer videos, alg | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [monorepo-turborepo](monorepo-turborepo/SKILL.md) | Turborepo/NX monorepo setup, shared packages, build cache, workspace protocol | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [navbar-gallery](navbar-gallery/SKILL.md) | Curated navigation bar architecture, header patterns, and interactive menu systems inspired by navbar.gallery. Covers floating island navbar | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [openfda-database](openfda-database/SKILL.md) | > | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [opentargets-database](opentargets-database/SKILL.md) | > | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [pdb-database](pdb-database/SKILL.md) | > | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [pick-ui-library](pick-ui-library/SKILL.md) | Pick the right library for a given frontend task from a curated, opinionated list — numbers, OTP inputs, charts, command menus, virtualizati | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [propagate-design-change](propagate-design-change/SKILL.md) | Finds architecture decisions (ADRs) made stale by a changed GDD and walks through resolving each. Use when the user changed a number or rule | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [pubchem-database](pubchem-database/SKILL.md) | > | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [pubmed-database](pubmed-database/SKILL.md) | >- | `TIER_1_INFRASTRUCTURE_CORE` | Open Science Permissive (DeepMind/NCBI) |
| [rag-patterns](rag-patterns/SKILL.md) | Retrieval Augmented Generation — chunking, embedding, vector store, reranking, hybrid search | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [reactome-database](reactome-database/SKILL.md) | > | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [redis-patterns](redis-patterns/SKILL.md) | Redis cache strategy, pub/sub, rate limiting, session store, distributed locks | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [regression-suite](regression-suite/SKILL.md) | Map test coverage to GDD critical paths, find fixed bugs lacking regression tests, flag drift from new features. | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [reverse-document](reverse-document/SKILL.md) | Generate missing design or architecture docs from existing implementation — works backwards from code and prototypes. | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [scientific-agent-skills](scientific-agent-skills/SKILL.md) | Turn AI agents into AI Scientists. Unified scientific agent skill library covering computational biology, chemistry, genomics, medicine, ast | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [sql-optimization](sql-optimization/SKILL.md) | PostgreSQL EXPLAIN ANALYZE, index strategy, CTE, window functions, query optimization | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [stack-diagram](stack-diagram/SKILL.md) | Create cloud-architecture-style diagrams of tech stacks, system architectures, infra layouts, and service topologies — with real brand logos | `TIER_1_INFRASTRUCTURE_CORE` | MIT |
| [string-database](string-database/SKILL.md) | > | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [test-evidence-review](test-evidence-review/SKILL.md) | Quality review of test files and evidence — goes beyond existence, evaluates assertion coverage. ADEQUATE/INCOMPLETE/MISSING/NOT ASSESSED pe | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [typed-service-contracts](typed-service-contracts/SKILL.md) | Architecture standard for building robust, type-safe TypeScript services using the "Spec and Handler" pattern. Use when building CLIs, libra | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [unibind-database](unibind-database/SKILL.md) | >- | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [uniprot-database](uniprot-database/SKILL.md) | >- | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [vector-db](vector-db/SKILL.md) | ChromaDB/Pinecone/Weaviate — collection design, hybrid search, metadata filters | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [vertical-slice](vertical-slice/SKILL.md) | Pre-production validation — end-to-end build to confirm the full loop is achievable before committing to Production. After GDDs, architectur | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [websocket-realtime](websocket-realtime/SKILL.md) | WebSocket, SSE, Socket.io real-time patterns, connection management, reconnect logic | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [writing-fragments](writing-fragments/SKILL.md) | Writing, explore: mine raw fragments, no structure yet. | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [writing-shape](writing-shape/SKILL.md) | Writing, exploit: shape raw material into an article, paragraph by paragraph. | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |

### Harness Engineering & Multi-Agent Reliability (107 skills)

| Skill Name | Description | Routing Tier | License |
| :--- | :--- | :---: | :--- |
| [ads-budget](ads-budget/SKILL.md) | Budget allocation and bidding strategy review across all ad platforms. Evaluates spend distribution, bidding strategy appropriateness, scali | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [ads-linkedin](ads-linkedin/SKILL.md) | LinkedIn Ads deep analysis for B2B advertising. Evaluates 27 checks across technical setup, audience targeting, creative quality, lead gen f | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [ads-meta](ads-meta/SKILL.md) | Meta Ads deep analysis covering Facebook, Instagram, and Threads advertising in the Andromeda + GEM + Lattice era. Evaluates 50 checks acros | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [ads-tiktok](ads-tiktok/SKILL.md) | TikTok Ads deep analysis covering creative quality, tracking, bidding, campaign structure, and TikTok Shop under the TikTok USDS Joint Ventu | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [agent-dx-cli-scale](agent-dx-cli-scale/SKILL.md) | A scoring scale for evaluating how well a CLI is designed for AI agents, based on the "Rewrite Your CLI for AI Agents" principles. | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [agent-memory](agent-memory/SKILL.md) | Read and write the shared long-term memory store. Use before starting a task that | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [ai-memory-retrieval](ai-memory-retrieval/SKILL.md) | Use this skill for any request whose goal is read-only retrieval from ai-memory: project history, prior context, decisions, rules, gotchas,  | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [andrej-karpathy-skills](andrej-karpathy-skills/SKILL.md) | Karpathy Guidelines for epistemic honesty and lean engineering. Enforces the 4 core rules targeting over-engineering, speculative features,  | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License |
| [animation-performance](animation-performance/SKILL.md) | Diagnose dropped animation frames and choose properties, rendering paths, and profiling checks for smooth web motion. | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [autoplan](autoplan/SKILL.md) | Auto-review pipeline — reads the full CEO, design, eng, and DX review skills from disk and runs them sequentially with auto-decisions using  | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [awesome-harness-engineering](awesome-harness-engineering/SKILL.md) | Comprehensive harness engineering patterns for AI agents: sandbox isolation, deterministic verification, context trimming, test-driven self- | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [babysit-pr](babysit-pr/SKILL.md) | Monitor a pull request through review and CI. Use when the user asks to monitor, watch, or babysit a PR. | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [break-ui](break-ui/SKILL.md) | Try to break a piece of UI by feeding it worst-case data — long names, unbreakable emails, one-letter names, missing fields, huge counts, ze | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [browser-use-qa](browser-use-qa/SKILL.md) | QA-test a website or web app and return a 1-5 quality score (5 = flawless, 1 = broken) with evidence. Use when the user wants to test, QA, e | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [bug-triage](bug-triage/SKILL.md) | Re-evaluate open bugs — priority vs severity, assign to sprints, surface systemic trends. Run when the count grows. | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [chief-of-staff](chief-of-staff/SKILL.md) | Pursue a long-running goal in a single session by co-ordinating subagents. | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [claude-mem](claude-mem/SKILL.md) | Persistent cross-session episodic memory and vector recall system. Automatically captures project milestones, architectural decisions, and s | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License |
| [code-review](code-review/SKILL.md) | Review the changes since a fixed point (commit, branch, tag, or merge-base) along two axes: Standards (does the code follow this repo's docu | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [code-review-and-quality](code-review-and-quality/SKILL.md) | Conducts multi-axis code review. Use before merging any change. Use when reviewing code written by yourself, another agent, or a human. Use  | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License |
| [code-simplification](code-simplification/SKILL.md) | Simplifies code for clarity. Use when refactoring code for clarity without changing behavior. Use when code works but is harder to read, mai | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License |
| [compose-preview](compose-preview/SKILL.md) | Instructions for the Android Compose Preview sidecar, which renders Jetpack Compose @Preview functions with `android preview render` and sho | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [context-and-decisions](context-and-decisions/SKILL.md) | >- | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License |
| [context-restore](context-restore/SKILL.md) | Restore working context saved earlier by /context-save. (gstack) | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [context-save](context-save/SKILL.md) | Save working context. (gstack) | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [cookie-debugging](cookie-debugging/SKILL.md) | Uses Chrome DevTools MCP for inspecting, debugging, and testing cookies, session state, authentication issues, and cookie consent compliance | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [debug-optimize-lcp](debug-optimize-lcp/SKILL.md) | Guides debugging and optimizing Largest Contentful Paint (LCP) using Chrome DevTools MCP tools. Use this skill whenever the user asks about  | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [debugging-and-error-recovery](debugging-and-error-recovery/SKILL.md) | Guides systematic root-cause debugging. Use when tests fail, builds break, something that worked yesterday broke, behavior doesn't match exp | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License |
| [deploy-to-vercel](deploy-to-vercel/SKILL.md) | Deploy applications and websites to Vercel. Use when the user requests deployment actions like "deploy my app", "deploy and give me the link | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [design-consultation](design-consultation/SKILL.md) | Design consultation: understands your product, researches the landscape, proposes a complete design system (aesthetic, typography, color, la | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [design-review](design-review/SKILL.md) | Designer's eye QA: finds visual inconsistency, spacing issues, hierarchy problems, AI slop patterns, and slow interactions — then fixes them | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [design-taste-frontend](design-taste-frontend/SKILL.md) | tasteskill v2, the anti-slop frontend skill. Art direction for websites, distilled from a study of 247 curated gallery sites (One Page Love, | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [diagnosing-superpowers](diagnosing-superpowers/SKILL.md) | Use when a superpowers session went wrong and your human partner wants to know why — repeated work, ignored plans, stumbles, poor results, a | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [dispatching-parallel-agents](dispatching-parallel-agents/SKILL.md) | Use when facing 2+ independent tasks that can be worked on without shared state or sequential dependencies | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [doc-coauthoring](doc-coauthoring/SKILL.md) | Guide users through a structured workflow for co-authoring documentation. Use when user wants to write documentation, proposals, technical s | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License |
| [durable-harness](durable-harness/SKILL.md) | Vercel durable harness for AI coding agents. Runs Claude Code, Codex, Pi, fx as durable agents on Workflow SDK with crash resumption, event  | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [earshot](earshot/SKILL.md) | Listen with earshot whenever you must judge, choose, trim, verify or compare sound you cannot hear - picking a sound effect, music or ambien | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [executing-plans](executing-plans/SKILL.md) | Use when executing an implementation plan in the current session as the implementer yourself — your human partner chose inline execution, or | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [export-download-debugging](export-download-debugging/SKILL.md) | \| | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [export-pipeline](export-pipeline/SKILL.md) | Production export from Blender to FBX, GLTF, OBJ, USD, and Alembic with scale, pivot, rotation, normals, materials, animation, and collision | `TIER_1_INFRASTRUCTURE_CORE` | MIT |
| [ethos](ethos/SKILL.md) | Create, review or update an AI agent's ethos.md (purpose, boundaries, success criteria; 14 sections, script-validated). Use when defining an | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 |
| [fantasy-worlds](fantasy-worlds/SKILL.md) | Fantasy world-building art direction for Blender covering medieval, high fantasy, dark fantasy, and urban fantasy asset language. | `TIER_1_INFRASTRUCTURE_CORE` | MIT |
| [find-animation-opportunities](find-animation-opportunities/SKILL.md) | Search a codebase or UI for places that don't animate but should, and reject everything that shouldn't. Read-only; it proposes motion with e | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [flutter-add-widget-preview](flutter-add-widget-preview/SKILL.md) | Adds interactive widget previews to the project using the previews.dart system. Use when creating new UI components or updating existing scr | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [free-claude-code](free-claude-code/SKILL.md) | Multi-harness terminal engine connecting heterogeneous development environments and local terminals across operating systems. Enables cross- | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License |
| [game-design-review](game-design-review/SKILL.md) | Reviews one design document for completeness, internal consistency, implementability, and design standards. Before handing to programmers. | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [git-workflow-and-versioning](git-workflow-and-versioning/SKILL.md) | Structures git workflow practices. Use when making any code change. Use when committing, branching, resolving conflicts, splitting uncommitt | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License |
| [grill-me-codex](grill-me-codex/SKILL.md) | SUPERSEDED by /claudex-loop (formerly /crucible; adds a Phase 0 research/recon pass + rebuilt interview) — prefer that skill unless you expl | `TIER_1_INFRASTRUCTURE_CORE` | MIT |
| [grill-with-docs-codex](grill-with-docs-codex/SKILL.md) | SUPERSEDED by /claudex-loop (formerly /crucible; its docs-aware mode covers this variant) — prefer that skill unless you explicitly want thi | `TIER_1_INFRASTRUCTURE_CORE` | MIT |
| [gsap-react](gsap-react/SKILL.md) | Official GSAP skill for React — useGSAP hook, refs, gsap.context(), cleanup. Use when the user wants animation in React or Next.js, or asks  | `TIER_1_INFRASTRUCTURE_CORE` | MIT |
| [handoff](handoff/SKILL.md) | Compact the current conversation into a handoff document for another agent to pick up. | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [hatch-pet](hatch-pet/SKILL.md) | Create, repair, validate, preview, and package Codex-compatible animated pet spritesheets from character art, screenshots, generated images, | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 |
| [html-ppt-retro-quarterly-review](html-ppt-retro-quarterly-review/SKILL.md) | \| | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [i18n-sync](i18n-sync/SKILL.md) | Translate and synchronize application JSON locale files using source-key usage, project terminology, and focused validation. Use when adding | `TIER_1_INFRASTRUCTURE_CORE` | MIT |
| [investigate](investigate/SKILL.md) | Systematic debugging with root cause investigation. (gstack) | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [karpathy-guidelines](karpathy-guidelines/SKILL.md) | Behavioral guidelines to reduce common LLM coding mistakes. Use when writing, reviewing, or refactoring code to avoid overcomplication, make | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License |
| [leaving-pr-comments](leaving-pr-comments/SKILL.md) | Use whenever leaving comments on GitHub. | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [localize](localize/SKILL.md) | Localization pipeline — find hardcoded strings, extract string tables, cultural review, VO, RTL, enforce string freeze. | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [memory-leak-debugging](memory-leak-debugging/SKILL.md) | Diagnoses and resolves memory leaks in JavaScript/Node.js applications. Use when a user reports high memory usage, OOM errors, or wants to c | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [milestone-review](milestone-review/SKILL.md) | Milestone progress review — completeness, quality metrics, risk, go/no-go recommendation. At checkpoints or before a deadline. | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [mobile-native](mobile-native/SKILL.md) | Make a web app feel native on a phone — the small CSS and meta-tag fixes that separate "a website in a browser" from something that feels in | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [motionmaxxing](motionmaxxing/SKILL.md) | Direct and build professional motion-graphics films (launch videos, product promos, feature reveals, brand stings, kinetic-type pieces, soci | `TIER_1_INFRASTRUCTURE_CORE` | Apache-2.0 |
| [n8n-official](n8n-official/SKILL.md) | Official n8n workflow rules: expressions, Code nodes, node config, loops, sub-workflows, error handling, debugging, credentials, AI agents,  | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [obra-superpowers](obra-superpowers/SKILL.md) | Spec-driven multi-agent software engineering framework. Enforces rigorous brainstorming, formal specification drafting, subagent dispatch, a | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License |
| [openviking-memory](openviking-memory/SKILL.md) | Recall and persist long-term memory through the OpenViking MCP tools. Use at the start of any substantive task (coding, configuration, debug | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [openviking-rule-search](openviking-rule-search/SKILL.md) | Retrieve applicable OpenViking Rules and check compliance. Use when planning an action or response subject to task-specific constraints. | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [openviking-skills](openviking-skills/SKILL.md) | > | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [ov-experience-memory](ov-experience-memory/SKILL.md) | Retrieve and apply OpenViking Experience memories through the Agent runtime's generic OpenViking search and read tools. Use before or during | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [ov-kanban](ov-kanban/SKILL.md) | Work through tasks on a kanban board stored in OpenViking (viking://agent/kanban/<board>/, one markdown file per task). Use when the user sa | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [ov-memory-troubleshoot](ov-memory-troubleshoot/SKILL.md) | Diagnose OpenViking memory issues by tracing backward from a memory file to its archive memory_diff.json and, when needed, session messages. | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [ov-resources](ov-resources/SKILL.md) | Search and read documents, repos, URLs, and other resources stored in OpenViking under viking://resources/. Use whenever the user asks about | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [plan-ceo-review](plan-ceo-review/SKILL.md) | CEO/founder-mode plan review. (gstack) | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [plan-design-review](plan-design-review/SKILL.md) | Designer's eye plan review — interactive, like CEO and Eng review. (gstack) | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [plan-devex-review](plan-devex-review/SKILL.md) | Interactive developer experience plan review. (gstack) | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [plan-eng-review](plan-eng-review/SKILL.md) | Eng manager-mode plan review. (gstack) | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [ponytail-review](ponytail-review/SKILL.md) | > | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [pr-feedback-quality-gate](pr-feedback-quality-gate/SKILL.md) | \| | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [prompt-optimizer](prompt-optimizer/SKILL.md) | Analyze draft prompts, detect intent and missing context, match ECC commands, skills, and agents, and output a ready-to-paste optimized prom | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License |
| [receiving-code-review](receiving-code-review/SKILL.md) | Use when receiving code review feedback, before implementing suggestions, especially if feedback seems unclear or technically questionable - | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [requesting-code-review](requesting-code-review/SKILL.md) | Use when completing tasks, implementing major features, or before merging to verify work meets requirements | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [release-checklist](release-checklist/SKILL.md) | Pre-release checklist — build verification, certification requirements, store metadata, launch readiness. | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [remove-animations](remove-animations/SKILL.md) | Find the animations an interface doesn't need and remove them — motion on keyboard actions, high-frequency surfaces, functional data, and de | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [review](review/SKILL.md) | Pre-landing PR review. (gstack) | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [review-all-gdds](review-all-gdds/SKILL.md) | Holistic cross-GDD review — contradictions between systems, dominant strategies, economic imbalance, cognitive overload, pillar drift. | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [review-animations](review-animations/SKILL.md) | Reviews animation and motion code against a high craft bar derived from Emil Kowalski's design engineering philosophy. Default to flagging;  | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [ship](ship/SKILL.md) | Ship workflow: detect + merge base branch, run tests, review diff, bump VERSION, update CHANGELOG, commit, push, create PR. (gstack) | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [skill-creator](skill-creator/SKILL.md) | Create new skills, modify and improve existing skills, and measure skill performance. Use when users want to create a skill from scratch, ed | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License |
| [stop-slop](stop-slop/SKILL.md) | Remove AI writing patterns from prose. Use when drafting, editing, or reviewing text to eliminate predictable AI tells. | `TIER_1_INFRASTRUCTURE_CORE` | MIT |
| [strategic-compact](strategic-compact/SKILL.md) | Suggests manual context compaction at logical intervals to preserve context through task phases rather than arbitrary auto-compaction. Use w | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [subagent-driven-development](subagent-driven-development/SKILL.md) | Use when executing implementation plans with independent tasks in the current session | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [systematic-debugging](systematic-debugging/SKILL.md) | Use when encountering any bug, test failure, or unexpected behavior, before proposing fixes | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [taste-skill](taste-skill/SKILL.md) | Visual aesthetics, typography, and art direction enforcement for agentic UI design. Enforces quiet luxury design principles, eliminates visu | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [tdd](tdd/SKILL.md) | Test-driven development. Use when the user wants to build features or fix bugs test-first, mentions "red-green-refactor", or wants integrati | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [tdd-red-green-refactor](tdd-red-green-refactor/SKILL.md) | > | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [team-ui](team-ui/SKILL.md) | Orchestrate the UI team through the UX pipeline — authoring, visual design, implementation, review, polish. Uses /ux-design, /ux-review, stu | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [typescript-patterns](typescript-patterns/SKILL.md) | TypeScript patterns for strict, type-safe, maintainable code in modern TypeScript and JavaScript applications. Covers strict compiler config | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License |
| [ux-design](ux-design/SKILL.md) | Section-by-section UX spec authoring for a screen, flow or HUD. Reads the player journey to provide context; also project-wide accessibility | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [ux-review](ux-review/SKILL.md) | Validate a UX spec, HUD design or pattern library — accessibility, GDD alignment, readiness. APPROVED / NOT ASSESSED / NEEDS REVISION / MAJO | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [ui-animation](ui-animation/SKILL.md) | Implement, review, and measure UI motion. Reconstruct easing, springs and gestures from a recording using bundled frame extraction, tracking | `TIER_1_INFRASTRUCTURE_CORE` | MIT |
| [ui-ux-pro-max](ui-ux-pro-max/SKILL.md) | Comprehensive design guide for web and mobile applications. Use when designing new UI components or pages, choosing color palettes and typog | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [unbla](unbla/SKILL.md) | Antidote against Blind LLM Agent (BLA) prompt injection attacks, opaque predicates, Tarjan SCC labyrinths, and bankrupt context bloat. | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [using-git-worktrees](using-git-worktrees/SKILL.md) | Use when starting feature work that needs isolation from current workspace or before executing implementation plans - ensures an isolated wo | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [using-superpowers](using-superpowers/SKILL.md) | Use when starting any conversation - establishes how to find and use skills, requiring skill invocation before ANY response including clarif | `TIER_0_CORE_GOVERNANCE` | Open Agent Skills Standard |
| [vercel-react-best-practices](vercel-react-best-practices/SKILL.md) | React and Next.js performance optimization guidelines from Vercel Engineering. This skill should be used when writing, reviewing, or refacto | `TIER_1_INFRASTRUCTURE_CORE` | MIT |
| [verification-before-completion](verification-before-completion/SKILL.md) | Use when about to claim work is complete, fixed, or passing, before committing or creating PRs - requires running verification commands and  | `TIER_0_CORE_GOVERNANCE` | Open Agent Skills Standard |
| [webapp-testing](webapp-testing/SKILL.md) | Toolkit for interacting with and testing local web applications using Playwright. Supports verifying frontend functionality, debugging UI be | `TIER_1_INFRASTRUCTURE_CORE` | EJII Sovereign License |
| [weread-year-in-review-video-template](weread-year-in-review-video-template/SKILL.md) | \| | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |
| [write-swift](write-swift/SKILL.md) | How to write modern Swift well — modeling with value types, Swift 6 data-race safety and approachable concurrency (@concurrent, main-actor-b | `TIER_1_INFRASTRUCTURE_CORE` | Open Agent Skills Standard |

### UI/UX, Frontend Design & Motion Engineering (211 skills)

| Skill Name | Description | Routing Tier | License |
| :--- | :--- | :---: | :--- |
| [_gstack-command](_gstack-command/SKILL.md) | Router for the gstack skill suite. (gstack) | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [ads-dna](ads-dna/SKILL.md) | Brand DNA extractor for paid advertising. Scans a website URL to extract visual identity, tone of voice, color palette, typography, and imag | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [ads-generate](ads-generate/SKILL.md) | AI image generation for paid ad creatives. Reads campaign-brief.md and brand-profile.json to produce platform-sized ad images using banana-c | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [ads-math](ads-math/SKILL.md) | PPC financial calculator and modeling tool. CPA, ROAS, CPL calculations, break-even analysis, impression share opportunity sizing, budget fo | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [ads-photoshoot](ads-photoshoot/SKILL.md) | Product photography enhancement for ad creatives using banana-claude image generation. Takes a product image and generates 5 professional ph | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [ads-test](ads-test/SKILL.md) | A/B test design and experiment planning for paid advertising. Structured hypothesis framework, statistical significance calculator, test dur | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [anatomy](anatomy/SKILL.md) | Build crafted, highly detailed, interactive isometric SVG figures that explain a technical idea as a real physical object (a test rig, a dia | `TIER_2_ON_DEMAND` | MIT |
| [android-cli](android-cli/SKILL.md) | Provides instructions for installing and using the `android` CLI. The `android` command-line tool is a critical tool for Android development | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [animate-expo](animate-expo/SKILL.md) | Build animations in React Native and Expo, making the decisions in the order that determines whether they feel right — should it animate, wh | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [animated-shorts](animated-shorts/SKILL.md) | Make a ~55-70 s vertical cartoon story short in the "2D characters in a colourful 3D world" style (flat bean-head cartoon cards with ink out | `TIER_2_ON_DEMAND` | MIT |
| [animation](animation/SKILL.md) | Game-ready animation in Blender including walk/run/idle cycles, combat, mechanical animation, camera animation, constraints, Graph Editor, a | `TIER_2_ON_DEMAND` | MIT |
| [animation-vocabulary](animation-vocabulary/SKILL.md) | Reverse-lookup glossary that turns a vague description of a web animation or motion effect into its exact term ("the bouncy thing when a pop | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [animejs-animation](animejs-animation/SKILL.md) | Advanced JavaScript animation library skill for creating complex, high-performance web animations. | `TIER_2_ON_DEMAND` | EJII Sovereign License |
| [antigravity-design-expert](antigravity-design-expert/SKILL.md) | Core UI/UX engineering skill for building highly interactive, spatial, weightless, and glassmorphism-based web interfaces using GSAP and 3D  | `TIER_2_ON_DEMAND` | EJII Sovereign License |
| [archviz](archviz/SKILL.md) | Architectural visualization in Blender for interiors/exteriors with real-world scale, camera composition, PBR materials, and still/animation | `TIER_2_ON_DEMAND` | MIT |
| [article-magazine](article-magazine/SKILL.md) | Huashu / huashu-md-html-inspired magazine article layout for turning Markdown or notes into a polished long-form HTML essay. | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [artifacts-builder](artifacts-builder/SKILL.md) | \| | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [ask-sonner](ask-sonner/SKILL.md) | Guide to Sonner, the React toast library — install and wire up the Toaster, pick the right toast() call, promise and loading toasts, updatin | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [audio-design](audio-design/SKILL.md) | > | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [brand-guidelines](brand-guidelines/SKILL.md) | \| | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [browser-use-x402](browser-use-x402/SKILL.md) | Set up Browser Use Cloud payments with x402 — pay per request from a crypto wallet (USDC on Base mainnet), no signup or API key. Two setups  | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [brutalist-skill](brutalist-skill/SKILL.md) | \| | `TIER_2_ON_DEMAND` | MIT |
| [building-data-apps](building-data-apps/SKILL.md) | \| | `TIER_2_ON_DEMAND` | Apache-2.0 |
| [camera-cinematography](camera-cinematography/SKILL.md) | Cinematic camera work in Blender including framing, lenses, composition, camera animation, and shot language beyond basic rendering setup vi | `TIER_2_ON_DEMAND` | MIT |
| [canvas-design](canvas-design/SKILL.md) | Create beautiful visual art in .png and .pdf documents using design philosophy. You should use this skill when the user asks to create a pos | `TIER_2_ON_DEMAND` | Complete terms in LICENSE.txt |
| [card-twitter](card-twitter/SKILL.md) | Twitter quote or data card designed to pair with a post. | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [cartoon-style](cartoon-style/SKILL.md) | Cartoon art direction for Blender with squash-stretch readable shapes, bold colors, and graphic silhouettes for games and animation. | `TIER_2_ON_DEMAND` | MIT |
| [character-artist](character-artist/SKILL.md) | AAA character modeling for human anatomy, stylization, facial topology, clothing, hair, and animation-ready meshes. Use for game characters, | `TIER_2_ON_DEMAND` | MIT |
| [chat-motion-overlay](chat-motion-overlay/SKILL.md) | Generate configurable chat motion overlays from a transcript or screenshot, including plain bubble scenes, app-style chat containers, option | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [choreograph](choreograph/SKILL.md) | Coordinate several elements that animate together — decide what moves, in what order, how much they overlap, and what stays still — so a gro | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [ci-cd-and-automation](ci-cd-and-automation/SKILL.md) | Automates CI/CD pipeline setup. Use when setting up or modifying build and deployment pipelines. Use when you need to automate quality gates | `TIER_2_ON_DEMAND` | EJII Sovereign License |
| [cloudflare-dev](cloudflare-dev/SKILL.md) | Build and deploy on Cloudflare: product choice, Workers, Wrangler, Agents SDK, Durable Objects, Next.js on Workers, email, web perf. Use for | `TIER_2_ON_DEMAND` | Apache-2.0 |
| [codebase-design](codebase-design/SKILL.md) | Shared vocabulary for designing deep modules. Use when the user wants to design or improve a module's interface, find deepening opportunitie | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [contract-first](contract-first/SKILL.md) | Coordinate frontend/backend or service-to-service work through one authoritative machine-checkable contract (OpenAPI, AsyncAPI, Protocol Buf | `TIER_2_ON_DEMAND` | EJII Sovereign License |
| [create-control-manifest](create-control-manifest/SKILL.md) | Builds a short list of must-do and never-do coding rules per system from accepted ADRs. Use when the user wants programmer rules or a cheat  | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [create-game-assets](create-game-assets/SKILL.md) | Plan, generate, source, normalize, and validate cohesive visual game assets. Use for art direction, style bibles, sprites, tilesets, backgro | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [create-stories](create-stories/SKILL.md) | Breaks one epic into implementable stories with acceptance criteria. Use when the user wants stories for an epic or the next batch of work t | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [creature-artist](creature-artist/SKILL.md) | AAA creature modeling for fantasy, aliens, monsters, and organic creature design with believable anatomy and movement. Use for creature bloc | `TIER_2_ON_DEMAND` | MIT |
| [cta-gallery](cta-gallery/SKILL.md) | High-converting Call-to-Action (CTA) sections, magnetic button interactions, banner triggers, and trial onboarding blocks inspired by callto | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [dart-build-cli-app](dart-build-cli-app/SKILL.md) | >- | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [dart-use-ffigen](dart-use-ffigen/SKILL.md) | Guide agents to use `package:ffigen` to automatically generate FFI bindings instead of writing them manually. Use this skill when a task inv | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [dart-write-documentation](dart-write-documentation/SKILL.md) | Rules and formatting guidelines for writing Dart /// API documentation and doc comments. Use when documenting Dart code, writing doc comment | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [dbt-patterns](dbt-patterns/SKILL.md) | dbt model design, tests, documentation, Jinja macros, incremental models, snapshot | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [deck-guizang-editorial](deck-guizang-editorial/SKILL.md) | Editorial magazine meets e-ink: 10 layouts and 5 palettes (Ink, Indigo Porcelain, Forest Ink, Kraft Paper, Dune). | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [deck-open-slide-canvas](deck-open-slide-canvas/SKILL.md) | Locked 1920x1080 canvas deck with React component-level free composition, not bound to a fixed template. | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [design-brief](design-brief/SKILL.md) | \| | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [design-html](design-html/SKILL.md) | Design finalization: generates production-quality Pretext-native HTML/CSS. (gstack) | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [design-md](design-md/SKILL.md) | \| | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [design-md-library](design-md-library/SKILL.md) | 84 DESIGN.md design-system analyses of known sites (Stripe, Linear, Apple, Vercel, Spotify, Tesla…). Use for "in the style of" UI requests o | `TIER_2_ON_DEMAND` | MIT |
| [design-shotgun](design-shotgun/SKILL.md) | Design shotgun: generate multiple AI design variants, open a comparison board, collect structured feedback, and iterate. (gstack) | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [design-system](design-system/SKILL.md) | Generate a design system from an existing codebase or audit one for visual consistency: extract tokens (colors, typography, spacing, shadows | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [design-taste-frontend-v1](design-taste-frontend-v1/SKILL.md) | \| | `TIER_2_ON_DEMAND` | MIT |
| [dev-story](dev-story/SKILL.md) | Implements one story in code with tests, following its ADRs. Use when the user says to build, implement or start working on a story. Not for | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [diagram](diagram/SKILL.md) | Turn an English description (or mermaid source) into a diagram triplet: the source, an editable .excalidraw file you can open (gstack) | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [dimensional-drawing](dimensional-drawing/SKILL.md) | Make an Apple-style monochrome dimensional drawing of a UI component or physical product — title-block summary plus one dense drawing sheet  | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [dimensional-drawing-motion](dimensional-drawing-motion/SKILL.md) | Turn a finished dimensional drawing sheet into a ~10 s Apple-style motion film — lines draw themselves in, the camera pulls back, layers lif | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [directing-stickman-videos](directing-stickman-videos/SKILL.md) | Turn topics, requirements, articles or scripts into stickman videos. Director mode creates approved storyboards and standalone video prompts | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [doc-kami-parchment](doc-kami-parchment/SKILL.md) | Warm parchment canvas (#f5f4ed), monochrome ink-blue accent (#1B365D), one serif family, and editorial-grade typography. | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [domain-modeling](domain-modeling/SKILL.md) | Build and sharpen a project's domain model. Use when discussing codebase terminology, writing or editing a GLOSSARY.md, or recording or edit | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [expo-mobile](expo-mobile/SKILL.md) | Build and ship React Native apps with Expo: Expo Router, native UI, data fetching, native modules, SDK upgrades, EAS Build/Submit/Update. Us | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [email-automation](email-automation/SKILL.md) | Klaviyo/Mailchimp flow design, segmentation, deliverability, transactional email, A/B testing | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [emil-design-eng](emil-design-eng/SKILL.md) | This skill encodes Emil Kowalski's philosophy on UI polish, component design, animation decisions, and the invisible details that make softw | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [emilkowalski-motion](emilkowalski-motion/SKILL.md) | \| | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [figma-code-connect-components](figma-code-connect-components/SKILL.md) | \| | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [figma-create-design-system-rules](figma-create-design-system-rules/SKILL.md) | \| | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [figma-create-new-file](figma-create-new-file/SKILL.md) | \| | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [figma-generate-design](figma-generate-design/SKILL.md) | \| | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [figma-generate-library](figma-generate-library/SKILL.md) | \| | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [figma-implement-design](figma-implement-design/SKILL.md) | \| | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [figma-use](figma-use/SKILL.md) | \| | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [flutter-add-integration-test](flutter-add-integration-test/SKILL.md) | Configures Flutter Driver for app interaction and converts MCP actions into permanent integration tests. Use when adding integration testing | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [flutter-build-responsive-layout](flutter-build-responsive-layout/SKILL.md) | Use `LayoutBuilder`, `MediaQuery`, or `Expanded/Flexible` to create a layout that adapts to different screen sizes. Use when you need the UI | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [footer-design](footer-design/SKILL.md) | Creative website footer design patterns, multi-column sitemaps, newsletter subscription forms, and dark editorial sub-footers inspired by fo | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [frame-data-chart-nyt](frame-data-chart-nyt/SKILL.md) | NYT-newsroom typography, staggered reveal animation, and editorial-grade charts (line, bar, or range band). | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [frame-liquid-bg-hero](frame-liquid-bg-hero/SKILL.md) | WebGL-style fluid displacement background with a quote overlay, suited to video intros, landing heroes, or posters. | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [frame-macos-notification](frame-macos-notification/SKILL.md) | Realistic macOS notification banner with app icon, title, and body, suited to video overlays or product teasers. | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [framer-motion](framer-motion/SKILL.md) | Framer Motion animation patterns — variants, gestures, layout animation, exit animations | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [frontend-design](frontend-design/SKILL.md) | Guidance for distinctive, intentional visual design when building new UI or reshaping an existing one. Helps with aesthetic direction, typog | `TIER_2_ON_DEMAND` | Complete terms in LICENSE.txt |
| [frontend-dev](frontend-dev/SKILL.md) | \| | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [frontend-skill](frontend-skill/SKILL.md) | \| | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [frontend-slides](frontend-slides/SKILL.md) | \| | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [frontend-ui-engineering](frontend-ui-engineering/SKILL.md) | Builds production-quality, accessible, responsive user-facing UIs. Use when building or modifying interfaces and pages, creating components, | `TIER_2_ON_DEMAND` | EJII Sovereign License |
| [frutiger-aero-style](frutiger-aero-style/SKILL.md) | Frutiger Aero art direction for Blender with glossy skeuomorphism, aqua UI cues, nature-tech optimism, and mid-2000s futurism. | `TIER_2_ON_DEMAND` | MIT |
| [game-engine](game-engine/SKILL.md) | Expert skill for building web-based game engines and games using HTML5, Canvas, WebGL, and JavaScript. Use when asked to create games, build | `TIER_2_ON_DEMAND` | MIT |
| [game-prototype](game-prototype/SKILL.md) | Concept prototype before GDDs — throwaway HTML, Engine or Paper build, PROCEED/PIVOT/KILL/NOT ASSESSED. After /brainstorm and /setup-engine. | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [game-ui-ux](game-ui-ux/SKILL.md) | > | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [gate-check](gate-check/SKILL.md) | Ready to advance between development phases? PASS/CONCERNS/NOT ASSESSED/FAIL with blockers and required artifacts. 'Can we move to productio | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [genre-card-party-idle](genre-card-party-idle/SKILL.md) | Art direction for card games, deck builders, party games, idle/incremental, educational, and rhythm game presentational spaces in Blender. | `TIER_2_ON_DEMAND` | MIT |
| [genre-strategy-sim](genre-strategy-sim/SKILL.md) | Art direction for strategy, RTS, turn-based strategy, tower defense, MOBA, city builder, colony sim, and simulation games in Blender. | `TIER_2_ON_DEMAND` | MIT |
| [geometry-nodes](geometry-nodes/SKILL.md) | Blender Geometry Nodes for procedural modeling, scatter systems, vegetation, buildings, pipes, cables, and reusable node groups. Use for pro | `TIER_2_ON_DEMAND` | MIT |
| [ghost-editor](ghost-editor/SKILL.md) | AI video editor for talking-head reels. Turns a raw phone recording of someone talking to camera (retakes, pauses, false starts) into a fini | `TIER_2_ON_DEMAND` | MIT |
| [godot-animation](godot-animation/SKILL.md) | > | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [godot-ui-control](godot-ui-control/SKILL.md) | > | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [google-antigravity-sdk](google-antigravity-sdk/SKILL.md) | Design, implement, and debug autonomous AI agents and multi-agent systems using the Google Antigravity (AGY) SDK. ACTIVATE this skill when t | `TIER_2_ON_DEMAND` | Apache-2.0 (Google Cloud Open Source) |
| [grill-me](grill-me/SKILL.md) | A relentless interview to sharpen a plan or design. | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [grill-with-docs](grill-with-docs/SKILL.md) | A relentless interview to sharpen a plan or design, which also creates docs (ADR's and glossary) as we go. | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [growth-loops](growth-loops/SKILL.md) | Viral loop design, referral mechanisms, NPS-driven expansion, product-led growth | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [gsap-core](gsap-core/SKILL.md) | Official GSAP skill for the core API — gsap.to(), from(), fromTo(), easing, duration, stagger, defaults, gsap.matchMedia() (responsive, pref | `TIER_2_ON_DEMAND` | MIT |
| [gsap-framer-scroll-animation](gsap-framer-scroll-animation/SKILL.md) | >- | `TIER_2_ON_DEMAND` | MIT |
| [gsap-performance](gsap-performance/SKILL.md) | Official GSAP skill for performance — prefer transforms, avoid layout thrashing, will-change, batching. Use when optimizing GSAP animations, | `TIER_2_ON_DEMAND` | MIT |
| [gsap-scrolltrigger](gsap-scrolltrigger/SKILL.md) | Official GSAP skill for ScrollTrigger — scroll-linked animations, pinning, scrub, triggers. Use when building or recommending scroll-based a | `TIER_2_ON_DEMAND` | MIT |
| [gsap-timeline](gsap-timeline/SKILL.md) | Official GSAP skill for timelines — gsap.timeline(), position parameter, nesting, playback. Use when sequencing animations, choreographing k | `TIER_2_ON_DEMAND` | MIT |
| [gsap-utils](gsap-utils/SKILL.md) | Official GSAP skill for gsap.utils — clamp, mapRange, normalize, interpolate, random, snap, toArray, wrap, pipe. Use when the user asks abou | `TIER_2_ON_DEMAND` | MIT |
| [hallmark](hallmark/SKILL.md) | Design skill for websites and new pages that look designed, not generated. Use when the user asks to build or design something new, or names | `TIER_2_ON_DEMAND` | MIT |
| [hand-drawn-diagrams](hand-drawn-diagrams/SKILL.md) | \| | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [high-end-visual-design](high-end-visual-design/SKILL.md) | \| | `TIER_2_ON_DEMAND` | MIT |
| [huashu-art-motion](huashu-art-motion/SKILL.md) | 辅助艺术动画与解说任务：35 种艺术风格配方、9 种解说语法、分镜与确定性 Canvas 绘制工具。按宿主时间轴实现，素材与导出使用宿主能力。 | `TIER_2_ON_DEMAND` | MIT |
| [imagegen-frontend-mobile](imagegen-frontend-mobile/SKILL.md) | \| | `TIER_2_ON_DEMAND` | MIT |
| [imagegen-frontend-web](imagegen-frontend-web/SKILL.md) | \| | `TIER_2_ON_DEMAND` | MIT |
| [impeccable-design-polish](impeccable-design-polish/SKILL.md) | \| | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [industrial-brutalist-ui](industrial-brutalist-ui/SKILL.md) | \| | `TIER_2_ON_DEMAND` | MIT |
| [ink](ink/SKILL.md) | Ink terminal renderer for json-render that turns JSON specs into interactive terminal UIs. Use when working with @json-render/ink, building  | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [interview-me](interview-me/SKILL.md) | Extracts what the user actually wants instead of what they think they should want. Achieves this through one-question-at-a-time interview un | `TIER_2_ON_DEMAND` | EJII Sovereign License |
| [ios-qa](ios-qa/SKILL.md) | Live-device iOS QA for SwiftUI apps. (gstack) | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [json-canvas](json-canvas/SKILL.md) | Create and edit JSON Canvas files (.canvas) with nodes, edges, groups, and connections. Use when working with .canvas files, creating visual | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [qa-plan](qa-plan/SKILL.md) | QA test plan for a sprint — classifies stories by Logic/Integration/Visual/UI, covers automated tests, manual cases, smoke scope. | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [quick-design](quick-design/SKILL.md) | Lightweight spec for small changes — tuning adjustments, minor mechanics. Embeds directly into stories; skips full GDD. | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [lemo-opuscar](lemo-opuscar/SKILL.md) | Direct and produce a short film made entirely in code, in one of the styles of the Lemo-Opuscar library (e.g. Impasto Oil Painting 油画厚涂, Wat | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [level-design](level-design/SKILL.md) | > | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [logo-designer](logo-designer/SKILL.md) | \| | `TIER_2_ON_DEMAND` | MIT |
| [loop-me](loop-me/SKILL.md) | Grill me about specs for the workflows I want to build, within this workspace. | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [magic-ui](magic-ui/SKILL.md) | Use this skill when users want to add, customize, or troubleshoot Magic UI components in React/Next.js projects. It covers component selecti | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [manga-style](manga-style/SKILL.md) | Manga-inspired art direction for Blender emphasizing monochrome value design, speed lines, screentone feel, and manga panel staging. | `TIER_2_ON_DEMAND` | MIT |
| [map-systems](map-systems/SKILL.md) | Decompose a concept into individual systems, map dependencies, prioritize design order, create the systems index. | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [mcp-builder](mcp-builder/SKILL.md) | Guide for creating high-quality MCP (Model Context Protocol) servers that enable LLMs to interact with external services through well-design | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [md-to-docx](md-to-docx/SKILL.md) | Convert Markdown files to professionally formatted Word (.docx) documents with embedded PNG images — pure JavaScript, no external tools requ | `TIER_2_ON_DEMAND` | MIT |
| [microsoft-ufo](microsoft-ufo/SKILL.md) | Windows OS desktop automation agent (Microsoft UFO² & UFO³ Galaxy). Automates native Windows applications (Word, Excel, PowerPoint, Edge, Fi | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [minimalist-skill](minimalist-skill/SKILL.md) | \| | `TIER_2_ON_DEMAND` | MIT |
| [minimalist-ui](minimalist-ui/SKILL.md) | \| | `TIER_2_ON_DEMAND` | MIT |
| [mockup-device-3d](mockup-device-3d/SKILL.md) | Static iPhone and MacBook 3D-style showcase with real HTML embedded on screens, glass-lens refraction, and 360-degree turntable composition. | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [modern-web-guidance](modern-web-guidance/SKILL.md) | \| | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [motion-design](motion-design/SKILL.md) | Apply motion craft to an active task: refine a brief, beat map, visual continuity, typography, pacing, and timeline implementation. Use when | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [motion-lab](motion-lab/SKILL.md) | 为当前网页或组件查找、选型和改造动效。包含 160 个案例的 HTML/CSS/JS、参数与中英文索引，覆盖基础、文字、交互和高级动效。 | `TIER_2_ON_DEMAND` | MIT |
| [notebook-guidance](notebook-guidance/SKILL.md) | \|- | `TIER_2_ON_DEMAND` | Apache-2.0 |
| [oil-motion](oil-motion/SKILL.md) | 处理视频和序列帧，编译滚动、指针、拖动与状态驱动的网页动效；内含本地媒体处理脚本和运行时。新素材生成使用宿主工具。 | `TIER_2_ON_DEMAND` | MIT |
| [openmontage](openmontage/SKILL.md) | Agentic video production studio for AI assistants. Covers 12 automated pipelines: script-to-video, short drama, commercial ads, podcast repu | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [personal-voice](personal-voice/SKILL.md) | Write in the user's own voice by learning from sample text they provide (past posts, emails, messages). Use when the user wants writing that | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [pixelfx](pixelfx/SKILL.md) | Make pixel art effects and sprite animations in code with the pixelfx library, which has 244 ready-made ones, acted out by a character who w | `TIER_2_ON_DEMAND` | MIT |
| [planning-and-task-breakdown](planning-and-task-breakdown/SKILL.md) | Breaks work into ordered tasks. Use when you have a spec or clear requirements and need to break work into implementable tasks. Use when a t | `TIER_2_ON_DEMAND` | EJII Sovereign License |
| [platform-design](platform-design/SKILL.md) | \| | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [procedural-modeling](procedural-modeling/SKILL.md) | Procedural asset creation for rocks, buildings, vegetation, roads, terrain, pipes, cables, and sci-fi panels using Geometry Nodes and modifi | `TIER_2_ON_DEMAND` | MIT |
| [prompt-engineering](prompt-engineering/SKILL.md) | Chain-of-thought, few-shot, system prompt design, temperature guide, structured output | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [prototype](prototype/SKILL.md) | Build a throwaway prototype to answer a design question. Use when the user wants to sanity-check whether a state model or logic feels right, | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [react-bits](react-bits/SKILL.md) | Production-grade animated, interactive, and customizable React & Next.js components library (216+ components across Text Animations, Backgro | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [react-native-expo](react-native-expo/SKILL.md) | Expo managed workflow, navigation, state management, EAS Build, OTA updates | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [redesign-existing-projects](redesign-existing-projects/SKILL.md) | \| | `TIER_2_ON_DEMAND` | MIT |
| [redesign-skill](redesign-skill/SKILL.md) | \| | `TIER_2_ON_DEMAND` | MIT |
| [reference-design-contract](reference-design-contract/SKILL.md) | \| | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [remotion](remotion/SKILL.md) | \| | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [repo-wiki](repo-wiki/SKILL.md) | Turn a repository into documentation: wiki catalogue, Mermaid pages, onboarding guides, AGENTS.md, llms.txt, changelog, VitePress, Q&A. Use  | `TIER_2_ON_DEMAND` | MIT |
| [retopology](retopology/SKILL.md) | Production retopology for animation-ready, low-poly, quad-dominant meshes with proper edge loops and efficient polygon flow. Use after sculp | `TIER_2_ON_DEMAND` | MIT |
| [rigging](rigging/SKILL.md) | Production rigging in Blender with armatures, IK/FK, constraints, weight painting, mechanical rigs, facial rigs, and drivers. Use before ani | `TIER_2_ON_DEMAND` | MIT |
| [roblox-ui](roblox-ui/SKILL.md) | > | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [rossark-motion-skill](rossark-motion-skill/SKILL.md) | Bring anything drawn to life with calm, believable motion. It covers characters and creatures (gliding pupils, blinks, breathing, head tilts | `TIER_2_ON_DEMAND` | MIT |
| [scrolltide](scrolltide/SKILL.md) | Cinematic scroll interactions, viewport progression, subtle parallax depth, and performance-conscious section reveals using Framer Motion, L | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [setup-ts-deep-modules](setup-ts-deep-modules/SKILL.md) | Wire dependency-cruiser into a TypeScript repo so each package is a deep module, with implementation hidden in subfolders and reachable only | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [shadcn-ui](shadcn-ui/SKILL.md) | shadcn/ui component system — setup, theming, dark mode, Radix primitives, customization | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [smoke-check](smoke-check/SKILL.md) | Critical-path smoke gate before QA hand-off — runs the automated suite. A failed check means the build is not QA-ready. | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [social-x-post-card](social-x-post-card/SKILL.md) | Realistic X post card with engagement metrics (likes, reposts, views), suited to video overlays or shareable image cards. | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [social-reddit-card](social-reddit-card/SKILL.md) | Realistic Reddit post card with vote rail and comment count, suited to video overlays or story sharing. | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [social-spotify-card](social-spotify-card/SKILL.md) | Spotify Now Playing-style card with album art, progress bar, and playback controls, suited to video overlays or personal homepages. | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [soft-skill](soft-skill/SKILL.md) | \| | `TIER_2_ON_DEMAND` | MIT |
| [software-factory](software-factory/SKILL.md) | Shared language for designing a software factory: the tasks it runs and the services it plugs into. | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [source-driven-development](source-driven-development/SKILL.md) | Grounds every implementation decision in official documentation. Use when you want to verify an approach against the official docs before im | `TIER_0_CORE_GOVERNANCE` | EJII Sovereign License |
| [spec-driven-development](spec-driven-development/SKILL.md) | Creates specs before coding. Use when starting a new project, feature, or significant change and no specification exists yet. Use when draft | `TIER_2_ON_DEMAND` | EJII Sovereign License |
| [start](start/SKILL.md) | Guides a first-time user through onboarding and picks the right workflow. Use when the user is new, just cloned or installed the studio, has | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [stickman-video-director](stickman-video-director/SKILL.md) | Turn topics, requirements, articles or scripts into stickman videos. Director mode creates approved storyboards and standalone video prompts | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [stitch-design](stitch-design/SKILL.md) | Design UI with Google Stitch (needs Stitch MCP): prompt enhancement, DESIGN.md taste rules, screen generation, then React/shadcn/React Nativ | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [stitch-design-taste](stitch-design-taste/SKILL.md) | \| | `TIER_2_ON_DEMAND` | MIT |
| [stitch-skill](stitch-skill/SKILL.md) | \| | `TIER_2_ON_DEMAND` | MIT |
| [stop-motion-craft-style](stop-motion-craft-style/SKILL.md) | Stop-motion and craft aesthetics for Blender including claymation, paper craft, and handmade physical-material cues. | `TIER_2_ON_DEMAND` | MIT |
| [story-done](story-done/SKILL.md) | Closes a finished story: verifies each acceptance criterion, checks for design or ADR deviations and updates its status. Use when the user s | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [story-readiness](story-readiness/SKILL.md) | Checks whether a story is ready to implement: clear acceptance criteria, no open questions, valid ADR and dependencies. Use when the user as | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [stylized-style](stylized-style/SKILL.md) | Stylized art direction for Blender with shape language, exaggeration, color harmony, NPR rendering, and hand-painted asset workflows. Use fo | `TIER_2_ON_DEMAND` | MIT |
| [supahero](supahero/SKILL.md) | Curated hero section design patterns, typography hierarchy, responsive hero layouts, and 3D/video backdrop treatments inspired by supahero.i | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [sync-gbrain](sync-gbrain/SKILL.md) | Keep gbrain current with this repo's code and refresh agent search guidance in CLAUDE.md. Wraps the gstack-gbrain-sync orchestrator with sta | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [swiftui-design](swiftui-design/SKILL.md) | \| | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [tailwind-v4](tailwind-v4/SKILL.md) | Tailwind CSS v4 CSS-first config, @theme directive, container queries, syntax changes | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [taste-art-direction](taste-art-direction/SKILL.md) | Visual aesthetics, typography, and art direction enforcement for agentic UI design. Enforces quiet luxury design principles, eliminates visu | `TIER_2_ON_DEMAND` | EJII Sovereign License |
| [taste-skill-v1](taste-skill-v1/SKILL.md) | \| | `TIER_2_ON_DEMAND` | MIT |
| [team-audio](team-audio/SKILL.md) | Orchestrate the audio team — audio-director, sound-designer, technical-artist, gameplay-programmer — direction through implementation. | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [team-combat](team-combat/SKILL.md) | Orchestrate the combat team — game-designer, gameplay-programmer, ai-programmer, technical-artist, sound-designer, qa-tester — design throug | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [team-level](team-level/SKILL.md) | Orchestrate the level team — level-designer, narrative-director, world-builder, art-director, systems-designer, qa-tester — for complete are | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [team-live-ops](team-live-ops/SKILL.md) | Orchestrate the live-ops team — live-ops-designer, economy-designer, analytics-engineer, community-manager, writer — for a season or live ev | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [team-narrative](team-narrative/SKILL.md) | Orchestrate the narrative team — narrative-director, writer, world-builder, level-designer — for story, world lore, narrative-driven levels. | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [team-polish](team-polish/SKILL.md) | Orchestrate the polish team — performance-analyst, technical-artist, sound-designer, qa-tester — to optimize and harden a feature or area. | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [teardown](teardown/SKILL.md) | Build an interactive 3D simulator of a real machine or mechanism (an engine, a landing gear, a walking linkage, a pump, a gearbox) as one of | `TIER_2_ON_DEMAND` | MIT |
| [theme-factory](theme-factory/SKILL.md) | Toolkit for styling artifacts with a theme. These artifacts can be slides, docs, reportings, HTML landing pages, etc. There are 10 pre-set t | `TIER_2_ON_DEMAND` | Complete terms in LICENSE.txt |
| [threejs](threejs/SKILL.md) | \| | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [threejs-3d](threejs-3d/SKILL.md) | Build interactive 3D in the browser with Three.js/WebGL: scenes, materials, lighting, GLTF loading, animation, interaction, post-processing, | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [threejs-gltf-loading](threejs-gltf-loading/SKILL.md) | > | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [threejs-materials-lighting](threejs-materials-lighting/SKILL.md) | > | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [threejs-scene-setup](threejs-scene-setup/SKILL.md) | > | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [threeui](threeui/SKILL.md) | Interactive Three.js UI component library and visual layout engine for 3D web apps, games, shaders, and immersive frontend experiences. | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [ui-quality](ui-quality/SKILL.md) | Final UI quality pass: WCAG 2.2 AA accessibility checklist plus design-engineering polish (radii, motion, hit areas, text-wrap). Use after b | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [ui-pipeline](ui-pipeline/SKILL.md) | 4-mərhələli ardıcıl UI/UX pipeline — planla, zövq al, qüsursuzlaşdır, cila ver. Trigger: /ui-pipeline | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [ui-skills](ui-skills/SKILL.md) | \| | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [unity-animation](unity-animation/SKILL.md) | > | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [unity-build-pipeline](unity-build-pipeline/SKILL.md) | > | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [unslop](unslop/SKILL.md) | Turns vibecoded, AI-looking UI into a designed interface with its own character. Finds a direction from the product itself, then fixes spaci | `TIER_2_ON_DEMAND` | CC-BY-4.0 |
| [vector-style](vector-style/SKILL.md) | Vector-clean art direction for Blender with flat fills, sharp silhouettes, and UI-like graphic clarity. | `TIER_2_ON_DEMAND` | MIT |
| [vercel-optimize](vercel-optimize/SKILL.md) | Use for Vercel cost and performance optimization on deployed projects, especially Next.js, SvelteKit, Nuxt, and limited Astro apps. Collect  | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [vercel-react-native-skills](vercel-react-native-skills/SKILL.md) | React Native and Expo best practices for building performant mobile apps. Use | `TIER_2_ON_DEMAND` | MIT |
| [vercel-react-view-transitions](vercel-react-view-transitions/SKILL.md) | Guide for implementing smooth, native-feeling animations using React's View Transition API (`<ViewTransition>` component, `addTransitionType | `TIER_2_ON_DEMAND` | MIT |
| [video-hyperframes](video-hyperframes/SKILL.md) | Hyperframes / Remotion-compatible continuous frame animation with autoplay support. | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [video-studio](video-studio/SKILL.md) | Edit and build videos with code: FFmpeg cuts/reframe/loudnorm, Remotion, HyperFrames (HTML to video), Manim math animations, captions, rende | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [video-use](video-use/SKILL.md) | Edit any video by conversation. Transcribe, cut, color grade, generate overlay animations, burn subtitles — for talking heads, montages, tut | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [visual-explainer](visual-explainer/SKILL.md) | Generate rich self-contained HTML pages that explain systems, diffs, plans and data visually, plus slide decks. Use when the user wants a vi | `TIER_2_ON_DEMAND` | MIT |
| [web-artifacts-builder](web-artifacts-builder/SKILL.md) | \| | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [web-asset-generator](web-asset-generator/SKILL.md) | Generate web assets including favicons, app icons (PWA), and social media meta images (Open Graph) for Facebook, Twitter, WhatsApp, and Link | `TIER_2_ON_DEMAND` | MIT |
| [writing-plans](writing-plans/SKILL.md) | Use when you have a spec or requirements for a multi-step task, before touching code | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |

### Mobile Development (iOS, Android, Flutter & Expo) (31 skills)

| Skill Name | Description | Routing Tier | License |
| :--- | :--- | :---: | :--- |
| [android-dev](android-dev/SKILL.md) | Kotlin + Jetpack Compose, ViewModel, Room, Hilt DI, Android lifecycle | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [android-device-hub](android-device-hub/SKILL.md) | Instructions for working with the Android Device Hub sidecar, which lists, starts, stops, creates and removes Android Virtual Devices (AVDs) | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [asset-optimization](asset-optimization/SKILL.md) | Validates and optimizes Blender assets for polycount, topology, UV efficiency, material count, naming, collections, and game-ready performan | `TIER_2_ON_DEMAND` | MIT |
| [blender-director](blender-director/SKILL.md) | Use when starting any Blender asset task, planning a production pipeline, coordinating multiple disciplines, or matching a reference photo/c | `TIER_2_ON_DEMAND` | MIT |
| [character-archetypes](character-archetypes/SKILL.md) | Character archetype art direction for Blender covering fantasy races, horror creatures, roles (knight, assassin, detective), and body types  | `TIER_2_ON_DEMAND` | MIT |
| [dart-add-unit-test](dart-add-unit-test/SKILL.md) | Write and organize unit tests for functions, methods, and classes using `package:test`. Use when creating new logic or fixing bugs to ensure | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [dart-fix-runtime-errors](dart-fix-runtime-errors/SKILL.md) | Uses get_runtime_errors and lsp to fetch an active stack trace, locate the failing line, apply a fix, and verify resolution via hot_reload. | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [dart-migrate-to-checks-package](dart-migrate-to-checks-package/SKILL.md) | \|- | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [dart-resolve-package-conflicts](dart-resolve-package-conflicts/SKILL.md) | Workflow for fixing package version conflicts. Use this when `pub get` fails due to incompatible package versions. | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [dart-run-static-analysis](dart-run-static-analysis/SKILL.md) | Execute `dart analyze` to identify warnings and errors, and use `dart fix --apply` to automatically resolve mechanical lint issues. Use duri | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [dart-use-doc-examples](dart-use-doc-examples/SKILL.md) | How to inject external code examples into Dartdoc using the {@example} directive, and how to filter those files using #hide, #region, and #e | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [dart-use-path-package](dart-use-path-package/SKILL.md) | >- | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [dart-use-pattern-matching](dart-use-pattern-matching/SKILL.md) | >- | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [dart-use-primary-constructors](dart-use-primary-constructors/SKILL.md) | > | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [data-throughput-accelerator](data-throughput-accelerator/SKILL.md) | Diagnose and accelerate large data movement — ingestion, backfill, export, ETL, warehouse loading, manifest catch-up, and table synchronizat | `TIER_2_ON_DEMAND` | EJII Sovereign License |
| [esp32-iphone-agent](esp32-iphone-agent/SKILL.md) | See and drive a real iPhone through an ESP32 Agent board (USB mouse/keyboard + AirPlay screen mirroring, reached over Bluetooth). Use when a | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [flutter-animating-apps](flutter-animating-apps/SKILL.md) | \| | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [flutter-fix-layout-issues](flutter-fix-layout-issues/SKILL.md) | Fixes Flutter layout errors (overflows, unbounded constraints) using Dart and Flutter MCP tools. Use when addressing "RenderFlex overflowed" | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [flutter-setup-localization](flutter-setup-localization/SKILL.md) | Add `flutter_localizations` and `intl` dependencies, enable "generate true" in `pubspec.yaml`, and create an `l10n.yaml` configuration file. | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [flutter-use-http-package](flutter-use-http-package/SKILL.md) | Use the `http` package to execute GET, POST, PUT, or DELETE requests. Use when you need to fetch from or send data to a REST API. | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [godot-export](godot-export/SKILL.md) | > | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [handsy](handsy/SKILL.md) | See and drive a real iPhone through an ESP32 Agent (Handsy) board with the esp32agent CLI or MCP server. Use when asked to look at, tap, swi | `TIER_2_ON_DEMAND` | MIT |
| [ios-clean](ios-clean/SKILL.md) | Remove the DebugBridge SPM package and all #if DEBUG wiring from an iOS app. (gstack) | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [ios-fix](ios-fix/SKILL.md) | Autonomous iOS bug fixer. (gstack) | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [ios-sideload](ios-sideload/SKILL.md) | Sideload, install, and manage iOS apps (.ipa) on iPhone and iPad from Windows using pymobiledevice3, Sideloadly, and AltServer. | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [ios-sync](ios-sync/SKILL.md) | Regenerate the iOS debug bridge against the latest upstream gstack templates. (gstack) | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [push-notifications](push-notifications/SKILL.md) | FCM/APNs push notifications, Expo Notifications, topic subscriptions, notification templates | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [resume-modern](resume-modern/SKILL.md) | Modern minimal resume, single A4 page, ready for print or PDF export. | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [skill-comply](skill-comply/SKILL.md) | Visualize whether skills, rules, and agent definitions are actually followed — auto-generates scenarios at 3 prompt strictness levels, runs  | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [unity-export](unity-export/SKILL.md) | Unity-specific Blender export for scale, axis, materials, humanoid/generic rigs, LODs, and collision import via MCP. | `TIER_2_ON_DEMAND` | MIT |
| [unreal-export](unreal-export/SKILL.md) | Unreal Engine-specific Blender export for FBX scale, LODs, UCX collision, sockets, materials, and skeletal mesh workflows via MCP. | `TIER_2_ON_DEMAND` | MIT |

### DeepMind Science, Genomics & Computational Biology (9 skills)

| Skill Name | Description | Routing Tier | License |
| :--- | :--- | :---: | :--- |
| [alphagenome-atlas-website-links](alphagenome-atlas-website-links/SKILL.md) | >- | `TIER_2_ON_DEMAND` | Open Science Permissive (DeepMind/NCBI) |
| [alphagenome-single-variant-analysis](alphagenome-single-variant-analysis/SKILL.md) | > | `TIER_2_ON_DEMAND` | Open Science Permissive (DeepMind/NCBI) |
| [alphagenome-variant-impact-score](alphagenome-variant-impact-score/SKILL.md) | >- | `TIER_2_ON_DEMAND` | Open Science Permissive (DeepMind/NCBI) |
| [literature-search-arxiv](literature-search-arxiv/SKILL.md) | > | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [literature-search-biorxiv](literature-search-biorxiv/SKILL.md) | > | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [ncbi-sequence-fetch](ncbi-sequence-fetch/SKILL.md) | > | `TIER_2_ON_DEMAND` | Open Science Permissive (DeepMind/NCBI) |
| [protein-sequence-msa](protein-sequence-msa/SKILL.md) | > | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [protein-sequence-similarity-search](protein-sequence-similarity-search/SKILL.md) | > | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [pymol](pymol/SKILL.md) | > | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |

### Browser Automation, Scraping & CDP Agents (18 skills)

| Skill Name | Description | Routing Tier | License |
| :--- | :--- | :---: | :--- |
| [agent-browser](agent-browser/SKILL.md) | \| | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [axuse](axuse/SKILL.md) | Accessibility-first browser/computer use over MCP. Works in any MCP-capable | `TIER_2_ON_DEMAND` | CUSTOM_PERMISSIVE |
| [benchmark](benchmark/SKILL.md) | Measure performance baselines and detect regressions across browser Core Web Vitals (LCP, INP, CLS, page weight), API endpoint latency perce | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [browse](browse/SKILL.md) | Fast headless browser for QA testing and site dogfooding. (gstack) | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [browser-use-cloud](browser-use-cloud/SKILL.md) | > | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [browser-use-open-source](browser-use-open-source/SKILL.md) | > | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [browser-use-remote-browser](browser-use-remote-browser/SKILL.md) | Controls an isolated Browser Use Cloud browser from a sandboxed machine with the current Browser Use CLI. | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [full-page-screenshot](full-page-screenshot/SKILL.md) | \| | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [github-issue-creator](github-issue-creator/SKILL.md) | Convert raw notes, error logs, voice dictation, or screenshots into crisp GitHub-flavored markdown issue reports. Use when the user pastes b | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [lookdev](lookdev/SKILL.md) | Look development loop for Blender assets combining materials, lighting, camera, and screenshot comparison until shading reads correctly via  | `TIER_2_ON_DEMAND` | MIT |
| [open-gstack-browser](open-gstack-browser/SKILL.md) | Launch GStack Browser — AI-controlled Chromium with the sidebar extension baked in. | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [pair-agent](pair-agent/SKILL.md) | Pair a remote AI agent with your browser. (gstack) | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [scrape](scrape/SKILL.md) | Pull data from a web page. (gstack) | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [screenshot](screenshot/SKILL.md) | \| | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [screenshots-marketing](screenshots-marketing/SKILL.md) | \| | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [setup-browser-cookies](setup-browser-cookies/SKILL.md) | Import cookies from your real Chromium browser into the headless browse session. (gstack) | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [skillify](skillify/SKILL.md) | Codify the most recent successful /scrape flow into a permanent browser-skill on disk. (gstack) | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |
| [testing-e2e](testing-e2e/SKILL.md) | End-to-end testing with Playwright and Cypress — setup, selectors, fixtures, CI | `TIER_2_ON_DEMAND` | Open Agent Skills Standard |

### Specialized Engineering, Game Dev, 3D & Creative (375 skills)

| Skill Name | Description | Routing Tier | License |
| :--- | :--- | :---: | :--- |
| [3dicons](3dicons/SKILL.md) | Open-source 3D icon library (1440+ icon variations across 100+ unique concepts, 4 styles: Clay, Gradient, Color, Dynamic, and 3 camera angle | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [8-bit-orbit-video-template](8-bit-orbit-video-template/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [accidental-data-loss-prevention](accidental-data-loss-prevention/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Apache-2.0 |
| [ad-creative](ad-creative/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [ads-competitor](ads-competitor/SKILL.md) | Competitor ad intelligence analysis across Google, Meta, LinkedIn, TikTok, Microsoft, and Apple Ads. Analyzes competitor ad copy, creative s | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [after-hours-editorial-template](after-hours-editorial-template/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [ai-behavior-trees-utility-ai](ai-behavior-trees-utility-ai/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [ai-memory-durable-pages](ai-memory-durable-pages/SKILL.md) | Use this skill for any explicit wiki mutation in ai-memory: saving durable or time-bounded project knowledge, recording a rule or annotation | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [ai-memory-routing-install](ai-memory-routing-install/SKILL.md) | Use this skill for any request to install, refresh, repair, inspect, or remove ai-memory's agent-facing routing: managed instruction snippet | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [ai-memory-status](ai-memory-status/SKILL.md) | Check whether ai-memory is capturing this session and its memory tools can reach the server. Run it when memory looks missing or after insta | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [ai-music-album](ai-music-album/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [algorithmic-art](algorithmic-art/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [analog-found-footage-horror](analog-found-footage-horror/SKILL.md) | Analog, VHS, CRT, and found-footage horror aesthetics for Blender shots including camera imperfections and documentary framing. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [anime-style](anime-style/SKILL.md) | Anime and cel-shaded art direction for Blender with hard color breaks, toon shaders, clean silhouettes, and anime proportion language. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [apocalypse-worlds](apocalypse-worlds/SKILL.md) | Apocalyptic and dystopian world art direction for Blender including post-apocalyptic, zombie, alien invasion, post-human, dystopian, and uto | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [apple-hig](apple-hig/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [arena-skill](arena-skill/SKILL.md) | >- | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [art-bible](art-bible/SKILL.md) | Author the Art Bible — visual identity gating asset production. Run before /map-systems. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [ask-matt](ask-matt/SKILL.md) | Ask which skill or flow fits your situation. A router over the skills in this repo. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [asset-spec](asset-spec/SKILL.md) | Per-asset visual specs plus AI generation prompts from GDDs and character profiles. After the art bible. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [audio-studio-mcp](audio-studio-mcp/SKILL.md) | Local AI music and sound effects generator MCP for Claude Code and coding agents. Generates background music, instrument loops, sound effect | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [awesome-claude-skills](awesome-claude-skills/SKILL.md) | Curated aggregator and registry of MCP servers, agent toolkits, and modular runtime capabilities. Acts as a lookup registry when checking if | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | EJII Sovereign License |
| [aws-patterns](aws-patterns/SKILL.md) | AWS Lambda, S3, RDS, ECS, CDK — serverless and container patterns, IAM least privilege | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [balance-check](balance-check/SKILL.md) | Find balance outliers, broken progressions, degenerate strategies, economy imbalances in formulas and data. 'Check game balance'. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [baoyu-comic](baoyu-comic/SKILL.md) | Knowledge comic creator supporting multiple art styles and tones. Creates original educational comics with detailed panel layouts and batch- | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [benchmark-models](benchmark-models/SKILL.md) | Cross-model benchmark for gstack skills. (gstack) | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [bevy-ecs](bevy-ecs/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [biome-worlds](biome-worlds/SKILL.md) | Biome and setting art direction for Blender covering underwater, desert, arctic, jungle, underground, and floating-island environments. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [biomolecular-structure-viewer](biomolecular-structure-viewer/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [blender-modeler](blender-modeler/SKILL.md) | Core Blender modeling specialist for Edit Mode, modifiers, collections, precision modeling, and scene organization. Use for general 3D model | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [body-horror-style](body-horror-style/SKILL.md) | Body horror art direction for Blender focusing on flesh wrongness, mutation, fusion, and visceral material storytelling. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [brainstorming](brainstorming/SKILL.md) | You MUST use this before any creative work - creating features, building components, adding functionality, modifying behavior, or planning a | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [brand-extract](brand-extract/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [brandkit](brandkit/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [bug-report](bug-report/SKILL.md) | Structured bug report from a description, or analyze code for potential bugs. Reproduction steps, severity. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [bun-runtime](bun-runtime/SKILL.md) | Bun as runtime, package manager, bundler, and test runner. When to choose Bun vs Node, migration notes, and Vercel support. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | EJII Sovereign License |
| [camera-systems](camera-systems/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [canary](canary/SKILL.md) | Post-deploy canary monitoring. (gstack) | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [card-game](card-game/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [card-xiaohongshu](card-xiaohongshu/SKILL.md) | Xiaohongshu-style knowledge cards, arranged as a swipeable multi-card carousel. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [caveman](caveman/SKILL.md) | Token reduction proxy and linguistic root compression. Use when compressing massive raw multi-engine wire traces, PCAP streams, and telemetr | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [change-impact](change-impact/SKILL.md) | >- | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | EJII Sovereign License |
| [changelog](changelog/SKILL.md) | Auto-generate a changelog from git commits and sprint data. Internal and player-facing versions. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [changelog-writer](changelog-writer/SKILL.md) | Conventional commits to changelog, semver versioning, release notes, GitHub release automation | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [chibi-style](chibi-style/SKILL.md) | Chibi and SD proportion art direction for Blender characters with oversized heads, simplified anatomy, and cute silhouette rules. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [chrome-extensions](chrome-extensions/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [claude-code-best-practice](claude-code-best-practice/SKILL.md) | Agentic engineering handbook for terminal workflows, sub-process monitoring, and cross-examination cycles during long-running tasks. Used by | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | EJII Sovereign License |
| [claude-handoff](claude-handoff/SKILL.md) | Hand the current conversation off to a fresh background agent that picks up the work immediately. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [claude-shorts](claude-shorts/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [cli-anything-apps](cli-anything-apps/SKILL.md) | Drive installed apps from the command line via CLI-Anything: Blender (3D/render), Godot (projects/GDScript), LibreOffice (documents), Ollama | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Apache-2.0 |
| [cloth-sim](cloth-sim/SKILL.md) | Garment blockout, cloth simulation, pin groups, and bake to shape keys or caches for characters and props in Blender via MCP. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [codex](codex/SKILL.md) | OpenAI Codex CLI wrapper — three modes. (gstack) | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [collision-proxy](collision-proxy/SKILL.md) | Collision proxy authoring for games including UCX/UHX naming, convex hulls, capsules, and simple collider meshes in Blender via MCP. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [color-expert](color-expert/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [comic-book-style](comic-book-style/SKILL.md) | Comic book and graphic-novel art direction for Blender with ink-line emphasis, halftone cues, and high-contrast framing. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [competitive-ads-extractor](competitive-ads-extractor/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [compositing](compositing/SKILL.md) | Blender compositor workflows for beauty stacks, render passes, color grade, glare, and delivery outputs via MCP. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [consistency-check](consistency-check/SKILL.md) | Scan GDDs against the entity registry for cross-document conflicts. Grep-first approach targets conflicting sections, different stats. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [copywriting](copywriting/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [cosmic-eldritch-horror](cosmic-eldritch-horror/SKILL.md) | Cosmic, eldritch, and Lovecraftian horror art direction for Blender with non-Euclidean cues, impossible scale, and incomprehensible forms. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [council](council/SKILL.md) | Trigger this if the user says 'council'. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [cozy-wholesome-mood](cozy-wholesome-mood/SKILL.md) | Cozy, cute, wholesome, relaxing, and peaceful mood direction for Blender assets and scenes. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [creative-director](creative-director/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [credentials](credentials/SKILL.md) | >- | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [d3-visualization](d3-visualization/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [dark-gritty-mood](dark-gritty-mood/SKILL.md) | Dark, grim, gritty, rusty, abandoned, decayed, industrial, lonely, and melancholic mood direction for Blender. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [data-report](data-report/SKILL.md) | Turns CSV, Excel, or JSON data into a polished visual report page. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [day-one-patch](day-one-patch/SKILL.md) | Day-one launch patch — focused fix for known issues found after gold master. Mini-sprint with QA gate and rollback. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [deck-swiss-international](deck-swiss-international/SKILL.md) | 16-column grid, one saturated accent, and 22 locked layouts (Klein Blue, Lemon, Mint, Safety Orange). | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [defold-core](defold-core/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [diagnosing-bugs](diagnosing-bugs/SKILL.md) | Diagnosis loop for hard bugs and performance regressions. Use when the user says "diagnose"/"debug this", or reports something broken/throwi | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [dialogue-systems](dialogue-systems/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [digits-fintech-swiss-template](digits-fintech-swiss-template/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [doc](doc/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [docx](docx/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [document-generate](document-generate/SKILL.md) | Generate missing documentation from scratch for a feature, module, or entire project. (gstack) | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [document-release](document-release/SKILL.md) | Post-ship documentation update. (gstack) | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [domain-name-brainstormer](domain-name-brainstormer/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [dream-surreal-mood](dream-surreal-mood/SKILL.md) | Dreamlike, surreal, mysterious, mystical, hopeful, and chaotic mood direction for Blender scenes. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [dream-weirdcore-style](dream-weirdcore-style/SKILL.md) | Dreamcore, weirdcore, and traumacore-inspired art direction for Blender with nostalgic wrongness, liminal nostalgia, and surreal childhood s | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [ebitengine-game](ebitengine-game/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [ecommerce-image-workflow](ecommerce-image-workflow/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [editorial-burgundy-principles-template](editorial-burgundy-principles-template/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [embl-ebi-ols](embl-ebi-ols/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [enforcing-resource-attribution](enforcing-resource-attribution/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Apache-2.0 |
| [enhance-prompt](enhance-prompt/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [estimate](estimate/SKILL.md) | Estimate task effort from complexity, dependencies, velocity, risk. Structured estimate with confidence levels. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [faq-page](faq-page/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [fal-3d](fal-3d/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [fal-generate](fal-generate/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [fal-image-edit](fal-image-edit/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [fal-kling-o3](fal-kling-o3/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [fal-lip-sync](fal-lip-sync/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [fal-media-studio](fal-media-studio/SKILL.md) | Generate/edit images, video, audio and 3D via fal.ai with recipes for cinematic shots, character consistency/anime, storyboards, UGC, ads, u | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [fal-realtime](fal-realtime/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [fal-restore](fal-restore/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [fal-train](fal-train/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [fal-tryon](fal-tryon/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [fal-upscale](fal-upscale/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [fal-video-edit](fal-video-edit/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [fal-vision](fal-vision/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [federate-lakehouse-catalog](federate-lakehouse-catalog/SKILL.md) | >- | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Apache-2.0 |
| [field-notes-editorial-template](field-notes-editorial-template/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [file-pr](file-pr/SKILL.md) | File a concise pull request. Use when the user asks to file, open, or create a PR. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [finishing-a-development-branch](finishing-a-development-branch/SKILL.md) | Use when implementation is complete, all tests pass, and you need to decide how to integrate the work | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [firestore-rules-creation](firestore-rules-creation/SKILL.md) | >- | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [foldseek-structural-search](foldseek-structural-search/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [folk-horror-style](folk-horror-style/SKILL.md) | Folk horror art direction for Blender with rural ritual uncanny, pastoral daylight dread, and community-wrongness storytelling. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [fps-shooter](fps-shooter/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [frame-flowchart-sticky](frame-flowchart-sticky/SKILL.md) | SVG curve connectors, sticky-note nodes, and cursor interaction with a whiteboard-brainstorm feel. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [frame-glitch-title](frame-glitch-title/SKILL.md) | Digital glitch, chromatic offset, and data-corruption title frame for video transitions or cyberpunk heroes. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [frame-light-leak-cinema](frame-light-leak-cinema/SKILL.md) | Film light leaks, grain, 16:9 letterbox, and large serif type for cinematic openings or chapter cards. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [frame-logo-outro](frame-logo-outro/SKILL.md) | Segmented logo assembly, glow bloom, and tagline reveal for video outros or brand closing frames. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [freeze](freeze/SKILL.md) | Restrict file edits to a specific directory for the session. (gstack) | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [full-output-enforcement](full-output-enforcement/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [full-send](full-send/SKILL.md) | Trigger this if the user says 'full send'. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [full-stop](full-stop/SKILL.md) | Trigger this if the user says 'full stop', even as a closing "Full stop." that reads like emphasis. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [ga4-gtm](ga4-gtm/SKILL.md) | GA4 event tracking, GTM container setup, custom dimensions, conversion events, funnel analysis | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [game-ai](game-ai/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [game-feel](game-feel/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [game-jam](game-jam/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [game-studio-pipeline](game-studio-pipeline/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [gamedev-router](gamedev-router/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [genre-action-combat](genre-action-combat/SKILL.md) | Art direction for action, hack-and-slash, beat 'em up, and fighting-game readable combat spaces and prop language in Blender. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [genre-metroidvania-roguelike](genre-metroidvania-roguelike/SKILL.md) | Art direction for metroidvania, roguelike, and roguelite games in Blender with biome gates, room modules, and run-readable props. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [genre-narrative-vn](genre-narrative-vn/SKILL.md) | Art direction for visual novel, interactive movie, walking simulator, and story-driven presentation spaces in Blender. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [genre-open-world-sandbox](genre-open-world-sandbox/SKILL.md) | Art direction for open world and sandbox games in Blender with biome landmarks, traversable scale, and discovery props. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [genre-puzzle-platformer](genre-puzzle-platformer/SKILL.md) | Art direction for puzzle and platformer games in Blender with readable interactables, jump volumes, and clear hazard language. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [genre-racing-sports](genre-racing-sports/SKILL.md) | Art direction for racing and sports games in Blender with track landmarks, stadium kits, and high-speed readability. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [genre-rpg](genre-rpg/SKILL.md) | Art direction for RPG, JRPG, CRPG, ARPG, and MMORPG worlds in Blender including loot rarity reads and region identity. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [genre-shooter](genre-shooter/SKILL.md) | Art direction for FPS, TPS, shooter, battle royale, and extraction-shooter maps and props in Blender with sightline and cover language. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [genre-soulslike](genre-soulslike/SKILL.md) | Art direction for soulslike games in Blender with monumental melancholy spaces, fog gates, bonfire landmarks, and lethal readability. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [genre-stealth](genre-stealth/SKILL.md) | Art direction for stealth-game spaces in Blender with shadow volumes, patrol-friendly layouts, and concealment materials. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [genre-survival](genre-survival/SKILL.md) | Art direction for survival and survival-horror gameplay spaces in Blender emphasizing resource props, crafting readability, and tension rout | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [gif-sticker-maker](gif-sticker-maker/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [git-commit-formatter](git-commit-formatter/SKILL.md) | Formats git commit messages according to Conventional Commits specification. Use this when the user asks to commit changes or write a commit | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | EJII Sovereign License |
| [godot-2d-movement](godot-2d-movement/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [godot-3d-essentials](godot-3d-essentials/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [godot-audio](godot-audio/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [godot-csharp](godot-csharp/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [godot-gdscript](godot-gdscript/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [godot-gdscript-headless-testing](godot-gdscript-headless-testing/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [godot-multiplayer](godot-multiplayer/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [godot-nodes-scenes](godot-nodes-scenes/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [godot-physics](godot-physics/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [godot-resources](godot-resources/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [godot-shaders](godot-shaders/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [godot-signals-groups](godot-signals-groups/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [godot-tilemap](godot-tilemap/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [gpt-taste](gpt-taste/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [gpt-tasteskill](gpt-tasteskill/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [gravitas](gravitas/SKILL.md) | > | `TIER_0_CORE_GOVERNANCE` | EJII Sovereign License |
| [gravitas-highstakes](gravitas-highstakes/SKILL.md) | > | `TIER_0_CORE_GOVERNANCE` | EJII Sovereign License |
| [gravitas-typescript](gravitas-typescript/SKILL.md) | > | `TIER_0_CORE_GOVERNANCE` | EJII Sovereign License |
| [grilling](grilling/SKILL.md) | Grill the user relentlessly about a plan, decision, or idea. Use when the user wants to stress-test their thinking, or uses any 'grill' trig | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [gstack](gstack/SKILL.md) | Router for the gstack skill suite. (gstack) | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [gstack-upgrade](gstack-upgrade/SKILL.md) | Upgrade gstack to the latest version. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [hair-groom](hair-groom/SKILL.md) | Hair and fur grooming in Blender using curves, particle hair, geometry nodes, and game hair-card workflows. Use for characters, creatures, a | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [hand-painted-style](hand-painted-style/SKILL.md) | Hand-painted texture art direction for Blender with brushwork albedo, soft value transitions, and stylized PBR restraint. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [hard-surface](hard-surface/SKILL.md) | AAA hard surface modeling for sci-fi, industrial, military, vehicles, weapons, robotics, and mechanical props. Use for boolean/bevel workflo | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [hd-2d-style](hd-2d-style/SKILL.md) | HD-2D art direction combining pixel characters/sprites with 3D environments, depth of field, and theatrical lighting. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [health](health/SKILL.md) | Code quality dashboard. (gstack) | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [help](help/SKILL.md) | What should I do next? Use when stuck or you don't know what to do. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [historical-worlds](historical-worlds/SKILL.md) | Historical and period world art direction for Blender including Western, pirate, samurai/ninja, Viking, ancient Egypt/Greece/Rome, Victorian | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [horror-style](horror-style/SKILL.md) | Psychological horror art direction for Blender assets inspired by Silent Hill, Resident Evil, Chilla's Art, Fear to Fathom, and Iron Lung. U | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [humanizer](humanizer/SKILL.md) | Rewrite AI-sounding text to read as human-written — removes stock phrasing, over-hedging, and robotic structure. Use when the user says text | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [idea-refine](idea-refine/SKILL.md) | Refines raw ideas into sharp, actionable concepts through structured divergent and convergent thinking. Use when an idea is still vague, whe | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | EJII Sovereign License |
| [image-enhancer](image-enhancer/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [image-to-code](image-to-code/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [image-to-code-skill](image-to-code-skill/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [imagegen](imagegen/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [imagen](imagen/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [imozuru](imozuru/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [implement](implement/SKILL.md) | Implement a piece of work based on a spec or set of tickets. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [implement-spec](implement-spec/SKILL.md) | Implement the result of /to-spec and /to-tickets in code. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [incremental-implementation](incremental-implementation/SKILL.md) | Delivers changes incrementally in thin, verifiable slices. Use when implementing any feature or change that touches more than one file, or w | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | EJII Sovereign License |
| [indie-horror-aesthetics](indie-horror-aesthetics/SKILL.md) | Indie horror aesthetic pack for Blender covering Silent Hill, Fear to Fathom, Puppet Combo, corporate horror, cabin/forest/hospital horror,  | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [input-systems](input-systems/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [isometric-style](isometric-style/SKILL.md) | Isometric and strategy-game art direction for Blender including diorama framing, true-iso camera setup, readable silhouettes, and tile asset | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [itch-publish](itch-publish/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [qa](qa/SKILL.md) | Systematically QA test a web application and fix bugs found. (gstack) | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [qa-only](qa-only/SKILL.md) | Report-only QA testing. (gstack) | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [land-and-deploy](land-and-deploy/SKILL.md) | Land and deploy workflow. (gstack) | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| `last-30-days` *(Quarantined Metadata)* | Research what people actually say about any topic in the last 30 days. Pulls posts and engagement from Reddit, X, YouTube, TikTok, Hacker Ne | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| `last30days` *(Quarantined Metadata)* | Research what people actually say about any topic in the last 30 days. Pulls posts and engagement from Reddit, X, YouTube, TikTok, Hacker Ne | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [last30days-skill](last30days-skill/SKILL.md) | Multi-source temporal timeline synthesis and changelog aggregation. Identifies recent infrastructural shifts, config mutations, and deployme | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | EJII Sovereign License |
| [launch-checklist](launch-checklist/SKILL.md) | Launch readiness across every department: code, content, store, marketing, community, infrastructure, legal, go/no-go sign-offs. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [learn](learn/SKILL.md) | Manage project learnings. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [learn-claude-code](learn-claude-code/SKILL.md) | Zero-dependency agent loop architectural blueprints. Explains and implements low-overhead agentic loops, state machines, and terminal execut | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | EJII Sovereign License |
| [legal-templates](legal-templates/SKILL.md) | Privacy Policy, Terms of Service, NDA, GDPR/KVKK compliance templates for SaaS products | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [library-curator](library-curator/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [lighting](lighting/SKILL.md) | Cinematic and game lighting in Blender including three-point lighting, HDRI, horror lighting, volumetrics, rim lighting, and mood-driven ill | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [linkedin-ads](linkedin-ads/SKILL.md) | LinkedIn Campaign Manager, Lead Gen Forms, matched audiences, B2B funnel, ABM targeting | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [literature-search-europepmc](literature-search-europepmc/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [literature-search-openalex](literature-search-openalex/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [local-tts](local-tts/SKILL.md) | Offline text-to-speech on this PC (sherpa-onnx; Turkish and English voices, no cloud or key). Use to narrate text, make a voiceover or read  | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [lod-pipeline](lod-pipeline/SKILL.md) | Dedicated LOD generation, naming, screen-size targets, and validation for game meshes in Blender via MCP. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [login-flow](login-flow/SKILL.md) | Mobile login and authentication flow screens | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [love2d-core](love2d-core/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [lowpoly-style](lowpoly-style/SKILL.md) | Low-poly art direction for Blender inspired by PS1/PS2, Lethal Company, Mouthwashing, and Fear to Fathom. Use for readable silhouettes, mini | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [make-pdf](make-pdf/SKILL.md) | Turn any markdown file into a publication-quality PDF. (gstack) | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [managing-python-dependencies](managing-python-dependencies/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Apache-2.0 |
| [marketing-psychology](marketing-psychology/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [mascot-puppet-horror](mascot-puppet-horror/SKILL.md) | Mascot and puppet horror art direction for Blender with cheerful brand characters made wrong, felt/foam materials, and uncanny performance. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [materials](materials/SKILL.md) | Blender PBR and stylized material creation for metal, wood, concrete, fabric, glass, dirt, rust, and procedural shaders. Use for look develo | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [mattpocock](mattpocock/SKILL.md) | Engineering workflow interrogation and specification elicitation. Features /grillme and deep iterative Q&A to interrogate incomplete diagnos | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | EJII Sovereign License |
| [mattpocock-skills](mattpocock-skills/SKILL.md) | Engineering workflow interrogation and specification elicitation. Features /grillme and deep iterative Q&A to interrogate incomplete diagnos | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | EJII Sovereign License |
| [migrate-to-shoehorn](migrate-to-shoehorn/SKILL.md) | Migrate test files from `as` type assertions to @total-typescript/shoehorn. Use when user mentions shoehorn, wants to replace `as` in tests, | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [minimax-docx](minimax-docx/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [minimax-pdf](minimax-pdf/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [minimalist-style](minimalist-style/SKILL.md) | Minimalist and abstract-leaning art direction for Blender with reduced forms, limited palettes, and negative space. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [ml-best-practices](ml-best-practices/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Apache-2.0 |
| [mobile-testing](mobile-testing/SKILL.md) | Detox E2E, Maestro testing, mobile test automation, device farm integration | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [modernize](modernize/SKILL.md) | >- | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [nanobanana-ppt](nanobanana-ppt/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [neon-retrofuturism](neon-retrofuturism/SKILL.md) | Neon, vaporwave, synthwave, and retrofuturistic mood/art direction for Blender with grid horizons, chrome, and dusk palettes. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [new-game](new-game/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [noir-style](noir-style/SKILL.md) | Noir art direction for Blender with high-contrast lighting, wet streets, silhouettes, and monochrome or limited-color grading. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [obsidian-second-brain](obsidian-second-brain/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [od-next-media-inputs](od-next-media-inputs/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [office-hours](office-hours/SKILL.md) | YC Office Hours — two modes. (gstack) | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [ollama-local](ollama-local/SKILL.md) | Ollama local LLM setup, Modelfile customization, quantization selection, API integration | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [onboard](onboard/SKILL.md) | Onboarding doc for a new contributor or agent — project state, conventions, priorities relevant to the specified role. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [openapi-spec](openapi-spec/SKILL.md) | OpenAPI 3.1 specification, Zod-to-schema generation, SDK generation, mock servers | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [output-skill](output-skill/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [painterly-style](painterly-style/SKILL.md) | Painterly art direction spanning watercolor and oil-painting looks for Blender using soft edges, pigment texture, and illustrative lighting. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [pandas-analysis](pandas-analysis/SKILL.md) | Pandas/Polars data wrangling, EDA patterns, missing data handling, feature engineering | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [patch-notes](patch-notes/SKILL.md) | Player-facing patch notes from git history and changelogs. Translates developer language into player communication. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [paywall-upgrade-cro](paywall-upgrade-cro/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [pdf](pdf/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [perf-profile](perf-profile/SKILL.md) | Performance profiling — find bottlenecks, measure against budgets, produce ranked optimization recommendations. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [performance-optimization](performance-optimization/SKILL.md) | Optimizes application performance across frontend, backend, queries, and databases. Use when performance requirements exist, when you suspec | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [phaser-arcade-physics](phaser-arcade-physics/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [phaser-core](phaser-core/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [physics-sim](physics-sim/SKILL.md) | Rigid body, soft body, and destruction setups in Blender including constraints, cell fracture debris, and baked caches via MCP. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [physics-tuning](physics-tuning/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [pixel-art-style](pixel-art-style/SKILL.md) | Pixel-art and texel-constrained art direction for Blender assets destined for pixel rendering, low-res textures, or HD-2D-adjacent pixel rea | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [pixelbin-media](pixelbin-media/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [pixijs-rendering](pixijs-rendering/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [plan-tune](plan-tune/SKILL.md) | Self-tuning question sensitivity + developer psychographic for gstack (v1: observational). (gstack) | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [platformer](platformer/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [playtest-report](playtest-report/SKILL.md) | Structured playtest report template, or turn existing playtest notes into structured feedback. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [ponytail](ponytail/SKILL.md) | YAGNI-driven behavioral discipline enforcing lean code changes and lazy engineering logic. Restricts changes to the absolute minimum necessa | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [ponytail-debt](ponytail-debt/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [ponytail-gain](ponytail-gain/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [ponytail-help](ponytail-help/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [ponytail-lazy-dev](ponytail-lazy-dev/SKILL.md) | YAGNI-driven behavioral discipline enforcing lean code changes and lazy engineering logic. Restricts changes to the absolute minimum necessa | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | EJII Sovereign License |
| [poster-hero](poster-hero/SKILL.md) | Vertical poster or Moments-style share image with strong visual impact. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [ppt-keynote](ppt-keynote/SKILL.md) | Apple Keynote-quality slides, one card per screen, with keyboard left/right navigation. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [pptx](pptx/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [pptx-generator](pptx-generator/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [pr](pr/SKILL.md) | Use when writing a PR body. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [predictingthepast](predictingthepast/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [procedural-gen](procedural-gen/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [project-stage-detect](project-stage-detect/SKILL.md) | Analyze project state, detect stage, identify gaps, recommend next steps. 'Where are we in development?' | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [prompt-caching-strategy](prompt-caching-strategy/SKILL.md) | >- | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | EJII Sovereign License |
| [prompt-master](prompt-master/SKILL.md) | Generates optimized prompts for AI tools. Activates only when the user explicitly asks to write, fix, improve, or adapt a prompt for a speci | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [prop-artist](prop-artist/SKILL.md) | Everyday and hero prop modeling for furniture, tools, household objects, kitbash parts, and readable game props. Use when hard-surface is to | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [prototype-fast](prototype-fast/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [psx-horror-style](psx-horror-style/SKILL.md) | PS1/PSX-era horror art direction combining low-poly affine textures, limited color depth, fog, and psychological horror staging for Blender  | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [puzzle](puzzle/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [pygame-core](pygame-core/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [rea-video](rea-video/SKILL.md) | 逆向拆解一条视频是怎么做出来的——逐镜头判断实拍 / 影视片段 / AI 生成 / 3D 渲染 / 2D 动画 / 定格动画 / 代码模板渲染 / 录屏截图 / 静态图推拉 / 静帧，以及实拍是否经过 AI 加工（换脸、对口型、风格化），标出后期叠加层（逐句字幕时间轴、花字、标题 | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [realistic-style](realistic-style/SKILL.md) | Photorealistic AAA art direction for Blender including photogrammetry cleanup, real-world scale, high-poly workflows, PBR accuracy, and scan | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [release-notes-one-pager](release-notes-one-pager/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [rendering](rendering/SKILL.md) | Blender rendering with Cycles and Eevee including sampling, denoising, camera setup, render passes, color management, and render optimizatio | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [replicate](replicate/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [research](research/SKILL.md) | Investigate a question against high-trust primary sources and capture the findings as a Markdown file in the repo. Use when the user wants a | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [research-decision-room](research-decision-room/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [resolving-mcp-region-configs](resolving-mcp-region-configs/SKILL.md) | >- | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Apache-2.0 |
| [retro](retro/SKILL.md) | Conduct a retrospective on a coding session. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [retro-16bit-style](retro-16bit-style/SKILL.md) | Retro 16-bit art direction for Blender-assisted SNES/Genesis-era color richness, dither cues, and sprite-like clarity. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [retro-8bit-style](retro-8bit-style/SKILL.md) | Retro 8-bit art direction for Blender-assisted pixel/low-res aesthetics inspired by NES-era constraints. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [retrospective](retrospective/SKILL.md) | Sprint or milestone retrospective from completed work, velocity, blockers. Actionable insights for the next iteration. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [roblox-characters](roblox-characters/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [roblox-datastores](roblox-datastores/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [roblox-luau](roblox-luau/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [roblox-physics](roblox-physics/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [roblox-simulator-economy](roblox-simulator-economy/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [roblox-studio-workflow](roblox-studio-workflow/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [roguelike](roguelike/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [router](router/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [rpg](rpg/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [save-systems](save-systems/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [scaffold-exercises](scaffold-exercises/SKILL.md) | Create exercise directory structures with sections, problems, solutions, and explainers that pass linting. Use when user wants to scaffold e | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [scene-assembly](scene-assembly/SKILL.md) | Large scene layout in Blender with collections, linking, overrides, streaming-friendly organization, and set assembly via MCP. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [sci-fi-punk-worlds](sci-fi-punk-worlds/SKILL.md) | Sci-fi and punk world art direction for Blender including hard sci-fi, space, cyberpunk, steampunk, dieselpunk, atompunk, solarpunk, biopunk | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [scope-check](scope-check/SKILL.md) | Scope creep check — current scope versus the original plan. Flags additions, quantifies bloat, recommends cuts. 'Any scope creep?' | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [scroll-world](scroll-world/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [sculpting](sculpting/SKILL.md) | Blender sculpting for organic and hard surface detail using Dyntopo, multiresolution, brushes, alpha workflow, wrinkles, and damage. Use whe | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [seo-aeo](seo-aeo/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [seo-backlinks](seo-backlinks/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [seo-content](seo-content/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [seo-keywords](seo-keywords/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [seo-local](seo-local/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [set-dressing](set-dressing/SKILL.md) | Set dressing and environmental storytelling placement for interiors and exteriors using prop density, narrative clusters, and readability ru | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [settings](settings/SKILL.md) | View or change project config — effective merged values, or set locally in project.local.yaml. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [setup-deploy](setup-deploy/SKILL.md) | Configure deployment settings for /land-and-deploy. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [setup-engine](setup-engine/SKILL.md) | Configure engine and version. Pins it in CLAUDE.md; WebSearch fills reference docs when the version is beyond LLM training data. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| `setup-gbrain` *(Quarantined Metadata)* | Set up gbrain for this coding agent: install the CLI, initialize a local PGLite or Supabase brain, register MCP, capture per-remote trust po | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [setup-matt-pocock-skills](setup-matt-pocock-skills/SKILL.md) | Configure this repo for the engineering skills: set up its issue tracker, triage label vocabulary, and domain doc layout. Run once before fi | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [setup-pre-commit](setup-pre-commit/SKILL.md) | Set up Husky pre-commit hooks with lint-staged (Prettier), type checking, and tests in the current repo. Use when user wants to add pre-comm | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [shader-dev](shader-dev/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [shader-programming](shader-programming/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [skill-improve](skill-improve/SKILL.md) | Improve a skill via a test-fix-retest loop — static checks, targeted fixes, keep or revert on score change. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [slack-gif-creator](slack-gif-creator/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [slides](slides/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [soak-test](soak-test/SKILL.md) | Soak test protocol for extended play — what to observe and log for slow leaks, fatigue, late-appearing edge cases. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [sol-loop](sol-loop/SKILL.md) | Use when the user says "sol loop". | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [sora](sora/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [spec](spec/SKILL.md) | Turn vague intent into a precise, executable spec in five phases. (gstack) | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [speech](speech/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [sprint-plan](sprint-plan/SKILL.md) | New or updated sprint plan from the current milestone, completed work, and available capacity. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [sprint-status](sprint-status/SKILL.md) | Fast, concise sprint snapshot — burndown and emerging risks for situational awareness. 'How is the sprint going?' | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [steam-publish](steam-publish/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [stitch-loop](stitch-loop/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [stripe-integration](stripe-integration/SKILL.md) | Stripe checkout sessions, subscriptions, webhook handling, refunds, test mode | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [survival-crafting](survival-crafting/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [swiss-creative-mode-template](swiss-creative-mode-template/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [swiss-user-research-video-template](swiss-user-research-video-template/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [takeover](takeover/SKILL.md) | Take over existing work. Use when the user asks to take over a PR, branch, or agent thread, or requests a takeover. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [teach](teach/SKILL.md) | Teach the user a new skill or concept, within this workspace. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [team-qa](team-qa/SKILL.md) | Orchestrate the QA team through a full testing cycle — qa-lead strategy and test plan, qa-tester case writing, execution, sign-off. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [team-release](team-release/SKILL.md) | Orchestrate the release team — release-manager, qa-lead, devops-engineer, producer — to execute a release from candidate to deployment. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [tech-debt](tech-debt/SKILL.md) | Track, categorize and prioritize technical debt across the codebase — scans for debt indicators, maintains a register. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [technical-writing](technical-writing/SKILL.md) | Docs-as-code, Diátaxis framework (tutorial/how-to/reference/explanation), API docs, README | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [texture-workflow](texture-workflow/SKILL.md) | Production texture workflow for atlases, baking AO/curvature/normal/roughness maps, decals, and texture memory optimization. Use for game-re | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [test-driven-development](test-driven-development/SKILL.md) | Drives development with tests using the red-green-refactor loop. Use when implementing any logic, fixing any bug, or changing any behavior.  | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [test-helpers](test-helpers/SKILL.md) | Generate engine-specific test helper libraries — assertion utilities, factory functions, mocks in the engine's test folder. Reduces boilerpl | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [test-setup](test-setup/SKILL.md) | Scaffold the test framework and CI — tests/ directory, engine test runner, GitHub Actions workflow. Once, before the first sprint. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [to-questionnaire](to-questionnaire/SKILL.md) | Turn a decision you can't fully answer into a questionnaire for someone else to fill in. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [to-spec](to-spec/SKILL.md) | Turn the current conversation into a spec and publish it to the project issue tracker: no interview, just synthesis of what you've already d | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [to-tickets](to-tickets/SKILL.md) | Break a plan, spec, or the current conversation into a set of tracer-bullet tickets, each declaring its blocking edges, published to the con | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [tower-defense](tower-defense/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [triage](triage/SKILL.md) | Move issues and external PRs through a state machine of triage roles, categorise, verify, grill if needed, and write agent-ready briefs. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [troubleshooting](troubleshooting/SKILL.md) | Uses Chrome DevTools MCP and documentation to troubleshoot connection and target issues. Trigger this skill when list_pages, new_page, or na | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [ucsc-conservation-and-tfbs](ucsc-conservation-and-tfbs/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [unfreeze](unfreeze/SKILL.md) | Clear the freeze boundary set by /freeze, allowing edits to all directories again. (gstack) | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [unity-csharp-scripting](unity-csharp-scripting/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [unity-input-system](unity-input-system/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [unity-navmesh](unity-navmesh/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [unity-physics](unity-physics/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [unity-scriptableobjects](unity-scriptableobjects/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [unity-tilemap-2d](unity-tilemap-2d/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [unreal-behavior-trees](unreal-behavior-trees/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [unreal-blueprints](unreal-blueprints/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [unreal-cpp-gameplay](unreal-cpp-gameplay/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [unreal-enhanced-input](unreal-enhanced-input/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [unreal-niagara](unreal-niagara/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [unreal-packaging](unreal-packaging/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [using-agent-skills](using-agent-skills/SKILL.md) | Discovers and invokes agent skills. Use when starting a session, or when you need to decide which skill or workflow applies to the piece of  | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | EJII Sovereign License |
| [uv](uv/SKILL.md) | >- | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [vegetation-artist](vegetation-artist/SKILL.md) | Vegetation and foliage authoring for Blender including trees, plants, grass cards, canopy LODs, and game-friendly leaf atlases via MCP. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [vehicle-artist](vehicle-artist/SKILL.md) | Dedicated vehicle modeling for cars, trucks, aircraft, ships, boats, mechs, and transit assets with proportion, panel flow, and game LOD awa | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [venice-audio-music](venice-audio-music/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [venice-audio-speech](venice-audio-speech/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [venice-image-edit](venice-image-edit/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [venice-image-generate](venice-image-generate/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [venice-video](venice-video/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [vercel-composition-patterns](vercel-composition-patterns/SKILL.md) | React composition patterns that scale. Use when refactoring components with | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [vfx-fx](vfx-fx/SKILL.md) | Cinematic and game VFX in Blender including smoke, fire, particles, trails, and Geometry Nodes FX setups via MCP. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [vfx-text-cursor](vfx-text-cursor/SKILL.md) | Cursor light trail, chromatic rays, and directional flares for word-by-word quote reveals in video intros. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [video-downloader](video-downloader/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [visual-console-eras](visual-console-eras/SKILL.md) | Visual era art direction for Blender covering PS1–PS5 stylistic cues, retro arcade, DOS, CRT, VHS, and film-grain presentation. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [visual-novel](visual-novel/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [voxel-style](voxel-style/SKILL.md) | Voxel and Minecraft-adjacent art direction for Blender with block grid modeling, limited palettes, and chunk-friendly assets. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [youtube-clipper](youtube-clipper/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [wait-what](wait-what/SKILL.md) | Stop. That last message did not land: re-pitch it. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [wayfinder](wayfinder/SKILL.md) | Plan a huge chunk of work (more than one agent session can hold) as a shared map of decision tickets on your issue tracker, and resolve them | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [web-clone](web-clone/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | MIT |
| [workflow-skill-creator](workflow-skill-creator/SKILL.md) | > | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [wpds](wpds/SKILL.md) | \| | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [writing-beats](writing-beats/SKILL.md) | Writing, exploit; assemble raw material into a journey of beats, grounding each term before a beat leans on it. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [writing-for-agents](writing-for-agents/SKILL.md) | Writing documents for agents. Use when creating or editing skills, or modifying AGENTS.md or CLAUDE.md. | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
| [writing-skills](writing-skills/SKILL.md) | Use when creating new skills, editing existing skills, or verifying skills work before deployment | `TIER_3_DORMANT_EXPLICIT_INVOCATION` | Open Agent Skills Standard |
