---
name: awesome-claude-skills
description: Curated aggregator and registry of MCP servers, agent toolkits, and modular runtime capabilities. Acts as a lookup registry when checking if a secondary runtime capability is validly installed on the host.
license: Apache-2.0
---

# Awesome Claude Skills — Tool & MCP Capability Registry

This skill serves as an authoritative registry of standardized Model Context Protocol (MCP) servers, toolkits, and capability plugins. It allows the agent to inspect the local environment and verify whether required capabilities (e.g. database connectors, packet capture bridges, browser controllers) are available before invoking them.

---

## 🗂️ Standardized Capability Taxonomy

| Category | Typical Provider / Tool | EJII Native Subsystem |
| :--- | :--- | :--- |
| **Network Wire** | Npcap / Wireshark CLI | `src/sniffer/wire-dissector-apex.ts` |
| **Host CIM** | WMI / PowerShell Core | `src/systems/hardware-kernel-inspector.ts` |
| **Browser DOM** | Playwright / Chrome DevTools MCP | `tests/verify-e2e-browser-workflow.js` |
| **Database** | SQLite3 / Postgres MCP | `src/db/database.js` (WAL Mode) |
| **Time-Series** | Prometheus / OpenTelemetry | `src/systems/cncf-observability-exporter.js` |

---

## 💻 EJII Integration: Runtime Capability Discovery

Before launching complex multi-step diagnostics:
```javascript
export function verifyRuntimePrerequisites(requiredTools) {
  const missing = [];
  for (const tool of requiredTools) {
    if (!global.ejiiToolRegistry.has(tool)) {
      missing.push(tool);
    }
  }
  if (missing.length > 0) {
    throw new Error(`Capability Missing: ${missing.join(', ')}. Install or enable before continuing.`);
  }
  return true;
}
```
