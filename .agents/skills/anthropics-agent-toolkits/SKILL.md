---
name: anthropics-agent-toolkits
description: Official agentic runtime toolkits for low-level OS environments, bash/powershell controls, POSIX filesystem operations, and sub-process streams. Supplements EJII’s OS-native double-stack ICMP ping, routing table parsers, and /proc/net/ monitoring.
license: Apache-2.0
---

# Anthropics Agent Toolkits — Native OS Runtime & Sub-Process Integration

This skill packages the design patterns, security conventions, and execution idioms established by Anthropic for running autonomous agents directly within host environments, terminals, and containerized shells.

---

## 🔒 Safe Sub-Process Execution Patterns

When invoking host utilities (`ping`, `netstat`, `ipconfig`, `ip route`, `wmic`):

### 1. Bounded Execution Timeouts
- Every process spawn MUST have a hard, non-negotiable timeout (e.g. 5000ms for network probes, 15000ms for system reports).
- Never allow orphaned child processes or zombie threads.
```javascript
import { spawn } from 'child_process';

function execWithSafeTimeout(cmd, args, timeoutMs = 5000) {
  return new Promise((resolve, reject) => {
    const proc = spawn(cmd, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';

    const timer = setTimeout(() => {
      proc.kill('SIGTERM');
      reject(new Error(`Process timeout exceeded (${timeoutMs}ms)`));
    }, timeoutMs);

    proc.stdout.on('data', d => stdout += d);
    proc.stderr.on('data', d => stderr += d);

    proc.on('close', code => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
  });
}
```

### 2. Stream Buffering & Memory Protection
- Cap incoming `stdout` and `stderr` buffers to prevent memory exhaustion (e.g. max 1MB buffer cap).
- Gracefully truncate logs that exceed display or memory thresholds.

---

## 💻 EJII Integration: Native Network & Kernel Introspection

In EJII, `anthropics-agent-toolkits` supplements unprivileged diagnostics:
- **Windows Subsystems**: Native Win32 CIM/WMI queries for CPU core topology, RAM banks, and disk S.M.A.R.T. status.
- **Linux Subsystems**: Direct parsing of `/proc/net/dev`, `/proc/net/tcp`, and `/proc/sys/net/ipv4/*` without requiring external binaries.
- **Network Stack**: Native ICMP Echo Request driver, raw socket stream decoders, and cross-platform routing table parsers.
