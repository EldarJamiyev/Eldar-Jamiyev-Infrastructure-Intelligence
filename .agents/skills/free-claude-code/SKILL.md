---
name: free-claude-code
description: Multi-harness terminal engine connecting heterogeneous development environments and local terminals across operating systems. Enables cross-platform parity between desktop and mobile on-call workspaces.
license: MIT
---

# Free Claude Code — Multi-Harness Terminal Engine & Platform Parity

Free Claude Code bridges disparate execution environments (Windows Win32, Linux POSIX, macOS Darwin, containerized Docker shells, and mobile PWA terminals) into a single, unified execution abstraction.

---

## 🌐 Cross-Platform Abstraction Matrix

| Platform | Native Shell | Process Introspection | Network Routing |
| :--- | :--- | :--- | :--- |
| **Windows 11** | PowerShell / CMD | CIM / WMI `Get-CimInstance` | `Get-NetRoute` / `netstat` |
| **Linux (Ubuntu/Alpine)** | Bash / Sh | `/proc/` filesystem | `ip route` / `ss` |
| **Mobile PWA** | WebSockets CLI Bridge | REST Telemetry Poller | Remote Gateway API |

---

## 💻 EJII Integration: Mobile Responsive Field Control

In EJII, this skill provides runtime execution parity across devices:
- Operators running on mobile tablets or phones via `mobile/` access the exact same diagnostic capabilities and terminal outputs as desktop operators.
- Terminal commands are automatically normalized across OS boundaries (e.g. mapping `ipconfig` $\leftrightarrow$ `ip addr`).
