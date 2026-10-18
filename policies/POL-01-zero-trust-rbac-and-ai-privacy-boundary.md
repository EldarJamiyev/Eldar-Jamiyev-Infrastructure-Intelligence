# Security Policy POL-01: Zero-Trust Capability RBAC, SSRF Perimeter & AI Telemetry Redaction

## 1. Capability-Based Access Control
All HTTP REST routes and WebSocket control messages enforce explicit capabilities (`system.config.manage`, `users.roles.manage`, `host.remediation.execute`, `host.remediation.preview`, `network.capture.execute`, `network.diagnostics.execute`, `telemetry.read`). Spoofed client headers (`X-EJII-Role`) are unconditionally ignored.

## 2. SSRF & DNS-Rebinding Perimeter
All diagnostic probes canonicalize target inputs and block cloud metadata and link-local ranges (`169.254.0.0/16`, `::ffff:169.254.169.254`, `fd00:ec2::254`, `fe80::/10`, `0.0.0.0/8`, `224.0.0.0/4`, decimal dwords, hex/octal IPs, and HTTP 301/302/307/308 redirect hops to forbidden targets) while preserving RFC 1918 private LAN scopes (`10/8`, `172.16/12`, `192.168/16`) and loopback (`127.0.0.1`, `::1`).

## 3. AI Telemetry Privacy & Local-Only Default
Under `localOnlyPolicy: true`, zero raw telemetry leaves the workstation; ambiguous low-confidence investigations route strictly to air-gapped local Ollama (`qwen2.5-coder:14b`). Whenever external model routing (`OPENAI`, `CLAUDE`, `GEMINI`) is permitted by policy, `redactTelemetryForExternalModel()` strips all JWTs, Bearer tokens, passwords, cookies, and API keys prior to transmission.
