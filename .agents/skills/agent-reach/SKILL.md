---
name: agent-reach
description: Zero-fee local web research and threat intelligence scraper. Extracts and parses public security advisories, CVE databases, and IETF protocol specs via unprivileged CLI workflows without external API costs.
license: MIT
---

# Agent-Reach — Zero-Fee Web Research & Threat Intelligence

Agent-Reach equips the autonomous agent with unprivileged, zero-fee web retrieval capabilities to cross-reference local diagnostic signals against authoritative public sources (IETF RFCs, CVE databases, vendor OUI registrations, and CRL/OCSP endpoints).

---

## 🔍 Core Research Pipelines

1. **Local CLI Headless Fetching**:
   - Uses native `curl` or unprivileged HTTP clients with strict timeouts and memory caps.
   - Extracts semantic Markdown/text from HTML without rendering full JavaScript engines.
2. **IEEE OUI & Vendor Resolution**:
   - Downloads and maintains local cached mappings of MAC OUI prefixes to hardware manufacturers (Cisco, HP, Apple, Intel, Realtek).
3. **Public Vulnerability & Cipher Posture Auditing**:
   - Queries public cipher security databases to evaluate TLS 1.2/1.3 cipher suites and known certificate authority revocations.

---

## 💻 EJII Integration: TLS & Vulnerability Pipeline

In EJII, `agent-reach` powers external threat correlation:
- Validates discovered SSL/TLS certificate chains against root CA stores.
- Flags deprecated ciphers (RC4, 3DES, CBC-mode ciphers) based on current NIST and IETF deprecation standards.
- Enforces strict SSRF defense: all external queries are routed through canonicalized DNS proxies to prevent cloud metadata exfiltration.
