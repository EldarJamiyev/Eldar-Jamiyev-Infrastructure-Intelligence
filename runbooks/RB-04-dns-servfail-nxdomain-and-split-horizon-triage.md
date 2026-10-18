# Runbook RB-04: DNS SERVFAIL, NXDOMAIN, and Split-Horizon Resolution Triage

## Objective
Diagnose and isolate DNS query resolution anomalies, distinguishing between non-existent domain records (NXDOMAIN, RCODE 3), authoritative nameserver delegation failures (SERVFAIL, RCODE 2), recursive resolver timeout drops, and internal/external split-horizon routing divergence across local adapters.

## Step-by-Step Procedure in EJII
1. **Filter DNS Frames in Wireshark Sniffer:**
   - Use Display Filter AST: `dns || udp.port == 53 || tcp.port == 53`.
   - Alternatively click Plain English AI Filter -> `dns queries` or enter `dns errors`.
2. **Examine DNS Header Flags & RCODE:**
   - In 3-Pane Deep Packet Inspector, select the DNS response frame.
   - Inspect `dns.flags.rcode` (`0 = NoError`, `2 = ServFail`, `3 = NXDomain`, `5 = Refused`).
   - Check `dns.flags.authoritative` (AA bit) and `dns.flags.truncated` (TC bit forcing TCP fallback).
3. **Execute 5-Stage Guided Cross-Section Investigation:**
   - Enter target domain in Section 5 Investigation Workbench.
   - Stage 2 (RFC 1035 DNS Evaluation) runs active A/AAAA queries against all configured adapter DNS resolvers (`192.168.31.1`, upstream forwarders).
   - Verify if resolution succeeds via recursive server but fails via local stub cache (flush cache via PC Automation if poisoned).
4. **Autonomous Policy Compliance:**
   - Check if resolver is external or internal under POL-01 boundary rules.
