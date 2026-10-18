# Runbook RB-06: Path MTU Black Hole Detection and TCP Retransmission Forensics

## Objective
Identify silent packet loss caused by Path MTU (PMTU) black holes where Don't Fragment (DF) bit is set and intermediate routers discard packets without returning ICMP Type 3 Code 4 (`Destination Unreachable, Fragmentation Needed`), leading to connection stalls on large TCP payload segments despite successful initial 3-way handshakes.

## Step-by-Step Procedure in EJII
1. **Analyze TCP Retransmissions & Delta Timings:**
   - In Section 2 Wireshark Sniffer, view `⚠️ Failures Only` or filter: `tcp.analysis.retransmission || tcp.analysis.duplicate_ack`.
   - Observe the `TCP Delta / Retx` column. Check if small SYN/ACK packets (60-74 bytes) succeed with low latency, but subsequent large 1400-1500 byte TLS Application Data frames repeatedly retransmit.
2. **Execute Path MTU Dual Probe:**
   - From Section 1 Topology or Section 5 Diagnostics, initiate a Dual Probe with sweep payload sizing (1472, 1400, 1372, 1200 bytes) with DF bit asserted.
   - Determine the maximum unfragmented MTU across the physical path to the remote gateway.
3. **Inspect TCP Window & Zero-Window Advertisements:**
   - Verify whether receiver window size collapses to 0 (`[ZERO WIN]`), indicating host buffer exhaustion or socket read starvation by the receiving process.
4. **Remediate Host Interface MTU:**
   - In Section 4 PC Automation, utilize interface tuning scripts to adjust IPv4 MTU (e.g., `netsh interface ipv4 set subinterface "Wi-Fi" mtu=1400 store=persistent`) if tunneling or VPN overhead causes PMTU black holes.
