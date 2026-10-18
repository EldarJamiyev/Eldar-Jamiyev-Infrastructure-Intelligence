# Runbook RB-02: Disambiguating TCP Reset (ECONNREFUSED) vs. Stateful Firewall Silent Drop (ETIMEDOUT)

## Technical Evidence Matrix (RFC 793 & RFC 2979)
- **Case A: Explicit TCP RST Received (`ECONNREFUSED` / `WSAECONNREFUSED`):**
  - **Wire Proof:** Destination host replies to `TCP SYN` with `TCP [RST, ACK]` within $\approx 1\text{–}50\text{ms}$.
  - **Mathematical Deduction:** Proves L2 switching, L3 routing, and destination host OS kernel are 100% online. Eliminates `REMOTE_HOST_DOWN` ($0\%$) and `FIREWALL_SILENT_DROP` ($0\%$). Isolates fault to `PORT_CLOSED_SERVICE_STOPPED` ($\ge 90\%$).
  - **Remediation:** Verify target daemon/service status and listening socket binding (`netstat -ano | findstr LISTENING`).
- **Case B: No Response Within Timeout (`ETIMEDOUT` / `WSAETIMEDOUT`):**
  - **Wire Proof:** Client transmits `TCP SYN` and exponential-backoff `TCP SYN` retransmissions with zero response packets.
  - **Disambiguation:** Run `ICMP_PING_GATEWAY` (to verify local L2/L3 perimeter) followed by `ICMP_PING_TARGET` and `TCP_CONNECT_ALTERNATE_PORT`. If target responds on port 80/ICMP but drops port 443, promote `FIREWALL_SILENT_DROP` (RFC 2979).
