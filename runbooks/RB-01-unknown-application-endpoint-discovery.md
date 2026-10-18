# Runbook RB-01: Discovering Unknown Application Server IPs, Ports, and Transport Dependencies

## Objective
Identify the exact remote server IP address, destination port, transport protocol (TCP/UDP), and domain/SNI for a local Windows application when documentation is unavailable or connections fail silently.

## Step-by-Step Procedure in EJII
1. **Open Wireshark Live Sniffer -> App Finder Mode (`🖥️ App Finder`):**
   - Enter the executable name (e.g., `chrome.exe`, `finance-app.exe`, `Telegram.exe`) or PID in the process filter input.
   - Click **`👁️ Watch`** to activate the Live Application Endpoint Watcher strip.
2. **Correlate OS Kernel Socket Table with Wire Evidence:**
   - EJII queries `Get-NetTCPConnection` and `Get-NetUDPEndpoint` and cross-references local ephemeral ports against passive DNS A/AAAA responses and TLS 1.3 `ClientHello` SNI extensions.
3. **Execute 5-Stage Endpoint Troubleshooter:**
   - Click **`🔍 Troubleshoot`** or **`🚀 Run Full 5-Stage Guided Investigation`** on the discovered `Remote IP:Port`.
   - Review Stage 1 (Process Socket State), Stage 2 (RFC 1035 DNS), Stage 3 (L4 TCP 3-Way Handshake & OS Kernel Error Code), Stage 4 (RFC 8446 TLS 1.3 Handshake & Certificate Validity), and Stage 5 (Bayesian Root-Cause Verdict).
