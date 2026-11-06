# Runbook RB-08: Print Spooler, HP JetDirect (Port 9100) and Office LAN Equipment Triage

## Objective
Diagnose and resolve service-level printer failures on office local area networks where the printer is responsive to ICMP ping or ARP discovery, but client print jobs stall, time out, or fail to transmit. Standardize troubleshooting for HP JetDirect (RAW TCP `9100`), Internet Printing Protocol (IPP, TCP `631`), Line Printer Daemon (LPD, TCP `515`), and Windows Print Spooler (`spoolsv.exe`).

## Technical Root Cause Analysis
1. **RAW TCP Port 9100 / JetDirect Hang:**
   JetDirect listens on TCP port `9100` and accepts unformatted raw PostScript/PCL data directly into the printer buffer. If a corrupted job is sent or memory fills, the print server socket either drops incoming SYN packets (`ETIMEDOUT`) or actively refuses connections (`ECONNREFUSED`).
2. **Windows Print Spooler Queue Deadlock:**
   The client-side Windows Print Spooler service (`spoolsv.exe`) stores pending jobs in `C:\Windows\System32\spool\PRINTERS` as `.SPL` (Spool File) and `.SHD` (Shadow File) pairs. When a corrupt file locks the queue, subsequent print jobs accumulate indefinitely.
3. **Firmware Energy-Saving Deep Sleep:**
   Enterprise printers frequently enter deep power-saving states where the network PHY remains powered to respond to ARP, but the embedded controller disables the internal print listening daemons on ports `9100`/`631`.

## Dual-Audience Resolution Procedure in EJII

### For Everyday IT Support & L1 Helpdesk Staff
1. **Check Printer Reachability & Service Ports:**
   - In View 3 (Ultra IP Scanner), locate the printer row (icon `🖨️`) and click `[ 🩺 Plain-Language Troubleshooter ]`.
   - Check if the diagnosis indicates: `"Printer Network Online — Print Service / Spooler Stalled"`.
2. **Clear Stuck Print Queue on Windows PC:**
   - In View 4 (PC Automation), locate `Restart Print Spooler Service & Clear Queue.bat`.
   - Click **Run Script** (or use the 1-click button inside the Troubleshooter Modal).
   - This automatically stops the spooler service, clears jammed `.SHD`/`.SPL` files, and restarts the spooler.
3. **Power-Cycle the Printer:**
   - Turn the printer power off, wait 15 seconds, and power it back on to clear its internal memory buffer and reset port `9100`.

### For Senior Network Engineers & Systems Architects
1. **Active Port & Socket Forensic Inspection:**
   - Run low-level TCP socket check: probe ports `9100` (RAW), `631` (IPP/HTTPS), `515` (LPD), and `445` (SMB).
   - Differentiate between connection refusal (`ECONNREFUSED` = print daemon crashed) and silent drop (`ETIMEDOUT` = host firewall or routing ACL).
2. **TLS 1.3 Audit on Management Interface:**
   - For HTTPS administrative portals on port `443`, audit the TLS certificate and cipher suite to confirm expired internal SSL certificates are not blocking driver negotiation.
3. **MAC OUI & Digital Signature Tracking:**
   - Verify MAC vendor OUI matches physical hardware inventory (e.g. `HP Inc.`, `Canon`, `Xerox`, `Brother`).
