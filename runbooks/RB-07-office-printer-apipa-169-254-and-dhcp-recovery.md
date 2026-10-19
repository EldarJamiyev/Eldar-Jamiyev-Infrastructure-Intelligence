# Runbook RB-07: Office Printer, APIPA (169.254.x.x) and DHCP Recovery Triage

## Objective
Isolate and resolve RFC 3927 Automatic Private IP Addressing (APIPA, `169.254.1.0` to `169.254.254.255`) self-assignment faults occurring on office printers, multifunction devices (MFPs), VoIP desk phones, and operator workstations. Distinguish link-local self-assignment caused by DHCP DORA exhaustion or switchport VLAN partitioning from intentional link-local communication, while maintaining strict isolation from cloud metadata SSRF targets (`169.254.169.254`).

## Technical Root Cause Analysis
1. **RFC 2131 DHCP DORA Lease Failure:**
   When an office printer boots, its network interface sends a DHCPDISCOVER broadcast (`UDP 67/68`, `255.255.255.255`). If the office default gateway/DHCP router (`192.168.31.1`) does not reply with a DHCPOFFER within the timeout window (due to pool exhaustion, spanning-tree port convergence delay, or physical cable disconnection), RFC 3927 mandates that the host self-assign a pseudo-random address in `169.254.0.0/16`.
2. **Subnet Isolation:**
   Workstations on the office LAN (`192.168.31.0/24`) cannot route packets directly to `169.254.x.x` endpoints because routers do not forward link-local traffic across subnet boundaries.

## Dual-Audience Resolution Procedure in EJII

### For Everyday IT Support & L1 Helpdesk Staff
1. **Open Ultra IP Scanner (View 3):**
   - Click the `⚠️ APIPA / Issues` quick-filter pill or type the printer's display IP (e.g., `169.254.45.12`) into the **Diagnose Device / APIPA IP** input.
   - Click `[ 🩺 Plain-Language Troubleshooter ]` to view the **Visual Connection Path** and **Step-by-Step Fix Plan**.
2. **Verify Physical Cable and Link Lights:**
   - Confirm the Ethernet cable is firmly seated in the printer and wall port (verify solid green/amber activity LEDs).
3. **Power-Cycle Device or Release/Renew Lease:**
   - Turn the printer off, wait 15 seconds, and power it back on.
   - On printers with a control panel: Navigate to **Network Settings -> TCP/IP -> IPv4 -> DHCP** and select **Re-request DHCP Lease**.
4. **Assign Static Reserved Office IP:**
   - In the office router DHCP settings, reserve an IP address (e.g. `192.168.31.250`) mapped to the printer's MAC address (e.g., `00:1E:8F:xx:xx:xx`).

### For Senior Network Engineers & Systems Architects
1. **Wireshark BPF Stream Inspection:**
   - In View 2, set BPF filter: `bootp || udp.port == 67 || udp.port == 68`.
   - Inspect transaction IDs (`xid`), lease times (DHCP Option 51), and verify whether the DHCP server sends `DHCPNAK` (Option 53 = 6).
2. **ARP Conflict Detection (RFC 5227):**
   - Verify whether gratuitous ARP probes (`ARP Request for 169.254.x.x with sender 0.0.0.0`) receive conflicting replies.
3. **802.1Q VLAN Tagging & Port Security:**
   - Verify access port switch configuration: check for `switchport access vlan` mismatch or 802.1X port authorization failure blocking DHCP broadcasts.
