/**
 * EJII Junior-Admin & Rookie Operator Plain-Language Guidance Component
 * Global interactive cheat sheet (Ctrl+H) and plain-English concept explainers.
 */

(function(window) {
  'use strict';

  let isOpen = false;

  const CHEAT_SHEET_DATA = {
    ports: [
      { port: 20, proto: 'TCP', name: 'FTP-Data', desc: 'File Transfer Protocol (Active mode data channel).', sec: 'Insecure (plaintext).' },
      { port: 21, proto: 'TCP', name: 'FTP-Control', desc: 'File Transfer Protocol command channel.', sec: 'Insecure (plaintext credentials).' },
      { port: 22, proto: 'TCP', name: 'SSH / SFTP', desc: 'Secure Shell remote administration and secure file transfer.', sec: 'Encrypted. Secure default.' },
      { port: 23, proto: 'TCP', name: 'Telnet', desc: 'Legacy unencrypted terminal communication.', sec: 'HIGH RISK: Passwords sent in cleartext.' },
      { port: 25, proto: 'TCP', name: 'SMTP', desc: 'Simple Mail Transfer Protocol (MTA server-to-server relay).', sec: 'Opportunistic STARTTLS.' },
      { port: 53, proto: 'UDP/TCP', name: 'DNS', desc: 'Domain Name System resolution. UDP for queries < 512B, TCP for zone transfers/DoT.', sec: 'Plaintext unless DNSSEC/DoH/DoT.' },
      { port: 67, proto: 'UDP', name: 'DHCP-Server', desc: 'Dynamic Host Configuration Protocol server listener.', sec: 'Local broadcast. Rogue DHCP risk.' },
      { port: 68, proto: 'UDP', name: 'DHCP-Client', desc: 'Dynamic Host Configuration Protocol client listener.', sec: 'Local broadcast.' },
      { port: 80, proto: 'TCP', name: 'HTTP', desc: 'Cleartext Hypertext Transfer Protocol web requests.', sec: 'Insecure. Always redirect to HTTPS.' },
      { port: 123, proto: 'UDP', name: 'NTP', desc: 'Network Time Protocol (clock sync across infrastructure).', sec: 'Critical for Kerberos & auth logs.' },
      { port: 161, proto: 'UDP', name: 'SNMP', desc: 'Simple Network Management Protocol queries/polls.', sec: 'v1/v2c plaintext community string. Use v3 authPriv.' },
      { port: 162, proto: 'UDP', name: 'SNMP-Trap', desc: 'SNMP unsolicited alert notifications from switches/hosts.', sec: 'Monitor for flood anomalies.' },
      { port: 389, proto: 'TCP', name: 'LDAP', desc: 'Lightweight Directory Access Protocol (Active Directory directory search).', sec: 'Plaintext. Use LDAPS (636).' },
      { port: 443, proto: 'TCP', name: 'HTTPS / TLS', desc: 'TLS 1.2 / TLS 1.3 encrypted secure web traffic.', sec: 'Industry gold standard. Inspect cert validity.' },
      { port: 445, proto: 'TCP', name: 'SMB / CIFS', desc: 'Server Message Block Windows file sharing and named pipes.', sec: 'HIGH RISK over WAN: Block at edge firewall.' },
      { port: 636, proto: 'TCP', name: 'LDAPS', desc: 'LDAP over TLS/SSL (encrypted Active Directory auth).', sec: 'Secure encrypted directory lookup.' },
      { port: 3389, proto: 'TCP', name: 'RDP', desc: 'Microsoft Remote Desktop Protocol administration GUI.', sec: 'Enforce NLA + VPN. Never expose raw to WAN.' },
      { port: 8443, proto: 'TCP', name: 'EJI Platform', desc: 'Eldar Jamiyev Infrastructure Intelligence Control Plane & WebSocket Hub.', sec: 'Enterprise TLS/WebSocket endpoint.' }
    ],
    subnets: [
      { cidr: '/32', mask: '255.255.255.255', total: 1, usable: 1, use: 'Host route / Loopback interface (Single endpoint)' },
      { cidr: '/30', mask: '255.255.255.252', total: 4, usable: 2, use: 'Point-to-Point WAN router serial/interconnect links' },
      { cidr: '/29', mask: '255.255.255.248', total: 8, usable: 6, use: 'Small public IP allocation or Firewall HA cluster' },
      { cidr: '/28', mask: '255.255.255.240', total: 16, usable: 14, use: 'DMZ subnet or management appliance pool' },
      { cidr: '/26', mask: '255.255.255.192', total: 64, usable: 62, use: 'Department VLAN (HR, Finance, NOC)' },
      { cidr: '/24', mask: '255.255.255.0', total: 256, usable: 254, use: 'Standard corporate office floor or server subnet' },
      { cidr: '/23', mask: '255.255.254.0', total: 512, usable: 510, use: 'Large wireless guest pool or multi-wing floor' },
      { cidr: '/16', mask: '255.255.0.0', total: 65536, usable: 65534, use: 'Enterprise campus or private cloud VPC supernet' }
    ],
    concepts: {
      'rtt': {
        title: 'Round-Trip Time (RTT) & Network Jitter',
        summary: 'RTT is the total elapsed time in milliseconds for an ICMP or TCP probe to travel from EJI to the target and return.',
        whyMatters: 'Under 15ms is optimal for LANs; 20-50ms is normal for regional WANs; over 150ms degrades voice (VoIP) and database transactions. High Jitter (variance in RTT) indicates packet queuing, link bufferbloat, or wireless channel contention.'
      },
      'tcp_flags': {
        title: 'TCP Flags: SYN, ACK, FIN, and RST',
        summary: 'TCP establishes a guaranteed reliable two-way stream using 1-bit flags in the packet header.',
        whyMatters: 'SYN initiates the conversation; SYN-ACK accepts it; ACK confirms transmission. If you see RST (Reset), the destination host is online but deliberately refusing the connection (service stopped or blocked by firewall). If packets time out without a response, the host is dead or dropping packets.'
      },
      'arp': {
        title: 'ARP (Address Resolution Protocol) & MAC Tables',
        summary: 'ARP maps an IP address (Layer 3) to the physical Ethernet hardware MAC address (Layer 2) on the local switch.',
        whyMatters: 'If you can ping a gateway IP but not an internal workstation, check the ARP table. An entry with "00-00-00-00-00-00" or missing entry means Layer 2 physical failure (cable unplugged, bad VLAN, or dead NIC).'
      },
      'dual_custody': {
        title: 'Dual-Custody Automation Safety Doctrine',
        summary: 'Dual-custody enforces that Tier 3 destructive changes cannot be triggered by a single administrator without a second approver.',
        whyMatters: 'This eliminates catastrophic accidental downtime: no single rogue script or tired technician can accidentally reboot core routers, wipe routing tables, or shut down domain controllers without Application Owner cryptographic approval.'
      },
      'rca_suppression': {
        title: 'Topological Alert Suppression in Root-Cause Analysis',
        summary: 'When a parent node (like a core distribution switch) goes down, all 50 servers behind it also fail their ping checks.',
        whyMatters: 'Without RCA suppression, on-call admins get flooded with 51 separate screaming alarms. EJI automatically silences the 50 downstream symptoms and highlights only the single root-cause failure (the switch), saving hours of confusion.'
      }
    }
  };

  function renderCheatSheetModal() {
    let modal = document.getElementById('juniorAdminGuideModal') || document.getElementById('juniorAdminModal');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'juniorAdminGuideModal'; modal.setAttribute('data-alias', 'juniorAdminModal');
      modal.className = 'modal-overlay';
      modal.style.cssText = 'position: fixed !important; inset: 0 !important; width: 100vw !important; height: 100vh !important; background: rgba(15, 23, 42, 0.55) !important; backdrop-filter: blur(6px) !important; z-index: 9999 !important; display: none; align-items: center !important; justify-content: center !important;';
      modal.onclick = function(e) {
        if (e.target === modal) window.toggleJuniorAdminCheatSheet();
      };
      document.body.appendChild(modal);
    }

    modal.innerHTML = `
      <div class="modal-dialog" style="max-width: 960px; max-height: 85vh; width: 90%; background: #FFFFFF; border-radius: 16px; padding: 28px; box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04); border: 1px solid var(--border-default); display: flex; flex-direction: column; overflow: hidden;" onclick="event.stopPropagation()">
        <div class="modal-header" style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border-default); padding-bottom: 16px; margin-bottom: 16px;">
          <div style="display: flex; align-items: center; gap: 12px;">
            <div style="width: 36px; height: 36px; border-radius: 8px; background: #EEF2FF; color: var(--accent-primary); display: flex; align-items: center; justify-content: center; font-size: 18px;">
              📘
            </div>
            <div>
              <div style="font-size: 16px; font-weight: 800; color: var(--text-primary);">EJII Junior-Admin &amp; Rookie Operator Field Manual</div>
              <div style="font-size: 11px; color: var(--text-secondary);">Plain-Language Technical Guidance, Port Maps, Subnet Math &amp; Incident Triage (Press Esc to close)</div>
            </div>
          </div>
          <button onclick="window.toggleJuniorAdminCheatSheet()" class="btn btn-secondary" style="font-size: 14px; width: 32px; height: 32px; padding: 0; display: flex; align-items: center; justify-content: center; border-radius: 6px;">✕</button>
        </div>

        <div class="modal-body" style="overflow-y: auto; padding: 4px; font-size: 12px; line-height: 1.6;">
          <!-- Quick Search Filter -->
          <div style="margin-bottom: 16px; display: flex; align-items: center; gap: 10px;">
            <input type="text" id="manualSearchInput" class="form-input" placeholder="Search ports (e.g. 443, 53, SSH)..." style="width: 300px; font-size: 11.5px; padding: 8px 14px 8px 36px; border-radius: 6px; border: 1px solid var(--border-default);" oninput="window.filterManual(this.value)">
          </div>

          <!-- Section Tabs -->
          <div style="display: flex; gap: 8px; margin-bottom: 16px; border-bottom: 1px solid var(--border-color); padding-bottom: 8px;">
            <button class="btn btn-primary" id="tabBtnPorts" onclick="window.switchManualTab('ports')">🌐 Common Ports & Protocols</button>
            <button class="btn btn-secondary" id="tabBtnSubnets" onclick="window.switchManualTab('subnets')">🔢 Subnetting & CIDR Math</button>
            <button class="btn btn-secondary" id="tabBtnConcepts" onclick="window.switchManualTab('concepts')">💡 "Why Does This Matter?" Concepts</button>
            <button class="btn btn-secondary" id="tabBtnTriage" onclick="window.switchManualTab('triage')">🛠️ 5-Step Triage Checklist</button>
            <button class="btn btn-secondary" id="tabBtnPlaybooks" onclick="window.switchManualTab('playbooks')">📖 Helpdesk Playbooks</button>
            <button class="btn btn-secondary" id="tabBtnStandard" onclick="window.switchManualTab('standard')">🇦🇿 Dəqiq Problem Bildirişi (Incident Standard)</button>
          </div>

          <!-- Tab 1: Ports -->
          <div id="manualTabPorts">
            <div class="table-container" style="max-height: 400px; overflow-y: auto;">
              <table class="data-table" style="font-size: 11px;">
                <thead>
                  <tr>
                    <th style="width: 60px;">Port</th>
                    <th style="width: 70px;">Protocol</th>
                    <th style="width: 110px;">Service</th>
                    <th>Plain-Language Purpose & How It Works</th>
                    <th style="width: 140px;">Security Profile</th>
                  </tr>
                </thead>
                <tbody id="manualPortsTableBody">
                  ${CHEAT_SHEET_DATA.ports.map(p => `
                    <tr>
                      <td style="font-family: var(--font-mono); font-weight: 700; color: var(--accent);">${p.port}</td>
                      <td><span style="font-family: var(--font-mono);">${p.proto}</span></td>
                      <td style="font-weight: 600;">${p.name}</td>
                      <td>${p.desc}</td>
                      <td><span style="font-size: 10px; color: ${p.sec.includes('Insecure') || p.sec.includes('HIGH RISK') ? 'var(--danger)' : 'var(--success)'}; font-weight: 600;">${p.sec}</span></td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </div>
          </div>

          <!-- Tab 2: Subnets -->
          <div id="manualTabSubnets" style="display: none;">
            <div class="table-container" style="max-height: 400px; overflow-y: auto;">
              <table class="data-table" style="font-size: 11px;">
                <thead>
                  <tr>
                    <th style="width: 70px;">CIDR</th>
                    <th style="width: 140px;">Subnet Mask</th>
                    <th style="width: 80px;">Total IPs</th>
                    <th style="width: 80px;">Usable Hosts</th>
                    <th>Standard Engineering Use Case</th>
                  </tr>
                </thead>
                <tbody>
                  ${CHEAT_SHEET_DATA.subnets.map(s => `
                    <tr>
                      <td style="font-family: var(--font-mono); font-weight: 700; color: var(--accent);">${s.cidr}</td>
                      <td style="font-family: var(--font-mono);">${s.mask}</td>
                      <td>${s.total}</td>
                      <td style="font-weight: 700; color: var(--success);">${s.usable}</td>
                      <td>${s.use}</td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </div>
            <div style="background: var(--bg-input); padding: 10px; border-radius: 6px; margin-top: 12px; font-size: 11px; color: var(--text-dim);">
              <b>Junior Admin Tip:</b> The 2 non-usable addresses in any IPv4 subnet are always: (1) The Network Address (first IP, all host bits 0), and (2) The Broadcast Address (last IP, all host bits 1). Usable hosts are calculated as <code>2^(32 - Prefix) - 2</code>.
            </div>
          </div>

          <!-- Tab 3: Concepts -->
          <div id="manualTabConcepts" style="display: none;">
            <div style="display: flex; flex-direction: column; gap: 12px;">
              ${Object.keys(CHEAT_SHEET_DATA.concepts).map(k => {
                const c = CHEAT_SHEET_DATA.concepts[k];
                return `
                  <div style="background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 6px; padding: 12px;">
                    <div style="font-weight: 700; font-size: 13px; color: var(--accent); margin-bottom: 4px;">💡 ${c.title}</div>
                    <div style="color: var(--text-main); margin-bottom: 6px;"><b>What is it doing?</b> ${c.summary}</div>
                    <div style="color: var(--text-muted); font-size: 11px; background: var(--bg-input); padding: 8px; border-radius: 4px;">
                      <b style="color: var(--warning);">Why does this matter?</b> ${c.whyMatters}
                    </div>
                  </div>
                `;
              }).join('')}
            </div>
          </div>

          <!-- Tab 4: Triage -->
          <div id="manualTabTriage" style="display: none;">
            <div style="background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 6px; padding: 16px;">
              <div style="font-weight: 800; font-size: 14px; color: var(--accent); margin-bottom: 12px;">🛠️ The 5-Step Junior Admin Triage Method</div>
              
              <div style="display: flex; gap: 10px; margin-bottom: 10px;">
                <span style="font-weight: 800; color: var(--accent); font-size: 14px;">1.</span>
                <div>
                  <b>Layer 1 & 2 Physical / Data Link:</b> Check Ethernet link light and ARP cache.
                  <div style="color: var(--text-dim); font-size: 11px;">Run <code>arp -a</code> or check CMDB. Does the MAC address show up? If no MAC is learned, the cable is unplugged, bad patch, or wrong VLAN.</div>
                </div>
              </div>

              <div style="display: flex; gap: 10px; margin-bottom: 10px;">
                <span style="font-weight: 800; color: var(--accent); font-size: 14px;">2.</span>
                <div>
                  <b>Layer 3 Network Routing:</b> Check ICMP Echo to Default Gateway.
                  <div style="color: var(--text-dim); font-size: 11px;">Can you ping 10.168.195.1? If the gateway does not respond, the local link is severed. If the gateway responds but internet hosts fail, check upstream routing / ISP.</div>
                </div>
              </div>

              <div style="display: flex; gap: 10px; margin-bottom: 10px;">
                <span style="font-weight: 800; color: var(--accent); font-size: 14px;">3.</span>
                <div>
                  <b>Layer 4 Transport Handshake:</b> Test TCP Port Connection.
                  <div style="color: var(--text-dim); font-size: 11px;">Does port 80/443 respond with SYN-ACK, or ECONNREFUSED (RST)? If ECONNREFUSED, host is online but daemon crashed. If timeout, firewall is silently dropping.</div>
                </div>
              </div>

              <div style="display: flex; gap: 10px; margin-bottom: 10px;">
                <span style="font-weight: 800; color: var(--accent); font-size: 14px;">4.</span>
                <div>
                  <b>Layer 7 Application & TLS Health:</b> Check HTTP Code & Certificate.
                  <div style="color: var(--text-dim); font-size: 11px;">Is the SSL/TLS certificate expired? Run TLS Audit in NOC. Does the endpoint return HTTP 502/504 (upstream proxy issue) or 500 (backend application crash)?</div>
                </div>
              </div>

              <div style="display: flex; gap: 10px;">
                <span style="font-weight: 800; color: var(--accent); font-size: 14px;">5.</span>
                <div>
                  <b>Host Internals:</b> Check CPU Load, Working Set Memory & Sockets.
                  <div style="color: var(--text-dim); font-size: 11px;">Check Systems Admin Center. Is memory pinned at 98%? Is a rogue PID saturating network sockets? Use Safe Automation to restart service with dual custody approval.</div>
                </div>
              </div>
            </div>
          </div>

          <!-- Tab 5: Helpdesk Troubleshooting Playbooks -->
          <div id="manualTabPlaybooks" style="display: none;">
            <div style="display: flex; flex-direction: column; gap: 14px;">
              <!-- Playbook 1 -->
              <div style="background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 6px; padding: 14px;">
                <div style="font-weight: 700; font-size: 13px; color: var(--accent); margin-bottom: 6px;">🔌 Playbook 1: Workstation Has No Network Connectivity</div>
                <ol style="margin: 0; padding-left: 18px; font-size: 11px; line-height: 1.6; color: var(--text-main);">
                  <li><b>Verify Physical Link:</b> Check RJ-45 LED lights (Solid Amber/Green = Link Up, Flashing = Activity, Off = Broken Cable/Port).</li>
                  <li><b>Check IP Assignment:</b> Open PowerShell and run <code>ipconfig /all</code>. If IP is <code>169.254.x.x</code> (APIPA), DHCP lease failed.</li>
                  <li><b>Ping Default Gateway:</b> Run <code>ping 10.168.195.1</code>. If 100% loss, Layer 2 VLAN or router port is down.</li>
                  <li><b>Query DNS Resolver:</b> Run <code>nslookup google.com 10.22.10.11</code>. If timeout, DNS is unreachable.</li>
                  <li><b>Test External Web Access:</b> Run <code>Test-NetConnection -ComputerName google.com -Port 443</code>.</li>
                  <li><b>Remediation:</b> If gateway pings but DNS fails, use EJI Safe Automation to run <i>Flush DNS Cache</i>. If physical link is down, dispatch tech to patch panel.</li>
                </ol>
              </div>

              <!-- Playbook 2 -->
              <div style="background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 6px; padding: 14px;">
                <div style="font-weight: 700; font-size: 13px; color: var(--accent); margin-bottom: 6px;">🌐 Playbook 2: Corporate Website or Internal Portal is Unavailable</div>
                <ol style="margin: 0; padding-left: 18px; font-size: 11px; line-height: 1.6; color: var(--text-main);">
                  <li><b>Confirm Exact URL & Scheme:</b> Distinguish between <code>http://</code> (port 80) and <code>https://</code> (port 443).</li>
                  <li><b>Test DNS Resolution:</b> Run EJI DNS Diagnostic probe in NOC. Does the domain resolve to the expected VIP?</li>
                  <li><b>Inspect TCP Handshake:</b> Test port 443. If <code>ECONNREFUSED</code>, web daemon (IIS/Nginx/Apache) is stopped.</li>
                  <li><b>Audit TLS Certificate:</b> Check TLS Certificate Inspector in NOC. Has the certificate expired or failed SAN validation?</li>
                  <li><b>Check HTTP Status Code:</b> 502/504 = Reverse proxy/load balancer cannot reach backend. 500 = Application backend crash. 403 = WAF or ACL block.</li>
                </ol>
              </div>

              <!-- Playbook 3 -->
              <div style="background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 6px; padding: 14px;">
                <div style="font-weight: 700; font-size: 13px; color: var(--accent); margin-bottom: 6px;">🖨️ Playbook 3: Network Printer Unreachable or Spooler Frozen</div>
                <ol style="margin: 0; padding-left: 18px; font-size: 11px; line-height: 1.6; color: var(--text-main);">
                  <li><b>Locate Printer Asset in CMDB:</b> Verify configured IP and MAC address in EJI CMDB inventory.</li>
                  <li><b>Probe Printer Ports:</b> Sweep printer IP for Port 9100 (RAW print), Port 515 (LPR/LPD), and Port 631 (IPP).</li>
                  <li><b>Check Windows Print Spooler:</b> On client workstation or print server, verify <code>Spooler</code> service status in Systems Admin Center.</li>
                  <li><b>Clear Stuck Print Job:</b> If spooler is locked, stop Spooler service, purge <code>C:\\Windows\\System32\\spool\\PRINTERS\\*</code>, and restart Spooler.</li>
                </ol>
              </div>

              <!-- Playbook 4 -->
              <div style="background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 6px; padding: 14px;">
                <div style="font-weight: 700; font-size: 13px; color: var(--accent); margin-bottom: 6px;">🐢 Playbook 4: Workstation Extremely Slow or Freezing</div>
                <ol style="margin: 0; padding-left: 18px; font-size: 11px; line-height: 1.6; color: var(--text-main);">
                  <li><b>Check CPU & Core Throttling:</b> Inspect host metrics in Systems Admin Center. Is CPU usage pegged at 100%?</li>
                  <li><b>Inspect Working Set RAM:</b> Check Top Memory Processes table. Look for memory leaks in browser or database daemons.</li>
                  <li><b>Audit Storage Free Space:</b> Verify disk usage on C:. If free space is under 5 GB, Windows virtual memory paging thrashing occurs.</li>
                  <li><b>Inspect Sockets Forensics:</b> Check if a background process is spawning hundreds of TCP sockets (possible malware beacon or crawler).</li>
                </ol>
              </div>

              <!-- Playbook 5 -->
              <div style="background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 6px; padding: 14px;">
                <div style="font-weight: 700; font-size: 13px; color: var(--accent); margin-bottom: 6px;">🔍 Playbook 5: Intermittent or Failing DNS Lookups</div>
                <ol style="margin: 0; padding-left: 18px; font-size: 11px; line-height: 1.6; color: var(--text-main);">
                  <li><b>Identify Assigned DNS Resolvers:</b> Check active DNS addresses in EJI Physical Network Detector (e.g. <code>10.22.10.11</code>).</li>
                  <li><b>Dual Probe DNS Server:</b> Run Port 53 TCP check and UDP query in NOC. Distinguish server network failure from DNS daemon failure.</li>
                  <li><b>Inspect Stale Client Cache:</b> Use Safe Automation to execute <code>ipconfig /flushdns</code>.</li>
                  <li><b>Compare Resolvers:</b> Test query against upstream public resolvers (<code>1.1.1.1</code> and <code>8.8.8.8</code>) to isolate internal AD DNS issues from root zone outages.</li>
                </ol>
              </div>
            </div>
          </div>

          <!-- Tab 6: Caspel / Enterprise Dəqiq Problem Bildirişi Standartı -->
          <div id="manualTabStandard" style="display: none;">
            <div style="display: flex; flex-direction: column; gap: 16px;">
              <!-- Rəsmi Bildiriş Kartı -->
              <div style="background: linear-gradient(135deg, rgba(245, 158, 11, 0.08) 0%, rgba(14, 165, 233, 0.08) 100%); border: 1px solid rgba(245, 158, 11, 0.35); border-radius: 8px; padding: 18px;">
                <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px; border-bottom: 1px solid rgba(245, 158, 11, 0.25); padding-bottom: 10px;">
                  <div style="display: flex; align-items: center; gap: 8px;">
                    <span style="font-size: 20px;">📢</span>
                    <span style="font-weight: 800; font-size: 14px; color: var(--warning);">RƏSMİ İNFORMASİYA TEXNOLOGİYALARI VƏ ƏMƏKDAŞLIQ BİLDİRİŞİ</span>
                  </div>
                  <span style="background: rgba(245, 158, 11, 0.2); color: var(--warning); padding: 3px 8px; border-radius: 4px; font-size: 10px; font-weight: 700;">CASPEL & ENTERPRISE STANDARTI</span>
                </div>

                <div style="font-size: 13px; line-height: 1.7; color: #e2e8f0;">
                  <p style="margin-top: 0; font-weight: 700; color: #ffffff;">Salam, hörmətli həmkarlar.</p>
                  <p>Sizdən bir xahişim olacaq. Zəhmət olmasa, hər hansı texniki problem yarandıqda bizə mümkün qədər <b>dəqiq və ətraflı məlumat</b> təqdim edin.</p>
                  <p style="background: rgba(0,0,0,0.4); padding: 8px 12px; border-left: 3px solid var(--danger); border-radius: 4px; margin: 10px 0; color: #fca5a5;">
                    ⚠️ Məsələn, istifadəçi sizə <i>“Əvvəl hər şey işləyirdi, indi heç nə işləmir”</i> dedikdə, ilk növbədə konkret olaraq nəyin işləmədiyini müəyyənləşdirib bizə bildirməyinizi xahiş edirik.
                  </p>
                  <p style="margin-bottom: 6px; color: #f8fafc;"><b>Nümunə üçün:</b></p>
                  <ul style="margin: 0 0 10px 0; padding-left: 20px; color: #cbd5e1;">
                    <li><code style="color: #38bdf8;">mail.taxes.gov.az</code> ünvanına müəyyən IP-dən sorğu göndərilir, lakin cavab alınmır.</li>
                    <li>Əvvəl A IP ünvanından B IP ünvanına bağlantı mövcud idi, hazırda isə bağlantı qurulmur.</li>
                    <li>Mümkün olduqda, <b>Source IP</b>, <b>Destination IP</b>, <b>URL / Veb-səhifə və ya Poçt Serveri</b> (məs: <code style="color: #38bdf8;">mail.taxes.gov.az</code>), <b>Port nömrəsi</b> və <b>Alınan xəta mesajını</b> da qeyd etməyinizi xahiş edirik.</li>
                  </ul>
                  <p style="color: #cbd5e1; font-size: 12px; margin-bottom: 4px;">
                    Bu cür dəqiq məlumatların təqdim edilməsi problemin daha operativ araşdırılmasına, səbəbinin müəyyənləşdirilməsinə və qısa müddətdə həll olunmasına kömək edəcək. Məqsədimiz problemi birlikdə daha sürətli və effektiv şəkildə həll etməkdir.
                  </p>
                  <p style="margin-bottom: 0; font-style: italic; color: #38bdf8; font-weight: 600;">Əməkdaşlığınız üçün əvvəlcədən təşəkkür edirəm.</p>
                </div>
              </div>

              <!-- Dəqiq Diaqnostika və Problem Bildirişi Forması (Interactive Dispatcher) -->
              <div style="background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; padding: 18px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px;">
                  <div>
                    <div style="font-weight: 800; font-size: 13px; color: var(--accent);">⚡ Dəqiq Diaqnostika və Problem Bildirişi Forması</div>
                    <div style="font-size: 11px; color: var(--text-dim);">Aşağıdakı sahələri dolduraraq dərhal şəbəkə yoxlanışı aparın, şablonu kopyalayın və ya formal ITSM bileti açın.</div>
                  </div>
                  <!-- Quick Preset Chips -->
                  <div style="display: flex; gap: 6px;">
                    <button class="btn btn-secondary" onclick="window.fillStandardPreset('taxes')" style="font-size: 10px; padding: 2px 8px;">🏢 mail.taxes.gov.az</button>
                    <button class="btn btn-secondary" onclick="window.fillStandardPreset('gateway')" style="font-size: 10px; padding: 2px 8px;">🌐 Gateway (192.168.31.1)</button>
                    <button class="btn btn-secondary" onclick="window.fillStandardPreset('dns')" style="font-size: 10px; padding: 2px 8px;">🛡️ DNS (192.168.31.1)</button>
                  </div>
                </div>

                <div class="grid-2" style="margin-bottom: 12px;">
                  <div class="form-group" style="margin-bottom: 10px;">
                    <label class="form-label" style="font-size: 11px;">Mənbə IP (Source IP — Sizin Kompüter)</label>
                    <input type="text" id="stdSrcIp" class="form-input" value="192.168.31.89" style="font-family: var(--font-mono); font-size: 11px;">
                  </div>
                  <div class="form-group" style="margin-bottom: 10px;">
                    <label class="form-label" style="font-size: 11px;">Hədəf Host və ya IP (Destination IP / Hostname)</label>
                    <input type="text" id="stdDstHost" class="form-input" value="mail.taxes.gov.az" style="font-family: var(--font-mono); font-size: 11px;">
                  </div>
                </div>

                <div class="grid-3" style="margin-bottom: 12px;">
                  <div class="form-group" style="margin-bottom: 10px;">
                    <label class="form-label" style="font-size: 11px;">URL / Veb-səhifə və ya Server</label>
                    <input type="text" id="stdUrl" class="form-input" value="https://mail.taxes.gov.az" style="font-family: var(--font-mono); font-size: 11px;">
                  </div>
                  <div class="form-group" style="margin-bottom: 10px;">
                    <label class="form-label" style="font-size: 11px;">Port Nömrəsi (Port)</label>
                    <input type="number" id="stdPort" class="form-input" value="443" style="font-family: var(--font-mono); font-size: 11px;">
                  </div>
                  <div class="form-group" style="margin-bottom: 10px;">
                    <label class="form-label" style="font-size: 11px;">Alınan Xəta Mesajı / Kodu</label>
                    <input type="text" id="stdErrorMsg" class="form-input" value="Sorğu göndərilir, cavab alınmır (ETIMEDOUT / Timeout)" style="font-size: 11px;">
                  </div>
                </div>

                <div class="form-group" style="margin-bottom: 14px;">
                  <label class="form-label" style="font-size: 11px;">İlkin Vəziyyət və Problem Təsviri</label>
                  <textarea id="stdContext" class="form-input" rows="2" style="font-size: 11px;">Əvvəl A IP (10.168.195.33) ünvanından B IP (mail.taxes.gov.az) ünvanına bağlantı mövcud idi, hazırda isə bağlantı qurulmur.</textarea>
                </div>

                <!-- Action Buttons -->
                <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                  <button class="btn btn-primary" onclick="window.runStandardLiveProbe()" style="font-size: 11px; font-weight: 700;">
                    ⚡ Dərhal Canlı Diaqnostika Apar (Live Probe)
                  </button>
                  <button class="btn btn-secondary" onclick="window.copyStandardReportText()" style="font-size: 11px;">
                    📋 Dəqiq Şablon Mətnini Kopyala (WhatsApp / Telegram)
                  </button>
                  <button class="btn btn-secondary" onclick="window.createStandardItsmTicket()" style="font-size: 11px;">
                    🎫 EJI ITSM-də Rəsmi İnsident Aç
                  </button>
                </div>

                <!-- Live Diagnostic Probe Output Area -->
                <div id="stdProbeOutput" style="display: none; margin-top: 14px; background: var(--bg-input); border: 1px solid var(--border-color); border-radius: 6px; padding: 12px; font-family: var(--font-mono); font-size: 11px; max-height: 200px; overflow-y: auto;">
                  <!-- Live probe results rendered here -->
                </div>
              </div>
            </div>
          </div>
        </div>

        <div class="modal-footer" style="display: flex; justify-content: space-between; align-items: center; border-top: 1px solid var(--border-color); padding: 10px 20px;">
          <div style="font-size: 11px; color: var(--text-dim);">Shortcut: Press <b>Ctrl+H</b> anytime to toggle this field manual.</div>
          <button class="btn btn-secondary" onclick="window.toggleJuniorAdminCheatSheet()">Close Manual</button>
        </div>
      </div>
    `;
  }

  window.toggleJuniorAdminCheatSheet = function() {
    let modal = document.getElementById('juniorAdminGuideModal') || document.getElementById('juniorAdminModal');
    if (!modal) {
      renderCheatSheetModal();
      modal = document.getElementById('juniorAdminGuideModal') || document.getElementById('juniorAdminModal');
    }

    isOpen = !isOpen;
    modal.style.display = isOpen ? 'flex' : 'none';
    if (document.body) { document.body.style.overflow = isOpen ? 'hidden' : ''; }

    if (isOpen) {
      const search = document.getElementById('manualSearchInput');
      if (search) search.focus();
    }
  };

  window.switchManualTab = function(tabName) {
    const tabs = ['ports', 'subnets', 'concepts', 'triage', 'playbooks', 'standard'];
    for (const t of tabs) {
      const el = document.getElementById(`manualTab${t.charAt(0).toUpperCase() + t.slice(1)}`);
      const btn = document.getElementById(`tabBtn${t.charAt(0).toUpperCase() + t.slice(1)}`);
      if (el) el.style.display = (t === tabName) ? 'block' : 'none';
      if (btn) {
        btn.className = (t === tabName) ? 'btn btn-primary' : 'btn btn-secondary';
      }
    }
  };

  window.filterManual = function(query) {
    const q = (query || '').toLowerCase().trim();
    const tbody = document.getElementById('manualPortsTableBody');
    if (!tbody) return;

    const filtered = CHEAT_SHEET_DATA.ports.filter(p => 
      String(p.port).includes(q) ||
      p.proto.toLowerCase().includes(q) ||
      p.name.toLowerCase().includes(q) ||
      p.desc.toLowerCase().includes(q) ||
      p.sec.toLowerCase().includes(q)
    );

    tbody.innerHTML = filtered.map(p => `
      <tr>
        <td style="font-family: var(--font-mono); font-weight: 700; color: var(--accent);">${p.port}</td>
        <td><span style="font-family: var(--font-mono);">${p.proto}</span></td>
        <td style="font-weight: 600;">${p.name}</td>
        <td>${p.desc}</td>
        <td><span style="font-size: 10px; color: ${p.sec.includes('Insecure') || p.sec.includes('HIGH RISK') ? 'var(--danger)' : 'var(--success)'}; font-weight: 600;">${p.sec}</span></td>
      </tr>
    `).join('');
  };

  window.fillStandardPreset = function(preset) {
    const src = document.getElementById('stdSrcIp');
    const dst = document.getElementById('stdDstHost');
    const url = document.getElementById('stdUrl');
    const port = document.getElementById('stdPort');
    const err = document.getElementById('stdErrorMsg');
    const ctx = document.getElementById('stdContext');

    if (preset === 'taxes') {
      if (src) src.value = '192.168.31.89';
      if (dst) dst.value = 'mail.taxes.gov.az';
      if (url) url.value = 'https://mail.taxes.gov.az';
      if (port) port.value = '443';
      if (err) err.value = 'Sorğu göndərilir, cavab alınmır (ETIMEDOUT / Timeout)';
      if (ctx) ctx.value = 'Əvvəl A IP (192.168.31.89) ünvanından B IP (mail.taxes.gov.az) ünvanına bağlantı mövcud idi, hazırda isə bağlantı qurulmur.';
    } else if (preset === 'gateway') {
      if (src) src.value = '192.168.31.89';
      if (dst) dst.value = '192.168.31.1';
      if (url) url.value = 'http://192.168.31.1';
      if (port) port.value = '80';
      if (err) err.value = 'Gateway ping check / L2 ARP verification';
      if (ctx) ctx.value = 'Lokal alt şəbəkə şlüzü (Default Subnet Gateway 192.168.31.1) ilə əlaqə yoxlanışı.';
    } else if (preset === 'dns') {
      if (src) src.value = '192.168.31.89';
      if (dst) dst.value = '192.168.31.1';
      if (url) url.value = 'dns://192.168.31.1';
      if (port) port.value = '53';
      if (err) err.value = 'Daxili DNS sorğuları cavabsız qalır və ya gecikir';
      if (ctx) ctx.value = 'Lokal / Müəssisə daxili Primary DNS resolver (192.168.31.1) ilə əlaqə və ad həlli.';
    }
  };

  window.copyStandardReportText = function() {
    const src = document.getElementById('stdSrcIp')?.value || '10.168.195.33';
    const dst = document.getElementById('stdDstHost')?.value || 'mail.taxes.gov.az';
    const url = document.getElementById('stdUrl')?.value || 'https://mail.taxes.gov.az';
    const port = document.getElementById('stdPort')?.value || '443';
    const err = document.getElementById('stdErrorMsg')?.value || 'Sorğu göndərilir, cavab alınmır';
    const ctx = document.getElementById('stdContext')?.value || 'Əvvəl bağlantı mövcud idi, hazırda qurulmur.';

    const report = 
`Salam, hörmətli həmkarlar.

Texniki problem barədə dəqiq və ətraflı məlumat:
• Mənbə IP (Source IP): ${src}
• Hədəf IP / Host (Destination IP): ${dst}
• URL / Veb-səhifə və ya Poçt: ${url}
• Port Nömrəsi: ${port}
• Alınan Xəta Mesajı: ${err}
• Ətraflı Vəziyyət: ${ctx}

Bu dəqiq məlumatların operativ araşdırılmasına köməklik göstərməyinizi xahiş edirik.
Əməkdaşlığınız üçün təşəkkür edirik!`;

    navigator.clipboard.writeText(report).then(() => {
      alert('✅ Dəqiq bildiriş mətni uğurla kopyalandı!\nİndi Helpdesk / Telegram / Email mesajına yapışdıra (Ctrl+V) bilərsiniz.');
    }).catch(() => {
      prompt('Mətni kopyalayın:', report);
    });
  };

  window.runStandardLiveProbe = async function() {
    const src = document.getElementById('stdSrcIp')?.value || '10.168.195.33';
    const dst = document.getElementById('stdDstHost')?.value || 'mail.taxes.gov.az';
    const port = parseInt(document.getElementById('stdPort')?.value, 10) || 443;
    const box = document.getElementById('stdProbeOutput');
    if (!box) return;

    box.style.display = 'block';
    box.innerHTML = `<span style="color: var(--accent);">⏳ Canlı 5-Layer Stepper aparılır: L1 Marşrut ➔ L2 ARP ➔ L3 ICMP ➔ L4 Socket ➔ L5 Banner...</span>`;

    const cleanHost = dst.replace(/^https?:\/\//i, '').split('/')[0].split(':')[0];

    try {
      const res = await window.api('/api/diagnostics/connectivity-matrix', {
        method: 'POST',
        body: JSON.stringify({ sourceIp: src, destination: cleanHost, port: port, protocol: 'TCP', timeoutMs: 3500 })
      });

      const st = res.stepper || {};
      const l1 = st.layer1_route || {};
      const l2 = st.layer2_arp || {};
      const l3 = st.layer3_icmp || {};
      const l4 = st.layer4_socket || {};
      const l5 = st.layer5_app || {};

      const isOpen = res.status === 'OPEN';
      const isTimeout = res.status === 'TIMEOUT' || res.status === 'FILTERED';
      const isReg = res.regression && res.regression.isRegression;

      // Auto-update form fields with technical facts
      const errInput = document.getElementById('stdErrorMsg');
      if (errInput) {
        errInput.value = isOpen ? `OPEN (Bağlantı uğurludur, ${l4.latencyMs}ms)` : (res.errorCode || res.status);
      }

      box.innerHTML = `
        <div style="font-weight: 700; color: ${isOpen ? 'var(--success)' : (isTimeout ? 'var(--danger)' : 'var(--warning)')}; margin-bottom: 6px; font-size: 12px;">
          📊 5-Layer Stepper Nəticəsi: ${res.status} — ${res.verdict} (${cleanHost}:${port})
        </div>

        ${isReg ? `
          <div style="background: rgba(239, 68, 68, 0.2); border: 1px solid var(--danger); border-radius: 4px; padding: 6px 10px; margin-bottom: 8px; color: var(--danger); font-size: 11px; font-weight: 700;">
            🚨 ${res.regression.notes}
          </div>
        ` : ''}

        <div style="display: flex; flex-direction: column; gap: 4px; font-size: 11px;">
          <div>
            <b>L1/L3 Marşrut:</b> Şlüz: <span style="font-family: var(--font-mono);">${l1.gatewayIp || 'N/A'}</span> (${l1.deliveryType || 'ROUTED'})
          </div>
          <div>
            <b>L2 ARP Qonşu:</b> <span style="font-family: var(--font-mono);">${l2.mac || 'N/A'}</span> 
            [<span style="color: var(--accent);">${l2.vendor || 'Unknown'}</span>]
          </div>
          <div>
            <b>L3 ICMP Ping:</b> 
            <span style="color: ${l3.lossPct === 0 ? 'var(--success)' : (l3.lossPct === 100 ? 'var(--warning)' : 'var(--danger)')};">
              ${l3.lossPct}% İtki (${l3.avgRttMs ? `${l3.avgRttMs}ms RTT` : 'ICMP firewall tərəfindən drop edilir'})
            </span>
          </div>
          <div>
            <b>L4 TCP Əl Sıxma:</b> 
            <span style="font-weight: 700; color: ${isOpen ? 'var(--success)' : 'var(--danger)'};">
              ${l4.status}
            </span> 
            ${l4.errorCode ? `(Xəta Kodu: ${l4.errorCode})` : `(Gecikmə: ${l4.latencyMs}ms)`}
          </div>
          <div>
            <b>L5 Tətbiq:</b> <span style="font-family: var(--font-mono);">${l5.banner || (isOpen ? 'Aktiv' : 'Yoxdur')}</span>
          </div>
        </div>

        <div style="margin-top: 8px; padding-top: 6px; border-top: 1px solid var(--border-color); color: var(--text-main); font-size: 11px;">
          <b>Texniki Rəy:</b> ${isOpen
            ? `TCP Port ${port} aktivdir və bağlantı qəbul edir. Əgər istifadəçidə xidmət açılmırsa, problem brauzer keşində, proksi parametrlərində və ya lokal autentifikasiyadadır.`
            : (isTimeout 
                ? `Port ${port} üzrə paketlər firewall tərəfindən drop edilir (ETIMEDOUT). Şəbəkə administratoru firewall ACL qaydalarını yoxlamalıdır.` 
                : `Port ${port} bağlantını rədd edir (ECONNREFUSED). Hədəf serverdə proqram xidməti dayandırılıb.`)}
        </div>
      `;
    } catch (err) {
      box.innerHTML = `<span style="color: var(--danger);">❌ Diaqnostika xətası: ${err.message}</span>`;
    }
  };

  window.createStandardItsmTicket = async function() {
    const src = document.getElementById('stdSrcIp')?.value || '10.168.195.33';
    const dst = document.getElementById('stdDstHost')?.value || 'mail.taxes.gov.az';
    const url = document.getElementById('stdUrl')?.value || 'https://mail.taxes.gov.az';
    const port = document.getElementById('stdPort')?.value || '443';
    const err = document.getElementById('stdErrorMsg')?.value || 'Sorğu göndərilir, cavab alınmır';
    const ctx = document.getElementById('stdContext')?.value || 'Əvvəl bağlantı mövcud idi, hazırda qurulmur.';

    const title = `Poçt / Şəbəkə Bağlantı Xətası: ${dst} (Port ${port})`;
    const description = 
`[DƏQİQ PROBLEM BİLDİRİŞİ — Standart Əsasında]
• Mənbə IP (Source IP): ${src}
• Hədəf IP / Host (Destination IP): ${dst}
• URL / Veb-səhifə və ya Poçt: ${url}
• Port Nömrəsi: ${port}
• Alınan Xəta Mesajı: ${err}
• Ətraflı Vəziyyət: ${ctx}`;

    try {
      const fullReport = `${title}\n\n${description}`;
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(fullReport);
      }
      alert(`✅ Rəsmi İnsident Bildirişi kopyalandı!\n\n${fullReport}\n\nHesabat mübadilə buferinə (clipboard) köçürüldü. NetOps komandasına və ya insident sisteminə göndərə bilərsiniz.`);
    } catch (e) {
      alert(`Hesabat:\n\n${title}\n\n${description}`);
    }
  };

  // Keyboard shortcut listener: Ctrl+H or Cmd+H toggles cheat sheet; Escape closes
  document.addEventListener('keydown', (e) => {
    if ((e.ctrlKey || e.metaKey) && (e.key === 'h' || e.key === 'H')) {
      e.preventDefault();
      window.toggleJuniorAdminCheatSheet();
    } else if (e.key === 'Escape' && isOpen) {
      window.toggleJuniorAdminCheatSheet();
    }
  });

})(window);
