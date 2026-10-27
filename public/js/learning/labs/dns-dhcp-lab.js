/**
 * EJII Learning Center — DNS & DHCP Troubleshooting Simulator Lab
 * Exactly 8 real-world enterprise infrastructure fault scenarios with diagnostic evidence and remediation.
 * Mandate: Pure educational simulation.
 */

'use strict';

if (typeof window !== 'undefined') {
  window.EJIILearning = window.EJIILearning || {};
  window.EJIILearning.Labs = window.EJIILearning.Labs || {};
}

(function() {
  const SCENARIOS = [
    {
      id: 'dhcp-pool-exhaustion',
      title: 'Scenario 1: Scope Pool Exhaustion & APIPA Fallback',
      difficulty: 'Intermediate',
      symptoms: [
        'New workstation boots up and cannot connect to internal or external network.',
        'Client ipconfig /all reports IPv4 Address: 169.254.14.92, Subnet Mask: 255.255.0.0, Default Gateway: blank.',
        'Existing workstations on the same VLAN continue to function normally.'
      ],
      telemetry: {
        cmd: 'Get-DhcpServerv4ScopeStatistics -ScopeId 10.0.20.0',
        output: 'ScopeId      Free   InUse   PercentageInUse\n-------      ----   -----   ---------------\n10.0.20.0    0      250     100.00%'
      },
      diagnosticOptions: [
        { id: 'opt-a', text: 'DHCP scope pool 10.0.20.0/24 is 100% full; lease requests are being ignored/dropped by the server.', isCorrect: true },
        { id: 'opt-b', text: 'Client network cable is unplugged causing physical link down.', isCorrect: false },
        { id: 'opt-c', text: 'Active Directory Domain Controller is offline.', isCorrect: false },
        { id: 'opt-d', text: 'Client has an invalid static IP address configured.', isCorrect: false }
      ],
      remediation: 'Expand the DHCP scope (e.g. migrate to /23 or add an exclusion cleanup policy) and reduce aggressive lease duration (e.g. from 8 days to 4 hours in dynamic BYOD environments).'
    },
    {
      id: 'rogue-dhcp-server',
      title: 'Scenario 2: Rogue DHCP Server Offering Bogus Default Gateway',
      difficulty: 'Intermediate',
      symptoms: [
        'Several users report internet access died suddenly after lunch.',
        'Affected machines have IP 192.168.100.45 with gateway 192.168.100.1, whereas enterprise subnet is 10.10.50.0/24.',
        'Corporate DHCP server event log shows no lease offers for these MAC addresses.'
      ],
      telemetry: {
        cmd: 'Packet Capture (udp.port == 67 or udp.port == 68)',
        output: 'DHCP Offer from 192.168.100.1 (MAC 50:C7:BF:AA:BB:CC - TP-Link Wireless AP)\nOption 3 (Router): 192.168.100.1\nOption 6 (DNS): 192.168.100.1'
      },
      diagnosticOptions: [
        { id: 'opt-a', text: 'A user plugged an unauthorized consumer Wi-Fi router into an enterprise wall jack, running a rogue DHCP server.', isCorrect: true },
        { id: 'opt-b', text: 'The enterprise core switch firmware crashed.', isCorrect: false },
        { id: 'opt-c', text: 'The client machines have malware injecting fake routes into Windows registry.', isCorrect: false },
        { id: 'opt-d', text: 'Active Directory DNS dynamic updates were disabled.', isCorrect: false }
      ],
      remediation: 'Enable DHCP Snooping on all access switches (mark upstream uplinks as trusted and user edge ports as untrusted), shut down the offending switchport, and confiscate the rogue device.'
    },
    {
      id: 'dns-missing-srv-record',
      title: 'Scenario 3: Missing Active Directory SRV Record for Kerberos/LDAP',
      difficulty: 'Advanced',
      symptoms: [
        'Client attempts to join computer to domain "corp.ejii.local" and receives error: "An Active Directory Domain Controller could not be contacted".',
        'Ping to domain controller IP 10.0.1.10 succeeds with 0% loss.',
        'General internet browsing works fine.'
      ],
      telemetry: {
        cmd: 'nslookup -type=SRV _ldap._tcp.dc._msdcs.corp.ejii.local',
        output: '*** dc01.corp.ejii.local can\'t find _ldap._tcp.dc._msdcs.corp.ejii.local: Non-existent domain (NXDOMAIN)'
      },
      diagnosticOptions: [
        { id: 'opt-a', text: 'DNS zone is missing the critical Active Directory SRV locator record (_ldap._tcp.dc._msdcs) pointing to DC01.', isCorrect: true },
        { id: 'opt-b', text: 'Kerberos port 88 TCP is blocked by Windows Firewall.', isCorrect: false },
        { id: 'opt-c', text: 'The client computer account password in Active Directory has expired.', isCorrect: false },
        { id: 'opt-d', text: 'The subnet mask on the client does not match the DC subnet mask.', isCorrect: false }
      ],
      remediation: 'Restart the "Netlogon" service on DC01 (or run "nltest /dsregdns") to force the Domain Controller to register its required SRV and host records in DNS.'
    },
    {
      id: 'ip-conflict',
      title: 'Scenario 4: Duplicate IP Address Conflict on Database Server',
      difficulty: 'Intermediate',
      symptoms: [
        'Production Database Server (10.0.1.50) intermittently drops connections.',
        'Network status icon on the server shows a yellow warning triangle.',
        'System Event Log records Event ID 4199: "The system detected an address conflict for IP address 10.0.1.50 with the system having network hardware address 00-15-5D-88-99-00".'
      ],
      telemetry: {
        cmd: 'arp -a | findstr 10.0.1.50',
        output: 'Internet Address      Physical Address      Type\n10.0.1.50             00-15-5d-88-99-00     dynamic (Hyper-V Test VM)\n10.0.1.50             00-50-56-a1-b2-c3     static  (Physical DB Host)'
      },
      diagnosticOptions: [
        { id: 'opt-a', text: 'Another host (a rogue or misconfigured test VM) was manually assigned the identical static IP address 10.0.1.50.', isCorrect: true },
        { id: 'opt-b', text: 'The physical NIC hardware on the database server has failed.', isCorrect: false },
        { id: 'opt-c', text: 'BGP routing loop is flapping between two core switches.', isCorrect: false },
        { id: 'opt-d', text: 'DHCP lease expired and server was dropped from the domain.', isCorrect: false }
      ],
      remediation: 'Locate the offending VM via its MAC address on the switch MAC table (show mac address-table address ...), reconfigure the test VM to use DHCP or a dedicated staging IP.'
    },
    {
      id: 'dhcp-relay-agent-misconfig',
      title: 'Scenario 5: DHCP Relay (IP Helper) Misconfigured on L3 Switch',
      difficulty: 'Intermediate',
      symptoms: [
        'VLAN 10 clients receive IP addresses immediately from DHCP.',
        'VLAN 30 (Engineering) clients fail to receive IP addresses and fall back to APIPA (169.254.x.x).',
        'DHCP server has an active scope for 10.0.30.0/24 with 180 available addresses.'
      ],
      telemetry: {
        cmd: 'show run interface Vlan30',
        output: 'interface Vlan30\n description Engineering_Department\n ip address 10.0.30.1 255.255.255.0\n ip helper-address 10.0.1.99  <-- (Typo! Actual DHCP server is 10.0.1.10)'
      },
      diagnosticOptions: [
        { id: 'opt-a', text: 'The Layer 3 switch interface Vlan30 has an incorrect "ip helper-address" forwarder IP (10.0.1.99 instead of 10.0.1.10).', isCorrect: true },
        { id: 'opt-b', text: 'DHCP option 82 is corrupted on all engineering workstations.', isCorrect: false },
        { id: 'opt-c', text: 'VLAN 30 does not support 802.1Q encapsulation.', isCorrect: false },
        { id: 'opt-d', text: 'The engineering switches need to have Spanning Tree disabled.', isCorrect: false }
      ],
      remediation: 'Correct the helper address on the SVI: configure "no ip helper-address 10.0.1.99" followed by "ip helper-address 10.0.1.10".'
    },
    {
      id: 'dns-forwarder-failure',
      title: 'Scenario 6: Broken External DNS Forwarder on Core DNS Server',
      difficulty: 'Intermediate',
      symptoms: [
        'All internal corporate websites (portal.ejii.local, git.ejii.local) resolve instantly and work perfectly.',
        'All external internet domains (github.com, microsoft.com, google.com) fail with Server Failure (SERVFAIL).',
        'Core DNS server can ping external IPs like 8.8.8.8 and 1.1.1.1 directly.'
      ],
      telemetry: {
        cmd: 'Get-DnsServerForwarder',
        output: 'IPAddress      Timeout(s)  EnableReordering\n---------      ----------  ----------------\n198.51.100.55  5           True  <-- (Decommissioned ISP DNS IP, completely unresponsive)'
      },
      diagnosticOptions: [
        { id: 'opt-a', text: 'Internal DNS server has an obsolete, dead external forwarder IP configured, causing all upstream recursive queries to time out.', isCorrect: true },
        { id: 'opt-b', text: 'The internet gateway router has died.', isCorrect: false },
        { id: 'opt-c', text: 'Root hints file on all client computers is missing.', isCorrect: false },
        { id: 'opt-d', text: 'External websites have blocked the company IP block.', isCorrect: false }
      ],
      remediation: 'Update the DNS forwarders on DC01/DNS01 using "Set-DnsServerForwarder -IPAddress 1.1.1.1, 8.8.8.8" or enable Root Hints fallback.'
    },
    {
      id: 'dns-cache-poison-stale',
      title: 'Scenario 7: Stale Client DNS Resolver Cache After IP Migration',
      difficulty: 'Beginner',
      symptoms: [
        'Internal CRM service was migrated from old host 10.0.1.75 to new high-availability cluster 10.0.1.200.',
        'Most users can access CRM, but several user workstations still attempt to connect to 10.0.1.75 and get connection timeouts.',
        'DNS server shows the A record for crm.ejii.local is correctly set to 10.0.1.200.'
      ],
      telemetry: {
        cmd: 'Get-DnsClientCache -Entry crm.ejii.local',
        output: 'Entry           RecordName       Type  Data        TTL\n-----           ----------       ----  ----        ---\ncrm.ejii.local  crm.ejii.local   A     10.0.1.75   3542'
      },
      diagnosticOptions: [
        { id: 'opt-a', text: 'The client workstation has a cached stale A record in its local DNS client resolver with 3500+ seconds remaining on its TTL.', isCorrect: true },
        { id: 'opt-b', text: 'The web browser is infected with a proxy hijacker.', isCorrect: false },
        { id: 'opt-c', text: 'The database cluster rejected the client SSL certificate.', isCorrect: false },
        { id: 'opt-d', text: 'The domain suffix search list was cleared.', isCorrect: false }
      ],
      remediation: 'Run "ipconfig /flushdns" (or Clear-DnsClientCache in PowerShell) on the affected client workstations to immediately dump stale cached records.'
    },
    {
      id: 'apipa-link-local-fallback',
      title: 'Scenario 8: Stopped DHCP Server Service Leading to Facility-Wide APIPA',
      difficulty: 'Intermediate',
      symptoms: [
        'Following a weekend power maintenance, Monday morning users across all departments report no network connectivity.',
        'Hundreds of machines across multiple subnets show IP addresses in the 169.254.0.0/16 range.',
        'Physical network switches, cabling, and gateway routers are all confirmed green and operational.'
      ],
      telemetry: {
        cmd: 'Get-Service -ComputerName DHCP01 -Name DHCPServer',
        output: 'Status   Name        DisplayName\n------   ----        -----------\nStopped  DHCPServer  DHCP Server'
      },
      diagnosticOptions: [
        { id: 'opt-a', text: 'The Windows DHCP Server service on the central server (DHCP01) failed to start after reboot and is in Stopped state.', isCorrect: true },
        { id: 'opt-b', text: 'All Ethernet network adapters worldwide have expired drivers.', isCorrect: false },
        { id: 'opt-c', text: 'The enterprise gateway router has corrupted its NAT translation table.', isCorrect: false },
        { id: 'opt-d', text: 'APIPA is a security protocol enforcing zero trust on Mondays.', isCorrect: false }
      ],
      remediation: 'Start the DHCP service on DHCP01 ("Start-Service DHCPServer"), set its startup type to Automatic, and investigate event log for any authorization or database initialization errors.'
    }
  ];

  function evaluateDiagnosis(scenarioId, selectedOptionId) {
    const scenario = SCENARIOS.find(s => s.id === scenarioId);
    if (!scenario) return { error: 'Scenario not found' };

    const selectedOption = scenario.diagnosticOptions.find(o => o.id === selectedOptionId);
    if (!selectedOption) return { error: 'Selected option not found' };

    return {
      scenarioId,
      selectedOptionId,
      isCorrect: selectedOption.isCorrect,
      explanation: selectedOption.isCorrect ?
        `Correct! ${selectedOption.text}\n\nRemediation Protocol:\n${scenario.remediation}` :
        `Incorrect diagnosis. Review the telemetry evidence carefully and re-examine the symptoms.`
    };
  }

  function renderDnsDhcpLab(containerEl) {
    if (!containerEl) return;

    let activeScenarioIdx = 0;
    let selectedOption = null;
    let diagnosisResult = null;

    function renderUI() {
      const scenario = SCENARIOS[activeScenarioIdx];

      containerEl.innerHTML = `
        <div class="ejii-learning-lab-header">
          <div>
            <span class="ejii-learning-badge ejii-learning-badge--accent">SIMULATED LAB</span>
            <span class="ejii-learning-badge" style="margin-left:8px;">DNS & DHCP Diagnostics</span>
            <h2 style="margin: 8px 0 4px; font-size: 20px;">DNS & DHCP Troubleshooting Simulator</h2>
            <p style="margin: 0; color: var(--text-secondary); font-size: 13px;">
              Master diagnosis and remediation of 8 real-world enterprise infrastructure faults.
            </p>
          </div>
          <div style="display: flex; gap: 8px; align-items: center;">
            <label style="font-size: 12px; color: var(--text-secondary);">Scenario:</label>
            <select id="selectScenario" class="ejii-learning-input" style="width: auto; padding: 4px 10px;">
              ${SCENARIOS.map((s, idx) => `
                <option value="${idx}" ${idx === activeScenarioIdx ? 'selected' : ''}>${idx + 1}. ${s.title.split(':')[1] || s.title}</option>
              `).join('')}
            </select>
          </div>
        </div>

        <!-- Scenario Banner -->
        <div style="background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; padding: 16px; margin-top: 16px;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
            <span style="font-size: 16px; font-weight: 600; color: var(--text-primary);">${scenario.title}</span>
            <span class="ejii-learning-badge ejii-learning-badge--warning">${scenario.difficulty}</span>
          </div>

          <div style="font-size: 13px; color: var(--text-secondary); margin-bottom: 12px;">
            <strong>Reported Symptoms:</strong>
            <ul style="margin: 6px 0 0 16px; padding: 0;">
              ${scenario.symptoms.map(sym => `<li style="margin-bottom: 4px;">${sym}</li>`).join('')}
            </ul>
          </div>

          <!-- Diagnostic Telemetry Inspection -->
          <div style="background: #0f172a; border: 1px solid #1e293b; border-radius: 6px; padding: 12px; margin-top: 12px;">
            <div style="font-size: 11px; text-transform: uppercase; color: #38bdf8; font-weight: 700; margin-bottom: 4px;">
              Diagnostic Telemetry Output &bull; <code style="color: #f1f5f9;">${scenario.telemetry.cmd}</code>
            </div>
            <pre style="margin: 0; font-family: monospace; font-size: 12px; color: #a5f3fc; white-space: pre-wrap; line-height: 1.4;">${scenario.telemetry.output}</pre>
          </div>
        </div>

        <!-- Diagnostic Options Form -->
        <div style="background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px; padding: 16px; margin-top: 16px;">
          <div style="font-weight: 600; font-size: 14px; margin-bottom: 8px; color: var(--text-primary);">
            Select Root Cause Diagnosis:
          </div>

          <div style="display: flex; flex-direction: column; gap: 10px; margin-bottom: 16px;">
            ${scenario.diagnosticOptions.map(opt => `
              <label style="display: flex; gap: 10px; align-items: flex-start; cursor: pointer; padding: 8px 12px; border-radius: 6px; background: ${selectedOption === opt.id ? 'rgba(59, 130, 246, 0.15)' : 'rgba(255,255,255,0.02)'}; border: 1px solid ${selectedOption === opt.id ? '#3b82f6' : 'var(--border-color)'};">
                <input type="radio" name="diagOpt" value="${opt.id}" ${selectedOption === opt.id ? 'checked' : ''} style="margin-top: 3px;">
                <span style="font-size: 13px; color: var(--text-primary); line-height: 1.4;">${opt.text}</span>
              </label>
            `).join('')}
          </div>

          <button id="btnSubmitDiagnosis" class="ejii-learning-btn ejii-learning-btn--primary" ${!selectedOption ? 'disabled' : ''}>
            Verify Diagnosis & View Remediation
          </button>
        </div>

        <!-- Result Box -->
        ${diagnosisResult ? `
          <div style="background: ${diagnosisResult.isCorrect ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)'}; border: 1px solid ${diagnosisResult.isCorrect ? '#10b981' : '#ef4444'}; border-radius: 8px; padding: 16px; margin-top: 16px;">
            <div style="font-weight: 700; font-size: 15px; color: ${diagnosisResult.isCorrect ? '#34d399' : '#f87171'}; margin-bottom: 6px;">
              ${diagnosisResult.isCorrect ? '&#10003; DIAGNOSIS VERIFIED' : '&#10007; INCORRECT DIAGNOSIS'}
            </div>
            <div style="font-size: 13px; color: var(--text-primary); white-space: pre-line; line-height: 1.5;">
              ${diagnosisResult.explanation}
            </div>
          </div>
        ` : ''}
      `;

      // Event handlers
      const selectScenario = containerEl.querySelector('#selectScenario');
      if (selectScenario) {
        selectScenario.addEventListener('change', (e) => {
          activeScenarioIdx = Number(e.target.value);
          selectedOption = null;
          diagnosisResult = null;
          renderUI();
        });
      }

      containerEl.querySelectorAll('input[name="diagOpt"]').forEach(radio => {
        radio.addEventListener('change', (e) => {
          selectedOption = e.target.value;
          const btn = containerEl.querySelector('#btnSubmitDiagnosis');
          if (btn) btn.disabled = false;
        });
      });

      const btnSubmit = containerEl.querySelector('#btnSubmitDiagnosis');
      if (btnSubmit) {
        btnSubmit.addEventListener('click', () => {
          if (!selectedOption) return;
          diagnosisResult = evaluateDiagnosis(scenario.id, selectedOption);
          renderUI();
        });
      }
    }

    renderUI();
  }

  if (typeof window !== 'undefined' && window.EJIILearning) {
    window.EJIILearning.Labs['sys-dns-dhcp-lab'] = {
      render: renderDnsDhcpLab,
      evaluateDiagnosis,
      SCENARIOS
    };
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
      renderDnsDhcpLab,
      evaluateDiagnosis,
      SCENARIOS
    };
  }
})();
