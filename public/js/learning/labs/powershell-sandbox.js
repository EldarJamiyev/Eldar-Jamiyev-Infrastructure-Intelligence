/**
 * EJII Learning Center — PowerShell Diagnostic Sandbox Lab
 * Deterministic administrative PowerShell cmdlet simulator.
 * Mandate: Pure educational simulation. Zero actual host execution.
 */

'use strict';

if (typeof window !== 'undefined') {
  window.EJIILearning = window.EJIILearning || {};
  window.EJIILearning.Labs = window.EJIILearning.Labs || {};
}

(function() {
  const VIRTUAL_STATE = {
    services: [
      { Status: 'Running', Name: 'Dnscache', DisplayName: 'DNS Client' },
      { Status: 'Running', Name: 'EventLog', DisplayName: 'Windows Event Log' },
      { Status: 'Stopped', Name: 'Spooler', DisplayName: 'Print Spooler' },
      { Status: 'Running', Name: 'TermService', DisplayName: 'Remote Desktop Services' },
      { Status: 'Running', Name: 'WinRM', DisplayName: 'Windows Remote Management (WS-Management)' },
      { Status: 'Stopped', Name: 'wuauserv', DisplayName: 'Windows Update' }
    ],
    processes: [
      { Id: 4, ProcessName: 'System', CPU: '1.24', WorkingSetMB: 8 },
      { Id: 688, ProcessName: 'lsass', CPU: '0.45', WorkingSetMB: 28 },
      { Id: 1024, ProcessName: 'svchost', CPU: '3.12', WorkingSetMB: 114 },
      { Id: 2048, ProcessName: 'explorer', CPU: '2.05', WorkingSetMB: 165 },
      { Id: 3456, ProcessName: 'powershell', CPU: '0.88', WorkingSetMB: 76 },
      { Id: 4890, ProcessName: 'chrome', CPU: '14.20', WorkingSetMB: 540 }
    ],
    netConfig: {
      InterfaceAlias: 'Ethernet0',
      IPv4Address: '192.168.10.45/24',
      IPv4DefaultGateway: '192.168.10.1',
      DNSServers: ['192.168.10.10', '1.1.1.1'],
      LinkSpeed: '10 Gbps',
      Status: 'Up'
    },
    tcpConnections: [
      { LocalAddress: '0.0.0.0', LocalPort: 135, RemoteAddress: '0.0.0.0', RemotePort: 0, State: 'Listen' },
      { LocalAddress: '0.0.0.0', LocalPort: 445, RemoteAddress: '0.0.0.0', RemotePort: 0, State: 'Listen' },
      { LocalAddress: '0.0.0.0', LocalPort: 3389, RemoteAddress: '0.0.0.0', RemotePort: 0, State: 'Listen' },
      { LocalAddress: '0.0.0.0', LocalPort: 5985, RemoteAddress: '0.0.0.0', RemotePort: 0, State: 'Listen' },
      { LocalAddress: '192.168.10.45', LocalPort: 54312, RemoteAddress: '140.82.121.4', RemotePort: 443, State: 'Established' }
    ]
  };

  function executePsCommand(rawCmd) {
    if (!rawCmd || typeof rawCmd !== 'string') {
      return '';
    }

    const cmd = rawCmd.trim();
    if (!cmd) return '';

    const lower = cmd.toLowerCase();

    if (lower === 'clear-host' || lower === 'cls') {
      return { clear: true };
    }

    if (lower === 'help' || lower === 'get-help') {
      return [
        'Available Simulated Cmdlets in EJII PowerShell Sandbox:',
        '  Get-Service                  List Windows services and their operational states',
        '  Get-Process                  Display active processes, PID, and CPU usage',
        '  Get-NetIPConfiguration       Display IP, subnet, gateway, and DNS servers',
        '  Get-NetTCPConnection         Inspect active TCP listening and established sockets',
        '  Test-NetConnection -Port <p> Test TCP port connectivity to remote target',
        '  Restart-Service -Name <svc>  Simulate restarting a service',
        '  Clear-Host (cls)             Clear console window',
        '',
        'Pipeline examples: Get-Service | Where-Object Status -eq Running'
      ].join('\n');
    }

    if (lower.startsWith('get-service')) {
      let filtered = [...VIRTUAL_STATE.services];
      if (lower.includes('running')) {
        filtered = filtered.filter(s => s.Status.toLowerCase() === 'running');
      } else if (lower.includes('stopped')) {
        filtered = filtered.filter(s => s.Status.toLowerCase() === 'stopped');
      }

      const lines = [
        'Status   Name               DisplayName',
        '------   ----               -----------'
      ];
      for (const s of filtered) {
        lines.push(`${s.Status.padEnd(8)} ${s.Name.padEnd(18)} ${s.DisplayName}`);
      }
      return lines.join('\n');
    }

    if (lower.startsWith('restart-service')) {
      const match = cmd.match(/restart-service\s+(-name\s+)?([a-zA-Z0-9_-]+)/i);
      const svcName = match ? match[2] : 'Spooler';
      const svc = VIRTUAL_STATE.services.find(s => s.Name.toLowerCase() === svcName.toLowerCase());
      if (svc) {
        svc.Status = 'Running';
        return `WARNING: Waiting for service '${svc.DisplayName} (${svc.Name})' to start...\nService '${svc.Name}' restarted successfully. Status: Running.`;
      }
      return `Cannot find any service with service name '${svcName}'.`;
    }

    if (lower.startsWith('get-process')) {
      const lines = [
        'Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id ProcessName',
        '-------  ------    -----      -----     ------     -- -----------'
      ];
      for (const p of VIRTUAL_STATE.processes) {
        const wsK = p.WorkingSetMB * 1024;
        lines.push(`    120      14    18400     ${String(wsK).padStart(6)}      ${p.CPU.padStart(5)}   ${String(p.Id).padStart(4)} ${p.ProcessName}`);
      }
      return lines.join('\n');
    }

    if (lower.startsWith('get-netipconfiguration') || lower === 'gip' || lower === 'ipconfig') {
      const n = VIRTUAL_STATE.netConfig;
      return [
        `InterfaceAlias               : ${n.InterfaceAlias}`,
        `InterfaceStatus              : ${n.Status}`,
        `LinkSpeed                    : ${n.LinkSpeed}`,
        `IPv4Address                  : ${n.IPv4Address}`,
        `IPv4DefaultGateway           : ${n.IPv4DefaultGateway}`,
        `DNSServer                    : ${n.DNSServers.join(', ')}`
      ].join('\n');
    }

    if (lower.startsWith('get-nettcpconnection')) {
      const lines = [
        'LocalAddress    LocalPort RemoteAddress   RemotePort State',
        '------------    --------- -------------   ---------- -----'
      ];
      for (const t of VIRTUAL_STATE.tcpConnections) {
        lines.push(`${t.LocalAddress.padEnd(15)} ${String(t.LocalPort).padEnd(9)} ${t.RemoteAddress.padEnd(15)} ${String(t.RemotePort).padEnd(10)} ${t.State}`);
      }
      return lines.join('\n');
    }

    if (lower.startsWith('test-netconnection')) {
      const portMatch = cmd.match(/-Port\s+(\d+)/i);
      const port = portMatch ? Number(portMatch[1]) : 443;
      const targetMatch = cmd.match(/(-ComputerName\s+)?([a-zA-Z0-9.-]+)/i);
      const target = (targetMatch && targetMatch[2] !== 'test-netconnection') ? targetMatch[2] : '192.168.10.10';

      const isOpen = (port === 53 || port === 443 || port === 3389 || port === 5985);
      return [
        `ComputerName     : ${target}`,
        `RemoteAddress    : 192.168.10.10`,
        `RemotePort       : ${port}`,
        `InterfaceAlias   : Ethernet0`,
        `SourceAddress    : 192.168.10.45`,
        `TcpTestSucceeded : ${isOpen}`
      ].join('\n');
    }

    return `The term '${cmd.split(' ')[0]}' is not recognized as the name of a cmdlet or function.\nType 'Get-Help' to see available sandbox commands.`;
  }

  function renderPowershellSandboxLab(containerEl) {
    if (!containerEl) return;

    let history = [];
    let historyIdx = -1;
    let consoleLines = [
      'Windows PowerShell',
      'Copyright (C) Microsoft Corporation. All rights reserved. [Simulated Sandbox]',
      'Type "Get-Help" for available commands, or click sample buttons below.',
      ''
    ];

    function renderUI() {
      containerEl.innerHTML = `
        <div class="ejii-learning-lab-header">
          <div>
            <span class="ejii-learning-badge ejii-learning-badge--accent">SIMULATED LAB</span>
            <span class="ejii-learning-badge" style="margin-left:8px;">Windows Administration</span>
            <h2 style="margin: 8px 0 4px; font-size: 20px;">PowerShell Diagnostic Sandbox</h2>
            <p style="margin: 0; color: var(--text-secondary); font-size: 13px;">
              Safe simulated Windows PowerShell console for practicing administrative cmdlets and pipelines.
            </p>
          </div>
          <button id="btnClearPs" class="ejii-learning-btn ejii-learning-btn--secondary">&#10006; Clear Console</button>
        </div>

        <!-- Sample Cmdlet Shortcuts -->
        <div style="margin-top: 16px; display: flex; gap: 8px; flex-wrap: wrap;">
          <span style="font-size: 12px; color: var(--text-secondary); align-self: center;">Quick Cmdlets:</span>
          <button class="ejii-learning-btn ejii-learning-btn--secondary ps-shortcut-btn" data-cmd="Get-Service">Get-Service</button>
          <button class="ejii-learning-btn ejii-learning-btn--secondary ps-shortcut-btn" data-cmd="Get-Service | Where-Object Status -eq Stopped">Get Stopped Services</button>
          <button class="ejii-learning-btn ejii-learning-btn--secondary ps-shortcut-btn" data-cmd="Restart-Service -Name Spooler">Restart-Service Spooler</button>
          <button class="ejii-learning-btn ejii-learning-btn--secondary ps-shortcut-btn" data-cmd="Get-Process">Get-Process</button>
          <button class="ejii-learning-btn ejii-learning-btn--secondary ps-shortcut-btn" data-cmd="Get-NetIPConfiguration">Get-NetIPConfiguration</button>
          <button class="ejii-learning-btn ejii-learning-btn--secondary ps-shortcut-btn" data-cmd="Get-NetTCPConnection">Get-NetTCPConnection</button>
          <button class="ejii-learning-btn ejii-learning-btn--secondary ps-shortcut-btn" data-cmd="Test-NetConnection -Port 53">Test-NetConnection -Port 53</button>
        </div>

        <!-- Terminal Window -->
        <div style="background: #012456; border: 1px solid #005a9e; border-radius: 8px; margin-top: 16px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.4);">
          <!-- Terminal Titlebar -->
          <div style="background: #003366; padding: 6px 12px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #005a9e;">
            <span style="font-family: monospace; font-size: 12px; color: #ffffff; font-weight: 600;">Administrator: Windows PowerShell (Simulated Environment)</span>
            <span style="font-size: 11px; color: #99ccff;">ReadOnly Sandbox</span>
          </div>

          <!-- Console Output Area -->
          <div id="psOutputArea" style="padding: 12px; min-height: 280px; max-height: 400px; overflow-y: auto; font-family: 'Consolas', 'Courier New', monospace; font-size: 13px; color: #f0f0f0; white-space: pre-wrap; line-height: 1.4;">
            ${consoleLines.join('\n')}
          </div>

          <!-- Command Input Row -->
          <div style="display: flex; align-items: center; background: #011b40; border-top: 1px solid #005a9e; padding: 8px 12px;">
            <span style="font-family: monospace; font-size: 13px; color: #ffffff; white-space: nowrap; margin-right: 8px;">PS C:\\Users\\Administrator&gt;</span>
            <input type="text" id="psCmdInput" style="flex: 1; background: transparent; border: none; color: #ffff00; font-family: monospace; font-size: 13px; outline: none;" autofocus autocomplete="off" spellcheck="false">
          </div>
        </div>
      `;

      const inputEl = containerEl.querySelector('#psCmdInput');
      const outputEl = containerEl.querySelector('#psOutputArea');

      function execute(cmdStr) {
        if (!cmdStr) return;
        history.push(cmdStr);
        historyIdx = history.length;

        consoleLines.push(`PS C:\\Users\\Administrator> ${cmdStr}`);
        const result = executePsCommand(cmdStr);
        if (result && result.clear) {
          consoleLines = [];
        } else if (result) {
          consoleLines.push(result);
        }
        consoleLines.push('');

        outputEl.textContent = consoleLines.join('\n');
        outputEl.scrollTop = outputEl.scrollHeight;
        inputEl.value = '';
      }

      if (inputEl) {
        inputEl.addEventListener('keydown', (e) => {
          if (e.key === 'Enter') {
            execute(inputEl.value);
          } else if (e.key === 'ArrowUp') {
            if (historyIdx > 0) {
              historyIdx--;
              inputEl.value = history[historyIdx] || '';
            }
          } else if (e.key === 'ArrowDown') {
            if (historyIdx < history.length - 1) {
              historyIdx++;
              inputEl.value = history[historyIdx] || '';
            } else {
              historyIdx = history.length;
              inputEl.value = '';
            }
          }
        });
      }

      containerEl.querySelectorAll('.ps-shortcut-btn').forEach(btn => {
        btn.addEventListener('click', () => {
          const cmd = btn.getAttribute('data-cmd');
          if (inputEl) inputEl.value = cmd;
          execute(cmd);
        });
      });

      const btnClear = containerEl.querySelector('#btnClearPs');
      if (btnClear) {
        btnClear.addEventListener('click', () => {
          consoleLines = [];
          outputEl.textContent = '';
          if (inputEl) inputEl.focus();
        });
      }
    }

    renderUI();
  }

  if (typeof window !== 'undefined' && window.EJIILearning) {
    window.EJIILearning.Labs['sys-powershell-sandbox'] = {
      render: renderPowershellSandboxLab,
      executePsCommand,
      VIRTUAL_STATE
    };
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
      renderPowershellSandboxLab,
      executePsCommand,
      VIRTUAL_STATE
    };
  }
})();
