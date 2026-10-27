/**
 * EJII Learning Center — Linux Command & Filesystem Trainer Lab
 * Virtual filesystem hierarchy (FHS), systemd service simulator, and terminal emulator.
 * Mandate: Pure educational simulation. Zero actual host execution.
 */

'use strict';

if (typeof window !== 'undefined') {
  window.EJIILearning = window.EJIILearning || {};
  window.EJIILearning.Labs = window.EJIILearning.Labs || {};
}

(function() {
  const VIRTUAL_FS = {
    '/': {
      type: 'dir',
      permissions: 'drwxr-xr-x',
      owner: 'root',
      group: 'root',
      children: {
        'etc': {
          type: 'dir',
          permissions: 'drwxr-xr-x',
          owner: 'root',
          group: 'root',
          children: {
            'hosts': {
              type: 'file',
              permissions: '-rw-r--r--',
              owner: 'root',
              group: 'root',
              content: '127.0.0.1   localhost\n127.0.1.1   srv-prod-01.ejii.internal srv-prod-01\n10.0.1.10   db-primary.ejii.internal\n10.0.1.20   redis-cluster.ejii.internal'
            },
            'resolv.conf': {
              type: 'file',
              permissions: '-rw-r--r--',
              owner: 'root',
              group: 'root',
              content: 'nameserver 1.1.1.1\nnameserver 8.8.8.8\nsearch ejii.internal'
            },
            'nginx': {
              type: 'dir',
              permissions: 'drwxr-xr-x',
              owner: 'root',
              group: 'root',
              children: {
                'nginx.conf': {
                  type: 'file',
                  permissions: '-rw-r--r--',
                  owner: 'root',
                  group: 'root',
                  content: 'user www-data;\nworker_processes auto;\nevents { worker_connections 1024; }\nhttp {\n    server {\n        listen 80;\n        server_name srv-prod-01;\n        location / { proxy_pass http://127.0.0.1:3000; }\n    }\n}'
                }
              }
            }
          }
        },
        'var': {
          type: 'dir',
          permissions: 'drwxr-xr-x',
          owner: 'root',
          group: 'root',
          children: {
            'log': {
              type: 'dir',
              permissions: 'drwxr-xr-x',
              owner: 'root',
              group: 'root',
              children: {
                'syslog': {
                  type: 'file',
                  permissions: '-rw-r-----',
                  owner: 'syslog',
                  group: 'adm',
                  content: 'Oct 27 10:00:01 srv-prod-01 systemd[1]: Starting Daily apt download activities...\nOct 27 10:00:15 srv-prod-01 kernel: [ 4520.12] TCP: eth0: link up, 10000Mbps, full-duplex\nOct 27 10:14:22 srv-prod-01 sshd[3420]: Accepted publickey for devops from 192.168.1.50 port 52311 ssh2'
                }
              }
            }
          }
        },
        'home': {
          type: 'dir',
          permissions: 'drwxr-xr-x',
          owner: 'root',
          group: 'root',
          children: {
            'devops': {
              type: 'dir',
              permissions: 'drwxr-xr-x',
              owner: 'devops',
              group: 'devops',
              children: {
                'README.md': {
                  type: 'file',
                  permissions: '-rw-rw-r--',
                  owner: 'devops',
                  group: 'devops',
                  content: '# Production Node 01\nManaged by EJII SRE Team.\nAutomated deployments enabled on branch main.'
                },
                'app.py': {
                  type: 'file',
                  permissions: '-rwxr-xr-x',
                  owner: 'devops',
                  group: 'devops',
                  content: '#!/usr/bin/env python3\nimport socket\nprint(f"Node: {socket.gethostname()} ready for production traffic.")'
                }
              }
            }
          }
        }
      }
    }
  };

  const VIRTUAL_SERVICES = {
    'nginx': { status: 'active (running)', pid: 1420, since: '3 hours ago', desc: 'A high performance web server and a reverse proxy that has 1 master and 2 worker processes.' },
    'sshd': { status: 'active (running)', pid: 890, since: '2 days ago', desc: 'OpenSSH server daemon listening on port 22.' },
    'cron': { status: 'active (running)', pid: 450, since: '2 days ago', desc: 'Regular background program processing daemon.' },
    'postgresql': { status: 'inactive (dead)', pid: 0, since: 'stopped', desc: 'PostgreSQL database server.' }
  };

  function resolvePath(currentDir, targetPath) {
    if (!targetPath || targetPath === '~') return '/home/devops';
    let path = targetPath.trim();
    if (!path.startsWith('/')) {
      path = (currentDir === '/' ? '' : currentDir) + '/' + path;
    }
    const parts = path.split('/').filter(p => p.length > 0 && p !== '.');
    const resolved = [];
    for (const p of parts) {
      if (p === '..') {
        resolved.pop();
      } else {
        resolved.push(p);
      }
    }
    return '/' + resolved.join('/');
  }

  function getNodeAt(path) {
    if (path === '/') return VIRTUAL_FS['/'];
    const parts = path.split('/').filter(Boolean);
    let curr = VIRTUAL_FS['/'];
    for (const part of parts) {
      if (!curr.children || !curr.children[part]) return null;
      curr = curr.children[part];
    }
    return curr;
  }

  function executeLinuxCommand(rawCmd, currentDir) {
    if (!rawCmd || typeof rawCmd !== 'string') return { output: '', newDir: currentDir };
    const cmd = rawCmd.trim();
    if (!cmd) return { output: '', newDir: currentDir };

    const parts = cmd.split(/\s+/);
    const bin = parts[0].toLowerCase();
    const args = parts.slice(1);

    if (bin === 'clear') {
      return { clear: true, newDir: currentDir };
    }

    if (bin === 'help') {
      const output = [
        'Available Simulated Linux Commands:',
        '  pwd                  Print current working directory',
        '  ls [-l, -la, path]   List directory contents and permissions',
        '  cd <dir>             Change working directory',
        '  cat <file>           Concatenate and display file content',
        '  systemctl status <svc> Check systemd service status (nginx, sshd, postgresql)',
        '  systemctl restart <svc> Restart simulated service',
        '  journalctl -u <svc>  View systemd service logs',
        '  ip a / ip route      Inspect network interfaces and routes',
        '  ss -tulpn            List active listening sockets',
        '  uname -a / df -h     System info and disk usage',
        '  clear                Clear console screen'
      ].join('\n');
      return { output, newDir: currentDir };
    }

    if (bin === 'pwd') {
      return { output: currentDir, newDir: currentDir };
    }

    if (bin === 'cd') {
      const target = args[0] || '~';
      const resolved = resolvePath(currentDir, target);
      const node = getNodeAt(resolved);
      if (!node) {
        return { output: `bash: cd: ${target}: No such file or directory`, newDir: currentDir };
      }
      if (node.type !== 'dir') {
        return { output: `bash: cd: ${target}: Not a directory`, newDir: currentDir };
      }
      return { output: '', newDir: resolved };
    }

    if (bin === 'ls') {
      const isLong = args.includes('-l') || args.includes('-la') || args.includes('-al');
      let targetPath = args.find(a => !a.startsWith('-')) || currentDir;
      const resolved = resolvePath(currentDir, targetPath);
      const node = getNodeAt(resolved);
      if (!node) {
        return { output: `ls: cannot access '${targetPath}': No such file or directory`, newDir: currentDir };
      }
      if (node.type === 'file') {
        return { output: isLong ? `${node.permissions} 1 ${node.owner} ${node.group} ${node.content.length} ${resolved.split('/').pop()}` : resolved.split('/').pop(), newDir: currentDir };
      }

      const entries = Object.keys(node.children || {}).sort();
      if (!isLong) {
        return { output: entries.join('  '), newDir: currentDir };
      }

      const lines = [`total ${entries.length * 4}`];
      for (const name of entries) {
        const item = node.children[name];
        const size = item.type === 'dir' ? 4096 : (item.content ? item.content.length : 0);
        lines.push(`${item.permissions} 1 ${item.owner.padEnd(6)} ${item.group.padEnd(6)} ${String(size).padStart(6)} Oct 27 10:00 ${name}`);
      }
      return { output: lines.join('\n'), newDir: currentDir };
    }

    if (bin === 'cat') {
      if (!args[0]) return { output: 'cat: missing operand', newDir: currentDir };
      const resolved = resolvePath(currentDir, args[0]);
      const node = getNodeAt(resolved);
      if (!node) {
        return { output: `cat: ${args[0]}: No such file or directory`, newDir: currentDir };
      }
      if (node.type === 'dir') {
        return { output: `cat: ${args[0]}: Is a directory`, newDir: currentDir };
      }
      return { output: node.content, newDir: currentDir };
    }

    if (bin === 'systemctl') {
      const sub = args[0] ? args[0].toLowerCase() : 'status';
      const svcName = args[1] ? args[1].toLowerCase().replace(/\.service$/, '') : 'nginx';
      const svc = VIRTUAL_SERVICES[svcName];

      if (!svc) {
        return { output: `Unit ${svcName}.service could not be found.`, newDir: currentDir };
      }

      if (sub === 'status') {
        const lines = [
          `● ${svcName}.service - ${svc.desc}`,
          `     Loaded: loaded (/lib/systemd/system/${svcName}.service; enabled; vendor preset: enabled)`,
          `     Active: ${svc.status} since Mon 2026-10-27 (${svc.since})`,
          `   Main PID: ${svc.pid} (${svcName})`,
          `      Tasks: 2 (limit: 4915)`,
          `     Memory: 24.5M`,
          `        CPU: 1.250s`,
          `     CGroup: /system.slice/${svcName}.service`
        ];
        return { output: lines.join('\n'), newDir: currentDir };
      }

      if (sub === 'restart') {
        svc.status = 'active (running)';
        svc.pid = Math.floor(Math.random() * 5000) + 1000;
        svc.since = 'just now';
        return { output: `Service ${svcName}.service restarted successfully.`, newDir: currentDir };
      }

      return { output: `systemctl: unsupported command: ${sub}`, newDir: currentDir };
    }

    if (bin === 'ip') {
      const sub = args[0] || 'a';
      if (sub.startsWith('a')) {
        return {
          output: [
            '1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000',
            '    inet 127.0.0.1/8 scope host lo',
            '2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP group default qlen 1000',
            '    inet 10.0.1.15/24 brd 10.0.1.255 scope global eth0'
          ].join('\n'),
          newDir: currentDir
        };
      }
      if (sub.startsWith('r')) {
        return {
          output: [
            'default via 10.0.1.1 dev eth0 proto dhcp src 10.0.1.15 metric 100',
            '10.0.1.0/24 dev eth0 proto kernel scope link src 10.0.1.15 metric 100'
          ].join('\n'),
          newDir: currentDir
        };
      }
    }

    if (bin === 'ss' || bin === 'netstat') {
      return {
        output: [
          'State   Recv-Q Send-Q Local Address:Port  Peer Address:Port Process',
          'LISTEN  0      128          0.0.0.0:80         0.0.0.0:*     users:(("nginx",pid=1420,fd=6))',
          'LISTEN  0      128          0.0.0.0:22         0.0.0.0:*     users:(("sshd",pid=890,fd=3))',
          'ESTAB   0      0         10.0.1.15:22      192.168.1.50:52311 users:(("sshd",pid=3420,fd=4))'
        ].join('\n'),
        newDir: currentDir
      };
    }

    if (bin === 'uname') {
      return { output: 'Linux srv-prod-01 6.8.0-45-generic #45-Ubuntu SMP PREEMPT_DYNAMIC x86_64 GNU/Linux', newDir: currentDir };
    }

    if (bin === 'df') {
      return {
        output: [
          'Filesystem     1K-blocks     Used Available Use% Mounted on',
          '/dev/sda1       49372160 12450840  34386400  27% /',
          '/dev/sdb1      102838272 45890120  51700200  48% /var',
          'tmpfs            4039168        0   4039168   0% /run'
        ].join('\n'),
        newDir: currentDir
      };
    }

    return { output: `bash: ${bin}: command not found (type 'help' for sandbox commands)`, newDir: currentDir };
  }

  function renderLinuxSandboxLab(containerEl) {
    if (!containerEl) return;

    let currentDir = '/home/devops';
    let history = [];
    let historyIdx = -1;
    let consoleLines = [
      'Welcome to Ubuntu 24.04 LTS (GNU/Linux 6.8.0-45-generic x86_64) [Simulated Sandbox]',
      ' * Documentation:  https://help.ubuntu.com',
      ' * Management:     EJII System Administration Lab',
      '',
      'Type "help" for available commands, or click sample buttons below.',
      ''
    ];

    function renderUI() {
      containerEl.innerHTML = `
        <div class="ejii-learning-lab-header">
          <div>
            <span class="ejii-learning-badge ejii-learning-badge--accent">SIMULATED LAB</span>
            <span class="ejii-learning-badge" style="margin-left:8px;">Linux Administration</span>
            <h2 style="margin: 8px 0 4px; font-size: 20px;">Linux Command & Filesystem Trainer</h2>
            <p style="margin: 0; color: var(--text-secondary); font-size: 13px;">
              Safe simulated Linux shell for practicing directory traversal, file inspection, systemctl, and networking.
            </p>
          </div>
          <button id="btnClearLinux" class="ejii-learning-btn ejii-learning-btn--secondary">&#10006; Clear Console</button>
        </div>

        <!-- Shortcut Buttons -->
        <div style="margin-top: 16px; display: flex; gap: 8px; flex-wrap: wrap;">
          <span style="font-size: 12px; color: var(--text-secondary); align-self: center;">Quick Commands:</span>
          <button class="ejii-learning-btn ejii-learning-btn--secondary linux-btn" data-cmd="ls -la">ls -la</button>
          <button class="ejii-learning-btn ejii-learning-btn--secondary linux-btn" data-cmd="cat /etc/hosts">cat /etc/hosts</button>
          <button class="ejii-learning-btn ejii-learning-btn--secondary linux-btn" data-cmd="cat /etc/nginx/nginx.conf">cat nginx.conf</button>
          <button class="ejii-learning-btn ejii-learning-btn--secondary linux-btn" data-cmd="systemctl status nginx">systemctl status nginx</button>
          <button class="ejii-learning-btn ejii-learning-btn--secondary linux-btn" data-cmd="ss -tulpn">ss -tulpn</button>
          <button class="ejii-learning-btn ejii-learning-btn--secondary linux-btn" data-cmd="ip a">ip a</button>
          <button class="ejii-learning-btn ejii-learning-btn--secondary linux-btn" data-cmd="df -h">df -h</button>
        </div>

        <!-- Terminal Window -->
        <div style="background: #1e1e1e; border: 1px solid #333333; border-radius: 8px; margin-top: 16px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.5);">
          <!-- Terminal Titlebar -->
          <div style="background: #2d2d2d; padding: 6px 12px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #3a3a3a;">
            <div style="display: flex; gap: 6px; align-items: center;">
              <span style="width: 10px; height: 10px; border-radius: 50%; background: #ff5f56; display: inline-block;"></span>
              <span style="width: 10px; height: 10px; border-radius: 50%; background: #ffbd2e; display: inline-block;"></span>
              <span style="width: 10px; height: 10px; border-radius: 50%; background: #27c93f; display: inline-block;"></span>
              <span style="font-family: monospace; font-size: 12px; color: #cccccc; font-weight: 600; margin-left: 8px;">devops@srv-prod-01: ${currentDir}</span>
            </div>
            <span style="font-size: 11px; color: #888888;">Simulated Ubuntu 24.04</span>
          </div>

          <!-- Console Output -->
          <div id="linuxOutputArea" style="padding: 12px; min-height: 280px; max-height: 400px; overflow-y: auto; font-family: 'Consolas', 'Courier New', monospace; font-size: 13px; color: #d4d4d4; white-space: pre-wrap; line-height: 1.4;">
            ${consoleLines.join('\n')}
          </div>

          <!-- Prompt Row -->
          <div style="display: flex; align-items: center; background: #181818; border-top: 1px solid #2a2a2a; padding: 8px 12px;">
            <span id="linuxPromptSpan" style="font-family: monospace; font-size: 13px; color: #4ec9b0; white-space: nowrap; margin-right: 8px;">devops@srv-prod-01:${currentDir}$</span>
            <input type="text" id="linuxCmdInput" style="flex: 1; background: transparent; border: none; color: #ffffff; font-family: monospace; font-size: 13px; outline: none;" autofocus autocomplete="off" spellcheck="false">
          </div>
        </div>
      `;

      const inputEl = containerEl.querySelector('#linuxCmdInput');
      const outputEl = containerEl.querySelector('#linuxOutputArea');
      const promptSpan = containerEl.querySelector('#linuxPromptSpan');

      function execute(cmdStr) {
        if (!cmdStr) return;
        history.push(cmdStr);
        historyIdx = history.length;

        consoleLines.push(`devops@srv-prod-01:${currentDir}$ ${cmdStr}`);
        const res = executeLinuxCommand(cmdStr, currentDir);
        if (res.clear) {
          consoleLines = [];
        } else if (res.output) {
          consoleLines.push(res.output);
        }
        consoleLines.push('');

        currentDir = res.newDir;
        if (promptSpan) promptSpan.textContent = `devops@srv-prod-01:${currentDir}$`;
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

      containerEl.querySelectorAll('.linux-btn').forEach(btn => {
        btn.addEventListener('click', () => {
          const cmd = btn.getAttribute('data-cmd');
          if (inputEl) inputEl.value = cmd;
          execute(cmd);
        });
      });

      const btnClear = containerEl.querySelector('#btnClearLinux');
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
    window.EJIILearning.Labs['sys-linux-sandbox'] = {
      render: renderLinuxSandboxLab,
      executeLinuxCommand,
      VIRTUAL_FS,
      VIRTUAL_SERVICES
    };
  }

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
      renderLinuxSandboxLab,
      executeLinuxCommand,
      VIRTUAL_FS,
      VIRTUAL_SERVICES
    };
  }
})();
