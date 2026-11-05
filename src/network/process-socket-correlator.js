/**
 * EJII Process Socket Correlator & Application Server Finder
 * Real-time correlation between OS active sockets, running processes, wire capture, DNS, and TLS SNI.
 *
 * Reveals unknown remote servers and ports used by client applications (e.g., ERP, SQL, RDP, browsers)
 * and generates 1-click deep-link troubleshooting actions directly into Core Diagnostics / RCA.
 *
 * 100% Genuine OS & Wire Telemetry — Zero Simulation.
 */

'use strict';

const { exec } = require('child_process');
const { IS_WINDOWS } = require('../config');

// Well-known ports to service labels
const WELL_KNOWN_SERVICES = {
  20: 'FTP-Data',
  21: 'FTP-Control',
  22: 'SSH',
  23: 'Telnet',
  25: 'SMTP',
  53: 'DNS',
  67: 'DHCP-Server',
  68: 'DHCP-Client',
  69: 'TFTP',
  80: 'HTTP',
  88: 'Kerberos',
  110: 'POP3',
  123: 'NTP',
  135: 'MS-RPC',
  137: 'NetBIOS-NS',
  138: 'NetBIOS-DGM',
  139: 'NetBIOS-SSN',
  143: 'IMAP',
  161: 'SNMP',
  389: 'LDAP',
  443: 'HTTPS',
  445: 'SMB/CIFS',
  465: 'SMTPS',
  514: 'Syslog',
  587: 'SMTP-Submission',
  636: 'LDAPS',
  993: 'IMAPS',
  995: 'POP3S',
  1433: 'MS-SQL Server',
  1521: 'Oracle DB',
  2049: 'NFS',
  3306: 'MySQL',
  3389: 'RDP (Remote Desktop)',
  5060: 'SIP (VoIP)',
  5432: 'PostgreSQL',
  5900: 'VNC',
  6379: 'Redis',
  8000: 'HTTP-Alt',
  8080: 'HTTP-Proxy/Alt',
  8443: 'HTTPS-Alt / EJII',
  9092: 'Apache Kafka',
  27017: 'MongoDB'
};


function buildCompositeProcessIdentity(procInfo = {}) {
  const pid = procInfo.pid || 0;
  const name = procInfo.processName || procInfo.name || 'unknown';
  const startToken = procInfo.startToken || procInfo.startTime || 't0';
  const exePath = procInfo.exePath || procInfo.path || procInfo.command || 'unknown';
  return `pid:${name}:${startToken}:${exePath}`;
}

class ProcessSocketCorrelator {
  constructor(options = {}) {
    this.packetStreamer = options.packetStreamer || null;
    this.processMap = new Map(); // pid -> processName
    this.endpoints = []; // Array of correlated endpoint objects
    this.endpointTimelineMap = new Map(); // rolling process endpoint history
    this.lastRefreshedAt = null;
    this.cacheTtlMs = options.cacheTtlMs || 2500;
  }

  /**
   * Set or update packet streamer reference for wire correlation
   */
  setPacketStreamer(streamer) {
    this.packetStreamer = streamer;
  }

  /**
   * Refresh OS process table and socket table
   */
  async refresh() {
    const processCache = await this._queryRunningProcesses();
    const rawSockets = await this._queryActiveSockets();

    // Ingest DNS and SNI maps from packet streamer if available
    const dnsMap = new Map();
    const sniMap = new Map();

    if (this.packetStreamer) {
      if (this.packetStreamer.ipToDomainCache) {
        for (const [ip, entry] of this.packetStreamer.ipToDomainCache.entries()) {
          dnsMap.set(ip, entry.domain || entry.hostname);
        }
      }
      if (this.packetStreamer.dnsResolutionMap) {
        for (const [ip, entry] of this.packetStreamer.dnsResolutionMap.entries()) {
          dnsMap.set(ip, entry.hostname || entry.domain);
        }
      }
      if (this.packetStreamer.tlsSniMap) {
        for (const [ip, sni] of this.packetStreamer.tlsSniMap.entries()) {
          sniMap.set(ip, sni);
        }
      }
    }

    const correlated = [];
    const now = Date.now();

    for (const sock of rawSockets) {
      const pid = sock.pid;
      let procName = sock.processNameFromSocket || processCache.get(pid) || `PID ${pid}`;


      // Normalize system/idle names
      if (pid === 0 || procName.toLowerCase().includes('idle')) {
        if (sock.state === 'TIME_WAIT') {
          procName = '[Closed Session (TIME_WAIT)]';
        } else if (sock.state === 'CLOSE_WAIT') {
          procName = '[Closed Session (CLOSE_WAIT)]';
        } else if (sock.state === 'LISTENING') {
          procName = '[Listening Socket]';
        } else {
          procName = 'System / Unmapped';
        }
      }

      // Resolve domain / SNI
      const domain = dnsMap.get(sock.remoteAddress) || null;
      const sni = sniMap.get(sock.remoteAddress) || null;

      // Determine service hint
      const knownService = WELL_KNOWN_SERVICES[sock.remotePort] || WELL_KNOWN_SERVICES[sock.localPort] || null;
      let serviceHint = knownService || (sock.remotePort ? `Port ${sock.remotePort}` : 'Unknown');
      if (sni) {
        serviceHint = `${serviceHint} (${sni})`;
      } else if (domain) {
        serviceHint = `${serviceHint} (${domain})`;
      }

      // Generate 1-click deep-link URL into Core Diagnostics / RCA
      const isRemoteValid = Boolean(
        sock.remoteAddress &&
        sock.remoteAddress !== '0.0.0.0' &&
        sock.remoteAddress !== '*' &&
        sock.remoteAddress !== '::' &&
        sock.remoteAddress !== '[::]' &&
        sock.remoteAddress !== '127.0.0.1' &&
        sock.remotePort > 0
      );
      const troubleshootUrl = isRemoteValid
        ? `/core-diagnostics?host=${encodeURIComponent(sock.remoteAddress)}&port=${sock.remotePort}`
        : null;

      correlated.push({
        pid,
        processName: procName,
        protocol: sock.protocol,
        localAddress: sock.localAddress,
        localPort: sock.localPort,
        remoteAddress: sock.remoteAddress,
        remotePort: sock.remotePort,
        state: sock.state,
        domain,
        sni,
        serviceHint,
        troubleshootUrl,
        isExternal: isRemoteValid,
        timestamp: now
      });
    }

    for (const ep of correlated) {
      const key = `${ep.processName}[PID:${ep.pid}]->${ep.remoteAddress}:${ep.remotePort}`;
      if (!this.endpointTimelineMap.has(key)) {
        this.endpointTimelineMap.set(key, []);
      }
      const ring = this.endpointTimelineMap.get(key);
      ring.push({
        state: ep.state,
        domain: ep.domain,
        sni: ep.sni,
        serviceHint: ep.serviceHint,
        timestamp: ep.timestamp
      });
      if (ring.length > 50) ring.shift();
    }

    this.endpoints = correlated.length > 2500 ? correlated.slice(-2500) : correlated;
    this.lastRefreshedAt = now;
    return this.endpoints;
  }

  /**
   * Get correlated endpoints with optional filtering
   * @param {Object} filter
   */
  async getCorrelatedEndpoints(filter = {}) {
    const now = Date.now();
    if (!this.lastRefreshedAt || (now - this.lastRefreshedAt > this.cacheTtlMs)) {
      await this.refresh();
    }

    let results = [...this.endpoints];

    if (filter.process) {
      const q = filter.process.toLowerCase();
      results = results.filter(e => e.processName.toLowerCase().includes(q) || String(e.pid) === q);
    }

    if (filter.remoteHost) {
      const q = filter.remoteHost.toLowerCase();
      results = results.filter(e =>
        (e.remoteAddress && e.remoteAddress.toLowerCase().includes(q)) ||
        (e.domain && e.domain.toLowerCase().includes(q)) ||
        (e.sni && e.sni.toLowerCase().includes(q))
      );
    }

    if (filter.port) {
      const p = parseInt(filter.port, 10);
      if (!isNaN(p)) {
        results = results.filter(e => e.remotePort === p || e.localPort === p);
      }
    }

    if (filter.state) {
      const s = filter.state.toUpperCase();
      if (s === 'FAILURES') {
        results = results.filter(e => e.state === 'SYN_SENT' || e.state === 'CLOSE_WAIT' || e.state === 'TIME_WAIT' || e.state === 'LAST_ACK');
      } else if (s === 'ACTIVE') {
        results = results.filter(e => e.state === 'ESTABLISHED');
      } else {
        results = results.filter(e => e.state === s);
      }
    }

    if (filter.externalOnly) {
      results = results.filter(e => e.isExternal);
    }

    return results;
  }

  /**
   * Get rolling timeline history of watched process endpoints
   */
  getWatchedProcessHistory(procFilter = '') {
    const q = (procFilter || '').toLowerCase().trim();
    const history = [];
    for (const [key, entries] of this.endpointTimelineMap.entries()) {
      if (!q || key.toLowerCase().includes(q)) {
        history.push({
          targetKey: key,
          snapshotsCount: entries.length,
          firstSeen: entries[0]?.timestamp || null,
          lastSeen: entries[entries.length - 1]?.timestamp || null,
          snapshots: entries.slice(-20)
        });
      }
    }
    return history;
  }

  /**
   * Aggregate active sockets into bi-directional conversations (flows)
   */
  async getConversations(limit = 100) {
    const endpoints = await this.getCorrelatedEndpoints();
    const convMap = new Map();

    for (const ep of endpoints) {
      if (!ep.remoteAddress || ep.remoteAddress === '0.0.0.0' || ep.remoteAddress === '*' || ep.remoteAddress === '::') {
        continue;
      }

      // Generate canonical conversation key (order agnostic for bidirectional flows)
      const a = `${ep.localAddress}:${ep.localPort}`;
      const b = `${ep.remoteAddress}:${ep.remotePort}`;
      const key = a < b ? `${a}<->${b}/${ep.protocol}` : `${b}<->${a}/${ep.protocol}`;

      if (!convMap.has(key)) {
        convMap.set(key, {
          conversationId: key,
          endpointA: a,
          endpointB: b,
          localAddress: ep.localAddress,
          localPort: ep.localPort,
          remoteAddress: ep.remoteAddress,
          remotePort: ep.remotePort,
          protocol: ep.protocol,
          processName: ep.processName,
          pid: ep.pid,
          state: ep.state,
          domain: ep.domain,
          sni: ep.sni,
          serviceHint: ep.serviceHint,
          troubleshootUrl: ep.troubleshootUrl,
          lastSeen: ep.timestamp
        });
      }
    }

    return Array.from(convMap.values()).slice(0, limit);
  }

  /**
   * Query OS running processes (PID -> Process Name)
   */
  _queryRunningProcesses() {
    return new Promise((resolve) => {
      const map = new Map();
      if (IS_WINDOWS) {
        exec('tasklist /fo csv /nh', { timeout: 3500 }, (err, stdout) => {
          if (!err && stdout) {
            const lines = stdout.split('\r\n');
            for (const line of lines) {
              const parts = line.split('","');
              if (parts.length >= 2) {
                const name = parts[0].replace(/^"/, '');
                const pid = parseInt(parts[1], 10);
                if (!isNaN(pid)) {
                  map.set(pid, name);
                }
              }
            }
          }
          resolve(map);
        });
      } else {
        exec('ps -eo pid,comm', { timeout: 3000 }, (err, stdout) => {
          if (!err && stdout) {
            const lines = stdout.split('\n');
            for (const line of lines) {
              const tokens = line.trim().split(/\s+/);
              if (tokens.length >= 2) {
                const pid = parseInt(tokens[0], 10);
                const name = tokens.slice(1).join(' ');
                if (!isNaN(pid) && name) {
                  map.set(pid, name);
                }
              }
            }
          }
          resolve(map);
        });
      }
    });
  }

  /**
   * Query OS active network sockets with truthful collection metadata
   */
  _queryActiveSockets() {
    const fs = require('fs');
    return new Promise((resolve) => {
      const sockets = [];
      this.lastCollectionMethod = null;
      this.lastCollectorError = null;
      this.lastProcessAttributionAvailable = false;
      this.lastPermissionRestricted = false;

      if (IS_WINDOWS) {
        exec('netstat -ano', { timeout: 4000 }, (err, stdout) => {
          if (err && !stdout) {
            this.lastCollectionMethod = 'netstat -ano';
            this.lastCollectorError = err.message || 'netstat -ano execution failed';
            return resolve([]);
          }
          this.lastCollectionMethod = 'netstat -ano';
          if (stdout) {
            const lines = stdout.split('\n');
            for (const line of lines) {
              const tokens = line.trim().split(/\s+/);
              if (tokens.length >= 4 && (tokens[0] === 'TCP' || tokens[0] === 'UDP')) {
                const protocol = tokens[0];
                const localStr = tokens[1];
                const remoteStr = tokens[2];
                const isTcp = protocol === 'TCP';
                const state = isTcp ? (tokens[3] || '').toUpperCase() : 'UNCONNECTED';
                const pid = parseInt(tokens[tokens.length - 1], 10);

                if (localStr && remoteStr && !isNaN(pid)) {
                  if (pid > 0) this.lastProcessAttributionAvailable = true;
                  const [localAddress, localPort] = this._parseHostPort(localStr);
                  const [remoteAddress, remotePort] = this._parseHostPort(remoteStr);

                  sockets.push({
                    protocol,
                    localAddress,
                    localPort,
                    remoteAddress,
                    remotePort,
                    state,
                    pid,
                    processNameFromSocket: null,
                    collectionMethod: 'netstat -ano'
                  });
                }
              }
            }
          }
          resolve(sockets);
        });
      } else {
        exec('ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null', { timeout: 3500 }, (err, stdout) => {
          if (!err && stdout && stdout.trim().split('\n').length > 1) {
            const isSs = stdout.includes('Netid') || stdout.includes('ESTAB') || stdout.includes('UNCONN');
            this.lastCollectionMethod = isSs ? 'ss -tunap' : 'netstat -tunap';
            const lines = stdout.split('\n');
            for (const line of lines) {
              const trimmed = line.trim();
              if (!trimmed || trimmed.startsWith('Netid') || trimmed.startsWith('Active') || trimmed.startsWith('Proto')) {
                continue;
              }
              const tokens = trimmed.split(/\s+/);
              if (tokens.length >= 5) {
                const protoToken = tokens[0].toUpperCase();
                if (!protoToken.startsWith('TCP') && !protoToken.startsWith('UDP')) continue;
                const proto = protoToken.startsWith('TCP') ? 'TCP' : 'UDP';
                let rawState = tokens[1].toUpperCase();
                let localStr = tokens[4] || '';
                let remoteStr = tokens[5] || '';
                if (!isSs) {
                  // netstat -tunap layout: Proto(0) Recv-Q(1) Send-Q(2) Local(3) Foreign(4) State(5) PID/Program(6)
                  localStr = tokens[3] || '';
                  remoteStr = tokens[4] || '';
                  rawState = proto === 'TCP' ? (tokens[5] || 'ESTABLISHED').toUpperCase() : 'UNCONNECTED';
                }
                const stateMap = {
                  ESTAB: 'ESTABLISHED',
                  ESTABLISHED: 'ESTABLISHED',
                  LISTEN: 'LISTENING',
                  LISTENING: 'LISTENING',
                  'TIME-WAIT': 'TIME_WAIT',
                  TIME_WAIT: 'TIME_WAIT',
                  'CLOSE-WAIT': 'CLOSE_WAIT',
                  CLOSE_WAIT: 'CLOSE_WAIT',
                  'SYN-SENT': 'SYN_SENT',
                  SYN_SENT: 'SYN_SENT',
                  'SYN-RECV': 'SYN_RECV',
                  'FIN-WAIT-1': 'FIN_WAIT_1',
                  'FIN-WAIT-2': 'FIN_WAIT_2',
                  'LAST-ACK': 'LAST_ACK',
                  UNCONN: 'UNCONNECTED'
                };
                const normalizedState = stateMap[rawState] || rawState;
                const [localAddress, localPort] = this._parseHostPort(localStr);
                const [remoteAddress, remotePort] = this._parseHostPort(remoteStr);

                // Extract process name & PID from users:(("node",pid=123,fd=20)) or 123/node
                let pid = 0;
                let procNameFromSock = null;
                const ssUserMatch = trimmed.match(/users:\(\("([^"]+)",pid=(\d+)/i);
                if (ssUserMatch) {
                  procNameFromSock = ssUserMatch[1];
                  pid = parseInt(ssUserMatch[2], 10) || 0;
                } else {
                  const pidMatch = trimmed.match(/pid=(\d+)/i) || trimmed.match(/\s(\d+)\/([^\s:]+)/);
                  if (pidMatch) {
                    pid = parseInt(pidMatch[1], 10) || 0;
                    if (pidMatch[2]) procNameFromSock = pidMatch[2];
                  }
                }
                if (pid > 0) this.lastProcessAttributionAvailable = true;

                sockets.push({
                  protocol: proto,
                  localAddress,
                  localPort,
                  remoteAddress,
                  remotePort,
                  state: normalizedState,
                  pid,
                  processNameFromSocket: procNameFromSock,
                  collectionMethod: this.lastCollectionMethod
                });
              }
            }
            if (sockets.length > 0 || (!err && stdout && stdout.includes('Netid'))) {
              this.lastCollectionSucceeded = true;
              this.lastPermissionRestricted = typeof process.getuid === 'function' && process.getuid() !== 0 && !sockets.some(s => s.pid > 0 && s.pid !== process.pid);
              return resolve(sockets);
            }
          }

          // Fallback to direct Linux /proc/net/{tcp,tcp6,udp} kernel socket table parsing
          try {
            const procRes = this._parseLinuxProcNetSockets();
            if (procRes.readable) {
              this.lastCollectionSucceeded = true;
              this.lastCollectionMethod = '/proc/net/tcp+/proc/net/udp';
              this.lastProcessAttributionAvailable = procRes.sockets.some(s => s.pid > 0);
              this.lastPermissionRestricted = typeof process.getuid === 'function' && process.getuid() !== 0;
              return resolve(procRes.sockets);
            } else {
              this.lastCollectionSucceeded = false;
              this.lastCollectorError = procRes.error || (err && err.message) || 'OS socket tables (/proc/net/tcp and ss/netstat) are unavailable or unreadable';
            }
          } catch (procErr) {
            this.lastCollectionSucceeded = false;
            this.lastCollectorError = procErr.message;
          }

          if (err && !this.lastCollectorError) {
            this.lastCollectionSucceeded = false;
            this.lastCollectorError = err.message || 'Unable to query OS socket table';
          }
          this.lastCollectionMethod = this.lastCollectionMethod || 'unavailable';
          resolve(sockets);
        });
      }
    });
  }

  /**
   * Parse Linux /proc/net/tcp and /proc/net/udp directly and map socket inodes to /proc/<pid>/fd when permitted
   */
  _parseLinuxProcNetSockets() {
    const fs = require('fs');
    const path = require('path');
    const results = [];
    const inodeToPid = new Map();
    let readableFilesCount = 0;

    // Map socket:[inode] from /proc/<pid>/fd for accessible processes
    try {
      const procEntries = fs.readdirSync('/proc');
      for (const entry of procEntries) {
        if (!/^\d+$/.test(entry)) continue;
        const pid = parseInt(entry, 10);
        let comm = `PID ${pid}`;
        try {
          comm = fs.readFileSync(`/proc/${pid}/comm`, 'utf8').trim() || comm;
        } catch (_) {}
        try {
          const fdDir = `/proc/${pid}/fd`;
          const fds = fs.readdirSync(fdDir);
          for (const fd of fds) {
            try {
              const link = fs.readlinkSync(path.join(fdDir, fd));
              const m = link.match(/^socket:\[(\d+)\]$/);
              if (m) {
                inodeToPid.set(m[1], { pid, processName: comm });
              }
            } catch (_) {}
          }
        } catch (_) {}
      }
    } catch (_) {}

    const tcpStates = {
      '01': 'ESTABLISHED',
      '02': 'SYN_SENT',
      '03': 'SYN_RECV',
      '04': 'FIN_WAIT_1',
      '05': 'FIN_WAIT_2',
      '06': 'TIME_WAIT',
      '07': 'CLOSED',
      '08': 'CLOSE_WAIT',
      '09': 'LAST_ACK',
      '0A': 'LISTENING',
      '0B': 'CLOSING'
    };

    const decodeHexIpV4 = (hexIpPort) => {
      const [hexIp, hexPort] = String(hexIpPort || '').split(':');
      if (!hexIp || hexIp.length !== 8) return ['0.0.0.0', 0];
      const ip = [
        parseInt(hexIp.slice(6, 8), 16),
        parseInt(hexIp.slice(4, 6), 16),
        parseInt(hexIp.slice(2, 4), 16),
        parseInt(hexIp.slice(0, 2), 16)
      ].join('.');
      const port = parseInt(hexPort || '0', 16) || 0;
      return [ip, port];
    };

    const parseProcFile = (filePath, protocol) => {
      if (!fs.existsSync(filePath)) return;
      const content = fs.readFileSync(filePath, 'utf8');
      readableFilesCount++;
      const lines = content.trim().split('\n').slice(1);
      for (const line of lines) {
        const cols = line.trim().split(/\s+/);
        if (cols.length < 10) continue;
        const [localAddress, localPort] = decodeHexIpV4(cols[1]);
        const [remoteAddress, remotePort] = decodeHexIpV4(cols[2]);
        const stateHex = (cols[3] || '').toUpperCase();
        const inode = cols[9];
        const procOwner = inodeToPid.get(inode);
        const state = protocol === 'UDP'
          ? (remoteAddress !== '0.0.0.0' && remotePort > 0 ? 'ESTABLISHED' : 'UNCONNECTED')
          : (tcpStates[stateHex] || 'UNKNOWN');

        results.push({
          protocol,
          localAddress,
          localPort,
          remoteAddress,
          remotePort,
          state,
          pid: procOwner ? procOwner.pid : 0,
          processNameFromSocket: procOwner ? procOwner.processName : null,
          collectionMethod: filePath
        });
      }
    };

    parseProcFile('/proc/net/tcp', 'TCP');
    parseProcFile('/proc/net/udp', 'UDP');
    return {
      readable: readableFilesCount > 0,
      sockets: results,
      error: readableFilesCount === 0 ? 'Neither /proc/net/tcp nor /proc/net/udp exists or is readable' : null
    };
  }

  /**
   * Collect a rich, truthful inventory of active connections and destination endpoints with full scope/permission metadata.
   * Never fabricates sockets and never presents a socket collection failure as a verified empty inventory.
   */
  async collectActiveConnectionsInventory(filter = {}, options = {}) {
    const fs = require('fs');
    const isContainer = Boolean(
      fs.existsSync('/.dockerenv') ||
      fs.existsSync('/run/.containerenv') ||
      (fs.existsSync('/proc/1/cgroup') && fs.readFileSync('/proc/1/cgroup', 'utf8').includes('docker'))
    );
    const collectionScope = isContainer ? 'container_network_namespace' : 'host_network_namespace';
    const scopeExplanation = isContainer
      ? 'Collected from the EJII container network namespace. Only sockets and processes visible inside this container namespace are listed; EJII does not claim visibility into a remote client workstation or outside its container namespace.'
      : 'Collected from the local host OS network stack.';

    if (options.forceFailureReason) {
      return {
        success: false,
        collectionStatus: 'collector_failed',
        connections: [],
        totalCount: null,
        establishedCount: null,
        listeningCount: null,
        externalDestinations: [],
        collectionMethod: 'unavailable',
        processAttributionAvailable: false,
        permissionRestricted: true,
        isContainer,
        collectionScope,
        scopeExplanation,
        collectorError: String(options.forceFailureReason),
        observedAt: new Date().toISOString()
      };
    }

    if (typeof options.collectorOverrideFn === 'function') {
      try {
        const customRes = await options.collectorOverrideFn(filter);
        if (customRes && customRes.success === false) {
          return {
            success: false,
            collectionStatus: 'collector_failed',
            connections: [],
            totalCount: null,
            establishedCount: null,
            listeningCount: null,
            externalDestinations: [],
            collectionMethod: customRes.collectionMethod || 'unavailable',
            processAttributionAvailable: false,
            permissionRestricted: true,
            isContainer,
            collectionScope,
            scopeExplanation,
            collectorError: customRes.collectorError || 'Socket collector failed',
            observedAt: new Date().toISOString()
          };
        }
      } catch (overrideErr) {
        return {
          success: false,
          collectionStatus: 'collector_failed',
          connections: [],
          totalCount: null,
          establishedCount: null,
          listeningCount: null,
          externalDestinations: [],
          collectionMethod: 'unavailable',
          processAttributionAvailable: false,
          permissionRestricted: true,
          isContainer,
          collectionScope,
          scopeExplanation,
          collectorError: overrideErr.message || 'Socket collector threw an exception',
          observedAt: new Date().toISOString()
        };
      }
    }

    await this.refresh();
    const filtered = await this.getCorrelatedEndpoints(filter);
    const collectionSucceeded = this.lastCollectionSucceeded !== false && !this.lastCollectorError;

    if (!collectionSucceeded && filtered.length === 0) {
      return {
        success: false,
        collectionStatus: 'collector_failed',
        connections: [],
        totalCount: null,
        establishedCount: null,
        listeningCount: null,
        externalDestinations: [],
        collectionMethod: this.lastCollectionMethod || 'unavailable',
        processAttributionAvailable: false,
        permissionRestricted: Boolean(this.lastPermissionRestricted),
        isContainer,
        collectionScope,
        scopeExplanation,
        collectorError: this.lastCollectorError || 'Socket table collection failed; unable to verify active connections.',
        observedAt: new Date().toISOString()
      };
    }

    const rows = filtered.map((ep) => ({
      processName: ep.processName || (ep.pid > 0 ? `PID ${ep.pid}` : 'Unattributed (OS Permission Scope)'),
      pid: ep.pid || null,
      protocol: ep.protocol || 'TCP',
      localAddress: ep.localAddress || '0.0.0.0',
      localPort: ep.localPort || 0,
      remoteAddress: ep.remoteAddress || '0.0.0.0',
      remotePort: ep.remotePort || 0,
      state: ep.state || 'UNKNOWN',
      isExternal: Boolean(ep.isExternal),
      serviceHint: ep.serviceHint || null,
      domain: ep.domain || null,
      sni: ep.sni || null,
      timestamp: new Date(ep.timestamp || Date.now()).toISOString(),
      collectionMethod: this.lastCollectionMethod || 'os_socket_table',
      processAttributionAvailable: Boolean(ep.pid && ep.pid > 0)
    }));

    return {
      success: true,
      collectionStatus: 'verified',
      connections: rows,
      totalCount: rows.length,
      establishedCount: rows.filter((r) => r.state === 'ESTABLISHED').length,
      listeningCount: rows.filter((r) => r.state === 'LISTENING').length,
      externalDestinations: Array.from(
        new Set(
          rows
            .filter((r) => r.remoteAddress && r.remoteAddress !== '0.0.0.0' && r.remoteAddress !== '*' && r.remoteAddress !== '::' && r.remotePort > 0)
            .map((r) => `${r.remoteAddress}:${r.remotePort}`)
        )
      ),
      collectionMethod: this.lastCollectionMethod || 'os_socket_table',
      processAttributionAvailable: Boolean(this.lastProcessAttributionAvailable),
      permissionRestricted: Boolean(this.lastPermissionRestricted),
      isContainer,
      collectionScope,
      scopeExplanation,
      collectorError: this.lastCollectorError || null,
      observedAt: new Date().toISOString()
    };
  }

  /**
   * Helper to parse IP:Port strings across IPv4 and IPv6
   */
  _parseHostPort(str) {
    if (!str) return ['', 0];
    const lastColon = str.lastIndexOf(':');
    if (lastColon === -1) return [str, 0];
    const host = str.slice(0, lastColon).replace(/^\[|\]$/g, '');
    const port = parseInt(str.slice(lastColon + 1), 10) || 0;
    return [host, port];
  }

  /**
   * Process-to-Endpoint & Service Dependency DAG (EJII Phase 4)
   * Maps each local process (pid, processName, serviceName) -> bound local IP/port
   * -> remote IP/port -> resolved DNS domain -> next-hop router/gateway MAC & IP.
   * Computes Service Blast Radius & Single-Point-of-Failure (SPOF) Criticality.
   */
  buildProcessServiceDependencyGraph(activeSockets = [], arpTable = [], routingTable = [], dnsCache = []) {
    const nodes = new Map(); // nodeId -> Node
    const edges = [];
    const processFlows = new Map(); // pid -> flows[]
    const blastRadiusMap = new Map(); // nodeId -> affectedProcessesCount

    const addNode = (id, label, type, metadata = {}) => {
      if (!nodes.has(id)) {
        nodes.set(id, { id, label, type, metadata });
      }
      return nodes.get(id);
    };

    const addEdge = (source, target, relationship, metadata = {}) => {
      edges.push({
        edgeId: `DEP-${source}->${target}`,
        source,
        target,
        relationship,
        metadata
      });
    };

    // Index ARP & DNS lookups
    const arpByIp = new Map();
    for (const entry of (arpTable || [])) {
      if (entry.ip) arpByIp.set(entry.ip, entry.mac);
    }

    const domainByIp = new Map();
    for (const entry of (dnsCache || [])) {
      if (entry.ip && entry.domain) domainByIp.set(entry.ip, entry.domain);
    }

    // Default Gateway resolution from routing table (only when verified)
    let defaultGatewayIp = null;
    for (const route of (routingTable || [])) {
      if (route.destination === '0.0.0.0' || route.dest === '0.0.0.0') {
        defaultGatewayIp = route.gateway || null;
        break;
      }
    }
    const gatewayNodeId = defaultGatewayIp ? `NODE-GW-${defaultGatewayIp}` : 'NODE-GW-UNVERIFIED';
    const gatewayMac = defaultGatewayIp ? (arpByIp.get(defaultGatewayIp) || null) : null;
    addNode(gatewayNodeId, defaultGatewayIp ? `Default Gateway (${defaultGatewayIp})` : 'Default Gateway (Unverified)', 'GATEWAY', {
      ip: defaultGatewayIp,
      mac: gatewayMac,
      layer: 'L3_ROUTER'
    });

    const socketsToProcess = Array.isArray(activeSockets) && activeSockets.length > 0 ? activeSockets : this.endpoints;


    for (const sock of socketsToProcess) {
      const pid = sock.pid || 0;
      const procName = sock.processName || (this.processMap.get(pid) || `Process-${pid}`);
      const procNodeId = `PROC-${pid}-${procName}`;
      const localEndpointId = `SOCK-LOC-${sock.localAddress || '127.0.0.1'}:${sock.localPort || 0}`;

      addNode(procNodeId, `${procName} (PID: ${pid})`, 'PROCESS', { pid, processName: procName });
      addNode(localEndpointId, `${sock.localAddress || '0.0.0.0'}:${sock.localPort || 0}`, 'SOCKET_LOCAL', {
        address: sock.localAddress,
        port: sock.localPort,
        protocol: sock.protocol || 'TCP'
      });
      addEdge(procNodeId, localEndpointId, 'BINDS_SOCKET');

      if (sock.remoteAddress && sock.remoteAddress !== '0.0.0.0' && sock.remoteAddress !== '*') {
        const remoteEndpointId = `SOCK-REM-${sock.remoteAddress}:${sock.remotePort || 0}`;
        const domain = domainByIp.get(sock.remoteAddress) || sock.domain || null;
        const serviceName = WELL_KNOWN_SERVICES[sock.remotePort] || (sock.remotePort === 443 ? 'HTTPS' : 'AppService');

        addNode(remoteEndpointId, `${domain || sock.remoteAddress}:${sock.remotePort || 0} [${serviceName}]`, 'SERVICE_ENDPOINT', {
          ip: sock.remoteAddress,
          port: sock.remotePort,
          domain,
          serviceName
        });
        addEdge(localEndpointId, remoteEndpointId, 'CONNECTS_TO', { state: sock.state || 'ESTABLISHED' });

        // Link external remote endpoint to Gateway dependency
        const isLoopback = sock.remoteAddress === '127.0.0.1' || sock.remoteAddress.startsWith('127.');
        if (!isLoopback) {
          addEdge(remoteEndpointId, gatewayNodeId, 'ROUTED_VIA');
        }

        // Track process flow
        if (!processFlows.has(procNodeId)) {
          processFlows.set(procNodeId, []);
        }
        processFlows.get(procNodeId).push({
          local: localEndpointId,
          remote: remoteEndpointId,
          domain,
          serviceName,
          gateway: !isLoopback ? gatewayNodeId : null
        });
      }
    }

    // Compute Blast Radius & SPOF Criticality
    const spofRankings = [];
    for (const [nodeId, node] of nodes.entries()) {
      let affectedPids = new Set();
      if (node.type === 'GATEWAY') {
        for (const [pId, flows] of processFlows.entries()) {
          if (flows.some(f => f.gateway === nodeId)) {
            affectedPids.add(pId);
          }
        }
      } else if (node.type === 'SERVICE_ENDPOINT') {
        for (const [pId, flows] of processFlows.entries()) {
          if (flows.some(f => f.remote === nodeId)) {
            affectedPids.add(pId);
          }
        }
      } else if (node.type === 'PROCESS') {
        affectedPids.add(nodeId);
      }

      blastRadiusMap.set(nodeId, affectedPids.size);
      spofRankings.push({
        nodeId,
        label: node.label,
        type: node.type,
        affectedProcessesCount: affectedPids.size,
        spofCriticalityPct: Number(((affectedPids.size / Math.max(1, processFlows.size)) * 100).toFixed(1))
      });
    }

    spofRankings.sort((a, b) => b.affectedProcessesCount - a.affectedProcessesCount);

    return {
      nodes: Array.from(nodes.values()),
      edges,
      totalProcesses: processFlows.size,
      spofRankings,
      generatedAtIso: new Date().toISOString()
    };
  }
}

const processSocketCorrelator = new ProcessSocketCorrelator();

module.exports = {
  ProcessSocketCorrelator,
  processSocketCorrelator,
  WELL_KNOWN_SERVICES
};
