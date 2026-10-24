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
      let procName = processCache.get(pid) || `PID ${pid}`;

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
      const isRemoteValid = sock.remoteAddress && sock.remoteAddress !== '0.0.0.0' && sock.remoteAddress !== '*' && sock.remoteAddress !== '::' && sock.remoteAddress !== '127.0.0.1';
      const troubleshootUrl = isRemoteValid && sock.remotePort > 0
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
   * Query OS active network sockets
   */
  _queryActiveSockets() {
    return new Promise((resolve) => {
      const sockets = [];
      if (IS_WINDOWS) {
        exec('netstat -ano', { timeout: 4000 }, (err, stdout) => {
          if (!err && stdout) {
            const lines = stdout.split('\n');
            for (const line of lines) {
              const tokens = line.trim().split(/\s+/);
              if (tokens.length >= 4 && (tokens[0] === 'TCP' || tokens[0] === 'UDP')) {
                const protocol = tokens[0];
                const localStr = tokens[1];
                const remoteStr = tokens[2];
                const isTcp = protocol === 'TCP';
                const state = isTcp ? (tokens[3] || '').toUpperCase() : 'ACTIVE';
                const pid = parseInt(tokens[tokens.length - 1], 10);

                if (localStr && remoteStr && !isNaN(pid)) {
                  const [localAddress, localPort] = this._parseHostPort(localStr);
                  const [remoteAddress, remotePort] = this._parseHostPort(remoteStr);

                  sockets.push({
                    protocol,
                    localAddress,
                    localPort,
                    remoteAddress,
                    remotePort,
                    state,
                    pid
                  });
                }
              }
            }
          }
          resolve(sockets);
        });
      } else {
        exec('ss -tunp || netstat -tunp', { timeout: 4000 }, (err, stdout) => {
          if (!err && stdout) {
            const lines = stdout.split('\n');
            for (const line of lines) {
              const tokens = line.trim().split(/\s+/);
              if (tokens.length >= 5) {
                const proto = tokens[0].toUpperCase().includes('TCP') ? 'TCP' : 'UDP';
                const localStr = tokens[3] || '';
                const remoteStr = tokens[4] || '';
                const [localAddress, localPort] = this._parseHostPort(localStr);
                const [remoteAddress, remotePort] = this._parseHostPort(remoteStr);
                const pidMatch = line.match(/pid=(\d+)/i) || line.match(/(\d+)\//);
                const pid = pidMatch ? parseInt(pidMatch[1], 10) : 0;

                sockets.push({
                  protocol: proto,
                  localAddress,
                  localPort,
                  remoteAddress,
                  remotePort,
                  state: 'ESTABLISHED',
                  pid
                });
              }
            }
          }
          resolve(sockets);
        });
      }
    });
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
}

const processSocketCorrelator = new ProcessSocketCorrelator();

module.exports = {
  ProcessSocketCorrelator,
  processSocketCorrelator,
  WELL_KNOWN_SERVICES
};
