/**
 * EJII Hardened Diagnostic Tool Sandbox & RBAC Controller
 * Provides strict JSON-schema parameter validation, prompt-injection / command-injection defenses,
 * role-based access control, and deterministic tool execution for the AI Brain.
 */

'use strict';

const net = require('net');
const dns = require('dns').promises;
const { execFile, exec } = require('child_process');
const { IS_WINDOWS } = require('../config');
const { isSafeNetworkTarget } = require('./ai-brain');

// Safe identifier validation regex
const SAFE_HOST_REGEX = /^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,253}[a-zA-Z0-9])?$/;
const SAFE_IP_REGEX = /^(\d{1,3}\.){3}\d{1,3}$|^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$/;
const DANGEROUS_CHARS = /[;&|`$><\n\r\0\x00\\!]/;

const ROLE_PERMISSIONS = {
  ADMIN: ['ping', 'pmtu_sweep', 'tcp_handshake', 'dns_resolve', 'arp_lookup', 'traceroute'],
  NETWORK_ADMIN: ['ping', 'pmtu_sweep', 'tcp_handshake', 'dns_resolve', 'arp_lookup', 'traceroute'],
  SYSADMIN: ['ping', 'pmtu_sweep', 'tcp_handshake', 'dns_resolve', 'arp_lookup', 'traceroute'],
  ANALYST: ['ping', 'pmtu_sweep', 'tcp_handshake', 'dns_resolve', 'arp_lookup', 'traceroute'],
  OPERATOR: ['ping', 'tcp_handshake', 'dns_resolve'],
  NOC_OPERATOR: ['ping', 'tcp_handshake', 'dns_resolve'],
  READONLY: []
};

class ToolExecutionError extends Error {
  constructor(message, code = 400) {
    super(message);
    this.name = 'ToolExecutionError';
    this.statusCode = code;
  }
}

class ToolSandbox {
  constructor() {
    this.auditLog = [];
    this.maxAuditSize = 1000;
  }

  /**
   * Return schema and metadata for available diagnostic tools
   */
  getToolRoster() {
    return [
      {
        name: 'ping',
        description: 'Send ICMP Echo Request probes to test node reachability and round-trip time.',
        requiredRole: 'OPERATOR',
        parameters: {
          type: 'object',
          required: ['target'],
          properties: {
            target: { type: 'string', description: 'Destination IP address or hostname' },
            count: { type: 'integer', minimum: 1, maximum: 10, default: 4 },
            timeout: { type: 'integer', minimum: 100, maximum: 5000, default: 1500 }
          }
        }
      },
      {
        name: 'pmtu_sweep',
        description: 'Progressive multi-size Path MTU DF sweep (e.g. 1472, 1400, 1200, 576 B) to detect fragmentation black holes.',
        requiredRole: 'ANALYST',
        parameters: {
          type: 'object',
          required: ['target'],
          properties: {
            target: { type: 'string', description: 'Destination IP address or hostname' },
            sizes: {
              type: 'array',
              items: { type: 'integer', minimum: 64, maximum: 9000 },
              default: [1472, 1400, 1200, 576]
            },
            timeout: { type: 'integer', minimum: 100, maximum: 5000, default: 1500 }
          }
        }
      },
      {
        name: 'tcp_handshake',
        description: 'Initiate non-intrusive TCP 3-way handshake to measure connection establishment latency or detect closed ports (RST).',
        requiredRole: 'OPERATOR',
        parameters: {
          type: 'object',
          required: ['target', 'port'],
          properties: {
            target: { type: 'string', description: 'Destination IP address or hostname' },
            port: { type: 'integer', minimum: 1, maximum: 65535 },
            timeout: { type: 'integer', minimum: 100, maximum: 5000, default: 2000 }
          }
        }
      },
      {
        name: 'dns_resolve',
        description: 'Perform forward or reverse DNS lookups across configured resolvers.',
        requiredRole: 'OPERATOR',
        parameters: {
          type: 'object',
          required: ['target'],
          properties: {
            target: { type: 'string', description: 'Domain name or IP address to resolve' },
            recordType: { type: 'string', enum: ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'PTR'], default: 'A' }
          }
        }
      },
      {
        name: 'arp_lookup',
        description: 'Query OS ARP cache table to retrieve hardware MAC address for a local IP.',
        requiredRole: 'ANALYST',
        parameters: {
          type: 'object',
          required: ['ip'],
          properties: {
            ip: { type: 'string', description: 'Local subnet IPv4 address' }
          }
        }
      },
      {
        name: 'traceroute',
        description: 'Perform layer 3 hop-by-hop trace to locate routing bottlenecks and upstream packet loss.',
        requiredRole: 'ANALYST',
        parameters: {
          type: 'object',
          required: ['target'],
          properties: {
            target: { type: 'string', description: 'Destination IP address or hostname' },
            maxHops: { type: 'integer', minimum: 1, maximum: 30, default: 15 }
          }
        }
      }
    ];
  }

  /**
   * Authorize and safely execute a diagnostic tool
   */
  async executeTool(toolName, params = {}, userContext = { role: 'ANALYST', username: 'system' }) {
    const startTime = Date.now();
    const userRole = (userContext.role || 'ANALYST').toUpperCase();

    // 1. RBAC Verification
    const allowedTools = ROLE_PERMISSIONS[userRole] || [];
    if (!allowedTools.includes(toolName)) {
      throw new ToolExecutionError(
        `RBAC Violation: Role '${userRole}' is not authorized to execute tool '${toolName}'. Required role: ANALYST or ADMIN.`,
        403
      );
    }

    // 2. Parameter Sanitization and Schema Validation
    const sanitizedParams = this._validateAndSanitizeParams(toolName, params);

    // 3. Deterministic Execution
    let result;
    try {
      switch (toolName) {
        case 'ping':
          result = await this._execPing(sanitizedParams);
          break;
        case 'pmtu_sweep':
          result = await this._execPmtuSweep(sanitizedParams);
          break;
        case 'tcp_handshake':
          result = await this._execTcpHandshake(sanitizedParams);
          break;
        case 'dns_resolve':
          result = await this._execDnsResolve(sanitizedParams);
          break;
        case 'arp_lookup':
          result = await this._execArpLookup(sanitizedParams);
          break;
        case 'traceroute':
          result = await this._execTraceroute(sanitizedParams);
          break;
        default:
          throw new ToolExecutionError(`Unknown diagnostic tool: '${toolName}'`, 404);
      }
    } catch (err) {
      result = {
        success: false,
        error: err.message,
        evidence: { failed: true }
      };
    }

    const durationMs = Date.now() - startTime;
    const executionRecord = {
      tool: toolName,
      user: userContext.username || 'anonymous',
      role: userRole,
      timestamp: new Date().toISOString(),
      durationMs,
      params: sanitizedParams,
      result
    };

    this._recordAudit(executionRecord);

    return {
      tool: toolName,
      durationMs,
      timestamp: executionRecord.timestamp,
      result
    };
  }

  _recordAudit(record) {
    this.auditLog.push(record);
    if (this.auditLog.length > this.maxAuditSize) {
      this.auditLog.shift();
    }
  }

  getAuditLog(limit = 100) {
    return this.auditLog.slice(-limit).reverse();
  }

  /**
   * Validate and sanitize tool parameters
   */
  _validateAndSanitizeParams(toolName, params = {}) {
    if (!params || typeof params !== 'object') {
      throw new ToolExecutionError('Parameters must be a valid JSON object.');
    }

    const target = params.target || params.ip || params.domain;
    if (toolName !== 'arp_lookup' && !target) {
      throw new ToolExecutionError("Parameter 'target' is required.");
    }
    if (toolName === 'arp_lookup' && !params.ip) {
      throw new ToolExecutionError("Parameter 'ip' is required.");
    }

    // Command injection and SSRF defense
    const validateHost = (hostStr) => {
      const h = String(hostStr || '').trim();
      if (!h) throw new ToolExecutionError('Target cannot be empty.');
      if (DANGEROUS_CHARS.test(h)) {
        throw new ToolExecutionError(`Security rejection: Dangerous characters detected in target '${h}'.`);
      }
      if (!SAFE_HOST_REGEX.test(h) && !SAFE_IP_REGEX.test(h)) {
        throw new ToolExecutionError(`Security rejection: Invalid hostname or IP address format '${h}'.`);
      }
      if (!isSafeNetworkTarget(h)) {
        throw new ToolExecutionError('Target rejected by SSRF defense policy', 400);
      }
      return h;
    };

    const sanitized = {};

    if (params.target) sanitized.target = validateHost(params.target);
    if (params.ip) sanitized.ip = validateHost(params.ip);
    if (params.domain) sanitized.domain = validateHost(params.domain);

    if (params.port !== undefined) {
      const p = parseInt(params.port, 10);
      if (isNaN(p) || p < 1 || p > 65535) {
        throw new ToolExecutionError(`Parameter 'port' must be an integer between 1 and 65535. Received: ${params.port}`);
      }
      sanitized.port = p;
    }

    if (params.count !== undefined) {
      const c = parseInt(params.count, 10);
      if (isNaN(c) || c < 1 || c > 10) {
        throw new ToolExecutionError(`Parameter 'count' must be between 1 and 10. Received: ${params.count}`);
      }
      sanitized.count = c;
    } else {
      sanitized.count = 4;
    }

    if (params.timeout !== undefined) {
      const t = parseInt(params.timeout, 10);
      if (isNaN(t) || t < 50 || t > 10000) {
        throw new ToolExecutionError(`Parameter 'timeout' must be between 50 and 10000 ms.`);
      }
      sanitized.timeout = t;
    } else {
      sanitized.timeout = 1500;
    }

    if (toolName === 'pmtu_sweep') {
      if (params.sizes && Array.isArray(params.sizes)) {
        sanitized.sizes = params.sizes.map(s => {
          const sz = parseInt(s, 10);
          if (isNaN(sz) || sz < 64 || sz > 9000) throw new ToolExecutionError(`Invalid PMTU size: ${s}`);
          return sz;
        });
      } else {
        sanitized.sizes = [1472, 1400, 1200, 576];
      }
    }

    if (toolName === 'dns_resolve') {
      const rType = String(params.recordType || 'A').toUpperCase();
      const validTypes = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'PTR'];
      if (!validTypes.includes(rType)) {
        throw new ToolExecutionError(`Invalid DNS recordType '${rType}'. Allowed: ${validTypes.join(', ')}`);
      }
      sanitized.recordType = rType;
    }

    if (toolName === 'traceroute') {
      const mh = parseInt(params.maxHops || 15, 10);
      sanitized.maxHops = Math.min(30, Math.max(1, mh));
    }

    return sanitized;
  }

  // --- Safe Implementations ---

  async _execPing({ target, count, timeout }) {
    const isWindows = IS_WINDOWS;
    const cmd = isWindows ? 'ping' : 'ping';
    const args = isWindows
      ? ['-n', String(count), '-w', String(timeout), target]
      : ['-c', String(count), '-W', String(Math.ceil(timeout / 1000)), target];

    return new Promise((resolve) => {
      execFile(cmd, args, { timeout: (count * timeout) + 2000 }, (err, stdout, stderr) => {
        const outStr = (stdout || '') + (stderr || '');
        const alive = outStr.includes('TTL=') || outStr.includes('ttl=') || outStr.includes('bytes from');

        // Extract average latency
        let rttMs = null;
        const avgMatch = outStr.match(/Average = (\d+)ms/) || outStr.match(/min\/avg\/max[^\/]*\/(\d+\.?\d*)/);
        if (avgMatch) {
          rttMs = parseFloat(avgMatch[1]);
        }

        resolve({
          success: alive,
          target,
          alive,
          rttMs,
          rawOutput: outStr.trim(),
          evidence: {
            pingReachable: alive,
            latencyMs: rttMs
          }
        });
      });
    });
  }

  async _execPmtuSweep({ target, sizes, timeout }) {
    const results = [];
    let clampDetected = false;
    let maxSupportedMtu = null;

    for (const size of sizes) {
      const isWindows = IS_WINDOWS;
      const cmd = isWindows ? 'ping' : 'ping';
      // In Windows, -f sets DF, -l sets payload buffer size
      // Total MTU = size + 20 IP + 8 ICMP = size + 28
      const args = isWindows
        ? ['-n', '1', '-f', '-l', String(size), '-w', String(timeout), target]
        : ['-c', '1', '-M', 'do', '-s', String(size), '-W', String(Math.ceil(timeout / 1000)), target];

      const stepRes = await new Promise((resolve) => {
        execFile(cmd, args, { timeout: timeout + 1000 }, (err, stdout, stderr) => {
          const out = (stdout || '') + (stderr || '');
          const needsFrag = out.includes('Packet needs to be fragmented') ||
                            out.includes('Frag needed') ||
                            out.includes('too large');
          const success = (out.includes('TTL=') || out.includes('ttl=') || out.includes('bytes from')) && !needsFrag;

          resolve({
            payloadSize: size,
            wireMtu: size + 28,
            success,
            fragmentationNeeded: needsFrag,
            rawOutput: out.trim().split('\n')[0]
          });
        });
      });

      results.push(stepRes);
      if (stepRes.success) {
        if (!maxSupportedMtu || stepRes.wireMtu > maxSupportedMtu) {
          maxSupportedMtu = stepRes.wireMtu;
        }
      } else if (stepRes.fragmentationNeeded) {
        clampDetected = true;
      }
    }

    const baseline1472 = results.find(r => r.payloadSize === 1472);
    const baseline1400 = results.find(r => r.payloadSize === 1400);

    return {
      success: results.some(r => r.success),
      target,
      sweep: results,
      maxSupportedWireMtu: maxSupportedMtu,
      isClamped: clampDetected,
      evidence: {
        pmtuSweepExecuted: true,
        mtuSize: maxSupportedMtu || 1500,
        maxSupportedWireMtu: maxSupportedMtu,
        baseline1500Supported: baseline1472 ? baseline1472.success : null,
        clampedBelow1500: clampDetected
      }
    };
  }

  async _execTcpHandshake({ target, port, timeout }) {
    return new Promise((resolve) => {
      const start = process.hrtime.bigint();
      const socket = new net.Socket();
      socket.setTimeout(timeout);

      let finished = false;
      const finish = (result) => {
        if (finished) return;
        finished = true;
        socket.destroy();
        resolve(result);
      };

      socket.connect(port, target, () => {
        const end = process.hrtime.bigint();
        const rttMs = Number(end - start) / 1000000;
        finish({
          success: true,
          target,
          port,
          state: 'OPEN',
          handshakeLatencyMs: Number(rttMs.toFixed(2)),
          evidence: {
            portOpen: true,
            handshakeLatencyMs: Number(rttMs.toFixed(2))
          }
        });
      });

      socket.on('error', (err) => {
        const isRst = err.code === 'ECONNREFUSED';
        finish({
          success: false,
          target,
          port,
          state: isRst ? 'CLOSED_RST' : 'ERROR',
          code: err.code,
          message: err.message,
          evidence: {
            portOpen: false,
            tcpRstObserved: isRst,
            errorCode: err.code
          }
        });
      });

      socket.on('timeout', () => {
        finish({
          success: false,
          target,
          port,
          state: 'TIMEOUT_DROP',
          evidence: {
            portOpen: false,
            synDropped: true,
            timeout: true
          }
        });
      });
    });
  }

  async _execDnsResolve({ target, recordType }) {
    const start = Date.now();
    try {
      let records = [];
      if (recordType === 'PTR') {
        records = await dns.reverse(target);
      } else if (recordType === 'A') {
        records = await dns.resolve4(target);
      } else if (recordType === 'AAAA') {
        records = await dns.resolve6(target);
      } else {
        records = await dns.resolve(target, recordType);
      }
      return {
        success: true,
        target,
        recordType,
        records,
        durationMs: Date.now() - start,
        evidence: {
          dnsResolved: true,
          recordCount: records.length,
          firstRecord: records[0] || null
        }
      };
    } catch (err) {
      return {
        success: false,
        target,
        recordType,
        error: err.code || err.message,
        durationMs: Date.now() - start,
        evidence: {
          dnsResolved: false,
          dnsRcode: err.code || 'UNKNOWN_ERROR'
        }
      };
    }
  }

  async _execArpLookup({ ip }) {
    return new Promise((resolve) => {
      execFile('arp', ['-a'], { timeout: 3000 }, (err, stdout) => {
        const out = stdout || '';
        const lines = out.split('\n');
        let matchedMac = null;
        let entryType = null;

        for (const line of lines) {
          if (line.includes(ip)) {
            const tokens = line.trim().split(/\s+/);
            if (tokens.length >= 2) {
              const macCandidate = tokens.find(t => /^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$/.test(t));
              if (macCandidate) {
                matchedMac = macCandidate.replace(/-/g, ':').toUpperCase();
                entryType = tokens[tokens.indexOf(macCandidate) + 1] || 'dynamic';
                break;
              }
            }
          }
        }

        resolve({
          success: Boolean(matchedMac),
          ip,
          mac: matchedMac,
          entryType,
          evidence: {
            arpResolved: Boolean(matchedMac),
            macAddress: matchedMac
          }
        });
      });
    });
  }

  async _execTraceroute({ target, maxHops }) {
    const isWindows = IS_WINDOWS;
    const cmd = isWindows ? 'tracert' : 'traceroute';
    const args = isWindows ? ['-d', '-h', String(maxHops), '-w', '1000', target] : ['-n', '-m', String(maxHops), '-w', '1', target];

    return new Promise((resolve) => {
      execFile(cmd, args, { timeout: maxHops * 1500 + 3000 }, (err, stdout, stderr) => {
        const out = (stdout || '') + (stderr || '');
        const lines = out.split('\n');
        const hops = [];

        for (const line of lines) {
          const match = line.trim().match(/^(\d+)\s+(.+)$/);
          if (match) {
            hops.push({
              hop: parseInt(match[1], 10),
              raw: match[2].trim()
            });
          }
        }

        resolve({
          success: hops.length > 0,
          target,
          hopsCount: hops.length,
          hops,
          rawOutput: out.trim()
        });
      });
    });
  }
}

const defaultToolSandbox = new ToolSandbox();

module.exports = {
  ToolSandbox,
  toolSandbox: defaultToolSandbox,
  ToolExecutionError
};
