'use strict';

/**
 * EJII Project Atlas IV+ Evolution — Resilient UDP NAT Session Table
 *
 * Prevents UDP file-descriptor exhaustion and source-IP rotation DoS attacks by:
 *   1. Enforcing a global session cap (`maxSessions`, default 256) with strict O(1) Map-order LRU eviction.
 *   2. Enforcing per-subnet session quotas (`maxSessionsPerSubnet`, default 32 per IPv4 /24 or canonical IPv6 /64)
 *      backed by per-subnet LRU Maps (`subnetSessions: Map<subnet, Map<clientKey, entry>>`) for strict O(1)
 *      per-subnet eviction without scanning the global session table.
 *   3. Canonical IPv6 /64 expansion (`expandCanonicalIpv6`) normalizing compressed `::`, bracketed `[ipv6]:port`,
 *      and IPv4-mapped `::ffff:a.b.c.d` addresses so equivalent IPv6 representations always resolve to the same
 *      canonical `/64` prefix.
 *   4. Deterministically closing upstream `dgram.Socket` descriptors (idempotently via `_socketClosed`) and
 *      clearing idle timers on every eviction, timeout, error, or listener shutdown.
 */

const net = require('node:net');

function stripAddressDecorations(rawIp) {
  let clean = String(rawIp || '').trim();
  if (!clean) return '';
  if (clean.startsWith('[')) {
    const closeIdx = clean.indexOf(']');
    if (closeIdx > 1) {
      clean = clean.slice(1, closeIdx);
    }
  }
  const zoneIdx = clean.indexOf('%');
  if (zoneIdx > 0) {
    clean = clean.slice(0, zoneIdx);
  }
  return clean.toLowerCase();
}

function expandCanonicalIpv6(ipStr) {
  const clean = stripAddressDecorations(ipStr);
  if (!clean) return null;

  // Check IPv4-mapped IPv6 (e.g., ::ffff:192.168.1.10)
  if (clean.startsWith('::ffff:')) {
    const v4Part = clean.slice(7);
    if (net.isIP(v4Part) === 4) {
      return { isMappedV4: true, v4Address: v4Part };
    }
  }

  if (net.isIP(clean) !== 6) return null;

  let working = clean;
  // Handle embedded IPv4 tail in IPv6 (e.g., 64:ff9b::192.0.2.33)
  const lastColon = working.lastIndexOf(':');
  if (lastColon !== -1 && working.slice(lastColon + 1).includes('.')) {
    const v4Tail = working.slice(lastColon + 1);
    if (net.isIP(v4Tail) === 4) {
      const octets = v4Tail.split('.').map((o) => Number(o));
      const h1 = ((octets[0] << 8) | octets[1]).toString(16).padStart(4, '0');
      const h2 = ((octets[2] << 8) | octets[3]).toString(16).padStart(4, '0');
      working = `${working.slice(0, lastColon)}:${h1}:${h2}`;
    }
  }

  let groups = [];
  if (working.includes('::')) {
    const [leftRaw, rightRaw] = working.split('::');
    const leftGroups = leftRaw ? leftRaw.split(':').filter(Boolean) : [];
    const rightGroups = rightRaw ? rightRaw.split(':').filter(Boolean) : [];
    const missingCount = Math.max(0, 8 - (leftGroups.length + rightGroups.length));
    groups = [
      ...leftGroups,
      ...Array.from({ length: missingCount }, () => '0000'),
      ...rightGroups
    ];
  } else {
    groups = working.split(':');
  }

  if (groups.length !== 8) return null;
  const canonicalHextets = groups.map((g) => g.padStart(4, '0').slice(-4).toLowerCase());
  return {
    isMappedV4: false,
    hextets: canonicalHextets,
    prefix64: `${canonicalHextets.slice(0, 4).join(':')}::/64`
  };
}

function extractSubnetPrefix(ip) {
  const clean = stripAddressDecorations(ip);
  if (!clean) return 'unknown/0';

  if (net.isIP(clean) === 4) {
    const parts = clean.split('.');
    return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
  }

  const expandedV6 = expandCanonicalIpv6(clean);
  if (expandedV6) {
    if (expandedV6.isMappedV4) {
      const parts = expandedV6.v4Address.split('.');
      return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
    }
    return expandedV6.prefix64;
  }

  return `${clean}/32`;
}

class ResilientUdpNatTable {
  constructor(options = {}) {
    this.maxSessions = Math.max(4, Number(options.maxSessions) || 256);
    this.maxSessionsPerSubnet = Math.max(2, Number(options.maxSessionsPerSubnet) || 32);
    this.idleTimeoutMs = Math.max(50, Number(options.idleTimeoutMs) || 30_000);
    this.onSessionEvicted = typeof options.onSessionEvicted === 'function' ? options.onSessionEvicted : null;

    this.sessions = new Map(); // clientKey -> entry (Map insertion order = global LRU)
    this.subnetSessions = new Map(); // subnet -> Map<clientKey, entry> (Map insertion order = per-subnet LRU)

    this.metrics = {
      createdSessionsCount: 0,
      evictedLruCount: 0,
      evictedSubnetQuotaCount: 0,
      expiredIdleCount: 0,
      malformedEndpointRejectedCount: 0,
      socketsDeterministicallyClosedCount: 0
    };
  }

  get size() {
    return this.sessions.size;
  }

  has(clientKey) {
    return this.sessions.has(clientKey);
  }

  get(clientKey) {
    return this.sessions.get(clientKey);
  }

  keys() {
    return this.sessions.keys();
  }

  values() {
    return this.sessions.values();
  }

  entries() {
    return this.sessions.entries();
  }

  [Symbol.iterator]() {
    return this.sessions[Symbol.iterator]();
  }

  _getSubnetMap(subnet, createIfMissing = false) {
    let subMap = this.subnetSessions.get(subnet);
    if (!subMap && createIfMissing) {
      subMap = new Map();
      this.subnetSessions.set(subnet, subMap);
    }
    return subMap;
  }

  getOrCreateSession(clientKey, clientIp, clientPort, socketFactory) {
    const cleanIp = stripAddressDecorations(clientIp);
    const numPort = Number(clientPort);
    const isValidIp =
      cleanIp === 'localhost' ||
      net.isIP(cleanIp) === 4 ||
      net.isIP(cleanIp) === 6 ||
      Boolean(expandCanonicalIpv6(cleanIp));
    const isValidPort =
      clientPort === undefined ||
      clientPort === null ||
      (Number.isInteger(numPort) && numPort >= 1 && numPort <= 65535);
    if (!cleanIp || !isValidIp || !isValidPort) {
      this.metrics.malformedEndpointRejectedCount += 1;
      const err = new Error(
        `Invalid UDP NAT client endpoint (clientIp="${clientIp}", clientPort="${clientPort}")`
      );
      err.code = 'UDP_NAT_INVALID_CLIENT_ENDPOINT';
      throw err;
    }

    if (this.sessions.has(clientKey)) {
      return this.touchSession(clientKey);
    }

    const subnet = extractSubnetPrefix(clientIp);
    const subMap = this._getSubnetMap(subnet, true);

    // 1. Per-subnet O(1) LRU eviction if subnet quota is reached
    if (subMap.size >= this.maxSessionsPerSubnet) {
      const oldestInSubnetKey = subMap.keys().next().value;
      if (oldestInSubnetKey) {
        this.evictSession(oldestInSubnetKey, 'SUBNET_QUOTA_LRU_EVICTION');
        this.metrics.evictedSubnetQuotaCount += 1;
      }
    }

    // 2. Global O(1) LRU eviction if global capacity is reached
    if (this.sessions.size >= this.maxSessions) {
      const oldestGlobalKey = this.sessions.keys().next().value;
      if (oldestGlobalKey) {
        this.evictSession(oldestGlobalKey, 'GLOBAL_CAPACITY_LRU_EVICTION');
        this.metrics.evictedLruCount += 1;
      }
    }

    const socket = typeof socketFactory === 'function' ? socketFactory() : null;
    const now = Date.now();
    const entry = {
      sessionKey: clientKey,
      clientKey,
      clientIp,
      clientAddress: clientIp,
      clientPort,
      subnet,
      socket,
      _socketClosed: false,
      createdAt: now,
      lastActiveAt: now,
      lastSendPerfMs: 0,
      packetsForwarded: 0,
      packetsIn: 0,
      packetsOut: 0,
      bytesForwarded: 0,
      timer: null
    };

    this._armIdleTimer(entry);
    this.sessions.set(clientKey, entry);
    this._getSubnetMap(subnet, true).set(clientKey, entry);
    this.metrics.createdSessionsCount += 1;
    return entry;
  }

  touchSession(clientKey, bytesCount = 0) {
    const entry = this.sessions.get(clientKey);
    if (!entry) return null;

    // Promote to MRU in global Map (O(1))
    this.sessions.delete(clientKey);
    entry.lastActiveAt = Date.now();
    entry.packetsForwarded += 1;
    entry.bytesForwarded += Math.max(0, Number(bytesCount) || 0);
    this._armIdleTimer(entry);
    this.sessions.set(clientKey, entry);

    // Promote to MRU in per-subnet Map (O(1))
    const subMap = this.subnetSessions.get(entry.subnet);
    if (subMap) {
      subMap.delete(clientKey);
      subMap.set(clientKey, entry);
    }
    return entry;
  }

  _armIdleTimer(entry) {
    if (entry.timer) {
      clearTimeout(entry.timer);
    }
    entry.timer = setTimeout(() => {
      this.metrics.expiredIdleCount += 1;
      this.evictSession(entry.clientKey, 'IDLE_TIMEOUT_EXPIRED');
    }, this.idleTimeoutMs);
    if (entry.timer && typeof entry.timer.unref === 'function') {
      entry.timer.unref();
    }
  }

  evictSession(clientKey, reason = 'MANUAL_EVICTION') {
    const entry = this.sessions.get(clientKey);
    if (!entry) return false;

    this.sessions.delete(clientKey);
    const subMap = this.subnetSessions.get(entry.subnet);
    if (subMap) {
      subMap.delete(clientKey);
      if (subMap.size === 0) {
        this.subnetSessions.delete(entry.subnet);
      }
    }

    if (entry.timer) {
      clearTimeout(entry.timer);
      entry.timer = null;
    }

    if (entry.socket && !entry._socketClosed) {
      entry._socketClosed = true;
      try {
        if (typeof entry.socket.removeAllListeners === 'function') {
          entry.socket.removeAllListeners();
        }
        if (typeof entry.socket.close === 'function') {
          entry.socket.close();
          this.metrics.socketsDeterministicallyClosedCount += 1;
        }
      } catch (_) {}
    }

    if (this.onSessionEvicted) {
      try {
        this.onSessionEvicted(entry, reason);
      } catch (_) {}
    }
    return true;
  }

  delete(clientKey) {
    return this.evictSession(clientKey, 'MAP_DELETE');
  }

  clear() {
    return this.closeAllSessions('TABLE_CLEARED');
  }

  closeAllSessions(reason = 'LISTENER_SHUTDOWN') {
    const keys = Array.from(this.sessions.keys());
    for (const key of keys) {
      this.evictSession(key, reason);
    }
    return keys.length;
  }

  getDescriptorAudit() {
    let openSocketsCount = 0;
    let activeTimersCount = 0;
    let closedSocketsStillInTableCount = 0;
    for (const entry of this.sessions.values()) {
      if (entry._socketClosed) {
        closedSocketsStillInTableCount += 1;
      } else if (entry.socket) {
        openSocketsCount += 1;
      }
      if (entry.timer) {
        activeTimersCount += 1;
      }
    }
    const activeSessionsCount = this.sessions.size;
    let totalSubnetIndexedCount = 0;
    for (const subMap of this.subnetSessions.values()) {
      totalSubnetIndexedCount += subMap.size;
    }
    const descriptorLeakDetected =
      closedSocketsStillInTableCount > 0 ||
      totalSubnetIndexedCount !== activeSessionsCount ||
      activeTimersCount !== activeSessionsCount;
    return {
      activeSessionsCount,
      totalSubnetIndexedCount,
      openSocketsCount,
      activeTimersCount,
      closedSocketsStillInTableCount,
      descriptorLeakDetected,
      malformedEndpointRejectedCount: this.metrics.malformedEndpointRejectedCount,
      socketsDeterministicallyClosedCount: this.metrics.socketsDeterministicallyClosedCount
    };
  }

  getMetrics() {
    const subnetCounts = {};
    for (const [subnet, subMap] of this.subnetSessions.entries()) {
      subnetCounts[subnet] = subMap.size;
    }
    return {
      activeSessionsCount: this.sessions.size,
      activeSubnetsCount: this.subnetSessions.size,
      subnetCounts,
      maxSessions: this.maxSessions,
      maxSessionsPerSubnet: this.maxSessionsPerSubnet,
      idleTimeoutMs: this.idleTimeoutMs,
      ...this.metrics
    };
  }
}

module.exports = {
  ResilientUdpNatTable,
  extractSubnetPrefix,
  expandCanonicalIpv6
};
