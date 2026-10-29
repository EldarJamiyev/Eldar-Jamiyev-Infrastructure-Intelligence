/**
 * EJII Real DNS Diagnostic & Propagation Driver
 * Direct RFC 1035 resolver, system resolver fallback, multi-nameserver latency & record validation.
 */

const dns = require('dns');
const dnsPromises = dns.promises;

let cachedSystemDns = null;

// Resolve system nameservers dynamically, accounting for Windows adapter naming and loopback fallbacks
function getRealSystemDns() {
  if (cachedSystemDns) return cachedSystemDns;
  const servers = dns.getServers();
  const nonLoopback = servers.filter(s => s !== '127.0.0.1' && s !== '::1');
  if (nonLoopback.length > 0) {
    cachedSystemDns = nonLoopback[0];
    return cachedSystemDns;
  }
  if (process.platform === 'win32') {
    try {
      const { execSync } = require('child_process');
      const out = execSync('ipconfig /all', { timeout: 3000, encoding: 'utf8' });
      const matches = out.match(/DNS Servers[ .:]+([0-9.]+)/g);
      if (matches) {
        for (const m of matches) {
          const ipMatch = m.match(/([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/);
          if (ipMatch && ipMatch[1] !== '127.0.0.1') {
            cachedSystemDns = ipMatch[1];
            return cachedSystemDns;
          }
        }
      }
    } catch (e) {}
  }
  cachedSystemDns = '8.8.8.8';
  return cachedSystemDns;
}

function getBenchmarkNameservers() {
  const sysDns = getRealSystemDns();
  const list = [];
  list.push({ name: 'System Default DNS', ip: sysDns });
  list.push({ name: 'Cloudflare Primary', ip: '1.1.1.1' });
  list.push({ name: 'Google Public DNS', ip: '8.8.8.8' });
  list.push({ name: 'Quad9 Secure', ip: '9.9.9.9' });

  return list;
}

/**
 * Resolve a specific DNS record type using a chosen nameserver
 * @param {string} domain 
 * @param {string} recordType ('A', 'AAAA', 'MX', 'TXT', 'CNAME', 'NS', 'SOA')
 * @param {string} nameserver (optional custom nameserver IP)
 */
async function resolveRecord(domain, recordType = 'A', nameserver = null) {
  const startTime = performance.now();
  const cleanDomain = domain ? domain.trim() : '';

  if (!cleanDomain) {
    return {
      success: false,
      domain,
      recordType,
      nameserver: nameserver || 'default',
      durationMs: 0,
      records: [],
      error: 'Invalid or empty domain specified.'
    };
  }

  const resolver = new dnsPromises.Resolver({ timeout: 900, tries: 1 });
  const activeNs = nameserver ? String(nameserver).trim() : getRealSystemDns();
  const typeUpper = (recordType || 'A').toUpperCase();

  const withDnsTimeout = (promise, ms = 1100) => {
    let timer;
    return Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(() => {
          const timeoutErr = new Error(`DNS query timed out after ${ms}ms`);
          timeoutErr.code = 'ETIMEOUT';
          reject(timeoutErr);
        }, ms);
      })
    ]).finally(() => clearTimeout(timer));
  };

  try {
    if (nameserver) {
      if (!/^(\d{1,3}\.){3}\d{1,3}$|^([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}$/.test(activeNs)) {
        return {
          success: false,
          domain: cleanDomain,
          recordType,
          nameserver: activeNs,
          durationMs: 0,
          records: [],
          error: `Invalid nameserver IP address: ${activeNs}`,
          errorCode: 'EINVAL'
        };
      }
      resolver.setServers([activeNs]);
    } else if (activeNs && /^(\d{1,3}\.){3}\d{1,3}$/.test(activeNs)) {
      const sysServers = dns.getServers();
      if (sysServers.length > 0) {
        resolver.setServers(sysServers);
      } else {
        resolver.setServers([activeNs]);
      }
    }

    let records = [];

    switch (typeUpper) {
      case 'A':
        records = await withDnsTimeout(resolver.resolve4(cleanDomain), 1100);
        break;
      case 'AAAA':
        records = await withDnsTimeout(resolver.resolve6(cleanDomain), 1100);
        break;
      case 'MX':
        records = await withDnsTimeout(resolver.resolveMx(cleanDomain), 1100);
        break;
      case 'TXT':
        records = await withDnsTimeout(resolver.resolveTxt(cleanDomain), 1100);
        break;
      case 'CNAME':
        records = await withDnsTimeout(resolver.resolveCname(cleanDomain), 1100);
        break;
      case 'NS':
        records = await withDnsTimeout(resolver.resolveNs(cleanDomain), 1100);
        break;
      case 'SOA':
        records = [await withDnsTimeout(resolver.resolveSoa(cleanDomain), 1100)];
        break;
      case 'ANY':
        records = await withDnsTimeout(resolver.resolveAny(cleanDomain), 1100);
        break;
      default:
        records = await withDnsTimeout(resolver.resolve4(cleanDomain), 1100);
    }

    const durationMs = parseFloat((performance.now() - startTime).toFixed(2));

    return {
      success: true,
      domain: cleanDomain,
      recordType: typeUpper,
      nameserver: activeNs || 'System Default',
      resolutionMethod: 'dns_protocol',
      durationMs,
      records,
      error: null,
      errorCode: null
    };
  } catch (err) {
    // If system resolver socket failed or returned ETIMEOUT/ESERVFAIL/ECONNREFUSED, try OS native getaddrinfo with strict 900ms cap
    if (!nameserver && (typeUpper === 'A' || typeUpper === 'AAAA') && err.code !== 'ENOTFOUND' && err.code !== 'ENODATA') {
      try {
        const lookupRes = await withDnsTimeout(dnsPromises.lookup(cleanDomain, { all: true }), 900);
        const filtered = lookupRes
          .filter(r => (typeUpper === 'A' ? r.family === 4 : r.family === 6))
          .map(r => r.address);
        if (filtered.length > 0) {
          const durationMs = parseFloat((performance.now() - startTime).toFixed(2));
          return {
            success: true,
            domain: cleanDomain,
            recordType: typeUpper,
            nameserver: activeNs || 'System Native (getaddrinfo)',
            resolutionMethod: cleanDomain.toLowerCase() === 'localhost' ? 'local_hosts_table' : 'os_getaddrinfo',
            durationMs,
            records: filtered,
            error: null,
            errorCode: null
          };
        }
      } catch (fallbackErr) {
        if (cleanDomain.toLowerCase() === 'localhost') {
          const fallbackIp = typeUpper === 'AAAA' ? '::1' : '127.0.0.1';
          const durationMs = parseFloat((performance.now() - startTime).toFixed(2));
          return {
            success: true,
            domain: cleanDomain,
            recordType: typeUpper,
            nameserver: 'local_hosts_table',
            resolutionMethod: 'local_hosts_table',
            durationMs,
            records: [fallbackIp],
            error: null,
            errorCode: null
          };
        }
        const errCode = fallbackErr.code || err.code || 'ENOTFOUND';
        const durationMs = parseFloat((performance.now() - startTime).toFixed(2));
        return {
          success: false,
          domain: cleanDomain,
          recordType: typeUpper,
          nameserver: activeNs || 'System Native (getaddrinfo)',
          resolutionMethod: 'os_getaddrinfo',
          durationMs,
          records: [],
          error: errCode,
          errorCode: errCode
        };
      }

      if (cleanDomain.toLowerCase() === 'localhost') {
        const fallbackIp = typeUpper === 'AAAA' ? '::1' : '127.0.0.1';
        const durationMs = parseFloat((performance.now() - startTime).toFixed(2));
        return {
          success: true,
          domain: cleanDomain,
          recordType: typeUpper,
          nameserver: 'local_hosts_table',
          resolutionMethod: 'local_hosts_table',
          durationMs,
          records: [fallbackIp],
          error: null,
          errorCode: null
        };
      }
    }

    const errCode = err.code || err.message || 'ENOTFOUND';
    const durationMs = parseFloat((performance.now() - startTime).toFixed(2));
    return {
      success: false,
      domain: cleanDomain,
      recordType: typeUpper,
      nameserver: activeNs || 'System Default',
      resolutionMethod: 'dns_protocol',
      durationMs,
      records: [],
      error: errCode,
      errorCode: errCode
    };
  }
}

/**
 * Inspect local DNS configuration and perform a real DNS connectivity health check
 */
async function checkDnsConnectivityHealth(probeDomain = 'example.com') {
  const fs = require('fs');
  const startTime = performance.now();
  const configuredServers = dns.getServers();
  const primaryResolver = getRealSystemDns();
  let searchDomains = [];

  if (process.platform !== 'win32') {
    try {
      if (fs.existsSync('/etc/resolv.conf')) {
        const content = fs.readFileSync('/etc/resolv.conf', 'utf8');
        for (const line of content.split('\n')) {
          const trimmed = line.trim();
          if (trimmed.startsWith('search ') || trimmed.startsWith('domain ')) {
            searchDomains.push(...trimmed.split(/\s+/).slice(1));
          }
        }
      }
    } catch (_) {}
  }

  const [localhostProbe, externalProbe] = await Promise.all([
    resolveRecord('localhost', 'A'),
    resolveRecord(probeDomain || 'example.com', 'A')
  ]);

  const totalDurationMs = parseFloat((performance.now() - startTime).toFixed(2));
  return {
    configuredServers,
    primaryResolver,
    searchDomains,
    localhostProbe,
    externalProbe,
    healthy: Boolean(localhostProbe.success && externalProbe.success),
    localOnlyHealthy: Boolean(localhostProbe.success && !externalProbe.success),
    totalDurationMs,
    observedAt: new Date().toISOString()
  };
}

/**
 * Check DNS propagation across multiple nameservers
 * @param {string} domain 
 * @param {string} recordType 
 */
async function checkPropagation(domain, recordType = 'A') {
  const servers = getBenchmarkNameservers();
  const results = await Promise.all(
    servers.map(async (ns) => {
      const res = await resolveRecord(domain, recordType, ns.ip);
      return {
        serverName: ns.name,
        serverIp: ns.ip,
        ...res
      };
    })
  );

  const successful = results.filter((r) => r.success);
  const normalize = (records) => (records || []).map(x => typeof x === 'object' ? JSON.stringify(x) : String(x)).sort().join(',');
  const isConsistent =
    successful.length > 0 &&
    successful.every(
      (r) => normalize(r.records) === normalize(successful[0].records)
    );

  return {
    domain,
    recordType,
    serversQueried: results.length,
    successCount: successful.length,
    isConsistent,
    results
  };
}

module.exports = {
  resolveRecord,
  checkPropagation,
  getBenchmarkNameservers,
  getRealSystemDns,
  checkDnsConnectivityHealth
};


