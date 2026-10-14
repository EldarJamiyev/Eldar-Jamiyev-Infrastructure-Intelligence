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

  const resolver = new dnsPromises.Resolver();
  const activeNs = nameserver ? String(nameserver).trim() : getRealSystemDns();
  const typeUpper = (recordType || 'A').toUpperCase();

  try {
    if (activeNs) {
      // Validate IP format
      if (!/^(\d{1,3}\.){3}\d{1,3}$|^([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}$/.test(activeNs)) {
        return {
          success: false,
          domain: cleanDomain,
          recordType,
          nameserver: activeNs,
          durationMs: 0,
          records: [],
          error: `Invalid nameserver IP address: ${activeNs}`
        };
      }
      resolver.setServers([activeNs]);
    }

    let records = [];

    switch (typeUpper) {
      case 'A':
        records = await resolver.resolve4(cleanDomain);
        break;
      case 'AAAA':
        records = await resolver.resolve6(cleanDomain);
        break;
      case 'MX':
        records = await resolver.resolveMx(cleanDomain);
        break;
      case 'TXT':
        records = await resolver.resolveTxt(cleanDomain);
        break;
      case 'CNAME':
        records = await resolver.resolveCname(cleanDomain);
        break;
      case 'NS':
        records = await resolver.resolveNs(cleanDomain);
        break;
      case 'SOA':
        records = [await resolver.resolveSoa(cleanDomain)];
        break;
      case 'ANY':
        records = await resolver.resolveAny(cleanDomain);
        break;
      default:
        records = await resolver.resolve4(cleanDomain);
    }

    const durationMs = parseFloat((performance.now() - startTime).toFixed(2));

    return {
      success: true,
      domain: cleanDomain,
      recordType: typeUpper,
      nameserver: activeNs || 'System Default',
      durationMs,
      records,
      error: null
    };
  } catch (err) {
    // If system resolver socket failed with ECONNREFUSED/ETIMEOUT and domain exists in OS DNS, use OS native lookup
    if (!nameserver && (err.code === 'ECONNREFUSED' || err.code === 'ETIMEOUT') && (typeUpper === 'A' || typeUpper === 'AAAA')) {
      try {
        const lookupRes = await dnsPromises.lookup(cleanDomain, { all: true });
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
            durationMs,
            records: filtered,
            error: null
          };
        }
      } catch (fallbackErr) {}
    }

    const durationMs = parseFloat((performance.now() - startTime).toFixed(2));
    return {
      success: false,
      domain: cleanDomain,
      recordType: typeUpper,
      nameserver: activeNs || 'System Default',
      durationMs,
      records: [],
      error: err.code || err.message
    };
  }
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
  getBenchmarkNameservers
};
