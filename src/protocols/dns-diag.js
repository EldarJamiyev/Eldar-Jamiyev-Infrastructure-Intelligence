/**
 * EJII Real DNS Diagnostic & Propagation Driver
 * Direct RFC 1035 resolver, system resolver fallback, multi-nameserver latency & record validation.
 */

const dns = require('dns');
const dnsPromises = dns.promises;

// Resolve system nameservers dynamically
function getBenchmarkNameservers() {
  const systemServers = dns.getServers();
  const list = [];

  if (systemServers && systemServers.length > 0) {
    list.push({ name: 'System Default DNS', ip: systemServers[0] });
  }
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

  try {
    if (nameserver) {
      const cleanNs = String(nameserver).trim();
      // Validate IP format
      if (!/^(\d{1,3}\.){3}\d{1,3}$|^([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}$/.test(cleanNs)) {
        return {
          success: false,
          domain: cleanDomain,
          recordType,
          nameserver: cleanNs,
          durationMs: 0,
          records: [],
          error: `Invalid nameserver IP address: ${cleanNs}`
        };
      }
      resolver.setServers([cleanNs]);
    }

    let records = [];
    const typeUpper = recordType.toUpperCase();

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
      nameserver: nameserver || (dns.getServers()[0] || 'System Default'),
      durationMs,
      records,
      error: null
    };
  } catch (err) {
    const durationMs = parseFloat((performance.now() - startTime).toFixed(2));
    return {
      success: false,
      domain: cleanDomain,
      recordType: recordType.toUpperCase(),
      nameserver: nameserver || (dns.getServers()[0] || 'System Default'),
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
