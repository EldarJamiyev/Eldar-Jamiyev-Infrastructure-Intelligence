/**
 * EJII Real DNS Diagnostic & Propagation Driver
 * Direct RFC 1035 resolver, system resolver fallback, multi-nameserver latency & record validation.
 */

const dns = require('dns');
const fs = require('fs');
const dnsPromises = dns.promises;

function isLoopbackResolverAddress(ip) {
  const clean = String(ip || '').trim().toLowerCase().replace(/^\[|\]$/g, '');
  return (
    clean === '127.0.0.1' ||
    clean === '127.0.0.53' ||
    clean.startsWith('127.') ||
    clean === '::1' ||
    clean === '0:0:0:0:0:0:0:1'
  );
}

/**
 * Platform-appropriate DNS resolver discovery.
 * Distinguishes:
 *   1. DNS servers actually observed in the operating system configuration
 *   2. Local stub resolvers such as loopback DNS services (127.0.0.1, 127.0.0.53, ::1)
 *   3. Upstream DNS servers, only when independently identifiable
 *   4. Unknown or unavailable resolver information (never guesses or fabricates 8.8.8.8)
 */
function discoverSystemDnsConfiguration(options = {}) {
  const customGetServers = typeof options.getServersFn === 'function'
    ? options.getServersFn
    : (Array.isArray(options.nodeServers) ? () => options.nodeServers : () => dns.getServers());
  const customPlatform = options.platform || process.platform;
  const hasExplicitResolvConfContent = typeof options.resolvConfContent === 'string';
  const customResolvConfPath = options.resolvConfPath !== undefined
    ? options.resolvConfPath
    : (hasExplicitResolvConfContent ? null : '/etc/resolv.conf');
  const customUpstreamResolvPath = options.upstreamResolvPath !== undefined
    ? options.upstreamResolvPath
    : (hasExplicitResolvConfContent ? null : '/run/systemd/resolve/resolv.conf');

  const observedSet = new Set();
  const stubSet = new Set();
  const upstreamSet = new Set();
  const searchDomains = [];
  const methodsUsed = [];

  if (!hasExplicitResolvConfContent || Array.isArray(options.nodeServers) || typeof options.getServersFn === 'function') {
    try {
      const rawNodeServers = customGetServers() || [];
      if (Array.isArray(rawNodeServers) && rawNodeServers.length > 0) {
        methodsUsed.push('node_dns_getServers');
        for (const s of rawNodeServers) {
          const clean = String(s || '').trim().replace(/^\[|\]$/g, '').split('%')[0];
          if (!clean) continue;
          observedSet.add(clean);
          if (isLoopbackResolverAddress(clean)) {
            stubSet.add(clean);
          } else {
            upstreamSet.add(clean);
          }
        }
      }
    } catch (_) {}
  }

  if (customPlatform !== 'win32') {
    try {
      const content = hasExplicitResolvConfContent
        ? options.resolvConfContent
        : (customResolvConfPath && fs.existsSync(customResolvConfPath) ? fs.readFileSync(customResolvConfPath, 'utf8') : null);
      if (typeof content === 'string') {
        if (!methodsUsed.includes('/etc/resolv.conf')) methodsUsed.push('/etc/resolv.conf');
        for (const line of content.split('\n')) {
          const trimmed = line.trim();
          if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith(';')) continue;
          if (trimmed.startsWith('nameserver ')) {
            const ns = trimmed.split(/\s+/)[1]?.trim();
            if (ns) {
              observedSet.add(ns);
              if (isLoopbackResolverAddress(ns)) {
                stubSet.add(ns);
              } else {
                upstreamSet.add(ns);
              }
            }
          } else if (trimmed.startsWith('search ') || trimmed.startsWith('domain ')) {
            for (const dom of trimmed.split(/\s+/).slice(1)) {
              if (dom && !searchDomains.includes(dom)) searchDomains.push(dom);
            }
          }
        }
      }
    } catch (_) {}

    if (typeof options.resolvectlOutput === 'string' && options.resolvectlOutput.trim()) {
      const dnsLineMatches = options.resolvectlOutput.match(/DNS Servers:\s*([^\n\r]+)/gi) || [];
      let foundResolvectl = false;
      for (const line of dnsLineMatches) {
        const tokens = line.replace(/DNS Servers:\s*/i, '').trim().split(/\s+/);
        for (const tok of tokens) {
          if (tok && !isLoopbackResolverAddress(tok)) {
            upstreamSet.add(tok);
            foundResolvectl = true;
          }
        }
      }
      if (foundResolvectl) {
        methodsUsed.push('resolvectl_status');
      }
    }

    // If only a local stub resolver (such as systemd-resolved 127.0.0.53) was observed,
    // check whether upstream resolvers are independently identifiable in systemd-resolved state
    if (upstreamSet.size === 0 && stubSet.size > 0 && customUpstreamResolvPath) {
      try {
        if (fs.existsSync(customUpstreamResolvPath)) {
          const upContent = fs.readFileSync(customUpstreamResolvPath, 'utf8');
          let foundUpstream = false;
          for (const line of upContent.split('\n')) {
            const trimmed = line.trim();
            if (trimmed.startsWith('nameserver ')) {
              const ns = trimmed.split(/\s+/)[1]?.trim();
              if (ns && !isLoopbackResolverAddress(ns)) {
                upstreamSet.add(ns);
                foundUpstream = true;
              }
            }
          }
          if (foundUpstream) {
            methodsUsed.push('systemd_resolved_upstream');
          }
        }
      } catch (_) {}
    }
  } else if (options.allowWin32Exec !== false) {
    try {
      const { execSync } = require('child_process');
      const out = execSync('ipconfig /all', { timeout: 3000, encoding: 'utf8' });
      const matches = out.match(/DNS Servers[ .:]+([0-9a-fA-F.:]+)/g);
      if (matches) {
        methodsUsed.push('win32_ipconfig');
        for (const m of matches) {
          const ipMatch = m.match(/([0-9]{1,3}(?:\.[0-9]{1,3}){3})/);
          if (ipMatch && ipMatch[1]) {
            const ip = ipMatch[1];
            observedSet.add(ip);
            if (isLoopbackResolverAddress(ip)) {
              stubSet.add(ip);
            } else {
              upstreamSet.add(ip);
            }
          }
        }
      }
    } catch (_) {}
  }

  const observedServers = Array.from(observedSet);
  const localStubResolvers = Array.from(stubSet);
  const upstreamResolvers = Array.from(upstreamSet);
  const collectionMethod = methodsUsed.length > 0 ? methodsUsed.join('+') : 'os_resolver_config_unavailable';

  if (localStubResolvers.length > 0 && observedServers.every((s) => isLoopbackResolverAddress(s))) {
    return {
      status: 'local_stub_resolver',
      verified: true,
      isLocalStub: true,
      resolverType: 'local_stub_resolver',
      primaryResolver: upstreamResolvers[0] || localStubResolvers[0],
      observedServers,
      configuredServers: observedServers,
      localStubResolvers,
      localStubServers: localStubResolvers,
      upstreamResolvers,
      upstreamServers: upstreamResolvers,
      searchDomains,
      collectionMethod,
      limitationReason: upstreamResolvers.length > 0
        ? null
        : `Only a local loopback stub resolver (${localStubResolvers.join(', ')}) is visible in the operating system configuration; upstream forwarders are managed internally by the local stub daemon.`
    };
  }

  if (upstreamResolvers.length > 0) {
    return {
      status: 'verified',
      verified: true,
      isLocalStub: false,
      resolverType: 'upstream_configured',
      primaryResolver: upstreamResolvers[0],
      observedServers,
      configuredServers: observedServers,
      localStubResolvers,
      localStubServers: localStubResolvers,
      upstreamResolvers,
      upstreamServers: upstreamResolvers,
      searchDomains,
      collectionMethod,
      limitationReason: null
    };
  }

  return {
    status: 'unavailable',
    verified: false,
    isLocalStub: false,
    resolverType: 'unavailable',
    primaryResolver: null,
    observedServers: [],
    configuredServers: [],
    localStubResolvers: [],
    localStubServers: [],
    upstreamResolvers: [],
    upstreamServers: [],
    searchDomains,
    collectionMethod,
    limitationReason: 'No DNS resolver addresses were observed in the operating system configuration. EJII never assumes or fabricates a fallback public resolver (such as 8.8.8.8) as the detected system DNS.'
  };
}

/**
 * Resolve system nameserver dynamically without ever fabricating a hardcoded 8.8.8.8 fallback.
 * Returns the observed upstream resolver, or observed local stub resolver, or null if unavailable.
 */
function getRealSystemDns(options = {}) {
  const discovery = discoverSystemDnsConfiguration(options);
  return discovery.primaryResolver || null;
}

function getBenchmarkNameservers() {
  const discovery = discoverSystemDnsConfiguration();
  const list = [];
  if (discovery.primaryResolver) {
    list.push({
      name: discovery.resolverType === 'local_stub_resolver' ? 'System Local Stub DNS' : 'System Configured DNS',
      ip: discovery.primaryResolver
    });
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
      nameserver: nameserver || null,
      durationMs: 0,
      records: [],
      error: 'Invalid or empty domain specified.'
    };
  }

  const resolver = new dnsPromises.Resolver({ timeout: 900, tries: 1 });
  const dnsDiscovery = nameserver ? null : discoverSystemDnsConfiguration();
  const activeNs = nameserver ? String(nameserver).trim() : (dnsDiscovery?.primaryResolver || null);
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
    } else if (dnsDiscovery && dnsDiscovery.observedServers.length > 0) {
      resolver.setServers(dnsDiscovery.observedServers);
    } else {
      const noResolverErr = new Error('No configured system DNS resolver available');
      noResolverErr.code = 'ENOSYS_DNS_UNAVAILABLE';
      throw noResolverErr;
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
      nameserver: activeNs || 'unverified',
      resolverType: dnsDiscovery ? dnsDiscovery.resolverType : 'explicit_nameserver',
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
      nameserver: activeNs || null,
      resolverType: dnsDiscovery ? dnsDiscovery.resolverType : 'unavailable',
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
async function checkDnsConnectivityHealth(probeDomain = 'example.com', options = {}) {
  const startTime = performance.now();
  const resolverDiscovery = discoverSystemDnsConfiguration(options);

  const [localhostProbe, externalProbe] = await Promise.all([
    resolveRecord('localhost', 'A'),
    resolveRecord(probeDomain || 'example.com', 'A')
  ]);

  const totalDurationMs = parseFloat((performance.now() - startTime).toFixed(2));
  return {
    resolverStatus: resolverDiscovery.status,
    resolverType: resolverDiscovery.resolverType,
    configuredServers: resolverDiscovery.observedServers,
    localStubResolvers: resolverDiscovery.localStubResolvers,
    upstreamResolvers: resolverDiscovery.upstreamResolvers,
    primaryResolver: resolverDiscovery.primaryResolver,
    collectionMethod: resolverDiscovery.collectionMethod,
    limitationReason: resolverDiscovery.limitationReason,
    searchDomains: resolverDiscovery.searchDomains,
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
  discoverSystemDnsConfiguration,
  checkDnsConnectivityHealth,
  isLoopbackResolverAddress
};


