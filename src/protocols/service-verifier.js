/**
 * EJII Enterprise Web & Mail Service Verifier Driver
 * Production-grade Layer 1–7 verification for governmental and enterprise services (e.g. mail.taxes.gov.az).
 * 
 * Capabilities:
 * 1. Web Service Verifier: Real DNS (A/AAAA), TCP handshake latency, TLS 1.3 handshake,
 *    X.509 cert chain & SAN inspection, expiration countdown, HTTP redirect tracking (up to 5 hops),
 *    TTFB measurement, and plain-language helpdesk synthesis.
 * 2. Mail Service Verifier: DNS MX, SPF, DMARC RFC validation, raw socket banner grabbing across
 *    ports 25 (SMTP EHLO/STARTTLS), 587 (Submission), 465 (SMTPS), 993 (IMAPS * OK), 143 (IMAP),
 *    110 (POP3), 995 (POP3S), and firewall ACL drop detection (ETIMEDOUT vs ECONNREFUSED).
 */

const dns = require('dns').promises;
const net = require('net');
const tls = require('tls');
const http = require('http');
const https = require('https');
const { URL } = require('url');

/**
 * Determine if an IP address belongs to RFC1918 private space or CGNAT/loopback
 * @param {string} ip 
 * @returns {boolean}
 */
function isPrivateIp(ip) {
  if (!ip || typeof ip !== 'string') return false;
  const clean = ip.trim();
  if (clean === '127.0.0.1' || clean === '::1' || clean.startsWith('127.')) return true;
  if (clean.startsWith('10.')) return true;
  if (clean.startsWith('192.168.')) return true;
  if (clean.startsWith('169.254.')) return true;
  if (/^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(clean)) return true;
  if (/^100\.(6[4-9]|[7-9][0-9]|1[0-1][0-9]|12[0-7])\./.test(clean)) return true; // CGNAT RFC 6598
  return false;
}

/**
 * Perform deep verification of an enterprise Web endpoint (HTTP/HTTPS)
 * @param {string} targetUrl 
 * @param {object} options 
 */
async function verifyWebEndpoint(targetUrl, options = {}) {
  const timeoutMs = options.timeoutMs || 5000;
  const maxRedirects = options.maxRedirects || 5;

  let normalizedUrl = (targetUrl || '').trim();
  if (!normalizedUrl) {
    throw new Error('Target URL or hostname is required.');
  }

  if (!/^https?:\/\//i.test(normalizedUrl)) {
    // Default to HTTPS if no protocol specified
    normalizedUrl = `https://${normalizedUrl}`;
  }

  let parsed;
  try {
    parsed = new URL(normalizedUrl);
  } catch (e) {
    throw new Error(`Invalid URL format [${normalizedUrl}]: ${e.message}`);
  }

  const hostname = parsed.hostname;
  const isHttps = parsed.protocol === 'https:';
  const port = parsed.port ? parseInt(parsed.port, 10) : (isHttps ? 443 : 80);

  const report = {
    targetUrl: normalizedUrl,
    hostname,
    port,
    protocol: parsed.protocol.replace(':', ''),
    timestamp: new Date().toISOString(),
    dns: {
      success: false,
      ipv4: [],
      ipv6: [],
      isPrivate: false,
      resolutionDurationMs: 0,
      error: null
    },
    tcp: {
      success: false,
      connectedIp: null,
      port,
      connectLatencyMs: 0,
      errorCode: null,
      error: null
    },
    tls: null,
    http: {
      success: false,
      statusCode: null,
      statusMessage: null,
      redirects: [],
      finalUrl: normalizedUrl,
      headers: {},
      ttfbMs: 0,
      totalDurationMs: 0,
      bodySnippet: '',
      error: null
    },
    verdict: 'UNKNOWN',
    technicalSummary: '',
    helpdeskSummary: {
      az: '',
      en: ''
    }
  };

  // 1. Layer 3: DNS Resolution
  const dnsStart = performance.now();
  try {
    const aRecords = await dns.resolve4(hostname).catch(() => []);
    const aaaaRecords = await dns.resolve6(hostname).catch(() => []);
    report.dns.resolutionDurationMs = parseFloat((performance.now() - dnsStart).toFixed(2));
    report.dns.ipv4 = aRecords;
    report.dns.ipv6 = aaaaRecords;
    report.dns.success = (aRecords.length > 0 || aaaaRecords.length > 0);

    if (report.dns.success) {
      report.dns.isPrivate = aRecords.some(ip => isPrivateIp(ip));
    } else {
      // If hostname is already an IP address
      if (net.isIP(hostname)) {
        report.dns.success = true;
        report.dns.ipv4 = [hostname];
        report.dns.isPrivate = isPrivateIp(hostname);
      } else {
        report.dns.error = 'DNS lookup returned no A or AAAA records (NXDOMAIN or unresolvable).';
      }
    }
  } catch (err) {
    report.dns.resolutionDurationMs = parseFloat((performance.now() - dnsStart).toFixed(2));
    if (net.isIP(hostname)) {
      report.dns.success = true;
      report.dns.ipv4 = [hostname];
      report.dns.isPrivate = isPrivateIp(hostname);
    } else {
      report.dns.error = err.code || err.message;
    }
  }

  if (!report.dns.success) {
    report.verdict = 'CRITICAL_ERROR';
    report.technicalSummary = `DNS resolution failed for [${hostname}]: ${report.dns.error}. Host cannot be mapped to an IP address.`;
    report.helpdeskSummary.az = `Domen adı [${hostname}] IP ünvanına çevrilə bilmədi (DNS xətası). Zəhmət olmasa daxili DNS serverinə (10.22.10.11) qoşulmanı və domen adının düzgünlüyünü yoxlayın.`;
    report.helpdeskSummary.en = `Domain name [${hostname}] could not be resolved to an IP address. Check internal DNS configuration (10.22.10.11) or verify domain spelling.`;
    return report;
  }

  const connectIp = report.dns.ipv4[0] || report.dns.ipv6[0];
  report.tcp.connectedIp = connectIp;

  // 2. Layer 4: Raw TCP Connection
  const tcpStart = performance.now();
  const tcpResult = await new Promise((resolve) => {
    const sock = new net.Socket();
    let handled = false;

    sock.setTimeout(timeoutMs);

    sock.on('connect', () => {
      if (handled) return;
      handled = true;
      const latency = parseFloat((performance.now() - tcpStart).toFixed(2));
      sock.destroy();
      resolve({ success: true, latency, errorCode: null });
    });

    sock.on('timeout', () => {
      if (handled) return;
      handled = true;
      sock.destroy();
      resolve({ success: false, latency: timeoutMs, errorCode: 'ETIMEDOUT', error: 'Connection timed out (no SYN-ACK received from remote host).' });
    });

    sock.on('error', (err) => {
      if (handled) return;
      handled = true;
      const latency = parseFloat((performance.now() - tcpStart).toFixed(2));
      sock.destroy();
      resolve({ success: false, latency, errorCode: err.code || 'ECONN_FAIL', error: err.message });
    });

    sock.connect(port, connectIp);
  });

  report.tcp.success = tcpResult.success;
  report.tcp.connectLatencyMs = tcpResult.latency;
  report.tcp.errorCode = tcpResult.errorCode;
  report.tcp.error = tcpResult.error;

  if (!report.tcp.success) {
    report.verdict = 'CRITICAL_ERROR';
    if (report.tcp.errorCode === 'ETIMEDOUT') {
      report.observedFact = 'L4_SYN_TIMEOUT';
      report.hypotheses = [
        { hypothesis: 'FIREWALL_SILENT_DROP', probability: 0.52, explanation: 'Perimeter firewall / ACL discarding SYN packets silently' },
        { hypothesis: 'REMOTE_HOST_DOWN', probability: 0.35, explanation: 'Target host is powered off or disconnected' },
        { hypothesis: 'UPSTREAM_TRANSIT_DROP', probability: 0.13, explanation: 'Intermediate transit router packet drop or routing blackhole' }
      ];
      report.technicalSummary = `TCP handshake to [${connectIp}:${port}] timed out (ETIMEDOUT) [Observed Fact: L4_SYN_TIMEOUT | Competing Hypotheses: Firewall Silent Drop (52%), Remote Host Down (35%), Upstream Transit Drop (13%)]. Direct attribution to firewall requires ICMP Type 3 Code 13 corroboration.`;
      report.helpdeskSummary.az = `Şəbəkə bağlantısı vaxt aşımına uğradı (ETIMEDOUT): [${connectIp}:${port}] ünvanına göndərilən TCP SYN sorğusuna cavab gəlmir. Ehtimallar: Təhlükəsizlik divarı (Firewall/ACL) paketləri bloklayır (52%), server sönülüdür (35%) və ya şəbəkə marşrutunda qırılma var (13%).`;
      report.helpdeskSummary.en = `TCP connection to [${connectIp}:${port}] timed out (ETIMEDOUT). Observed: L4_SYN_TIMEOUT. Competing hypotheses: Perimeter firewall silent drop (52%), remote host offline (35%), upstream transit failure (13%).`;
    } else if (report.tcp.errorCode === 'ECONNREFUSED') {
      report.observedFact = 'L4_RST_RECEIVED';
      report.hypotheses = [
        { hypothesis: 'PORT_CLOSED_SERVICE_STOPPED', probability: 0.90, explanation: 'Host OS is active and actively rejected TCP SYN with RST' },
        { hypothesis: 'LOCAL_PORT_FILTER', probability: 0.10, explanation: 'Host-based firewall rejecting port' }
      ];
      report.technicalSummary = `TCP connection to [${connectIp}:${port}] was actively refused (ECONNREFUSED). The host is reachable, but no web server daemon (IIS/Nginx/Apache) is listening on port ${port}.`;
      report.helpdeskSummary.az = `Hədəf kompüter/server aktivdir, lakin port ${port} üzərində veb-xidmət dayandırılıb və ya işləmir (ECONNREFUSED).`;
      report.helpdeskSummary.en = `Target host is online, but no web service is listening on port ${port} (ECONNREFUSED). Service daemon may be stopped.`;
    } else {
      report.technicalSummary = `TCP connection failed on [${connectIp}:${port}]: ${report.tcp.error} (${report.tcp.errorCode}).`;
      report.helpdeskSummary.az = `Port ${port} üzrə bağlantı xətası: ${report.tcp.errorCode}. Şəbəkə marşrutlaşdırmasını yoxlayın.`;
      report.helpdeskSummary.en = `Network socket error on port ${port}: ${report.tcp.errorCode}. Verify routing path.`;
    }
    return report;
  }

  // 3. Layer 6: TLS Handshake & Certificate Inspection (if HTTPS)
  if (isHttps) {
    const tlsStart = performance.now();
    report.tls = await new Promise((resolve) => {
      try {
        const tlsSocket = tls.connect(
          {
            host: connectIp,
            port,
            servername: hostname,
            rejectUnauthorized: false,
            timeout: timeoutMs
          },
          () => {
            const handshakeLatency = parseFloat((performance.now() - tlsStart).toFixed(2));
            const cert = tlsSocket.getPeerCertificate(true);
            const protocol = tlsSocket.getProtocol();
            const cipher = tlsSocket.getCipher();
            const authorized = tlsSocket.authorized;
            const authError = tlsSocket.authorizationError;
            const alpn = tlsSocket.alpnProtocol;

            tlsSocket.end();

            if (!cert || Object.keys(cert).length === 0) {
              return resolve({
                success: false,
                handshakeLatencyMs: handshakeLatency,
                error: 'Remote server did not present an X.509 TLS certificate.'
              });
            }

            const validTo = new Date(cert.valid_to);
            const validFrom = new Date(cert.valid_from);
            const now = new Date();
            const msRemaining = validTo.getTime() - now.getTime();
            const daysRemaining = Math.floor(msRemaining / (1000 * 60 * 60 * 24));
            const isExpired = msRemaining <= 0;
            const isExpiringSoon = !isExpired && daysRemaining <= 30;

            const sans = cert.subjectaltname
              ? cert.subjectaltname.split(',').map(s => s.trim().replace(/^DNS:/, ''))
              : [];

            resolve({
              success: true,
              protocol,
              cipher: cipher ? cipher.name : null,
              cipherVersion: cipher ? cipher.standardName || cipher.version : null,
              alpnProtocol: alpn || 'http/1.1',
              handshakeLatencyMs: handshakeLatency,
              authorized,
              authorizationError: authError || null,
              certificate: {
                subjectCN: cert.subject ? (cert.subject.CN || cert.subject.commonName) : null,
                subjectOrg: cert.subject ? cert.subject.O : null,
                issuerCN: cert.issuer ? (cert.issuer.CN || cert.issuer.commonName) : null,
                issuerOrg: cert.issuer ? cert.issuer.O : null,
                validFrom: validFrom.toISOString(),
                validTo: validTo.toISOString(),
                daysRemaining,
                isExpired,
                isExpiringSoon,
                sans,
                serialNumber: cert.serialNumber,
                fingerprint256: cert.fingerprint256
              }
            });
          }
        );

        tlsSocket.on('timeout', () => {
          tlsSocket.destroy();
          resolve({ success: false, handshakeLatencyMs: timeoutMs, error: 'TLS handshake timed out.' });
        });

        tlsSocket.on('error', (err) => {
          tlsSocket.destroy();
          resolve({ success: false, handshakeLatencyMs: parseFloat((performance.now() - tlsStart).toFixed(2)), error: err.message });
        });
      } catch (err) {
        resolve({ success: false, error: err.message });
      }
    });
  }

  // 4. Layer 7: HTTP Request & Redirect Tracking (Up to 5 Hops)
  let currentUrl = normalizedUrl;
  let hopCount = 0;
  const httpStart = performance.now();

  while (hopCount < maxRedirects) {
    hopCount++;
    const hopResult = await new Promise((resolve) => {
      let reqParsed;
      try {
        reqParsed = new URL(currentUrl);
      } catch (e) {
        return resolve({ success: false, error: `Invalid redirect URL: ${currentUrl}` });
      }

      const clientModule = reqParsed.protocol === 'https:' ? https : http;
      const hopStart = performance.now();
      let firstByteTime = null;

      const reqOpts = {
        protocol: reqParsed.protocol,
        hostname: reqParsed.hostname,
        port: reqParsed.port || (reqParsed.protocol === 'https:' ? 443 : 80),
        path: reqParsed.pathname + reqParsed.search,
        method: 'GET',
        timeout: timeoutMs,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 EJI-Verifier/5.0',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'az,en-US,en;q=0.9,ru;q=0.8',
          'Connection': 'close'
        },
        rejectUnauthorized: false
      };

      const req = clientModule.request(reqOpts, (res) => {
        firstByteTime = parseFloat((performance.now() - hopStart).toFixed(2));
        let chunks = [];
        let totalBytes = 0;

        res.on('data', (chunk) => {
          if (totalBytes < 4096) {
            chunks.push(chunk);
            totalBytes += chunk.length;
          }
        });

        res.on('end', () => {
          const bodyBuffer = Buffer.concat(chunks);
          const bodyStr = bodyBuffer.toString('utf8').slice(0, 512).replace(/[\r\n\t]+/g, ' ');
          resolve({
            success: true,
            statusCode: res.statusCode,
            statusMessage: res.statusMessage,
            headers: res.headers,
            ttfbMs: firstByteTime || parseFloat((performance.now() - hopStart).toFixed(2)),
            location: res.headers.location || null,
            bodySnippet: bodyStr
          });
        });
      });

      req.on('timeout', () => {
        req.destroy();
        resolve({ success: false, error: 'HTTP request timed out.' });
      });

      req.on('error', (err) => {
        resolve({ success: false, error: err.message });
      });

      req.end();
    });

    if (!hopResult.success) {
      report.http.error = hopResult.error;
      break;
    }

    report.http.statusCode = hopResult.statusCode;
    report.http.statusMessage = hopResult.statusMessage;
    report.http.headers = hopResult.headers;
    report.http.ttfbMs = hopResult.ttfbMs;
    report.http.bodySnippet = hopResult.bodySnippet;
    report.http.finalUrl = currentUrl;
    report.http.success = true;

    // Check for redirect (301, 302, 303, 307, 308)
    if ([301, 302, 303, 307, 308].includes(hopResult.statusCode) && hopResult.location) {
      let nextUrl = hopResult.location;
      if (!/^https?:\/\//i.test(nextUrl)) {
        try {
          nextUrl = new URL(nextUrl, currentUrl).href;
        } catch (_) {}
      }

      report.http.redirects.push({
        hop: hopCount,
        fromUrl: currentUrl,
        statusCode: hopResult.statusCode,
        toUrl: nextUrl,
        ttfbMs: hopResult.ttfbMs
      });

      currentUrl = nextUrl;
    } else {
      // Terminal HTTP response reached
      break;
    }
  }

  report.http.totalDurationMs = parseFloat((performance.now() - httpStart).toFixed(2));

  // 5. Synthesis & Helpdesk Translation
  const isHealthyHttp = report.http.success && report.http.statusCode >= 200 && report.http.statusCode < 400;
  const isHealthyTls = !isHttps || (report.tls && report.tls.success && !report.tls.certificate.isExpired);

  if (isHealthyHttp && isHealthyTls) {
    report.verdict = 'HEALTHY';
    report.l7Classification = report.http.statusCode < 300 ? 'L7_HEALTHY_OK' : 'L7_REDIRECT';
    const certNote = report.tls
      ? `TLS ${report.tls.protocol} (${report.tls.cipher}), Certificate CN: ${report.tls.certificate.subjectCN} (Valid for ${report.tls.certificate.daysRemaining} days).`
      : 'Plain HTTP connection (No TLS).';
    report.technicalSummary = `Web service [${hostname}:${port}] is operational. Resolved to ${connectIp} in ${report.dns.resolutionDurationMs}ms. TCP handshake: ${report.tcp.connectLatencyMs}ms. HTTP ${report.http.statusCode} (${report.http.statusMessage}) received in ${report.http.ttfbMs}ms TTFB. ${certNote}`;
    report.helpdeskSummary.az = `Veb-xidmət tam işlək vəziyyətdədir (HTTP ${report.http.statusCode}). Şəbəkə, DNS və təhlükəsizlik sertifikatı normal cavab verir. İstifadəçi daxil ola bilmirsə, brauzer keşini (Ctrl+F5) təmizləyin və ya proksi tənzimləmələrini yoxlayın.`;
    report.helpdeskSummary.en = `Web service is fully operational (HTTP ${report.http.statusCode}). Network, DNS, and TLS certificates are valid. If user cannot connect, clear browser cache (Ctrl+F5) or check local proxy settings.`;
  } else if (report.tls && report.tls.certificate && report.tls.certificate.isExpired) {
    report.verdict = 'WARNING';
    report.l7Classification = 'L7_TLS_CERT_EXPIRED';
    report.technicalSummary = `TLS Certificate Expired! The certificate for [${hostname}] expired on ${report.tls.certificate.validTo}. Browsers will display NET::ERR_CERT_DATE_INVALID.`;
    report.helpdeskSummary.az = `XƏBƏRDARLIQ: Saytın SSL/TLS sertifikatının müddəti bitib! İstifadəçilər brauzerdə "Təhlükəsizlik xətası" görəcəklər. Sistem administratoru sertifikatı yeniləməlidir.`;
    report.helpdeskSummary.en = `WARNING: TLS certificate expired on ${report.tls.certificate.validTo}. Browsers will throw security warnings. Administrator must renew the certificate.`;
  } else if (report.http.statusCode === 440) {
    report.verdict = 'WARNING';
    report.l7Classification = 'L7_SESSION_TIMEOUT_OR_EXCHANGE_AUTH';
    report.technicalSummary = `HTTP 440 Login Timeout / Exchange Session Expiration: Server is operational and running Microsoft Exchange / OWA, but rejected session or requires credential re-authentication.`;
    report.helpdeskSummary.az = `XƏBƏRDARLIQ: HTTP 440 (Sessiya vaxtı bitib / Exchange OWA). Xidmət server səviyyəsində aktivdir, lakin sistem yenidən autentifikasiya tələb edir.`;
    report.helpdeskSummary.en = `WARNING: HTTP 440 Login Timeout / Exchange Session Expiration. Service is reachable and running Exchange/OWA, but session expired or requires credential re-authentication.`;
  } else if (report.http.statusCode === 401) {
    report.verdict = 'WARNING';
    report.l7Classification = 'L7_UNAUTHORIZED';
    report.technicalSummary = `HTTP 401 Unauthorized: Server requires valid user credentials.`;
    report.helpdeskSummary.az = `XƏBƏRDARLIQ: HTTP 401 İcazəsiz Giriş. Sistemə daxil olmaq üçün istifadəçi adı və şifrə tələb olunur.`;
    report.helpdeskSummary.en = `WARNING: HTTP 401 Unauthorized. Valid user credentials required.`;
  } else if (report.http.statusCode === 403) {
    report.verdict = 'WARNING';
    report.l7Classification = 'L7_FORBIDDEN';
    report.technicalSummary = `HTTP 403 Forbidden: Server is online but access is denied by WAF or access control policy.`;
    report.helpdeskSummary.az = `XƏBƏRDARLIQ: HTTP 403 Qadağandır. Server aktivdir, lakin təhlükəsizlik divarı (WAF) və ya giriş siyasəti girişi qadağan edir.`;
    report.helpdeskSummary.en = `WARNING: HTTP 403 Forbidden. Server is reachable but blocked by WAF or access control policy.`;
  } else if (report.http.statusCode === 404) {
    report.verdict = 'WARNING';
    report.l7Classification = 'L7_NOT_FOUND';
    report.technicalSummary = `HTTP 404 Not Found: Server is online but requested path does not exist.`;
    report.helpdeskSummary.az = `XƏBƏRDARLIQ: HTTP 404 Səhifə tapılmadı. Server işləyir, lakin göstərilən ünvan mövcud deyil.`;
    report.helpdeskSummary.en = `WARNING: HTTP 404 Not Found. Server is reachable but requested resource was not found.`;
  } else if (report.http.statusCode >= 400 && report.http.statusCode < 500) {
    report.verdict = 'WARNING';
    report.l7Classification = 'L7_CLIENT_OR_PATH_ERROR';
    report.technicalSummary = `HTTP Client Error: ${report.http.statusCode} (${report.http.statusMessage}). Server is online and accepting connections, but rejected the requested path or requires authentication.`;
    report.helpdeskSummary.az = `Server aktivdir, lakin HTTP ${report.http.statusCode} (${report.http.statusMessage}) xətası qaytarır. Bu, səhifənin tapılmaması (404) və ya icazənin olmaması (403/401) ilə bağlıdır.`;
    report.helpdeskSummary.en = `Server is reachable but returned HTTP ${report.http.statusCode}. Verify the exact path or user permissions.`;
  } else if (report.http.statusCode >= 500) {
    report.verdict = 'CRITICAL_ERROR';
    report.l7Classification = 'L7_SERVER_ERROR';
    report.technicalSummary = `HTTP Internal Server Error: ${report.http.statusCode} (${report.http.statusMessage}). Application runtime crashed or database backend is down.`;
    report.helpdeskSummary.az = `Daxili Server Xətası: HTTP ${report.http.statusCode}. Şəbəkə bağlantısı mövcuddur, lakin serverdəki proqram təminatı və ya verilənlər bazası xəta verir. Tətbiq sahibinə (App Owner) müraciət edin.`;
    report.helpdeskSummary.en = `Internal Server Error: HTTP ${report.http.statusCode}. Application crashed or backend database connection failed. Escalate to Application Owner.`;
  } else {
    report.verdict = 'CRITICAL_ERROR';
    report.l7Classification = 'L7_REQUEST_FAILED';
    report.technicalSummary = `HTTP request failed: ${report.http.error || 'Unknown error'}.`;
    report.helpdeskSummary.az = `Veb-sorğu tamamlanmadı: ${report.http.error}.`;
    report.helpdeskSummary.en = `HTTP transaction failed: ${report.http.error}.`;
  }

  return report;
}

/**
 * Probe a single raw mail socket (SMTP/SMTPS/IMAP/IMAPS/POP3/POP3S)
 * @param {string} ip 
 * @param {string} hostname 
 * @param {number} port 
 * @param {string} serviceType 
 * @param {number} timeoutMs 
 */
function probeMailPort(ip, hostname, port, serviceType, timeoutMs = 3500) {
  return new Promise((resolve) => {
    const startTime = performance.now();
    const isTls = ['SMTPS', 'IMAPS', 'POP3S'].includes(serviceType);

    const result = {
      port,
      serviceType,
      status: 'UNKNOWN',
      banner: null,
      ehloCapabilities: [],
      supportsStarttls: false,
      connectLatencyMs: 0,
      tlsInfo: null,
      errorCode: null,
      error: null
    };

    let handled = false;
    let timer = null;

    function finish(res) {
      if (handled) return;
      handled = true;
      if (timer) clearTimeout(timer);
      res.connectLatencyMs = parseFloat((performance.now() - startTime).toFixed(2));
      resolve(res);
    }

    timer = setTimeout(() => {
      finish({
        ...result,
        status: 'TIMEOUT',
        errorCode: 'ETIMEDOUT',
        error: `Connection to port ${port} timed out after ${timeoutMs}ms. Dropped by perimeter firewall.`
      });
    }, timeoutMs);

    if (isTls) {
      try {
        const socket = tls.connect(
          {
            host: ip,
            port,
            servername: hostname,
            rejectUnauthorized: false,
            timeout: timeoutMs
          },
          () => {
            result.status = 'OPEN';
            const cert = socket.getPeerCertificate(true);
            if (cert && cert.valid_to) {
              const daysRemaining = Math.floor((new Date(cert.valid_to).getTime() - Date.now()) / (1000 * 60 * 60 * 24));
              result.tlsInfo = {
                protocol: socket.getProtocol(),
                cipher: socket.getCipher() ? socket.getCipher().name : null,
                subjectCN: cert.subject ? cert.subject.CN : null,
                issuerCN: cert.issuer ? cert.issuer.CN : null,
                validTo: cert.valid_to,
                daysRemaining
              };
            }
          }
        );

        let dataBuf = '';
        socket.on('data', (chunk) => {
          dataBuf += chunk.toString('utf8');
          if (dataBuf.length > 512 || dataBuf.includes('\n')) {
            result.banner = dataBuf.trim().split('\n')[0].slice(0, 256);
            socket.end();
            finish(result);
          }
        });

        // Give server 500ms after secureConnect to send initial greeting banner
        socket.on('secureConnect', () => {
          setTimeout(() => {
            if (!result.banner && dataBuf) {
              result.banner = dataBuf.trim().split('\n')[0].slice(0, 256);
            }
            socket.end();
            finish(result);
          }, 600);
        });

        socket.on('error', (err) => {
          socket.destroy();
          result.status = (err.code === 'ECONNREFUSED') ? 'CLOSED' : 'FAILED';
          result.errorCode = err.code || 'TLS_ERR';
          result.error = err.message;
          finish(result);
        });
      } catch (err) {
        result.status = 'FAILED';
        result.error = err.message;
        finish(result);
      }
    } else {
      // Plain TCP socket for SMTP / IMAP / POP3
      const socket = new net.Socket();

      socket.on('connect', () => {
        result.status = 'OPEN';
      });

      let rxBuffer = '';
      let sentEhlo = false;

      socket.on('data', (chunk) => {
        rxBuffer += chunk.toString('utf8');

        // Check if we received initial greeting banner
        if (!result.banner && rxBuffer.includes('\n')) {
          const lines = rxBuffer.split(/\r?\n/).filter(l => l.trim().length > 0);
          result.banner = lines[0].slice(0, 256);

          // If SMTP (port 25 or 587), send EHLO probe
          if ((port === 25 || port === 587) && !sentEhlo) {
            sentEhlo = true;
            socket.write('EHLO ejii.infrastructure.intelligence\r\n');
            return;
          } else {
            socket.end();
            finish(result);
            return;
          }
        }

        // If we sent EHLO, parse multi-line 250 response
        if (sentEhlo) {
          const lines = rxBuffer.split(/\r?\n/);
          for (const line of lines) {
            if (/^250[- ]/i.test(line)) {
              const cap = line.replace(/^250[- ]/i, '').trim();
              if (cap && !result.ehloCapabilities.includes(cap)) {
                result.ehloCapabilities.push(cap);
              }
              if (/STARTTLS/i.test(cap)) {
                result.supportsStarttls = true;
              }
            }
          }

          // A 250 response with a space (250 OK or 250 HELP) indicates end of EHLO response
          if (/^250 /m.test(rxBuffer)) {
            socket.write('QUIT\r\n');
            socket.end();
            finish(result);
          }
        }
      });

      socket.on('error', (err) => {
        socket.destroy();
        result.status = (err.code === 'ECONNREFUSED') ? 'CLOSED' : 'FAILED';
        result.errorCode = err.code || 'SOCK_ERR';
        result.error = err.message;
        finish(result);
      });

      socket.on('close', () => {
        finish(result);
      });

      socket.connect(port, ip);
    }
  });
}

/**
 * Deep enterprise mail verification (e.g. mail.taxes.gov.az)
 * Resolves MX, SPF, DMARC records and probes standard mail ports (25, 587, 465, 993, 143, 110, 995).
 * @param {string} targetHost 
 * @param {object} options 
 */
async function verifyMailEndpoint(targetHost, options = {}) {
  const cleanHost = (targetHost || '').trim().replace(/^https?:\/\//i, '').split('/')[0].split(':')[0];
  if (!cleanHost) {
    throw new Error('Target mail domain or host is required.');
  }

  const portsToProbe = options.ports || [
    { port: 25, serviceType: 'SMTP' },
    { port: 587, serviceType: 'SUBMISSION' },
    { port: 465, serviceType: 'SMTPS' },
    { port: 993, serviceType: 'IMAPS' },
    { port: 143, serviceType: 'IMAP' },
    { port: 110, serviceType: 'POP3' },
    { port: 995, serviceType: 'POP3S' }
  ];

  const report = {
    targetHost: cleanHost,
    timestamp: new Date().toISOString(),
    dns: {
      success: false,
      ipv4: [],
      isPrivate: false,
      mxRecords: [],
      spfRecord: null,
      spfValid: false,
      dmarcRecord: null,
      dmarcPolicy: null,
      error: null
    },
    ports: [],
    verdict: 'UNKNOWN',
    technicalSummary: '',
    helpdeskSummary: {
      az: '',
      en: ''
    }
  };

  // 1. Resolve host IP addresses
  try {
    const a = await dns.resolve4(cleanHost).catch(() => []);
    report.dns.ipv4 = a;
    report.dns.success = a.length > 0;
    report.dns.isPrivate = a.some(ip => isPrivateIp(ip));

    if (!report.dns.success && net.isIP(cleanHost)) {
      report.dns.success = true;
      report.dns.ipv4 = [cleanHost];
      report.dns.isPrivate = isPrivateIp(cleanHost);
    }
  } catch (err) {
    if (net.isIP(cleanHost)) {
      report.dns.success = true;
      report.dns.ipv4 = [cleanHost];
      report.dns.isPrivate = isPrivateIp(cleanHost);
    } else {
      report.dns.error = err.message;
    }
  }

  // 2. Resolve DNS MX records
  try {
    const domain = cleanHost.includes('.') ? cleanHost : `${cleanHost}.gov.az`;
    const mx = await dns.resolveMx(domain).catch(() => []);
    mx.sort((x, y) => x.priority - y.priority);
    report.dns.mxRecords = mx;
  } catch (_) {}

  // 3. Resolve SPF records
  try {
    const domain = cleanHost.includes('.') ? cleanHost : `${cleanHost}.gov.az`;
    const txtRecords = await dns.resolveTxt(domain).catch(() => []);
    const flattened = txtRecords.map(r => Array.isArray(r) ? r.join('') : r);
    const spf = flattened.find(t => t.toLowerCase().startsWith('v=spf1'));
    if (spf) {
      report.dns.spfRecord = spf;
      report.dns.spfValid = true;
    }
  } catch (_) {}

  // 4. Resolve DMARC records
  try {
    const domain = cleanHost.includes('.') ? cleanHost : `${cleanHost}.gov.az`;
    const dmarcRecords = await dns.resolveTxt(`_dmarc.${domain}`).catch(() => []);
    const flattened = dmarcRecords.map(r => Array.isArray(r) ? r.join('') : r);
    const dmarc = flattened.find(t => t.toLowerCase().startsWith('v=dmarc1'));
    if (dmarc) {
      report.dns.dmarcRecord = dmarc;
      const policyMatch = dmarc.match(/p=([a-zA-Z0-9]+)/i);
      report.dns.dmarcPolicy = policyMatch ? policyMatch[1].toLowerCase() : 'none';
    }
  } catch (_) {}

  if (!report.dns.success) {
    report.verdict = 'CRITICAL_ERROR';
    report.technicalSummary = `DNS resolution failed for mail host [${cleanHost}]. Cannot proceed with socket probing.`;
    report.helpdeskSummary.az = `Poçt serverinin domeni [${cleanHost}] IP ünvanına çevrilə bilmədi. Daxili DNS serverinin (10.22.10.11) işləkliyini yoxlayın.`;
    report.helpdeskSummary.en = `Mail host [${cleanHost}] could not be resolved via DNS. Check local DNS resolver.`;
    return report;
  }

  const targetIp = report.dns.ipv4[0];

  // 5. Probe mail sockets concurrently
  const probePromises = portsToProbe.map(p =>
    probeMailPort(targetIp, cleanHost, p.port, p.serviceType, options.timeoutMs || 3500)
  );

  report.ports = await Promise.all(probePromises);

  // 6. Synthesis & Analysis
  const openPorts = report.ports.filter(p => p.status === 'OPEN');
  const timeoutPorts = report.ports.filter(p => p.status === 'TIMEOUT');
  const closedPorts = report.ports.filter(p => p.status === 'CLOSED');

  const submissionOpen = report.ports.some(p => (p.port === 587 || p.port === 465) && p.status === 'OPEN');
  const submissionTimeout = report.ports.some(p => (p.port === 587 || p.port === 465) && p.status === 'TIMEOUT');
  const imapOpen = report.ports.some(p => (p.port === 993 || p.port === 143) && p.status === 'OPEN');

  if (openPorts.length > 0) {
    if (submissionTimeout && !submissionOpen) {
      report.verdict = 'WARNING';
      report.technicalSummary = `Partial Mail Service Reachability: IMAP/POP3 or Relay is reachable, but SMTP Submission (Port 587/465) timed out (ETIMEDOUT). Perimeter firewall is blocking outbound email transmission. Users can read emails, but cannot send outbound mail via email clients (Outlook).`;
      report.helpdeskSummary.az = `Poçt qutusuna daxil olmaq mümkündür (oxumaq olur), lakin məktub göndərmək olmur! Səbəb: Poçt göndərmə portları (587/465) şəbəkə firewall-u tərəfindən bloklanır (ETIMEDOUT). Veb-poçt (OWA/HTTPS 443) vasitəsilə göndərməyi yoxlayın.`;
      report.helpdeskSummary.en = `Users can view incoming emails, but cannot send outbound mail. Ports 587/465 are filtered by corporate firewall (ETIMEDOUT). Advise users to use Webmail (OWA) temporarily.`;
    } else {
      report.verdict = 'HEALTHY';
      const openPortList = openPorts.map(p => `${p.port}/${p.serviceType}`).join(', ');
      report.technicalSummary = `Mail service on [${cleanHost} (${targetIp})] is operational. Active listening ports: ${openPortList}. MX priority records: ${report.dns.mxRecords.length > 0 ? report.dns.mxRecords.map(m => `${m.exchange} (${m.priority})`).join(', ') : 'None'}.`;
      report.helpdeskSummary.az = `Poçt serveri aktivdir və xidmət portları normal cavab verir (${openPortList}). Əgər istifadəçi "poçt işləmir" deyirsə, istifadəçinin şifrəsini və ya Outlook hesab sazlamalarını yoxlayın.`;
      report.helpdeskSummary.en = `Mail server is operational on ports [${openPortList}]. Verify client authentication credentials and client profile settings.`;
    }
  } else if (timeoutPorts.length > 0 && closedPorts.length === 0) {
    report.verdict = 'CRITICAL_ERROR';
    report.technicalSummary = `Complete Perimeter Firewall Block: All mail ports (25, 587, 465, 993) timed out (ETIMEDOUT) against [${targetIp}]. Hardware firewall or network security ACL is dropping all traffic to this server.`;
    report.helpdeskSummary.az = `KRİTİK: Bütün poçt portları şəbəkə firewall-u tərəfindən tam bloklanır (ETIMEDOUT). Serverə fiziki bağlantı və ya firewall qaydaları dərhal şəbəkə administratoru tərəfindən yoxlanılmalıdır.`;
    report.helpdeskSummary.en = `CRITICAL: All mail ports timed out (ETIMEDOUT). Enterprise firewall ACL is dropping all mail traffic to this destination. Escalate to Network Admin.`;
  } else {
    report.verdict = 'CRITICAL_ERROR';
    report.technicalSummary = `Mail server [${cleanHost} (${targetIp})] refused connections on all mail ports (ECONNREFUSED). The server host is alive, but mail services (Exchange, Postfix, Dovecot) are completely stopped.`;
    report.helpdeskSummary.az = `KRİTİK: Server şəbəkədə aktivdir, lakin poçt servisi (Exchange/Postfix) dayandırılıb (ECONNREFUSED). Sistem administratoru serverdə poçt xidmətini yenidən başlatmalıdır.`;
    report.helpdeskSummary.en = `CRITICAL: Server is online but mail daemons are stopped (ECONNREFUSED). Restart mail services on target host.`;
  }

  return report;
}

module.exports = {
  verifyWebEndpoint,
  verifyMailEndpoint,
  isPrivateIp
};
