/**
 * EJII Real TLS / SSL Security Audit Driver
 * Raw TLS handshake, X.509 certificate chain inspection, cipher negotiation, and expiration auditor.
 */

const tls = require('tls');
const net = require('net');
const { resolveAndValidateTarget } = require('../core/security');

function parseHostAndPort(rawHost, defaultPort = 443) {
  if (!rawHost) return { host: '', port: defaultPort };
  let str = String(rawHost).trim().replace(/^https?:\/\//i, '').split('/')[0];
  if (str.startsWith('[')) {
    const closeBracket = str.indexOf(']');
    if (closeBracket !== -1) {
      const hostPart = str.slice(1, closeBracket);
      const after = str.slice(closeBracket + 1);
      const portPart = after.startsWith(':') ? parseInt(after.slice(1), 10) : defaultPort;
      return { host: hostPart, port: isNaN(portPart) ? defaultPort : portPart };
    }
  }
  if (net.isIPv6(str)) {
    return { host: str, port: defaultPort };
  }
  if (str.includes(':')) {
    const parts = str.split(':');
    const portPart = parseInt(parts[1], 10);
    return { host: parts[0], port: isNaN(portPart) ? defaultPort : portPart };
  }
  return { host: str, port: defaultPort };
}


/**
 * Perform a real TLS audit on a target host and port
 * @param {string} host 
 * @param {number} port 
 * @param {number} timeoutMs 
 */
async function auditTls(host, port = 443, timeoutMs = 4000, servernameOverride = null) {
  const parsed = parseHostAndPort(host, port);
  const cleanHost = parsed.host;
  const safePort = parsed.port;

  if (!cleanHost) {
    return { success: false, host, port, error: 'Target host is required.' };
  }

  if (isNaN(safePort) || safePort < 1 || safePort > 65535) {
    return {
      success: false,
      host: cleanHost,
      port,
      error: `Invalid port number [${port}]. Port must be between 1 and 65535.`
    };
  }

  const validated = await resolveAndValidateTarget(cleanHost);
  if (!validated.valid) {
    return {
      success: false,
      host: cleanHost,
      port: safePort,
      error: validated.error || 'Target rejected by SSRF defense policy'
    };
  }
  const pinnedIp = validated.pinnedIp;
  const originalHostname = servernameOverride || (validated.isIpLiteral ? undefined : cleanHost);

  return new Promise((resolve) => {
    const startTime = performance.now();
    try {
      const socket = tls.connect(
        {
          host: pinnedIp,
          port: safePort,
          servername: originalHostname,
          rejectUnauthorized: false,
          timeout: timeoutMs
        },
        () => {
        const handshakeLatencyMs = parseFloat((performance.now() - startTime).toFixed(2));
        const cert = socket.getPeerCertificate(true);
        const protocol = socket.getProtocol();
        const cipher = socket.getCipher();
        const authorized = socket.authorized;
        const authError = socket.authorizationError;

        socket.end();

        if (!cert || Object.keys(cert).length === 0) {
          return resolve({
            success: false,
            host: cleanHost,
            port,
            handshakeLatencyMs,
            error: 'No TLS certificate presented by the remote server.'
          });
        }

        const validTo = new Date(cert.valid_to);
        const validFrom = new Date(cert.valid_from);
        const now = new Date();
        const msRemaining = validTo.getTime() - now.getTime();
        const daysRemaining = Math.floor(msRemaining / (1000 * 60 * 60 * 24));
        const isExpired = msRemaining <= 0;
        const isExpiringSoon = !isExpired && daysRemaining <= 30;

        // Parse Subject Alternative Names (SAN)
        const sans = cert.subjectaltname
          ? cert.subjectaltname.split(',').map((s) => s.trim().replace(/^DNS:/, ''))
          : [];

        // Evaluate cipher strength
        let cipherRisk = 'SECURE';
        if (protocol === 'TLSv1' || protocol === 'TLSv1.1') {
          cipherRisk = 'CRITICAL_DEPRECATED_PROTOCOL';
        } else if (cipher && (cipher.name.includes('RC4') || cipher.name.includes('DES') || cipher.name.includes('MD5'))) {
          cipherRisk = 'VULNERABLE_LEGACY_CIPHER';
        } else if (cipher && cipher.name.includes('CBC')) {
          cipherRisk = 'WARNING_CBC_MODE';
        }

        resolve({
          success: true,
          host: cleanHost,
          port,
          handshakeLatencyMs,
          protocol,
          cipher: {
            name: cipher ? cipher.name : 'Unknown',
            version: cipher ? cipher.version : 'Unknown',
            standardName: cipher ? cipher.standardName : 'Unknown',
            riskLevel: cipherRisk
          },
          certificate: {
            subjectCn: cert.subject ? cert.subject.CN : 'Unknown',
            subjectOrg: cert.subject ? cert.subject.O : null,
            issuerCn: cert.issuer ? cert.issuer.CN : 'Unknown',
            issuerOrg: cert.issuer ? cert.issuer.O : null,
            validFrom: cert.valid_from,
            validTo: cert.valid_to,
            daysRemaining,
            isExpired,
            isExpiringSoon,
            serialNumber: cert.serialNumber,
            fingerprint256: cert.fingerprint256,
            sans
          },
          validation: {
            authorized,
            error: authError ? String(authError) : null
          }
        });
      }
    );

    socket.on('timeout', () => {
      socket.destroy();
      resolve({
        success: false,
        host: cleanHost,
        port,
        handshakeLatencyMs: parseFloat((performance.now() - startTime).toFixed(2)),
        error: 'TLS handshake timed out after ' + timeoutMs + 'ms'
      });
    });

    socket.on('error', (err) => {
      socket.destroy();
      resolve({
        success: false,
        host: cleanHost,
        port: safePort,
        handshakeLatencyMs: parseFloat((performance.now() - startTime).toFixed(2)),
        error: err.code || err.message
      });
    });
  } catch (syncErr) {
    resolve({
      success: false,
      host: cleanHost,
      port: safePort,
      handshakeLatencyMs: 0,
      error: syncErr.message
    });
  }
  });
}

module.exports = {
  auditTls
};
