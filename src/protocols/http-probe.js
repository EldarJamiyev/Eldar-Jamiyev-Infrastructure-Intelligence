/**
 * EJII Real HTTP/HTTPS Synthetic Probe Driver
 * High-precision network waterfall timing decomposition.
 */

const http = require('http');
const https = require('https');
const dgram = require('dgram');
const net = require('net');
const { URL } = require('url');
const { isSafeNetworkTarget, resolveAndValidateTarget } = require('../core/security');

/**
 * Execute real HTTP/HTTPS synthetic probe with waterfall timing
 * @param {string} targetUrl 
 * @param {string} method ('GET', 'HEAD', 'POST')
 * @param {number} timeoutMs 
 */
async function probeHttp(targetUrl, method = 'GET', timeoutMs = 5000) {
  if (typeof method === 'number') {
    timeoutMs = method;
    method = 'GET';
  }
  return new Promise(async (resolve) => {
    let parsedUrl;
    try {
      const normalized = targetUrl.startsWith('http://') || targetUrl.startsWith('https://')
        ? targetUrl
        : `http://${targetUrl}`;
      parsedUrl = new URL(normalized);
    } catch (e) {
      return resolve({
        success: false,
        url: targetUrl,
        error: 'Invalid URL format: ' + e.message
      });
    }

    if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
      return resolve({
        success: false,
        url: targetUrl,
        error: 'Protocol not allowed: ' + parsedUrl.protocol
      });
    }

    if (!isSafeNetworkTarget(parsedUrl.hostname)) {
      return resolve({
        success: false,
        url: targetUrl,
        error: 'Target rejected by SSRF defense policy'
      });
    }

    const isHttps = parsedUrl.protocol === 'https:';
    const client = isHttps ? https : http;

    const timings = {
      start: performance.now(),
      dnsLookup: null,
      tcpConnection: null,
      tlsHandshake: null,
      firstByte: null,
      end: null
    };

    let bodyData = '';
    let resolved = false;

    function finish(result) {
      if (resolved) return;
      resolved = true;
      resolve(result);
    }

    let pinnedIp = parsedUrl.hostname;
    let addressFamily = 4;
    try {
      const val = await resolveAndValidateTarget(parsedUrl.hostname);
      if (!val.valid) {
        return finish({
          success: false,
          url: targetUrl,
          error: val.error || 'Target rejected by SSRF defense policy'
        });
      }
      pinnedIp = val.pinnedIp;
      addressFamily = val.addressFamily || 4;
    } catch (e) {
      return finish({
        success: false,
        url: targetUrl,
        error: e.message
      });
    }

    const options = {
      protocol: parsedUrl.protocol,
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (isHttps ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method,
      timeout: timeoutMs,
      lookup: (hostname, opts, cb) => {
        if (typeof opts === 'function') {
          cb = opts;
          opts = {};
        }
        if (opts && opts.all) {
          return cb(null, [{ address: pinnedIp, family: addressFamily }]);
        }
        cb(null, pinnedIp, addressFamily);
      },
      headers: {
        'User-Agent': 'EJII-Infrastructure-Intelligence/1.0 (+https://ejii.internal)',
        'Accept': '*/*',
        'Host': parsedUrl.host
      },
      rejectUnauthorized: false
    };

    if (isHttps) {
      options.servername = parsedUrl.hostname;
    }

    const req = client.request(options);

    req.on('socket', (socket) => {
      socket.on('lookup', () => {
        timings.dnsLookup = performance.now();
      });

      socket.on('connect', () => {
        timings.tcpConnection = performance.now();
      });

      socket.on('secureConnect', () => {
        timings.tlsHandshake = performance.now();
      });
    });

    req.on('response', (res) => {
      timings.firstByte = performance.now();

      // Universal Protocol Driver & Redirect-Hop SSRF Defense
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        try {
          const redirectUrl = new URL(res.headers.location, parsedUrl.href);
          if (!isSafeNetworkTarget(redirectUrl.hostname)) {
            req.destroy();
            return finish({
              success: false,
              ssrfRedirectBlocked: true,
              redirectLocation: res.headers.location,
              url: parsedUrl.href,
              method,
              statusCode: res.statusCode,
              statusMessage: res.statusMessage,
              error: 'Target rejected by SSRF defense policy'
            });
          }
        } catch (_) {}
      }

      res.on('data', (chunk) => {
        if (bodyData.length < 4096) {
          bodyData += chunk.toString('utf8');
        }
      });

      res.on('end', () => {
        timings.end = performance.now();

        const dnsTimeMs = timings.dnsLookup
          ? parseFloat((timings.dnsLookup - timings.start).toFixed(2))
          : 0;

        const connectBase = timings.dnsLookup || timings.start;
        const tcpTimeMs = timings.tcpConnection
          ? parseFloat((timings.tcpConnection - connectBase).toFixed(2))
          : 0;

        const tlsBase = timings.tcpConnection || connectBase;
        const tlsTimeMs = timings.tlsHandshake
          ? parseFloat((timings.tlsHandshake - tlsBase).toFixed(2))
          : 0;

        const ttfbBase = timings.tlsHandshake || timings.tcpConnection || timings.start;
        const ttfbMs = timings.firstByte
          ? parseFloat((timings.firstByte - ttfbBase).toFixed(2))
          : 0;

        const transferMs = timings.firstByte && timings.end
          ? parseFloat((timings.end - timings.firstByte).toFixed(2))
          : 0;

        const totalMs = parseFloat((timings.end - timings.start).toFixed(2));

        const statusCode = res.statusCode;
        const isSuccess = statusCode >= 200 && statusCode < 400;
        const http3Info = detectHttp3AltSvc(res.headers);

        finish({
          success: isSuccess,
          url: parsedUrl.href,
          method,
          statusCode,
          statusMessage: res.statusMessage,
          headers: res.headers,
          http3Advertised: http3Info.http3Advertised,
          http3Details: http3Info,
          bodySnippet: bodyData.slice(0, 500),
          waterfall: {
            dnsLookupMs: dnsTimeMs,
            tcpConnectMs: tcpTimeMs,
            tlsHandshakeMs: tlsTimeMs,
            ttfbMs,
            contentTransferMs: transferMs,
            totalMs
          },
          error: isSuccess ? null : `HTTP status code ${statusCode} (${res.statusMessage})`
        });
      });
    });

    req.on('timeout', () => {
      req.destroy();
      finish({
        success: false,
        url: parsedUrl.href,
        method,
        statusCode: null,
        error: `Request timed out after ${timeoutMs}ms`,
        waterfall: null
      });
    });

    req.on('error', (err) => {
      finish({
        success: false,
        url: parsedUrl.href,
        method,
        statusCode: null,
        error: err.code || err.message,
        waterfall: null
      });
    });

    req.end();
  });
}

/**
 * Detect HTTP/3 advertisement from RFC 7838 Alt-Svc headers
 * e.g. alt-svc: h3=":443"; ma=86400, h3-29=":443"
 */
function detectHttp3AltSvc(headers = {}) {
  const altSvc = headers['alt-svc'] || headers['Alt-Svc'] || null;
  if (!altSvc || typeof altSvc !== 'string') {
    return { http3Advertised: false, altSvcHeader: null, h3Versions: [] };
  }
  const matches = altSvc.match(/h3(?:-[0-9]+)?="?:?(\d+)"?/g) || [];
  const versions = matches.map((m) => m.split('=')[0]);
  return {
    http3Advertised: versions.length > 0,
    altSvcHeader: altSvc,
    h3Versions: versions
  };
}

/**
 * Real RFC 9000 QUIC Initial / Version Negotiation probe over UDP port 443
 * Checks whether remote endpoint responds to QUIC datagrams on UDP transport.
 *
 * @param {string} targetHost - Hostname or IPv4/IPv6 address
 * @param {number} port - UDP port (default 443)
 * @param {number} timeoutMs - Timeout in milliseconds (default 2500)
 * @returns {Promise<Object>}
 */
async function probeQuicHttp3(targetHost, port = 443, timeoutMs = 2500) {
  const startTime = performance.now();
  let cleanHost = String(targetHost || '').trim().replace(/^https?:\/\//i, '').split('/')[0];
  let targetPort = port;

  const bracketedMatch = cleanHost.match(/^\[([0-9a-fA-F:]+)\](?::(\d+))?$/);
  if (bracketedMatch) {
    cleanHost = bracketedMatch[1];
    if (bracketedMatch[2] && (!port || port === 443)) {
      targetPort = Number(bracketedMatch[2]);
    }
  } else if (!net.isIPv6(cleanHost) && cleanHost.includes(':')) {
    const parts = cleanHost.split(':');
    if (parts.length === 2 && /^\d+$/.test(parts[1])) {
      cleanHost = parts[0];
      if (!port || port === 443) {
        targetPort = Number(parts[1]);
      }
    }
  }

  let pinnedIp = cleanHost;
  let family = 4;
  try {
    const val = await resolveAndValidateTarget(cleanHost);
    if (!val.valid) {
      return {
        success: false,
        host: cleanHost,
        port: targetPort,
        quicSupported: false,
        http3Ready: false,
        status: 'SECURITY_BLOCKED',
        error: val.error || 'Target rejected by SSRF defense policy'
      };
    }
    pinnedIp = val.pinnedIp;
    family = val.addressFamily || (net.isIPv6(pinnedIp) ? 6 : 4);
  } catch (err) {
    return {
      success: false,
      host: cleanHost,
      port: targetPort,
      quicSupported: false,
      http3Ready: false,
      status: 'SECURITY_BLOCKED',
      error: err.message
    };
  }

  return new Promise((resolve) => {
    let resolved = false;
    const socket = dgram.createSocket(family === 6 ? 'udp6' : 'udp4');

    const finish = (result) => {
      if (resolved) return;
      resolved = true;
      try {
        socket.close();
      } catch (_) {}
      resolve(result);
    };

    const timer = setTimeout(() => {
      const latencyMs = parseFloat((performance.now() - startTime).toFixed(2));
      finish({
        success: false,
        host: cleanHost,
        pinnedIp,
        port: targetPort,
        quicSupported: false,
        http3Ready: false,
        status: 'TIMEOUT_OR_FILTERED',
        latencyMs,
        error: `No QUIC UDP response received on port ${targetPort} within ${timeoutMs}ms (likely dropped by firewall or QUIC not enabled)`
      });
    }, timeoutMs);

    socket.on('error', (err) => {
      clearTimeout(timer);
      const latencyMs = parseFloat((performance.now() - startTime).toFixed(2));
      finish({
        success: false,
        host: cleanHost,
        pinnedIp,
        port: targetPort,
        quicSupported: false,
        http3Ready: false,
        status: err.code === 'ECONNREFUSED' ? 'PORT_UNREACHABLE' : 'SOCKET_ERROR',
        latencyMs,
        error: err.message
      });
    });

    socket.on('message', (msg, rinfo) => {
      clearTimeout(timer);
      const latencyMs = parseFloat((performance.now() - startTime).toFixed(2));
      const firstByte = msg[0] || 0;
      const isLongHeader = (firstByte & 0x80) !== 0;
      let quicVersion = null;
      let packetType = 'UNKNOWN';

      if (isLongHeader && msg.length >= 5) {
        quicVersion = msg.readUInt32BE(1);
        if (quicVersion === 0x00000000) {
          packetType = 'VERSION_NEGOTIATION';
        } else if (quicVersion === 0x00000001) {
          packetType = 'INITIAL_OR_RETRY';
        } else {
          packetType = `QUIC_DRAFT_OR_VENDOR_0x${quicVersion.toString(16)}`;
        }
      } else {
        packetType = 'SHORT_HEADER_1RTT';
      }

      finish({
        success: true,
        host: cleanHost,
        pinnedIp,
        port: targetPort,
        quicSupported: true,
        http3Ready: true,
        status: 'QUIC_PACKET_RECEIVED',
        packetType,
        quicVersion: quicVersion !== null ? `0x${quicVersion.toString(16)}` : null,
        responseBytes: msg.length,
        latencyMs,
        sender: rinfo.address
      });
    });

    // Build RFC 9000 compliant 1200-byte QUIC probe packet (Version Negotiation trigger)
    const probePacket = Buffer.alloc(1200);
    probePacket[0] = 0xc0; // Long Header, Fixed Bit = 1, Type = Initial
    probePacket.writeUInt32BE(0x00000000, 1); // Version = 0x0 triggers Version Negotiation
    probePacket[5] = 0x08; // DCID length 8
    Buffer.from('EJII-Q01').copy(probePacket, 6);
    probePacket[14] = 0x08; // SCID length 8
    Buffer.from('EJII-S01').copy(probePacket, 15);

    try {
      socket.send(probePacket, targetPort, pinnedIp, (err) => {
        if (err) {
          clearTimeout(timer);
          finish({
            success: false,
            host: cleanHost,
            pinnedIp,
            port: targetPort,
            quicSupported: false,
            http3Ready: false,
            status: 'SEND_FAILED',
            error: err.message
          });
        }
      });
    } catch (err) {
      clearTimeout(timer);
      finish({
        success: false,
        host: cleanHost,
        pinnedIp,
        port: targetPort,
        quicSupported: false,
        http3Ready: false,
        status: 'SEND_FAILED',
        error: err.message
      });
    }
  });
}

module.exports = {
  probeHttp,
  probeQuicHttp3,
  detectHttp3AltSvc
};
