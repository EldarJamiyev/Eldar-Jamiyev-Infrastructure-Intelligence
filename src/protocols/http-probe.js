/**
 * EJII Real HTTP/HTTPS Synthetic Probe Driver
 * High-precision network waterfall timing decomposition.
 */

const http = require('http');
const https = require('https');
const { URL } = require('url');
const { isSafeNetworkTarget } = require('../core/ai-brain');

/**
 * Execute real HTTP/HTTPS synthetic probe with waterfall timing
 * @param {string} targetUrl 
 * @param {string} method ('GET', 'HEAD', 'POST')
 * @param {number} timeoutMs 
 */
function probeHttp(targetUrl, method = 'GET', timeoutMs = 5000) {
  return new Promise((resolve) => {
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

    const options = {
      protocol: parsedUrl.protocol,
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || (isHttps ? 443 : 80),
      path: parsedUrl.pathname + parsedUrl.search,
      method,
      timeout: timeoutMs,
      headers: {
        'User-Agent': 'EJII-Infrastructure-Intelligence/1.0 (+https://ejii.internal)',
        'Accept': '*/*'
      },
      rejectUnauthorized: false // Inspect invalid cert sites as well
    };

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

        finish({
          success: isSuccess,
          url: parsedUrl.href,
          method,
          statusCode,
          statusMessage: res.statusMessage,
          headers: res.headers,
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

module.exports = {
  probeHttp
};
