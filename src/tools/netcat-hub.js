/**
 * EJII Netcat (nc) Hub
 * Raw TCP and UDP arbitrary socket connector, banner grabbing, and raw payload piping.
 * 100% Genuine Network Socket I/O — Zero Simulated Data.
 */

const net = require('net');
const dgram = require('dgram');
const { performance } = require('perf_hooks');

/**
 * Connect to an arbitrary TCP host and port, send a payload, and capture the response
 * @param {Object} options
 * @param {string} options.host
 * @param {number} options.port
 * @param {string} options.payload
 * @param {number} options.timeoutMs
 */
function netcatTcp({ host, port, payload = '', timeoutMs = 3000 }) {
  return new Promise((resolve) => {
    const startTime = performance.now();
    const cleanHost = String(host || '').trim();
    const safePort = parseInt(port, 10);

    if (!cleanHost || isNaN(safePort) || safePort < 1 || safePort > 65535) {
      return resolve({ success: false, error: 'Valid host and port (1-65535) are required.' });
    }

    const socket = new net.Socket();
    let responseChunks = [];
    let isConnected = false;

    socket.setTimeout(timeoutMs);

    socket.connect(safePort, cleanHost, () => {
      isConnected = true;
      if (payload) {
        socket.write(payload + '\r\n');
      }
    });

    socket.on('data', (data) => {
      responseChunks.push(data);
      // If we received data, allow a short window then close
      setTimeout(() => {
        socket.end();
      }, 300);
    });

    socket.on('timeout', () => {
      socket.destroy();
    });

    socket.on('error', (err) => {
      socket.destroy();
      const elapsed = parseFloat((performance.now() - startTime).toFixed(2));
      resolve({
        success: false,
        host: cleanHost,
        port: safePort,
        latencyMs: elapsed,
        error: err.code || err.message,
        receivedBytes: 0,
        response: ''
      });
    });

    socket.on('close', () => {
      const elapsed = parseFloat((performance.now() - startTime).toFixed(2));
      const fullBuffer = Buffer.concat(responseChunks);
      resolve({
        success: isConnected,
        host: cleanHost,
        port: safePort,
        latencyMs: elapsed,
        receivedBytes: fullBuffer.length,
        response: fullBuffer.toString('utf8'),
        hexDump: fullBuffer.toString('hex').match(/../g)?.join(' ') || ''
      });
    });
  });
}

/**
 * Send a raw UDP datagram and await optional reply
 * @param {Object} options
 * @param {string} options.host
 * @param {number} options.port
 * @param {string} options.payload
 * @param {number} options.timeoutMs
 */
function netcatUdp({ host, port, payload = '', timeoutMs = 2000 }) {
  return new Promise((resolve) => {
    const startTime = performance.now();
    const cleanHost = String(host || '').trim();
    const safePort = parseInt(port, 10);

    if (!cleanHost || isNaN(safePort) || safePort < 1 || safePort > 65535) {
      return resolve({ success: false, error: 'Valid host and port (1-65535) are required.' });
    }

    const client = dgram.createSocket('udp4');
    let received = null;

    const timer = setTimeout(() => {
      client.close();
      const elapsed = parseFloat((performance.now() - startTime).toFixed(2));
      resolve({
        success: true,
        host: cleanHost,
        port: safePort,
        latencyMs: elapsed,
        message: 'Datagram transmitted. No reply received within timeout window.',
        response: received ? received.toString('utf8') : null
      });
    }, timeoutMs);

    client.on('message', (msg) => {
      received = msg;
      clearTimeout(timer);
      client.close();
      const elapsed = parseFloat((performance.now() - startTime).toFixed(2));
      resolve({
        success: true,
        host: cleanHost,
        port: safePort,
        latencyMs: elapsed,
        receivedBytes: msg.length,
        response: msg.toString('utf8'),
        hexDump: msg.toString('hex').match(/../g)?.join(' ') || ''
      });
    });

    client.on('error', (err) => {
      clearTimeout(timer);
      client.close();
      resolve({
        success: false,
        host: cleanHost,
        port: safePort,
        error: err.code || err.message
      });
    });

    const msgBuffer = Buffer.from(payload || 'PING');
    client.send(msgBuffer, 0, msgBuffer.length, safePort, cleanHost);
  });
}

module.exports = {
  netcatTcp,
  netcatUdp
};
