/**
 * EJII iPerf / iPerf3 Bandwidth & Jitter Benchmarking Engine
 * TCP socket saturation benchmarking, UDP RFC 3550 interarrival jitter, and packet loss metrics.
 * 100% Genuine Network Socket I/O — Zero Simulated Data.
 */

const net = require('net');
const dgram = require('dgram');
const { performance } = require('perf_hooks');

/**
 * Measure TCP Throughput between two endpoints or local loopback socket pair
 * Transmits real payload bytes and calculates genuine Megabits per second.
 * @param {Object} options
 * @param {number} options.durationSeconds - Duration to stream data (default: 3)
 * @param {number} options.chunkSizeBytes - Size of each buffer chunk (default: 64KB)
 */
function benchmarkTcpLoopback(durationSeconds = 2, chunkSizeBytes = 65536) {
  return new Promise((resolve) => {
    let bytesReceived = 0;
    const chunk = Buffer.alloc(chunkSizeBytes, 0xAA);
    let isRunning = true;
    let startTime = 0;

    // Start local ephemeral benchmark server
    const server = net.createServer((socket) => {
      socket.on('data', (data) => {
        bytesReceived += data.length;
      });
    });

    server.listen(0, '127.0.0.1', () => {
      const port = server.address().port;
      const client = new net.Socket();

      client.connect(port, '127.0.0.1', () => {
        startTime = performance.now();

        function sendData() {
          while (isRunning) {
            const canContinue = client.write(chunk);
            if (!canContinue) {
              client.once('drain', sendData);
              return;
            }
          }
        }

        sendData();

        setTimeout(() => {
          isRunning = false;
          client.end(() => {
            const durationMs = performance.now() - startTime;
            server.close(() => {
              const durationSec = durationMs / 1000;
              const megabytesTransferred = bytesReceived / (1024 * 1024);
              const megabitsPerSec = parseFloat(((bytesReceived * 8) / (durationSec * 1000000)).toFixed(2));

              resolve({
                protocol: 'TCP',
                mode: 'Loopback Benchmark',
                durationSeconds: parseFloat(durationSec.toFixed(2)),
                bytesTransferred: bytesReceived,
                megabytesTransferred: parseFloat(megabytesTransferred.toFixed(2)),
                throughputMbps: megabitsPerSec,
                chunkSizeBytes
              });
            });
          });
        }, durationSeconds * 1000);
      });

      client.on('error', (err) => {
        server.close();
        resolve({ error: 'Client socket error: ' + err.message });
      });
    });

    server.on('error', (err) => {
      resolve({ error: 'Benchmark server error: ' + err.message });
    });
  });
}

/**
 * Benchmark UDP Stream with RFC 3550 Interarrival Jitter calculation
 * @param {number} packetCount (default: 100)
 * @param {number} packetSizeBytes (default: 1024)
 */
function benchmarkUdpJitter(packetCount = 100, packetSizeBytes = 1024) {
  return new Promise((resolve) => {
    const server = dgram.createSocket('udp4');
    const client = dgram.createSocket('udp4');

    const receivedPackets = [];
    const delays = [];
    let jitter = 0; // RFC 3550 jitter: J = J + (|D(i-1, i)| - J) / 16

    server.on('message', (msg) => {
      const receiveTime = performance.now();
      const sendTime = msg.readDoubleBE(0);
      const seq = msg.readUInt32BE(8);

      const delay = receiveTime - sendTime;
      delays.push(delay);

      if (delays.length > 1) {
        const dDiff = Math.abs(delays[delays.length - 1] - delays[delays.length - 2]);
        jitter = jitter + (dDiff - jitter) / 16;
      }

      receivedPackets.push({ seq, delay });
    });

    server.bind(0, '127.0.0.1', () => {
      const port = server.address().port;
      const startTime = performance.now();

      const buf = Buffer.alloc(packetSizeBytes);
      let sentCount = 0;

      const interval = setInterval(() => {
        if (sentCount >= packetCount) {
          clearInterval(interval);

          // Allow 200ms for in-flight packets to arrive
          setTimeout(() => {
            const totalDurationMs = performance.now() - startTime;
            server.close();
            client.close();

            const packetsReceived = receivedPackets.length;
            const packetsLost = packetCount - packetsReceived;
            const lossPct = parseFloat(((packetsLost / packetCount) * 100).toFixed(2));

            const avgDelayMs = delays.length > 0 ? (delays.reduce((a, b) => a + b, 0) / delays.length) : 0;
            const minDelayMs = delays.length > 0 ? Math.min(...delays) : 0;
            const maxDelayMs = delays.length > 0 ? Math.max(...delays) : 0;

            const totalBytes = packetsReceived * packetSizeBytes;
            const throughputMbps = parseFloat(((totalBytes * 8) / ((totalDurationMs / 1000) * 1000000)).toFixed(2));

            resolve({
              protocol: 'UDP',
              packetsSent: packetCount,
              packetsReceived,
              packetsLost,
              packetLossPct: lossPct,
              rfc3550JitterMs: parseFloat(jitter.toFixed(3)),
              minDelayMs: parseFloat(minDelayMs.toFixed(3)),
              avgDelayMs: parseFloat(avgDelayMs.toFixed(3)),
              maxDelayMs: parseFloat(maxDelayMs.toFixed(3)),
              throughputMbps,
              durationMs: parseFloat(totalDurationMs.toFixed(2))
            });
          }, 200);

          return;
        }

        buf.writeDoubleBE(performance.now(), 0);
        buf.writeUInt32BE(sentCount, 8);
        client.send(buf, 0, packetSizeBytes, port, '127.0.0.1');
        sentCount++;
      }, 5); // Send every 5ms
    });
  });
}

module.exports = {
  benchmarkTcpLoopback,
  benchmarkUdpJitter
};
