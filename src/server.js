/**
 * EJII — Eldar Jamiyev's Infrastructure Intelligence
 * Pure NOC Workstation: Network Topology & Wireshark-Grade Packet Dissection Engine
 * Zero-Simulation Standard: 100% Genuine OS & Physical Wire Telemetry.
 */

const express = require('express');
const http = require('http');
const path = require('path');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');
const { PORT, HOST } = require('./config');
const { db, initSchema } = require('./db/database');
const { seedDatabase } = require('./db/seed');
const { probeNodeDual } = require('./protocols/dual-prober');

// Clean Route Modules
const authRoutes = require('./api/routes-auth');
const diagRoutes = require('./api/routes-diagnostics');
const hostRemediationRoutes = require('./api/routes-diagnostics-remediation');
const networkRoutes = require('./api/routes-network');
const toolsRoutes = require('./api/routes-tools');
const rcaRoutes = require('./api/routes-rca');

// Ensure database and baseline seeds are ready
initSchema();
seedDatabase();

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

// Security Headers Middleware
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  
  const correlationId = req.headers['x-correlation-id'] || ('CID-' + crypto.randomBytes(4).toString('hex'));
  req.correlationId = correlationId;
  res.setHeader('X-Correlation-ID', correlationId);
  next();
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve frontend static files
app.use(express.static(path.join(__dirname, '..', 'public')));

// Primary NOC Workstation API Routes
app.use('/api/auth', authRoutes);
app.use('/api/diagnostics', hostRemediationRoutes);
app.use('/api/diagnostics', diagRoutes);
app.use('/api/network', networkRoutes);
app.use('/api/tools', toolsRoutes);
app.use('/api/rca', rcaRoutes);

// Catch-all fallback middleware for SPA client navigation
app.use((req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'API endpoint not found.' });
  }
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

// WebSocket real-time connections
const activeClients = new Set();
const { verifyToken, hasPermission } = require('./core/security');

wss.on('connection', (ws, req) => {
  activeClients.add(ws);

  // Authenticate WebSocket connection via query param, auth header, or cookie
  let token = null;
  try {
    const urlObj = new URL(req.url, 'http://localhost');
    token = urlObj.searchParams.get('token');
  } catch (e) {}

  if (!token && req.headers['authorization']) {
    const authHdr = req.headers['authorization'];
    if (authHdr.startsWith('Bearer ')) token = authHdr.slice(7).trim();
  }

  if (!token && req.headers.cookie) {
    const match = req.headers.cookie.match(/eji_session=([^;]+)/);
    if (match) token = match[1];
  }

  const decoded = token ? verifyToken(token) : null;
  ws.user = decoded ? {
    id: decoded.id,
    username: decoded.username,
    role: (decoded.role || 'READONLY').toUpperCase()
  } : {
    id: 'ANON',
    username: 'unauthenticated',
    role: 'READONLY'
  };

  ws.send(JSON.stringify({
    type: 'CONNECTED',
    message: 'EJII Pure NOC Workstation Stream Connected.',
    user: { username: ws.user.username, role: ws.user.role },
    timestamp: new Date().toISOString()
  }));

  const { packetStreamer } = require('./network/packet-streaming/packet-streamer');

  ws.on('message', (raw) => {
    try {
      const data = JSON.parse(raw.toString());
      if (data.type === 'START_PACKET_STREAM') {
        const canCapture = hasPermission(ws.user.role, 'network.capture.execute') || hasPermission(ws.user.role, 'telemetry.read');
        if (!canCapture && ws.user.role === 'READONLY') {
          return ws.send(JSON.stringify({
            type: 'STREAM_ERROR',
            error: 'Access denied: Packet capture stream requires network.capture.execute capability.'
          }));
        }
        packetStreamer.startStreaming((t, p) => broadcast(t, p));
        ws.send(JSON.stringify({ type: 'PACKET_STREAM_STATUS', active: true }));
      } else if (data.type === 'STOP_PACKET_STREAM') {
        packetStreamer.stopStreaming();
        ws.send(JSON.stringify({ type: 'PACKET_STREAM_STATUS', active: false }));
      }
    } catch (e) {}
  });

  ws.on('error', (err) => {
    activeClients.delete(ws);
  });

  ws.on('close', () => {
    activeClients.delete(ws);
  });
});

/**
 * Broadcast payload to all connected WebSocket clients
 */
function broadcast(type, payload) {
  const message = JSON.stringify({ type, payload, timestamp: new Date().toISOString() });
  for (const client of activeClients) {
    if (client.readyState === 1) { // OPEN
      try {
        client.send(message);
      } catch (err) {
        activeClients.delete(client);
      }
    }
  }
}

app.locals.broadcast = broadcast;

// Initialize AI Brain broadcast handler for live diagnostic streaming
const { aiBrain } = require('./core/ai-brain');
aiBrain.setBroadcastHandler((type, payload) => broadcast(type, payload));

// Initialize live packet streamer
const { packetStreamer } = require('./network/packet-streaming/packet-streamer');
packetStreamer.startStreaming((type, payload) => broadcast(type, payload));

// Background Telemetry Poller: real dual-protocol polling (ICMP + TCP fallback)
let isPolling = false;
async function pollRegisteredNodes() {
  if (isPolling) return;
  isPolling = true;

  try {
    const nodes = db.prepare('SELECT * FROM topology_nodes').all();
    const insertTelemetry = db.prepare(`
      INSERT INTO link_telemetry (node_id, latency_ms, timestamp)
      VALUES (?, ?, ?)
    `);

    for (const node of nodes) {
      const probeRes = await probeNodeDual(node);
      const now = new Date().toISOString();
      const prevStatus = node.status;

      if (!probeRes.success || probeRes.status === 'critical') {
        db.prepare("UPDATE topology_nodes SET status = 'critical', last_checked = ?, last_latency_ms = null WHERE id = ?").run(now, node.id);

        insertTelemetry.run(node.id, null, now);

        broadcast('NODE_ALERT', {
          nodeId: node.id,
          nodeName: node.name,
          ip: node.hostname_or_ip,
          status: 'critical',
          probe: probeRes
        });
      } else {
        const currentStatus = probeRes.status; // 'healthy' or 'degraded'
        const latency = probeRes.latencyMs || 0;

        db.prepare("UPDATE topology_nodes SET status = ?, last_checked = ?, last_latency_ms = ? WHERE id = ?")
          .run(currentStatus, now, latency, node.id);

        insertTelemetry.run(node.id, latency, now);

        if (prevStatus === 'critical' || prevStatus === 'degraded') {
          broadcast('NODE_RECOVERED', {
            nodeId: node.id,
            nodeName: node.name,
            ip: node.hostname_or_ip,
            status: 'healthy',
            latencyMs: latency,
            recoveredAt: now
          });
        }

        broadcast('NODE_UPDATE', {
          nodeId: node.id,
          nodeName: node.name,
          ip: node.hostname_or_ip,
          status: currentStatus,
          latencyMs: latency,
          lastChecked: now
        });
      }
    }
  } catch (err) {
    console.error('[Telemetry Poller Error]:', err.message);
  } finally {
    isPolling = false;
  }
}

// Run polling loop every 30 seconds
const pollingInterval = setInterval(pollRegisteredNodes, 30000);

// Run initial poll 3 seconds after boot
setTimeout(pollRegisteredNodes, 3000);

// Start server
server.listen(PORT, HOST, () => {
  console.log(`================================================================`);
  console.log(`  EJII — NOC Network Topology & Packet Dissection Workstation   `);
  console.log(`  Unprivileged Wire-Level Network Engineering Station           `);
  console.log(`================================================================`);
  console.log(`  Server Listening on: http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}`);
  console.log(`  Access Mode: Unprivileged NOC Operator                        `);
  console.log(`  Zero-Simulation Standard: Real Physical NIC & Sockets Active  `);
  console.log(`================================================================`);
});

// Graceful termination
function shutdown() {
  console.log('\nShutting down EJII gracefully...');
  clearInterval(pollingInterval);
  packetStreamer.stopStreaming();
  server.close(() => {
    console.log('HTTP and WebSocket servers closed.');
    process.exit(0);
  });
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

module.exports = { app, server, broadcast };
