/**
 * EJII — Eldar Jamiyev's Infrastructure Intelligence
 * Primary Application Server & Telemetry Engine
 */

const express = require('express');
const http = require('http');
const path = require('path');
const { WebSocketServer } = require('ws');
const { PORT, HOST } = require('./config');
const { db, initSchema } = require('./db/database');
const { seedDatabase } = require('./db/seed');
const { realPing } = require('./protocols/icmp-ping');
const { correlateAndReportIncident } = require('./core/rca-engine');

const crypto = require('crypto');
// Route modules
const authRoutes = require('./api/routes-auth');
const diagRoutes = require('./api/routes-diagnostics');
const networkRoutes = require('./api/routes-network');
const systemRoutes = require('./api/routes-system');
const rcaRoutes = require('./api/routes-rca');
const automationRoutes = require('./api/routes-automation');
const adminRoutes = require('./api/routes-admin');
const toolsRoutes = require('./api/routes-tools');
const integrationRoutes = require('./api/routes-integrations');

// Ensure database and baseline seeds are ready
initSchema();
seedDatabase();

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

// Enterprise Security Headers Middleware
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  
  // Correlation ID tracing
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

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/diagnostics', diagRoutes);
app.use('/api/network', networkRoutes);
app.use('/api/system', systemRoutes);
app.use('/api/rca', rcaRoutes);
app.use('/api/automation', automationRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/tools', toolsRoutes);
app.use('/api/integrations', integrationRoutes);

// Catch-all fallback middleware for SPA client navigation
app.use((req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'API endpoint not found.' });
  }
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

// WebSocket real-time connections
const activeClients = new Set();

wss.on('connection', (ws) => {
  activeClients.add(ws);

  ws.send(JSON.stringify({
    type: 'CONNECTED',
    message: 'EJII Real-Time Telemetry Stream Connected.',
    timestamp: new Date().toISOString()
  }));

  ws.on('error', (err) => {
    console.error('[WebSocket Client Error]:', err.message);
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

// Background Telemetry Poller: real ICMP polling of registered nodes
let isPolling = false;
async function pollRegisteredNodes() {
  if (isPolling) return;
  isPolling = true;

  try {
    const nodes = db.prepare('SELECT * FROM nodes').all();
    const insertTelemetry = db.prepare(`
      INSERT INTO telemetry_history (node_id, metric_type, metric_name, value, unit, status, raw_payload, timestamp)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    for (const node of nodes) {
      // Execute genuine ping
      const pingRes = await realPing(node.hostname_or_ip, 2, 1000);
      const now = new Date().toISOString();
      const prevStatus = node.status;

      if (!pingRes.success || pingRes.packetLossPct === 100) {
        db.prepare("UPDATE nodes SET status = 'critical', last_checked = ?, last_latency_ms = null WHERE id = ?").run(now, node.id);

        insertTelemetry.run(
          node.id,
          'icmp_ping',
          'latency_ms',
          null,
          'ms',
          'critical',
          JSON.stringify(pingRes),
          now
        );

        // Node is failing -> correlate through RCA engine
        const correlation = correlateAndReportIncident({
          nodeId: node.id,
          metricType: 'ping',
          errorDescription: pingRes.error || '100% Packet Loss',
          telemetryPayload: pingRes
        });

        broadcast('NODE_ALERT', {
          nodeId: node.id,
          nodeName: node.name,
          status: 'critical',
          ping: pingRes,
          correlation
        });
      } else {
        const isDegraded = pingRes.packetLossPct > 0;
        const currentStatus = isDegraded ? 'degraded' : 'healthy';

        db.prepare("UPDATE nodes SET status = ?, last_checked = ?, last_latency_ms = ? WHERE id = ?")
          .run(currentStatus, now, pingRes.avgRttMs || 0, node.id);

        insertTelemetry.run(
          node.id,
          'icmp_ping',
          'latency_ms',
          pingRes.avgRttMs || 0,
          'ms',
          currentStatus,
          JSON.stringify(pingRes),
          now
        );

        // Detect recovery transition
        if (prevStatus === 'critical' || prevStatus === 'degraded' || prevStatus === 'warning') {
          broadcast('NODE_RECOVERED', {
            nodeId: node.id,
            nodeName: node.name,
            status: 'healthy',
            latencyMs: pingRes.avgRttMs || 0,
            recoveredAt: now
          });
        }

        broadcast('NODE_UPDATE', {
          nodeId: node.id,
          nodeName: node.name,
          status: currentStatus,
          latencyMs: pingRes.avgRttMs || 0,
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
  console.log(`  EJI — Eldar Jamiyev's Infrastructure Intelligence Server      `);
  console.log(`  Real Enterprise IT Management & Observability Platform        `);
  console.log(`================================================================`);
  console.log(`  Server Listening on: http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}`);
  console.log(`  Operational Roles: Helpdesk, Network Admin, Sysadmin, App Owner`);
  console.log(`  Zero-Simulation Policy Active: 100% Genuine OS & Network I/O  `);
  console.log(`================================================================`);
});

// Graceful termination
function shutdown() {
  console.log('\nShutting down EJII gracefully...');
  clearInterval(pollingInterval);
  server.close(() => {
    console.log('HTTP and WebSocket servers closed.');
    process.exit(0);
  });
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

module.exports = { app, server, broadcast };
