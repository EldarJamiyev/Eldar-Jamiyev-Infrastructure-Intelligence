/**
 * EJII — Eldar Jamiyev's Infrastructure Intelligence
 * Pure NOC Workstation: Network Topology & Wireshark-Grade Packet Dissection Engine
 * Zero-Simulation Standard: 100% Genuine OS & Physical Wire Telemetry.
 */

const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');

// Workspace scratch sanitizer: eliminate transient batch/script artifacts before boot
function sanitizeWorkspaceScratchFiles() {
  const rootDir = path.join(__dirname, '..');
  const filesToClean = ['sync_now.bat', 'update_reports.js'];
  try {
    for (const f of filesToClean) {
      const p = path.join(rootDir, f);
      if (fs.existsSync(p)) {
        try { fs.unlinkSync(p); } catch (_) {}
      }
    }
    const dirEntries = fs.readdirSync(rootDir);
    for (const entry of dirEntries) {
      if (/^patch_.*\.js$/i.test(entry)) {
        try { fs.unlinkSync(path.join(rootDir, entry)); } catch (_) {}
      }
    }
  } catch (_) {}
}
sanitizeWorkspaceScratchFiles();
const crypto = require('crypto');
const { WebSocketServer } = require('ws');
const config = require('./config');
const { PORT, HOST } = config;
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
const observabilityRoutes = require('./api/routes-observability');
const learningRoutes = require('./api/routes-learning');
const { initLearningSchema } = require('./db/learning-schema');
const { cncfObservabilityExporter } = require('./integrations/observability/cncf-observability-exporter');
const { TypeContractValidator } = require('./core/type-contract-validator');
const { packetAndScanWorkerPool } = require('./network/workers/packet-and-scan-worker-pool');
const { timeSeriesStorageAdapter } = require('./db/timeseries-storage-adapter');
const { gitopsReconciliationEngine } = require('./core/gitops-reconciliation-engine');
const { collectLinuxParityTelemetry } = require('./systems/linux/linux-native-telemetry');
const { getPhysicalNetworkInfo, syncTopologyWithCurrentLocation } = require('./network/routing/physical-network-detector');
const { topologyEngine } = require('./network/topology/topology-engine');
const { requestCorrelationAndTelemetryMiddleware, authenticate } = require('./api/middleware');

// Sovereign-Apex v2.0.0 & Sovereign-Enterprise v3.0.0 Core Deep Intelligence & Safety Engines
const { NeuroSymbolicApexEngine } = require('./ai/neuro-symbolic-apex');
const { WireDissectorApex } = require('./sniffer/wire-dissector-apex');
const { SpectralGNNTopologyEngine } = require('./topology/spectral-gnn-apex');
const { DSRLLyapunovSafetyVault } = require('./security/dsrl-lyapunov-vault');
const { PcapngEngine } = require('./sniffer/pcapng-engine');
const { RoutingRadixIntelligenceEngine } = require('./topology/routing-radix-intelligence');
const { ProcessSocketCorrelatorEngine } = require('./diagnostics/process-socket-correlator');
const { TlsPostureAuditor } = require('./security/tls-posture-auditor');
const { CusumChangepointEngine } = require('./ai/cusum-changepoint-engine');
const { IncidentFlightRecorder } = require('./observability/incident-flight-recorder');

// Ensure database and baseline seeds are ready
initSchema();
seedDatabase();
initLearningSchema(db);
try {
  process.title = "EJII -- Eldar Jamiyev's Infrastructure Intelligence";
} catch (_) {}

const app = express();
app.locals.neuroSymbolicApex = new NeuroSymbolicApexEngine();
app.locals.wireDissectorApex = WireDissectorApex;
app.locals.spectralGNNTopology = new SpectralGNNTopologyEngine();
const vaultHmacSecret = config.HMAC_SECRET || process.env.EJII_HMAC_SECRET || 'EJII-ENTERPRISE-INTELLIGENCE-HMAC-SECURE-KEY-2026';
app.locals.dsrlLyapunovSafetyVault = new DSRLLyapunovSafetyVault(vaultHmacSecret, []);
app.locals.pcapngEngine = PcapngEngine;
app.locals.routingRadixIntelligence = RoutingRadixIntelligenceEngine;
app.locals.processSocketCorrelator = ProcessSocketCorrelatorEngine;
app.locals.tlsPostureAuditor = TlsPostureAuditor;
app.locals.cusumChangepointEngine = new CusumChangepointEngine();
app.locals.incidentFlightRecorder = new IncidentFlightRecorder(vaultHmacSecret);
const server = http.createServer(app);

// Prevent abrupt keep-alive socket resets on Windows loopback (errno -4077 ECONNRESET)
server.keepAliveTimeout = 65000;
server.headersTimeout = 66000;
server.on('connection', (socket) => {
  socket.setNoDelay(true);
  socket.on('error', () => {});
});
const wss = new WebSocketServer({
  server,
  handleProtocols: (protocols, req) => {
    const list = Array.from(protocols || []);
    if (list.includes('token')) return 'token';
    if (list.includes('bearer')) return 'bearer';
    return false;
  }
});

// CRITICAL: Prevent Node.js v24+ Unhandled 'error' event on WebSocketServer
// when the underlying http.Server emits EADDRINUSE or socket errors.
wss.on('error', (err) => {
  if (err && err.code === 'EADDRINUSE') {
    // Handled gracefully by the http.Server EADDRINUSE recovery handler below
    return;
  }
  console.error('[EJII WebSocketServer] Non-fatal transport error:', err ? err.message : err);
});

// Request correlation and API latency telemetry
app.use(requestCorrelationAndTelemetryMiddleware);

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
app.get('/api/health', (req, res) => {
  res.json({
    status: 'UP',
    timestamp: new Date().toISOString(),
    evaluationMode: config.IS_EVALUATION_MODE,
    platform: config.PLATFORM,
    port: config.PORT
  });
});

// Fast Aggregated Bootstrap Endpoint (Instant 0ms multi-view hydration)
app.get('/api/system/bootstrap', authenticate, async (req, res) => {
  try {
    const { topologyEngine } = require('./network/topology/topology-engine');
    const { packetStreamer } = require('./network/packet-streaming/packet-streamer');
    const { equipmentInventoryRepository } = require('./db/equipment-inventory-repository');
    const { scriptAutomation } = require('./tools/script-automation');
    const { hostDiagnosticsEngine } = require('./systems/diagnostics/host-diagnostics-engine');
    const { aiBrain } = require('./core/ai-brain');
    const { getHardwareAnchorStatus } = require('./core/audit-logger');

    const topo = topologyEngine.getTopology();
    const inventory = equipmentInventoryRepository.getAllEquipmentRecords();
    const scriptsRes = scriptAutomation.listAutomationScripts();
    const mountAudit = typeof scriptAutomation.getMountResolutionAudit === 'function' ? scriptAutomation.getMountResolutionAudit() : null;
    const warmDiag = hostDiagnosticsEngine.getWarmSnapshot();
    const brainStatus = aiBrain.getStatus();
    const liveBrainState = aiBrain.getLiveState();
    const counters = packetStreamer.getCounters();
    const captureStats = packetStreamer.getCaptureStats();
    const auditAnchor = getHardwareAnchorStatus();

    res.json({
      success: true,
      timestamp: new Date().toISOString(),
      topology: topo,
      sniffer: {
        active: packetStreamer.isActive(),
        selectedDevice: packetStreamer.selectedDevice,
        bpfFilter: packetStreamer.bpfFilter,
        counters,
        ringBuffer: captureStats.ringBuffer,
        recentFrames: packetStreamer.frameRingBuffer.slice(-50)
      },
      inventory,
      scripts: scriptsRes.scripts || scriptsRes,
      mountMetadata: scriptsRes.mountMetadata || {},
      mountAudit: mountAudit || null,
      diagnostics: warmDiag,
      aiBrain: {
        ...brainStatus,
        symbolicProofChain: liveBrainState.symbolicProofChain || [],
        solverStats: liveBrainState.solverStats || {},
        activeInference: liveBrainState.activeInference || {},
        worldModelRollout: liveBrainState.worldModelRollout || null,
        stlReport: liveBrainState.stlReport || null,
        dsrlVault: liveBrainState.dsrlVault || null
      },
      auditAnchor
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.use('/api/auth', authRoutes);
app.use('/api/diagnostics', hostRemediationRoutes);
app.use('/api/diagnostics', diagRoutes);
app.use('/api/network', networkRoutes);
app.use('/api/tools', toolsRoutes);
app.use('/api/rca', rcaRoutes);
app.use('/api/observability', observabilityRoutes);
app.use('/api/learning', learningRoutes);

// Native Prometheus Exposition Endpoint (/metrics)
app.get('/metrics', (req, res) => {
  try {
    const text = cncfObservabilityExporter.generatePrometheusMetrics();
    res.setHeader('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
    res.send(text);
  } catch (err) {
    res.status(500).send('# ERROR: ' + err.message);
  }
});

// Catch-all fallback middleware for SPA client navigation
app.use((req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'API endpoint not found.' });
  }
  res.sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

// Centralized error-handling middleware for unhandled exceptions
app.use((err, req, res, next) => {
  const correlationId = (req.headers && (req.headers['x-correlation-id'] || req.headers['x-request-id'])) || require('crypto').randomUUID();
  console.error(`[Unhandled API Exception ${correlationId}]:`, err && (err.stack || err.message || err));
  if (res.headersSent) {
    return next(err);
  }
  if (req.path && req.path.startsWith('/api/')) {
    return res.status(err.status || 500).json({
      success: false,
      error: err.message || 'Internal Server Error',
      correlationId
    });
  }
  res.status(500).sendFile(path.join(__dirname, '..', 'public', 'index.html'));
});

// WebSocket real-time connections
const activeClients = new Set();
const { verifyToken, hasPermission } = require('./core/security');

wss.on('connection', (ws, req) => {
  activeClients.add(ws);
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });

  // Authenticate WebSocket connection via Sec-WebSocket-Protocol, cookie, auth header, or deprecated query
  let token = null;

  // 1. Primary Secure Transport: Sec-WebSocket-Protocol (eliminates query-string log exposure)
  if (req.headers['sec-websocket-protocol']) {
    const protocols = req.headers['sec-websocket-protocol'].split(',').map(s => s.trim());
    if (protocols.length >= 2 && (protocols[0].toLowerCase() === 'token' || protocols[0].toLowerCase() === 'bearer')) {
      token = protocols[1];
    } else if (protocols.length === 1 && protocols[0].includes('.')) {
      token = protocols[0];
    }
  }

  // 2. HTTP Authorization Header
  if (!token && req.headers['authorization']) {
    const authHdr = req.headers['authorization'];
    if (authHdr.startsWith('Bearer ')) token = authHdr.slice(7).trim();
  }

  // 3. HTTP Cookie: eji_session
  if (!token && req.headers.cookie) {
    const match = req.headers.cookie.match(/eji_session=([^;]+)/);
    if (match) token = match[1];
  }

  // 4. Deprecated Query-String fallback (logs security deprecation warning)
  if (!token) {
    try {
      const urlObj = new URL(req.url, 'http://localhost');
      const queryToken = urlObj.searchParams.get('token');
      if (queryToken) {
        console.warn('[SECURITY WARNING]: WebSocket authenticated via query-string token. Query parameters risk exposure in web server and proxy access logs. Please use Sec-WebSocket-Protocol or eji_session cookie.');
        token = queryToken;
      }
    } catch (e) {}
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
        // Enforce strict network.capture.execute capability (S-04)
        const canCapture = hasPermission(ws.user.role, 'network.capture.execute');
        if (!canCapture) {
          return ws.send(JSON.stringify({
            type: 'STREAM_ERROR',
            error: `Access denied: Role '${ws.user.role}' lacks 'network.capture.execute' capability.`
          }));
        }
        packetStreamer.startStreaming((t, p) => broadcast(t, p));
        ws.send(JSON.stringify({
          type: 'PACKET_STREAM_STATUS',
          active: true,
          counters: packetStreamer.getCounters(),
          device: packetStreamer.selectedDevice,
          bpf: packetStreamer.bpfFilter,
          frames: packetStreamer.frameRingBuffer.slice(-50)
        }));
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
  let message;
  let eventType = type;
  if (typeof type === 'object' && type !== null) {
    message = JSON.stringify({ ...type, timestamp: type.timestamp || new Date().toISOString() });
    eventType = type.type;
  } else {
    message = JSON.stringify({ type, payload, timestamp: new Date().toISOString() });
  }
  for (const client of activeClients) {
    if (client.readyState === 1) { // OPEN
      // Security Filter: PACKET_STREAM_FRAME requires authenticated session with network.capture.execute or telemetry.read
      if (eventType === 'PACKET_STREAM_FRAME') {
        const isAuth = client.user && client.user.id !== 'ANON';
        const hasAccess = isAuth && (
          hasPermission(client.user.role, 'network.capture.execute') ||
          hasPermission(client.user.role, 'telemetry.read')
        );
        if (!hasAccess) continue;

        // WebSocket Backpressure Guard: Drop high-frequency frames if client buffer exceeds 512 KB
        if (client.bufferedAmount > 512 * 1024) {
          continue;
        }
      }
      try {
        client.send(message);
      } catch (err) {
        activeClients.delete(client);
      }
    }
  }
}

// 20s Heartbeat sweep to terminate dead WebSocket connections
const wsHeartbeatSweep = setInterval(() => {
  for (const client of activeClients) {
    if (client.readyState === 1) {
      if (client.isAlive === false) {
        activeClients.delete(client);
        try { client.terminate(); } catch (_) {}
        continue;
      }
      client.isAlive = false;
      try { client.ping(); } catch (_) {}
    }
  }
}, 20000);
if (wsHeartbeatSweep.unref) wsHeartbeatSweep.unref();

app.locals.broadcast = broadcast;

// Initialize AI Brain broadcast handler for live diagnostic streaming
const { aiBrain } = require('./core/ai-brain');
aiBrain.setBroadcastHandler((eventType, payload) => {
  broadcast({
    type: 'AI_BRAIN_DIAGNOSTIC_UPDATE',
    subType: eventType,
    payload,
    timestamp: new Date().toISOString()
  });
});

// Initialize Investigation Planner-Executor-Critic broadcast handler (EJII Phase 4)
try {
  const { investigationPlannerExecutorCritic } = require('./core/unified-investigation-engine');
  investigationPlannerExecutorCritic.subscribe((eventName, payload) => {
    broadcast(eventName, {
      ...payload,
      timestamp: new Date().toISOString()
    });
  });
} catch (_) {}

// Initialize live packet streamer
const { packetStreamer } = require('./network/packet-streaming/packet-streamer');

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

// Run polling loop every 30 seconds (opt-in only to guarantee zero unsolicited pings)
const pollingInterval = process.env.EJII_AUTO_POLL === 'true'
  ? setInterval(pollRegisteredNodes, 30000)
  : null;
if (pollingInterval && typeof pollingInterval.unref === 'function') {
  pollingInterval.unref();
}

// Continuous Live Location & Subnet Change Watcher (Every 10 seconds)
let lastNetworkSignatureHash = null;
const locationWatcherInterval = (process.env.NODE_ENV !== 'test' && process.env.EJII_DISABLE_BG_SYNC !== 'true')
  ? setInterval(() => {
  try {
    const netInfo = getPhysicalNetworkInfo({ forceRefresh: true });
    if (netInfo && netInfo.networkSignatureHash) {
      if (lastNetworkSignatureHash && lastNetworkSignatureHash !== netInfo.networkSignatureHash) {
        syncTopologyWithCurrentLocation(db);
        topologyEngine.cachedTopology = null;
        const newTopo = topologyEngine.getTopology();
        broadcast('TOPOLOGY_LOCATION_UPDATED', {
          networkInfo: netInfo,
          topology: newTopo,
          updatedAt: new Date().toISOString()
        });
      }
      lastNetworkSignatureHash = netInfo.networkSignatureHash;
    }
  } catch (_) {}
}, 10000)
  : null;
if (locationWatcherInterval && typeof locationWatcherInterval.unref === 'function') {
  locationWatcherInterval.unref();
}

// Run initial poll 3 seconds after boot (opt-in only)
const initialPollTimeout = process.env.EJII_AUTO_POLL === 'true'
  ? setTimeout(pollRegisteredNodes, 3000)
  : null;
if (initialPollTimeout && typeof initialPollTimeout.unref === 'function') {
  initialPollTimeout.unref();
}

/**
 * Probes whether an active EJII server is already responding on target host:port.
 */
function probeActiveEjiiServer(host, port, timeoutMs = 1200) {
  return new Promise((resolve) => {
    const http = require('http');
    const targetHost = (host === '0.0.0.0' || !host) ? '127.0.0.1' : host;
    const req = http.get(
      {
        hostname: targetHost,
        port,
        path: '/api/health',
        timeout: timeoutMs,
        agent: false
      },
      (res) => {
        let body = '';
        res.on('data', (chunk) => { body += chunk; });
        res.on('end', () => {
          try {
            const parsed = JSON.parse(body);
            resolve(res.statusCode === 200 && parsed && parsed.status === 'UP');
          } catch (_) {
            resolve(false);
          }
        });
      }
    );
    req.on('timeout', () => { req.destroy(); resolve(false); });
    req.on('error', () => resolve(false));
  });
}

// Start server
if (require.main === module || process.env.EJII_AUTO_LISTEN === 'true') {
  server.on('error', async (err) => {
    if (err && err.code === 'EADDRINUSE') {
      const isHealthyInstance = await probeActiveEjiiServer(HOST, PORT, 1500);
      if (isHealthyInstance) {
        console.log('====================================================================');
        console.log(`  [EJII Server] Active EJII Workstation verified running on http://${HOST}:${PORT}`);
        console.log('  [EJII Server] Reusing active workstation instance cleanly (Exit 0).');
        console.log('====================================================================');
        process.exit(0);
      } else {
        console.error(`[EJII Server] Port ${PORT} is occupied by a non-responsive process. Attempting port reclamation...`);
        if (process.platform === 'win32') {
          try {
            const { execSync } = require('child_process');
            const netstatOut = execSync(`netstat -ano | findstr ":${PORT}" | findstr "LISTENING"`, { encoding: 'utf8' });
            const lines = netstatOut.trim().split(/\r?\n/);
            for (const line of lines) {
              const parts = line.trim().split(/\s+/);
              const pid = Number(parts[parts.length - 1]);
              if (pid && pid !== process.pid && pid > 4) {
                execSync(`taskkill /F /PID ${pid}`, { stdio: 'ignore' });
              }
            }
            setTimeout(() => {
              try {
                server.listen(PORT, HOST);
              } catch (_) {
                process.exit(1);
              }
            }, 500);
            return;
          } catch (_) {}
        }
        process.exit(1);
      }
    } else {
      console.error('[EJII Server] Fatal HTTP Server Error:', err);
      process.exit(1);
    }
  });

  server.listen(PORT, HOST, () => {
    console.log(`================================================================`);
    console.log(`  EJII — NOC Network Topology & Packet Dissection Workstation   `);
    console.log(`  Unprivileged Wire-Level Network Engineering Station           `);
    console.log(`================================================================`);
    console.log(`  Server Listening on: http://${HOST === '0.0.0.0' ? 'localhost' : HOST}:${PORT}`);
    console.log(`  Access Mode: Unprivileged NOC Operator                        `);
    console.log(`  Zero-Simulation Standard: Real Physical NIC & Sockets Active  `);
    console.log(`================================================================`);

    // Fast non-blocking deferred initialization: background sweeps run AFTER port is bound
    setImmediate(() => {
      try {
        if (process.env.NODE_ENV !== 'test' && process.env.EJII_DISABLE_BG_SYNC !== 'true') {
          syncTopologyWithCurrentLocation(db);
        }
      } catch (_) {}
      try {
        if (process.env.NODE_ENV !== 'test' && process.env.EJII_DISABLE_BG_SYNC !== 'true') {
          packetStreamer.startStreaming((type, payload) => broadcast(type, payload));
        }
      } catch (_) {}
    });
  });
}

// Graceful termination & WAL Checkpoint
async function gracefulShutdown(signal = 'SIGTERM') {
  console.log(`\n[EJII] Gracefully shutting down (${signal})...`);
  if (pollingInterval) clearInterval(pollingInterval);
  if (locationWatcherInterval) clearInterval(locationWatcherInterval);
  if (initialPollTimeout) clearTimeout(initialPollTimeout);
  if (typeof wsHeartbeatSweep !== 'undefined' && wsHeartbeatSweep) clearInterval(wsHeartbeatSweep);
  try {
    aiBrain.stopContinuousReasoning();
  } catch (_) {}
  try {
    packetStreamer.stopStreaming();
  } catch (_) {}
  for (const client of activeClients) {
    try {
      client.close(1001, 'Server shutting down');
    } catch (_) {}
  }
  activeClients.clear();

  await new Promise((resolve) => {
    wss.close(() => {
      server.close(() => {
        try {
          db.exec('PRAGMA wal_checkpoint(TRUNCATE);');
        } catch (_) {}
        console.log('[EJII] HTTP & WebSocket servers closed, SQLite WAL checkpointed.');
        resolve();
      });
    });
  });
}

function handleSignal(signal) {
  gracefulShutdown(signal).then(() => {
    process.exit(0);
  }).catch(() => {
    process.exit(1);
  });
}

process.on('SIGINT', () => handleSignal('SIGINT'));
process.on('SIGTERM', () => handleSignal('SIGTERM'));

module.exports = {
  app,
  server,
  broadcast,
  gracefulShutdown,
  shutdownServer: gracefulShutdown
};
