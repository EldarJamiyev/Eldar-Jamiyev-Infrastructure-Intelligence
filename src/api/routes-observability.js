/**
 * EJII CNCF Observability & Open Standards API Routes
 * Exposes Prometheus /metrics, OpenTelemetry OTLP JSON, Grafana Dashboard,
 * Loki Structured Logs, and Pluggable Time-Series Storage Exporters.
 */

const express = require('express');
const router = express.Router();
const { authenticate, requirePermission } = require('./middleware');
const { cncfObservabilityExporter } = require('../integrations/observability/cncf-observability-exporter');
const { timeSeriesStorageAdapter } = require('../db/timeseries-storage-adapter');

/**
 * GET /api/observability/prometheus
 * Standard Prometheus Scrape Endpoint
 */
router.get('/prometheus', (req, res) => {
  try {
    const text = cncfObservabilityExporter.generatePrometheusMetrics();
    res.setHeader('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
    res.send(text);
  } catch (err) {
    res.status(500).send('# ERROR: ' + err.message);
  }
});

/**
 * GET /api/observability/otel/v1/traces
 * OpenTelemetry OTLP/JSON Trace Exporter
 */
router.get('/otel/v1/traces', (req, res) => {
  try {
    const otlp = cncfObservabilityExporter.exportOtelTracesJson();
    res.json(otlp);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/observability/grafana-dashboard
 * Grafana v11 Provisioning Dashboard JSON Model
 */
router.get('/grafana-dashboard', (req, res) => {
  try {
    const dash = cncfObservabilityExporter.generateGrafanaDashboardModel();
    res.json(dash);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/observability/loki-logs
 * Grafana Loki Structured Log Stream
 */
router.get('/loki-logs', (req, res) => {
  try {
    const limit = Math.max(1, Math.min(500, parseInt(req.query.limit, 10) || 50));
    const logs = cncfObservabilityExporter.exportLokiStructuredLogs(limit);
    res.json(logs);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/observability/storage-adapter/status
 */
router.get('/storage-adapter/status', (req, res) => {
  try {
    res.json(timeSeriesStorageAdapter.getAdapterStatus());
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * POST /api/observability/storage-adapter/export
 */
router.post('/storage-adapter/export', (req, res) => {
  try {
    const { format = 'influx', limit = 50 } = req.body || {};
    let payload = '';
    if (format === 'clickhouse') {
      payload = timeSeriesStorageAdapter.exportClickHouseJsonEachRow(limit);
      res.setHeader('Content-Type', 'application/x-ndjson');
    } else if (format === 'timescaledb') {
      payload = timeSeriesStorageAdapter.exportTimescaleDbSqlBatch(limit);
      res.setHeader('Content-Type', 'text/plain');
    } else {
      payload = timeSeriesStorageAdapter.exportInfluxLineProtocol(limit);
      res.setHeader('Content-Type', 'text/plain');
    }
    res.send(payload);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

/**
 * GET /api/observability/flight-recorder/dossier
 * Phase 6 Engine 6: Black-Box Incident Flight Recorder & Signed Post-Mortem Dossier
 */
router.get('/flight-recorder/dossier', (req, res) => {
  try {
    const { IncidentFlightRecorder } = require('../observability/incident-flight-recorder');
    const recorder = new IncidentFlightRecorder();
    const dossier = recorder.createSignedDossier();

    if (req.query.format === 'markdown') {
      res.setHeader('Content-Type', 'text/markdown; charset=utf-8');
      res.setHeader('Content-Disposition', `attachment; filename="${dossier.incidentId}-post-mortem.md"`);
      return res.send(dossier.executiveMarkdown);
    }

    res.json({
      success: true,
      ...dossier
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Flight recorder dossier generation failed: ' + err.message });
  }
});

/**
 * POST /api/observability/flight-recorder/verify
 * Phase 6 Engine 6: Cryptographic Verification of Submitted Incident Dossier
 */
router.post('/flight-recorder/verify', (req, res) => {
  try {
    const { IncidentFlightRecorder } = require('../observability/incident-flight-recorder');
    const recorder = new IncidentFlightRecorder();
    const dossier = req.body;

    if (!dossier || !dossier.snapshot || !dossier.dossierSignatureHmac) {
      return res.status(400).json({ success: false, valid: false, error: 'Dossier payload with signature required' });
    }

    const intact = recorder.verifyDossierSignature(dossier);
    res.json({
      success: true,
      valid: intact,
      incidentId: dossier.incidentId,
      tampered: !intact
    });
  } catch (err) {
    res.status(500).json({ success: false, error: 'Dossier verification failed: ' + err.message });
  }
});

/**
 * Sovereign-Singularity v5.0.0 Time-Machine DVR Endpoints
 */

/**
 * GET /api/observability/dvr/frames
 * Returns list of recorded historical telemetry keyframes
 */
router.get('/dvr/frames', (req, res) => {
  try {
    const { TelemetryDvrTimeMachine } = require('../observability/telemetry-dvr-timemachine');
    const dvr = req.app?.locals?.telemetryDvrTimeMachine || new TelemetryDvrTimeMachine();
    const frames = dvr.listFrames();
    res.json({
      success: true,
      totalFrames: frames.length,
      frames
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * POST /api/observability/dvr/record
 * Captures a new DVR keyframe snapshot
 */
router.post('/dvr/record', (req, res) => {
  try {
    const { TelemetryDvrTimeMachine } = require('../observability/telemetry-dvr-timemachine');
    const dvr = req.app?.locals?.telemetryDvrTimeMachine || new TelemetryDvrTimeMachine();
    const frameData = req.body || {};
    const recorded = dvr.recordFrame(frameData);
    res.json({
      success: true,
      frame: recorded
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

/**
 * GET /api/observability/dvr/diff
 * Computes exact structural delta between two keyframe snapshots
 */
router.get('/dvr/diff', (req, res) => {
  try {
    const { TelemetryDvrTimeMachine } = require('../observability/telemetry-dvr-timemachine');
    const dvr = req.app?.locals?.telemetryDvrTimeMachine || new TelemetryDvrTimeMachine();
    const { fromId, toId } = req.query;

    const frames = dvr.listFrames();
    if (frames.length < 2 && (!fromId || !toId)) {
      // Record a test second frame if needed for demonstration
      dvr.recordFrame({
        label: 'Simulated Network Transition',
        lambda2: 0.145,
        cpuPct: 32.4,
        nodesSnapshot: [
          { id: 'L1-WAN-ROUTER', ip: '8.8.8.8', latencyMs: 28.5 },
          { id: 'L2-EDGE-ROUTER', ip: '192.168.31.1', latencyMs: 4.2 },
          { id: 'L3-CORE-SWITCH', ip: '192.168.31.2', latencyMs: 1.1 },
          { id: 'L4-SERVICE-HOST', ip: '192.168.31.89', latencyMs: 0.9 },
          { id: 'L5-ACCESS-LAN', ip: '192.168.31.0/24', latencyMs: 2.4 },
          { id: 'L6-HOST-WORKSTATION', ip: '192.168.31.89', latencyMs: 0.1 }
        ]
      });
    }

    const updatedFrames = dvr.listFrames();
    const fromFrame = fromId ? dvr.getFrame(fromId) : updatedFrames[0];
    const toFrame = toId ? dvr.getFrame(toId) : updatedFrames[updatedFrames.length - 1];

    if (!fromFrame || !toFrame) {
      return res.status(404).json({ success: false, error: 'Keyframes not found for comparison' });
    }

    const diff = dvr.computeSnapshotDiff(fromFrame, toFrame);
    res.json({
      success: true,
      diff
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;
