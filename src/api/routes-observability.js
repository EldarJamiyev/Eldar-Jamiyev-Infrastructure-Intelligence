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

module.exports = router;
