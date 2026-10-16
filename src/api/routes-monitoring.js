/**
 * EJI Monitoring & Alerting API Routes
 */

const express = require('express');
const router = express.Router();
const MonitoringRepository = require('../database/repositories/monitoring-repository');
const AlertEvaluator = require('../monitoring/alerting/alert-evaluator');
const { authenticate } = require('./middleware');

router.use(authenticate);

// GET /api/monitoring/rules - List alert rules
router.get('/rules', (req, res) => {
  try {
    const rules = MonitoringRepository.listAlertRules();
    res.json({ success: true, count: rules.length, rules });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/monitoring/rules - Create alert rule
router.post('/rules', (req, res) => {
  try {
    const { name, metricName, targetCiType, conditionOperator, thresholdValue, durationSeconds, severity, description } = req.body;
    if (!name || !metricName || thresholdValue === undefined) {
      return res.status(400).json({ success: false, error: 'Missing name, metricName, or thresholdValue' });
    }

    const rule = MonitoringRepository.createAlertRule({
      name,
      metricName,
      targetCiType,
      conditionOperator: conditionOperator || '>=',
      thresholdValue,
      durationSeconds: durationSeconds ? parseInt(durationSeconds, 10) : 60,
      severity: severity || 'P2_HIGH',
      description
    });

    res.status(201).json({ success: true, rule });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/monitoring/alerts - List active alerts
router.get('/alerts', (req, res) => {
  try {
    const { severity, limit } = req.query;
    const alerts = MonitoringRepository.listActiveAlerts({
      severity: severity || null,
      limit: limit ? parseInt(limit, 10) : 100
    });
    res.json({ success: true, count: alerts.length, alerts });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/monitoring/alerts/:id/ack - Acknowledge alert
router.post('/alerts/:id/ack', (req, res) => {
  try {
    const updated = MonitoringRepository.acknowledgeAlert(req.params.id);
    res.json({ success: true, alert: updated });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/monitoring/alerts/:id/resolve - Resolve alert
router.post('/alerts/:id/resolve', (req, res) => {
  try {
    const updated = MonitoringRepository.resolveAlert(req.params.id);
    res.json({ success: true, alert: updated });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/monitoring/alerts/:id/suppress - Suppress alert
router.post('/alerts/:id/suppress', (req, res) => {
  try {
    const { reason } = req.body;
    const updated = MonitoringRepository.suppressAlert(req.params.id, reason);
    res.json({ success: true, alert: updated });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/monitoring/evaluate - Evaluate telemetry
router.post('/evaluate', (req, res) => {
  try {
    const { samples, sample } = req.body;
    if (samples && Array.isArray(samples)) {
      const results = AlertEvaluator.evaluateBatch(samples);
      return res.json({ success: true, evaluatedCount: samples.length, alertsTriggered: results.length, results });
    }
    if (sample) {
      const results = AlertEvaluator.evaluateSample(sample);
      return res.json({ success: true, alertsTriggered: results.length, results });
    }
    res.status(400).json({ success: false, error: 'Provide "sample" object or "samples" array' });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/monitoring/stats - Get alert metrics
router.get('/stats', (req, res) => {
  try {
    const stats = MonitoringRepository.getAlertStatistics();
    res.json({ success: true, stats });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// Outbound Notification Endpoints
const { dispatchAlert, sendTelegramAlert, sendSmtpAlert, sendWebhookAlert } = require('../integrations/notifications/notification-dispatcher');

// POST /api/monitoring/notifications/dispatch - Dispatch alert across channels
router.post('/notifications/dispatch', async (req, res) => {
  try {
    const { alertData, channels, options } = req.body;
    if (!alertData) {
      return res.status(400).json({ success: false, error: 'Missing alertData in request body.' });
    }

    const deliveryReport = await dispatchAlert(alertData, {
      channels: channels || ['telegram', 'email', 'webhook'],
      ...options
    });

    res.json({ success: true, deliveryReport });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/monitoring/notifications/test - Test a specific outbound notification channel
router.post('/notifications/test', async (req, res) => {
  try {
    const { channel, options } = req.body;
    let result = null;

    if (channel === 'telegram') {
      result = await sendTelegramAlert('🔔 <b>EJI Notification Test:</b> Outbound Telegram alert system is operational.', options);
    } else if (channel === 'email') {
      result = await sendSmtpAlert({
        subject: 'EJI Notification Test',
        text: 'EJI Native SMTP notification test message.',
        htmlBody: '<p><b>EJI Notification Test:</b> Native SMTP transport is operational.</p>',
        to: options?.to
      }, options);
    } else if (channel === 'webhook') {
      result = await sendWebhookAlert({
        name: 'EJI Webhook Test',
        severity: 'INFO',
        description: 'Test notification from EJI Operations Platform'
      }, options?.url, options);
    } else {
      return res.status(400).json({ success: false, error: 'Unknown channel. Choose telegram, email, or webhook.' });
    }

    res.json({ success: result.success, result });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;

