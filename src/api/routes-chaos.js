/**
 * EJI Chaos Engineering API Routes
 */

const express = require('express');
const router = express.Router();
const ChaosRepository = require('../database/repositories/chaos-repository');
const ChaosEngine = require('../chaos/lab/chaos-engine');
const { authenticate, requireRole } = require('./middleware');

router.use(authenticate);

// GET /api/chaos (and /experiments) - Overview & scenarios
router.get(['/', '/experiments'], (req, res) => {
  try {
    const scenarios = ChaosRepository.listScenarios();
    res.json({ success: true, count: scenarios.length, scenarios });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/chaos/scenarios - List scenarios
router.get('/scenarios', (req, res) => {
  try {
    const scenarios = ChaosRepository.listScenarios();
    res.json({ success: true, count: scenarios.length, scenarios });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/chaos/scenarios - Create scenario (sysadmin only)
router.post('/scenarios', requireRole('sysadmin'), (req, res) => {
  try {
    const { name, description, targetType, targetResource, parameters, durationSeconds, safetyGuardrails } = req.body;
    if (!name || !targetType || !targetResource) {
      return res.status(400).json({ success: false, error: 'Missing name, targetType, or targetResource' });
    }

    const scenario = ChaosRepository.createScenario({
      name,
      description: description || 'Chaos resilience experiment',
      targetType,
      targetResource,
      parameters: parameters || {},
      durationSeconds: durationSeconds ? parseInt(durationSeconds, 10) : 30,
      safetyGuardrails: safetyGuardrails || { maxDurationSec: 60, labOnly: true }
    });

    res.status(201).json({ success: true, scenario });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/chaos/executions - List executions
router.get('/executions', (req, res) => {
  try {
    const executions = ChaosRepository.listExecutions();
    res.json({ success: true, count: executions.length, executions });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/chaos/execute - Trigger safe lab experiment (sysadmin only)
router.post('/execute', requireRole('sysadmin'), async (req, res) => {
  try {
    const { scenarioId } = req.body;
    if (!scenarioId) return res.status(400).json({ success: false, error: 'scenarioId is required' });

    const result = await ChaosEngine.executeExperiment(scenarioId, req.user ? req.user.username : 'sysadmin');
    res.json({ success: true, ...result });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;
