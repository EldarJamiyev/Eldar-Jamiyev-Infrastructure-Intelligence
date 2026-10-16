/**
 * EJI Configuration Drift API Routes
 */

const express = require('express');
const router = express.Router();
const DriftRepository = require('../database/repositories/drift-repository');
const DriftEngine = require('../drift/diffing/drift-engine');
const { authenticate } = require('./middleware');

router.use(authenticate);

// GET /api/drift - Overview & recent observations
router.get('/', (req, res) => {
  try {
    const baselines = DriftRepository.listBaselines({});
    const observations = DriftRepository.listRecentObservations({ limit: 20 });
    res.json({
      success: true,
      baselineCount: baselines.length,
      recentObservations: observations
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/drift/baselines - List baselines
router.get('/baselines', (req, res) => {
  try {
    const { targetCiId, baselineType } = req.query;
    const baselines = DriftRepository.listBaselines({ targetCiId, baselineType });
    res.json({ success: true, count: baselines.length, baselines });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/drift/baselines - Create/upsert baseline
router.post('/baselines', (req, res) => {
  try {
    const { targetCiId, name, baselineType, expectedState } = req.body;
    if (!targetCiId || !name || !baselineType || !expectedState) {
      return res.status(400).json({ success: false, error: 'Missing targetCiId, name, baselineType, or expectedState' });
    }

    const baseline = DriftRepository.upsertBaseline({
      targetCiId,
      name,
      baselineType,
      expectedState
    });

    res.status(201).json({ success: true, baseline });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/drift/observations - List recent observations
router.get('/observations', (req, res) => {
  try {
    const { hasDriftOnly, limit } = req.query;
    const observations = DriftRepository.listRecentObservations({
      hasDriftOnly: hasDriftOnly === 'true',
      limit: limit ? parseInt(limit, 10) : 50
    });
    res.json({ success: true, count: observations.length, observations });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/drift/evaluate - Compare observed state with baseline
router.post('/evaluate', (req, res) => {
  try {
    const { baselineId, observedState } = req.body;
    if (!baselineId || !observedState) {
      return res.status(400).json({ success: false, error: 'Missing baselineId or observedState' });
    }

    const evaluation = DriftEngine.evaluateCiDrift(baselineId, observedState);
    res.json({ success: true, ...evaluation });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/drift/metrics - Summary metrics
router.get('/metrics', (req, res) => {
  try {
    const metrics = DriftRepository.getDriftMetrics();
    res.json({ success: true, metrics });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;
