/**
 * EJI Autonomous Control Loop API Routes
 */

const express = require('express');
const router = express.Router();
const ControlLoopEngine = require('../core/control-loop/control-loop-engine');
const { authenticate } = require('./middleware');

router.use(authenticate);

const engine = new ControlLoopEngine();

// POST /api/control-loop/cycle - Run 13-stage control loop cycle
router.post('/cycle', async (req, res) => {
  try {
    const { observations, baselineIntent } = req.body;
    const defaultObservations = [
      { ciId: 'NODE-LOCAL-HOST', metric: 'cpu_percent', value: 34.2, status: 'healthy' },
      { ciId: 'NODE-GW-01', metric: 'packet_loss', value: 0.0, status: 'healthy' },
      { ciId: 'NODE-DNS-PUBLIC', metric: 'latency_ms', value: 14.8, status: 'healthy' }
    ];

    const result = await engine.runLoop(observations || defaultObservations, {
      userContext: {
        username: req.user ? req.user.username : 'operator',
        role: req.user ? req.user.role : 'sysadmin'
      },
      baselineIntent: baselineIntent || {
        'NODE-LOCAL-HOST': { desiredState: 'HEALTHY' },
        'NODE-GW-01': { desiredState: 'HEALTHY' },
        'NODE-DNS-PUBLIC': { desiredState: 'HEALTHY' }
      }
    });

    res.json({ success: true, ...result });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/control-loop/status - Control plane health status
router.get('/status', (req, res) => {
  res.json({
    success: true,
    controlPlane: 'EJI_NEXUS_OMNIS_V2',
    status: 'ACTIVE_OBSERVING',
    activeStagesCount: 13,
    stages: [
      'OBSERVE', 'NORMALIZE', 'CORRELATE', 'UNDERSTAND_STATE',
      'COMPARE_INTENT', 'EVALUATE_POLICY', 'ASSESS_RISK',
      'PLAN', 'APPROVE', 'EXECUTE', 'VERIFY', 'AUDIT', 'RECONCILE'
    ],
    timestamp: new Date().toISOString()
  });
});

module.exports = router;
