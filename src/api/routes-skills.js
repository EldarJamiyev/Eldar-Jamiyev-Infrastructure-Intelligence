/**
 * EJII Universal AI Skill Router REST API Endpoints
 * Phase 22.0 Core Platform API
 */

'use strict';

const express = require('express');
const router = express.Router();
const { universalSkillRouter } = require('../core/skills/universal-skill-router');

/**
 * GET /api/skills/detect
 * Returns comprehensive auto-detection census across all 986 cataloged skills.
 */
router.get('/detect', (req, res) => {
  try {
    const census = universalSkillRouter.detectAllSkills();
    return res.json({
      success: true,
      census
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

/**
 * GET /api/skills/catalog
 * Returns filtered ecosystem catalog.
 */
router.get('/catalog', (req, res) => {
  try {
    const { category, tier, limit = 50, search } = req.query;
    let catalog = universalSkillRouter.getFullCatalog();

    if (category) {
      catalog = catalog.filter((s) => s.category === category);
    }
    if (tier) {
      catalog = catalog.filter((s) => s.tier === tier);
    }
    if (search) {
      const q = String(search).toLowerCase();
      catalog = catalog.filter(
        (s) => s.name.toLowerCase().includes(q) || (s.description && s.description.toLowerCase().includes(q))
      );
    }

    const maxItems = Math.min(200, Math.max(1, parseInt(limit, 10) || 50));
    return res.json({
      success: true,
      totalCataloged: catalog.length,
      returnedCount: Math.min(maxItems, catalog.length),
      skills: catalog.slice(0, maxItems)
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

/**
 * POST /api/skills/route
 * Routes an incoming task/telemetry context to the optimal skill bundle.
 */
router.post('/route', (req, res) => {
  try {
    const {
      task,
      taskDescription,
      domain,
      telemetry,
      errorContext,
      harness,
      tokenBudget,
      minScore,
      categoryFilter,
      tierFilter,
      includePrerequisites,
      includeTier0Governance
    } = req.body || {};

    const routeResult = universalSkillRouter.routeSkillSelection({
      taskDescription: taskDescription || task,
      domain,
      telemetry,
      errorContext,
      harness,
      tokenBudget,
      minScore,
      categoryFilter,
      tierFilter,
      includePrerequisites,
      includeTier0Governance
    });

    return res.json({
      success: true,
      route: routeResult
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

/**
 * POST /api/skills/recommend
 * Recommends skills based on live incident/anomaly telemetry.
 */
router.post('/recommend', (req, res) => {
  try {
    const { target, anomalyType, packetLossPct, rttMs, port } = req.body || {};
    const recommendation = universalSkillRouter.recommendSkillsForAnomaly({
      target: target || '127.0.0.1',
      anomalyType: anomalyType || 'GENERAL_NETWORK_ANOMALY',
      packetLossPct,
      rttMs,
      port
    });

    return res.json({
      success: true,
      recommendation
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

module.exports = router;
