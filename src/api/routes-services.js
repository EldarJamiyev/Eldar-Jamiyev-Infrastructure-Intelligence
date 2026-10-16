/**
 * EJI Business Service Catalog API Routes
 */

const express = require('express');
const router = express.Router();
const ServiceRepository = require('../database/repositories/service-repository');
const { authenticate } = require('./middleware');

router.use(authenticate);

// GET /api/services - List business services
router.get('/', (req, res) => {
  try {
    const { tier, healthStatus } = req.query;
    const services = ServiceRepository.listServices({ tier, healthStatus });
    res.json({ success: true, count: services.length, services });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/services/map/graph - Full dependency topology graph
router.get('/map/graph', (req, res) => {
  try {
    const graph = ServiceRepository.getServiceMap();
    res.json({ success: true, graph });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/services/:id - Get service details
router.get('/:id', (req, res) => {
  try {
    const service = ServiceRepository.getServiceById(req.params.id);
    if (!service) return res.status(404).json({ success: false, error: 'Service not found' });
    res.json({ success: true, service });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/services - Create business service
router.post('/', (req, res) => {
  try {
    const { name, businessServiceName, tier, ownerTeam, technicalLead, targetAvailabilitySlo, primaryCiId } = req.body;
    if (!name || !businessServiceName || !ownerTeam) {
      return res.status(400).json({ success: false, error: 'Missing name, businessServiceName, or ownerTeam' });
    }

    const service = ServiceRepository.createService({
      name,
      businessServiceName,
      tier,
      ownerTeam,
      technicalLead: technicalLead || (req.user ? req.user.username : 'admin'),
      targetAvailabilitySlo: targetAvailabilitySlo ? parseFloat(targetAvailabilitySlo) : 99.9,
      primaryCiId
    });

    res.status(201).json({ success: true, service });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// PATCH /api/services/:id - Update health status
router.patch('/:id', (req, res) => {
  try {
    const { healthStatus, currentAvailability } = req.body;
    if (!healthStatus) return res.status(400).json({ success: false, error: 'healthStatus is required' });

    const updated = ServiceRepository.updateServiceStatus(req.params.id, healthStatus, currentAvailability);
    res.json({ success: true, service: updated });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;
