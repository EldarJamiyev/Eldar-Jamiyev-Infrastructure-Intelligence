/**
 * EJI ITSM & Helpdesk Service API Routes
 */

const express = require('express');
const router = express.Router();
const TicketRepository = require('../database/repositories/ticket-repository');
const SlaEngine = require('../helpdesk/sla/sla-engine');
const { authenticate } = require('./middleware');

// Apply authentication to all ITSM routes
router.use(authenticate);

// GET /api/itsm/tickets - List tickets
router.get('/tickets', (req, res) => {
  try {
    const { status, priority, limit, offset } = req.query;
    const tickets = TicketRepository.listTickets({
      status: status || null,
      priority: priority || null,
      limit: limit ? parseInt(limit, 10) : 50,
      offset: offset ? parseInt(offset, 10) : 0
    });
    res.json({ success: true, count: tickets.length, tickets });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/itsm/tickets - Create ticket
router.post('/tickets', (req, res) => {
  try {
    const { title, description, category, priority, requesterName, requesterEmail, assignedTeam, affectedCiId, slaPolicyId } = req.body;
    if (!title || !description || !requesterName) {
      return res.status(400).json({ success: false, error: 'Missing required fields: title, description, requesterName' });
    }

    const ticket = TicketRepository.createTicket({
      title,
      description,
      category: category || 'incident',
      priority: priority || 'P3_MEDIUM',
      requesterName,
      requesterEmail,
      assignedTeam: assignedTeam || 'helpdesk',
      affectedCiId,
      slaPolicyId
    });

    res.status(201).json({ success: true, ticket });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/itsm/tickets/:id - Get ticket by ID
router.get('/tickets/:id', (req, res) => {
  try {
    const ticket = TicketRepository.getTicketById(req.params.id);
    if (!ticket) return res.status(404).json({ success: false, error: 'Ticket not found' });
    res.json({ success: true, ticket });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// PATCH /api/itsm/tickets/:id - Update ticket
router.patch('/tickets/:id', (req, res) => {
  try {
    const updated = TicketRepository.updateTicket(req.params.id, req.body);
    if (!updated) return res.status(404).json({ success: false, error: 'Ticket not found' });
    res.json({ success: true, ticket: updated });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/itsm/tickets/:id/comments - Add comment
router.post('/tickets/:id/comments', (req, res) => {
  try {
    const { commentText, isInternal } = req.body;
    if (!commentText) return res.status(400).json({ success: false, error: 'commentText is required' });

    const comment = TicketRepository.addComment({
      ticketId: req.params.id,
      userId: req.user ? req.user.id : null,
      authorName: req.user ? (req.user.fullName || req.user.username) : 'Helpdesk Agent',
      commentText,
      isInternal: isInternal ? 1 : 0
    });

    res.status(201).json({ success: true, comment });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/itsm/slas - List SLA policies
router.get('/slas', (req, res) => {
  try {
    const slas = TicketRepository.listSlaPolicies();
    res.json({ success: true, count: slas.length, slas });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/itsm/sla-metrics - Evaluate breaches and return metrics
router.get('/sla-metrics', (req, res) => {
  try {
    const breachResult = SlaEngine.evaluateBreaches();
    const metrics = SlaEngine.getSlaMetrics();
    res.json({ success: true, metrics, recentBreaches: breachResult });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/itsm/change-requests - List change requests
router.get('/change-requests', (req, res) => {
  try {
    const { status, limit } = req.query;
    const changes = TicketRepository.listChangeRequests({
      status: status || null,
      limit: limit ? parseInt(limit, 10) : 50
    });
    res.json({ success: true, count: changes.length, changes });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// POST /api/itsm/change-requests - Create change request
router.post('/change-requests', (req, res) => {
  try {
    const { title, description, justification, riskLevel, impactScope, backoutPlan, scheduledStart, scheduledEnd } = req.body;
    if (!title || !description) {
      return res.status(400).json({ success: false, error: 'Missing title or description' });
    }

    const cr = TicketRepository.createChangeRequest({
      title,
      description,
      justification,
      riskLevel: riskLevel || 'medium',
      impactScope,
      backoutPlan,
      requestedBy: req.user ? req.user.username : 'operator',
      scheduledStart,
      scheduledEnd
    });

    res.status(201).json({ success: true, changeRequest: cr });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

// GET /api/itsm/known-errors - List known error articles
router.get('/known-errors', (req, res) => {
  try {
    const errors = TicketRepository.listKnownErrors();
    res.json({ success: true, count: errors.length, errors });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

module.exports = router;
