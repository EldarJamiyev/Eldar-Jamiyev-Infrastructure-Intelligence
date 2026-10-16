/**
 * EJI ITSM Ticket Repository
 * Handles authoritative persistence for helpdesk tickets, SLA tracking, and audit comments.
 */

const { db } = require('../database');
const crypto = require('crypto');

class TicketRepository {
  static getNextTicketNumber() {
    const row = db.prepare('SELECT COALESCE(MAX(ticket_number), 1000) + 1 AS next_num FROM helpdesk_tickets').get();
    return row.next_num;
  }

  static createTicket({
    title,
    description,
    category = 'incident',
    priority = 'P3_MEDIUM',
    requesterName,
    requesterEmail = null,
    assignedToUserId = null,
    assignedTeam = 'helpdesk',
    affectedCiId = null,
    slaPolicyId = null
  }) {
    const id = 'TCK-' + crypto.randomBytes(4).toString('hex').toUpperCase();
    const ticketNumber = this.getNextTicketNumber();
    const now = new Date().toISOString();

    // Calculate SLA targets if policy provided or determine by priority
    let targetPolicyId = slaPolicyId;
    if (!targetPolicyId) {
      const policy = db.prepare('SELECT id, response_time_min, resolve_time_min FROM sla_policies WHERE priority = ?').get(priority);
      if (policy) targetPolicyId = policy.id;
    }

    let targetResponseAt = null;
    let targetResolveAt = null;

    if (targetPolicyId) {
      const policy = db.prepare('SELECT response_time_min, resolve_time_min FROM sla_policies WHERE id = ?').get(targetPolicyId);
      if (policy) {
        targetResponseAt = new Date(Date.now() + policy.response_time_min * 60000).toISOString();
        targetResolveAt = new Date(Date.now() + policy.resolve_time_min * 60000).toISOString();
      }
    }

    const teamMap = { network_admin: 'netops', sysadmin: 'sysops', app_owner: 'apps', security: 'secops' };
    const safeTeam = teamMap[assignedTeam] || (['helpdesk', 'netops', 'sysops', 'secops', 'apps'].includes(assignedTeam) ? assignedTeam : 'helpdesk');

    db.prepare(`
      INSERT INTO helpdesk_tickets (
        id, ticket_number, title, description, category, priority, status,
        requester_name, requester_email, assigned_to_user_id, assigned_team,
        affected_ci_id, sla_policy_id, sla_target_response_at, sla_target_resolve_at,
        sla_breached, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, 'new', ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
    `).run(
      id,
      ticketNumber,
      title.trim(),
      description.trim(),
      category,
      priority,
      requesterName.trim(),
      requesterEmail,
      assignedToUserId,
      safeTeam,
      affectedCiId,
      targetPolicyId,
      targetResponseAt,
      targetResolveAt,
      now,
      now
    );

    return this.getTicketById(id);
  }

  static getTicketById(id) {
    const ticket = db.prepare(`
      SELECT t.*, n.name as ci_name, n.hostname_or_ip as ci_ip, u.full_name as assigned_to_name
      FROM helpdesk_tickets t
      LEFT JOIN nodes n ON t.affected_ci_id = n.id
      LEFT JOIN users u ON t.assigned_to_user_id = u.id
      WHERE t.id = ?
    `).get(id);

    if (!ticket) return null;
    ticket.comments = this.getComments(id);
    return ticket;
  }

  static listTickets({ status, priority, category, assignedTeam, limit = 50, offset = 0 } = {}) {
    let sql = `
      SELECT t.*, n.name as ci_name, u.full_name as assigned_to_name
      FROM helpdesk_tickets t
      LEFT JOIN nodes n ON t.affected_ci_id = n.id
      LEFT JOIN users u ON t.assigned_to_user_id = u.id
      WHERE 1=1
    `;
    const params = [];

    if (status) {
      sql += ' AND t.status = ?';
      params.push(status);
    }
    if (priority) {
      sql += ' AND t.priority = ?';
      params.push(priority);
    }
    if (category) {
      sql += ' AND t.category = ?';
      params.push(category);
    }
    if (assignedTeam) {
      sql += ' AND t.assigned_team = ?';
      params.push(assignedTeam);
    }

    sql += ' ORDER BY t.created_at DESC LIMIT ? OFFSET ?';
    params.push(limit, offset);

    return db.prepare(sql).all(...params);
  }

  static updateTicket(id, { status, assignedToUserId, assignedTeam, priority, resolutionNotes }) {
    const ticket = this.getTicketById(id);
    if (!ticket) return null;

    const now = new Date().toISOString();
    let resolvedAt = ticket.resolved_at;
    if (status === 'resolved' || status === 'closed') {
      resolvedAt = resolvedAt || now;
    }

    db.prepare(`
      UPDATE helpdesk_tickets
      SET status = COALESCE(?, status),
          assigned_to_user_id = COALESCE(?, assigned_to_user_id),
          assigned_team = COALESCE(?, assigned_team),
          priority = COALESCE(?, priority),
          resolution_notes = COALESCE(?, resolution_notes),
          resolved_at = ?,
          updated_at = ?
      WHERE id = ?
    `).run(
      status || null,
      assignedToUserId || null,
      assignedTeam || null,
      priority || null,
      resolutionNotes || null,
      resolvedAt,
      now,
      id
    );

    return this.getTicketById(id);
  }

  static addComment({ ticketId, userId = null, authorName, commentText, isInternal = 0 }) {
    const id = 'CMT-' + crypto.randomBytes(4).toString('hex').toUpperCase();
    const now = new Date().toISOString();

    db.prepare(`
      INSERT INTO ticket_comments (id, ticket_id, user_id, author_name, is_internal, comment_text, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(id, ticketId, userId, authorName, isInternal ? 1 : 0, commentText.trim(), now);

    db.prepare('UPDATE helpdesk_tickets SET updated_at = ? WHERE id = ?').run(now, ticketId);
    return { id, ticketId, authorName, commentText, isInternal, createdAt: now };
  }

  static getComments(ticketId) {
    return db.prepare('SELECT * FROM ticket_comments WHERE ticket_id = ? ORDER BY created_at ASC').all(ticketId);
  }

  static listSlaPolicies() {
    return db.prepare('SELECT * FROM sla_policies ORDER BY response_time_min ASC').all();
  }

  static createSlaPolicy({ id, name, priority, responseTimeMin, resolveTimeMin, businessHoursOnly = 0, escalationEmail = null }) {
    const now = new Date().toISOString();
    db.prepare(`
      INSERT INTO sla_policies (id, name, priority, response_time_min, resolve_time_min, business_hours_only, escalation_email, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, name, priority, Number(responseTimeMin), Number(resolveTimeMin), businessHoursOnly ? 1 : 0, escalationEmail, now);
    return db.prepare('SELECT * FROM sla_policies WHERE id = ?').get(id);
  }

  static listChangeRequests({ status = null, limit = 50 } = {}) {
    let query = 'SELECT * FROM change_requests WHERE 1=1';
    const params = [];
    if (status) {
      query += ' AND status = ?';
      params.push(status);
    }
    query += ' ORDER BY created_at DESC LIMIT ?';
    params.push(limit);
    return db.prepare(query).all(...params);
  }

  static createChangeRequest({
    title, description, justification = null, riskLevel = 'medium',
    impactScope = null, backoutPlan = null, requestedBy, scheduledStart = null, scheduledEnd = null
  }) {
    const id = 'CR-' + crypto.randomBytes(4).toString('hex').toUpperCase();
    const now = new Date().toISOString();
    db.prepare(`
      INSERT INTO change_requests (
        id, title, description, justification, risk_level, impact_scope, backout_plan,
        status, requested_by, scheduled_start, scheduled_end, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 'draft', ?, ?, ?, ?)
    `).run(id, title.trim(), description.trim(), justification, riskLevel, impactScope, backoutPlan, requestedBy, scheduledStart, scheduledEnd, now);
    return db.prepare('SELECT * FROM change_requests WHERE id = ?').get(id);
  }

  static listKnownErrors({ category = null, limit = 50 } = {}) {
    let query = 'SELECT * FROM known_errors WHERE 1=1';
    const params = [];
    if (category) {
      query += ' AND category = ?';
      params.push(category);
    }
    query += ' ORDER BY created_at DESC LIMIT ?';
    params.push(limit);
    return db.prepare(query).all(...params);
  }

  static createKnownError({ title, symptomDescription, rootCause, workaround, permanentFix = null, category = 'network' }) {
    const id = 'KE-' + crypto.randomBytes(4).toString('hex').toUpperCase();
    const now = new Date().toISOString();
    db.prepare(`
      INSERT INTO known_errors (
        id, title, symptom_description, root_cause, workaround, permanent_fix, category, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, title.trim(), symptomDescription.trim(), rootCause.trim(), workaround.trim(), permanentFix, category, now);
    return db.prepare('SELECT * FROM known_errors WHERE id = ?').get(id);
  }

  static evaluateSlaBreaches() {
    const now = new Date().toISOString();
    const breached = db.prepare(`
      UPDATE helpdesk_tickets
      SET sla_breached = 1
      WHERE status NOT IN ('resolved', 'closed')
        AND sla_target_resolve_at IS NOT NULL
        AND sla_target_resolve_at < ?
        AND sla_breached = 0
    `).run(now);
    return breached.changes;
  }
}

module.exports = TicketRepository;
module.exports.TicketRepository = TicketRepository;
