/**
 * EJI Helpdesk SLA Engine
 * Evaluates ticket response & resolution deadlines, triggers breach flags, and tracks compliance metrics.
 */

const TicketRepository = require('../../database/repositories/ticket-repository');
const { db } = require('../../database/database');
const { logAudit } = require('../../core/audit-logger');

class SlaEngine {
  /**
   * Run breach evaluation across all active tickets
   */
  static evaluateBreaches() {
    const now = new Date().toISOString();

    // Find tickets that are about to breach or just breached
    const breachedTickets = db.prepare(`
      SELECT id, ticket_number, title, priority, sla_target_resolve_at
      FROM helpdesk_tickets
      WHERE status NOT IN ('resolved', 'closed')
        AND sla_target_resolve_at IS NOT NULL
        AND sla_target_resolve_at < ?
        AND sla_breached = 0
    `).all(now);

    if (breachedTickets.length === 0) {
      return { breachedCount: 0, tickets: [] };
    }

    for (const ticket of breachedTickets) {
      // Mark breached
      db.prepare('UPDATE helpdesk_tickets SET sla_breached = 1 WHERE id = ?').run(ticket.id);

      // Add system escalation comment
      TicketRepository.addComment({
        ticketId: ticket.id,
        authorName: 'SLA Escalation Engine',
        commentText: `SLA BREACH ALERT: Target resolution deadline of ${ticket.sla_target_resolve_at} was exceeded. Priority ${ticket.priority} escalated to on-call manager.`,
        isInternal: 1
      });

      logAudit({
        username: 'sla_engine',
        role: 'system',
        action: 'TICKET_SLA_BREACHED',
        resource: ticket.id,
        details: { ticketNumber: ticket.ticket_number, priority: ticket.priority }
      });
    }

    return {
      breachedCount: breachedTickets.length,
      tickets: breachedTickets
    };
  }

  /**
   * Get overall SLA performance statistics
   */
  static getSlaMetrics() {
    const stats = db.prepare(`
      SELECT
        COUNT(*) as total_tickets,
        SUM(CASE WHEN sla_breached = 1 THEN 1 ELSE 0 END) as breached_tickets,
        SUM(CASE WHEN status IN ('resolved', 'closed') AND sla_breached = 0 THEN 1 ELSE 0 END) as met_sla_tickets,
        SUM(CASE WHEN status NOT IN ('resolved', 'closed') THEN 1 ELSE 0 END) as open_tickets
      FROM helpdesk_tickets
    `).get();

    const total = stats.total_tickets || 0;
    const breached = stats.breached_tickets || 0;
    const complianceRate = total > 0 ? Number((((total - breached) / total) * 100).toFixed(1)) : 100.0;

    return {
      totalTickets: total,
      breachedTickets: breached,
      metSlaTickets: stats.met_sla_tickets || 0,
      openTickets: stats.open_tickets || 0,
      complianceRatePercent: complianceRate
    };
  }
}

module.exports = SlaEngine;
