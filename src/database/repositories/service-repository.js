/**
 * EJI Business Service Catalog & Dependency Repository
 * Authoritative persistence for business services, SLAs/SLOs, and dependency graphs.
 */

const { db } = require('../database');
const crypto = require('crypto');

class ServiceRepository {
  /**
   * List all business services with health and SLOs
   */
  static listServices({ tier = null, healthStatus = null } = {}) {
    let query = 'SELECT * FROM service_catalog WHERE 1=1';
    const params = [];

    if (tier) {
      query += ' AND tier = ?';
      params.push(tier);
    }
    if (healthStatus) {
      query += ' AND health_status = ?';
      params.push(healthStatus);
    }
    query += " ORDER BY CASE tier WHEN 'tier_1_mission_critical' THEN 1 WHEN 'tier_2_business_critical' THEN 2 ELSE 3 END, name ASC";

    return db.prepare(query).all(...params);
  }

  /**
   * Get service by ID with upstream and downstream dependencies
   */
  static getServiceById(id) {
    const service = db.prepare('SELECT * FROM service_catalog WHERE id = ?').get(id);
    if (!service) return null;

    // Upstream dependencies (what THIS service depends on)
    const upstream = db.prepare(`
      SELECT d.*, s.name as upstream_service_name, s.health_status as upstream_health
      FROM service_dependencies d
      JOIN service_catalog s ON d.depends_on_service_id = s.id
      WHERE d.service_id = ?
    `).all(id);

    // Downstream dependents (services that depend on THIS service)
    const downstream = db.prepare(`
      SELECT d.*, s.name as downstream_service_name, s.health_status as downstream_health
      FROM service_dependencies d
      JOIN service_catalog s ON d.service_id = s.id
      WHERE d.depends_on_service_id = ?
    `).all(id);

    return {
      ...service,
      upstreamDependencies: upstream,
      downstreamDependents: downstream
    };
  }

  /**
   * Create a new business service
   */
  static createService({
    name,
    businessServiceName,
    tier = 'tier_2_business_critical',
    ownerTeam,
    technicalLead,
    targetAvailabilitySlo = 99.9,
    primaryCiId = null
  }) {
    const id = 'SVC-' + crypto.randomBytes(4).toString('hex').toUpperCase();
    const now = new Date().toISOString();

    db.prepare(`
      INSERT INTO service_catalog (
        id, name, business_service_name, tier, owner_team, technical_lead,
        health_status, target_availability_slo, current_availability_30d,
        primary_ci_id, created_at, updated_at
      ) VALUES (?, ?, ?, ?, ?, ?, 'healthy', ?, 100.0, ?, ?, ?)
    `).run(
      id,
      name,
      businessServiceName,
      tier,
      ownerTeam,
      technicalLead,
      Number(targetAvailabilitySlo),
      primaryCiId,
      now,
      now
    );

    return this.getServiceById(id);
  }

  /**
   * Update service status and availability
   */
  static updateServiceStatus(id, healthStatus, currentAvailability = null) {
    const existing = this.getServiceById(id);
    if (!existing) throw new Error(`Service ${id} not found`);

    const now = new Date().toISOString();
    const avail = currentAvailability !== null ? Number(currentAvailability) : existing.current_availability_30d;

    db.prepare(`
      UPDATE service_catalog
      SET health_status = ?, current_availability_30d = ?, updated_at = ?
      WHERE id = ?
    `).run(healthStatus, avail, now, id);

    return this.getServiceById(id);
  }

  /**
   * Add a dependency link between services
   */
  static addDependency({ serviceId, dependsOnServiceId, dependencyType = 'hard', impactIfFailed }) {
    const id = 'DEP-' + crypto.randomBytes(4).toString('hex').toUpperCase();

    db.prepare(`
      INSERT INTO service_dependencies (id, service_id, depends_on_service_id, dependency_type, impact_if_failed)
      VALUES (?, ?, ?, ?, ?)
    `).run(id, serviceId, dependsOnServiceId, dependencyType, impactIfFailed);

    return { id, serviceId, dependsOnServiceId, dependencyType, impactIfFailed };
  }

  /**
   * Get full enterprise service map graph
   */
  static getServiceMap() {
    const services = this.listServices();
    const dependencies = db.prepare('SELECT * FROM service_dependencies').all();

    return {
      nodes: services.map(s => ({
        id: s.id,
        label: s.name,
        businessName: s.business_service_name,
        tier: s.tier,
        status: s.health_status,
        slo: s.target_availability_slo,
        availability: s.current_availability_30d
      })),
      edges: dependencies.map(d => ({
        id: d.id,
        source: d.service_id,
        target: d.depends_on_service_id,
        type: d.dependency_type,
        impact: d.impact_if_failed
      }))
    };
  }
}

module.exports = ServiceRepository;
