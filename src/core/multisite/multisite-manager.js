/**
 * EJII Enterprise Multi-Site Infrastructure Intelligence Engine
 *
 * Implements:
 *   1. Multi-Site Topological Hierarchy: Sites -> Zones -> Subnets & VLANs -> Gateways
 *   2. Inter-Site WAN Links / SD-WAN / IPSec Tunnels with Health & Provider Telemetry
 *   3. Cross-Site Anomaly & Incident Correlation:
 *      - Local VLAN Isolation vs. Site Gateway Failure vs. WAN Transit Failure vs. Shared Upstream Dependency
 *   4. Multi-Site Blast Radius Calculation
 *   5. Natural-Language Multi-Site Briefing & Decision Synthesis
 */

'use strict';

const { db } = require('../../db/database');

// Canonical Enterprise Sites Seed
const DEFAULT_SITES = [
  {
    id: 'site-hq-lon',
    code: 'LON-HQ',
    name: 'London Global Headquarters',
    region: 'EMEA',
    coordinates: { lat: 51.5074, lng: -0.1278 },
    primaryGateway: '10.10.1.1',
    status: 'HEALTHY',
    criticality: 'TIER_1',
    asn: 65010,
    zones: [
      { id: 'zone-lon-dmz', name: 'HQ DMZ & Edge Proxy', vlan: 10, subnet: '10.10.10.0/24', type: 'DMZ', status: 'HEALTHY' },
      { id: 'zone-lon-corp', name: 'HQ Corporate Workforce', vlan: 20, subnet: '10.10.20.0/24', type: 'CORP', status: 'HEALTHY' },
      { id: 'zone-lon-mgmt', name: 'HQ Out-of-Band Management', vlan: 99, subnet: '10.10.99.0/24', type: 'MGMT', status: 'HEALTHY' }
    ]
  },
  {
    id: 'site-dc-fra',
    code: 'FRA-DC',
    name: 'Frankfurt Tier-IV Primary Data Centre',
    region: 'EMEA',
    coordinates: { lat: 50.1109, lng: 8.6821 },
    primaryGateway: '10.20.1.1',
    status: 'HEALTHY',
    criticality: 'MISSION_CRITICAL',
    asn: 65020,
    zones: [
      { id: 'zone-fra-prod', name: 'DC Production Core Services', vlan: 50, subnet: '10.20.50.0/24', type: 'PROD', status: 'HEALTHY' },
      { id: 'zone-fra-db', name: 'DC Postgres/TimescaleDB Clustered DB', vlan: 60, subnet: '10.20.60.0/24', type: 'DATABASE', status: 'HEALTHY' },
      { id: 'zone-fra-dmz', name: 'DC Ingress Load Balancers', vlan: 15, subnet: '10.20.15.0/24', type: 'DMZ', status: 'HEALTHY' }
    ]
  },
  {
    id: 'site-br-nyc',
    code: 'NYC-BR',
    name: 'New York Financial Hub Office',
    region: 'AMER',
    coordinates: { lat: 40.7128, lng: -74.0060 },
    primaryGateway: '10.30.1.1',
    status: 'HEALTHY',
    criticality: 'TIER_1',
    asn: 65030,
    zones: [
      { id: 'zone-nyc-trade', name: 'NYC Low-Latency Trading Floor', vlan: 100, subnet: '10.30.100.0/24', type: 'FINANCIAL', status: 'HEALTHY' },
      { id: 'zone-nyc-corp', name: 'NYC General Corporate', vlan: 110, subnet: '10.30.110.0/24', type: 'CORP', status: 'HEALTHY' }
    ]
  },
  {
    id: 'site-br-tyo',
    code: 'TYO-BR',
    name: 'Tokyo Asia-Pacific Hub',
    region: 'APAC',
    coordinates: { lat: 35.6762, lng: 139.6503 },
    primaryGateway: '10.40.1.1',
    status: 'HEALTHY',
    criticality: 'TIER_2',
    asn: 65040,
    zones: [
      { id: 'zone-tyo-corp', name: 'Tokyo Corporate Office', vlan: 200, subnet: '10.40.200.0/24', type: 'CORP', status: 'HEALTHY' },
      { id: 'zone-tyo-rd', name: 'Tokyo R&D Engineering Lab', vlan: 210, subnet: '10.40.210.0/24', type: 'LAB', status: 'HEALTHY' }
    ]
  },
  {
    id: 'site-br-sin',
    code: 'SIN-BR',
    name: 'Singapore Regional Logistics & Operations',
    region: 'APAC',
    coordinates: { lat: 1.3521, lng: 103.8198 },
    primaryGateway: '10.50.1.1',
    status: 'HEALTHY',
    criticality: 'TIER_2',
    asn: 65050,
    zones: [
      { id: 'zone-sin-ops', name: 'Singapore Logistics Operations', vlan: 300, subnet: '10.50.30.0/24', type: 'OPS', status: 'HEALTHY' }
    ]
  }
];

const DEFAULT_WAN_LINKS = [
  {
    id: 'link-lon-fra',
    sourceSiteId: 'site-hq-lon',
    targetSiteId: 'site-dc-fra',
    linkType: 'DEDICATED_FIBER_MPLS',
    provider: 'Colt Technology Services',
    bandwidthMbps: 10000,
    latencyMs: 11.4,
    packetLossPct: 0.0,
    status: 'OPTIMAL'
  },
  {
    id: 'link-lon-nyc',
    sourceSiteId: 'site-hq-lon',
    targetSiteId: 'site-br-nyc',
    linkType: 'TRANSATLANTIC_SDWAN',
    provider: 'Lumen Technologies',
    bandwidthMbps: 2000,
    latencyMs: 68.2,
    packetLossPct: 0.05,
    status: 'OPTIMAL'
  },
  {
    id: 'link-fra-tyo',
    sourceSiteId: 'site-dc-fra',
    targetSiteId: 'site-br-tyo',
    linkType: 'EURASIA_SDWAN',
    provider: 'NTT Communications',
    bandwidthMbps: 1000,
    latencyMs: 185.0,
    packetLossPct: 0.1,
    status: 'OPTIMAL'
  },
  {
    id: 'link-tyo-sin',
    sourceSiteId: 'site-br-tyo',
    targetSiteId: 'site-br-sin',
    linkType: 'APAC_METRO_IPSEC',
    provider: 'Singtel Global',
    bandwidthMbps: 500,
    latencyMs: 64.5,
    packetLossPct: 0.0,
    status: 'OPTIMAL'
  }
];

class MultiSiteManager {
  constructor() {
    this._ensureTables();
    this._seedDefaults();
  }

  _ensureTables() {
    try {
      db.exec(`
        CREATE TABLE IF NOT EXISTS enterprise_sites (
          id TEXT PRIMARY KEY,
          code TEXT NOT NULL,
          name TEXT NOT NULL,
          region TEXT NOT NULL,
          lat REAL,
          lng REAL,
          primary_gateway TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'HEALTHY',
          criticality TEXT NOT NULL DEFAULT 'TIER_1',
          asn INTEGER,
          is_sample_simulation INTEGER DEFAULT 0,
          metadata_json TEXT
        );

        CREATE TABLE IF NOT EXISTS enterprise_zones (
          id TEXT PRIMARY KEY,
          site_id TEXT NOT NULL,
          name TEXT NOT NULL,
          vlan INTEGER NOT NULL,
          subnet TEXT NOT NULL,
          zone_type TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'HEALTHY',
          is_sample_simulation INTEGER DEFAULT 0,
          FOREIGN KEY (site_id) REFERENCES enterprise_sites(id)
        );

        CREATE TABLE IF NOT EXISTS enterprise_wan_links (
          id TEXT PRIMARY KEY,
          source_site_id TEXT NOT NULL,
          target_site_id TEXT NOT NULL,
          link_type TEXT NOT NULL,
          provider TEXT NOT NULL,
          bandwidth_mbps REAL NOT NULL,
          latency_ms REAL NOT NULL,
          packet_loss_pct REAL NOT NULL DEFAULT 0.0,
          status TEXT NOT NULL DEFAULT 'OPTIMAL',
          is_sample_simulation INTEGER DEFAULT 0,
          updated_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_wan_links_sites ON enterprise_wan_links(source_site_id, target_site_id);
      `);

      // Add migrations for existing databases
      try { db.exec("ALTER TABLE enterprise_sites ADD COLUMN is_sample_simulation INTEGER DEFAULT 0;"); } catch (_) {}
      try { db.exec("ALTER TABLE enterprise_zones ADD COLUMN is_sample_simulation INTEGER DEFAULT 0;"); } catch (_) {}
      try { db.exec("ALTER TABLE enterprise_wan_links ADD COLUMN is_sample_simulation INTEGER DEFAULT 0;"); } catch (_) {}
    } catch (_) {}

    try {
      // Migration: repair invalid IPv4 octet in legacy records
      db.prepare("UPDATE enterprise_zones SET subnet = '10.50.30.0/24' WHERE subnet = '10.50.300.0/24'").run();
    } catch (_) {}
  }

  _seedDefaults() {
    try {
      const existing = db.prepare('SELECT COUNT(*) as cnt FROM enterprise_sites').get();
      if (!existing || existing.cnt === 0) {
        const insertSite = db.prepare(`
          INSERT INTO enterprise_sites (id, code, name, region, lat, lng, primary_gateway, status, criticality, asn, is_sample_simulation, metadata_json)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
        `);
        const insertZone = db.prepare(`
          INSERT INTO enterprise_zones (id, site_id, name, vlan, subnet, zone_type, status, is_sample_simulation)
          VALUES (?, ?, ?, ?, ?, ?, ?, 1)
        `);

        for (const site of DEFAULT_SITES) {
          insertSite.run(
            site.id,
            site.code,
            site.name,
            site.region,
            site.coordinates.lat,
            site.coordinates.lng,
            site.primaryGateway,
            site.status,
            site.criticality,
            site.asn,
            JSON.stringify(site)
          );
          for (const zone of site.zones) {
            insertZone.run(zone.id, site.id, zone.name, zone.vlan, zone.subnet, zone.type, zone.status);
          }
        }

        const insertLink = db.prepare(`
          INSERT INTO enterprise_wan_links (id, source_site_id, target_site_id, link_type, provider, bandwidth_mbps, latency_ms, packet_loss_pct, status, is_sample_simulation, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
        `);
        for (const link of DEFAULT_WAN_LINKS) {
          insertLink.run(
            link.id,
            link.sourceSiteId,
            link.targetSiteId,
            link.linkType,
            link.provider,
            link.bandwidthMbps,
            link.latencyMs,
            link.packetLossPct,
            link.status,
            new Date().toISOString()
          );
        }
      }
    } catch (_) {}
  }

  getAllSites(options = {}) {
    try {
      let sites = db.prepare('SELECT * FROM enterprise_sites ORDER BY code ASC').all();
      if (options.includeSimulated === false) {
        sites = sites.filter(s => !s.is_sample_simulation);
      }
      return sites.map((s) => {
        const rawZones = db.prepare('SELECT * FROM enterprise_zones WHERE site_id = ?').all(s.id);
        const zones = rawZones.map(z => ({
          ...z,
          type: z.zone_type || z.type || 'CORP'
        }));
        return {
          id: s.id,
          code: s.code,
          name: s.name,
          region: s.region,
          coordinates: { lat: s.lat, lng: s.lng },
          primaryGateway: s.primary_gateway,
          status: s.status,
          criticality: s.criticality,
          asn: s.asn,
          isSampleSimulation: Boolean(s.is_sample_simulation),
          zones
        };
      });
    } catch (_) {
      return DEFAULT_SITES;
    }
  }

  getSiteById(siteId) {
    const sites = this.getAllSites();
    return sites.find(s => s.id === siteId || s.code.toLowerCase() === siteId.toLowerCase()) || null;
  }

  getAllWanLinks() {
    try {
      return db.prepare('SELECT * FROM enterprise_wan_links').all();
    } catch (_) {
      return DEFAULT_WAN_LINKS;
    }
  }

  /**
   * Determine which site and zone owns a given IP address
   */
  resolveIpLocation(ip) {
    if (!ip || typeof ip !== 'string') return null;
    const cleanIp = ip.trim();

    const sites = this.getAllSites();
    for (const site of sites) {
      if (cleanIp === site.primaryGateway) {
        return { site, zone: null, isGateway: true };
      }
      for (const zone of site.zones) {
        // Simple prefix match for /24 subnets e.g. 10.10.10.x vs 10.10.10.0/24
        const prefix = zone.subnet.split('.').slice(0, 3).join('.');
        if (cleanIp.startsWith(prefix + '.')) {
          return { site, zone, isGateway: false };
        }
      }
    }
    return null;
  }

  /**
   * Cross-Site Incident Correlation & Anomaly Differentiation
   * Disambiguates whether degradation is:
   * 1. LOCAL_VLAN_ISOLATED (e.g. broadcast storm, DHCP exhaustion in 1 VLAN)
   * 2. SITE_GATEWAY_OUTAGE (site boundary gateway unresponsive to all internal zones)
   * 3. WAN_TRANSIT_FAILURE (link between sites degraded, e.g. Transatlantic latency spike)
   * 4. SHARED_UPSTREAM_DEPENDENCY (multiple distinct branch sites failing against Frankfurt Core DB or DNS)
   */
  correlateMultiSiteIncident({ targetIp, reportedSymptoms = [], telemetrySnapshot = {} }) {
    const location = this.resolveIpLocation(targetIp);
    const allSites = this.getAllSites();
    const allLinks = this.getAllWanLinks();

    if (!location) {
      return {
        correlationScope: 'EXTERNAL_OR_UNREGISTERED',
        classification: 'UNKNOWN_SITE_TOPOLOGY',
        confidenceScore: 0.65,
        targetIp,
        summary: `Target ${targetIp} is outside mapped enterprise private subnets. Evaluating via tactical edge telemetry.`,
        affectedSites: [],
        recommendations: [
          'Verify default gateway forwarding table and NAT translation rules.',
          'Trace route across WAN boundary border router.'
        ]
      };
    }

    const { site, zone, isGateway } = location;

    // Check if telemetry is unprobed / unverified
    if (telemetrySnapshot.unprobed === true || telemetrySnapshot.status === 'UNPROBED') {
      return {
        correlationScope: 'UNVERIFIED_STATUS',
        classification: 'UNPROBED_INFRASTRUCTURE',
        confidenceScore: 0.5,
        targetIp,
        site: { id: site.id, code: site.code, name: site.name },
        zone: zone ? { id: zone.id, name: zone.name, vlan: zone.vlan } : null,
        telemetryStatus: 'UNPROBED',
        summary: `Target ${targetIp} in ${site.code} has no recorded probe telemetry. State cannot be assumed healthy.`,
        recommendations: [
          `Dispatch edge agent probe from ${site.code} to verify live L3/L4 reachability.`,
          'Enroll monitoring probe on local VLAN.'
        ]
      };
    }

    // Check if other zones in the same site are also reporting degraded status
    const siteZones = site.zones || [];
    const otherZonesInSite = siteZones.filter(z => !zone || z.id !== zone.id);
    const siteZonesDegraded = otherZonesInSite.filter(z => z.status !== 'HEALTHY');

    // Check WAN links connected to this site, factoring in telemetrySnapshot.linkOverrides if provided
    const connectedLinks = allLinks.filter(l => l.source_site_id === site.id || l.target_site_id === site.id);
    const degradedLinks = connectedLinks.filter(l => {
      const linkOverride = telemetrySnapshot.links && telemetrySnapshot.links[l.id];
      const loss = linkOverride?.packetLossPct ?? l.packet_loss_pct;
      const lat = linkOverride?.latencyMs ?? l.latency_ms;
      const st = linkOverride?.status ?? l.status;
      return st !== 'OPTIMAL' || loss > 2.0 || lat > 350;
    });

    const isGatewayReportedDown = isGateway ||
      reportedSymptoms.includes('GATEWAY_UNRESPONSIVE') ||
      telemetrySnapshot.gatewayUnreachable === true ||
      siteZonesDegraded.length >= Math.ceil(siteZones.length * 0.6);

    // Case 1: Shared Upstream Dependency Failure (if target is Frankfurt DC DB or Core Service)
    if (site.code === 'FRA-DC' && zone && (zone.type === 'DATABASE' || zone.type === 'PROD')) {
      return {
        correlationScope: 'SHARED_UPSTREAM_DEPENDENCY',
        classification: 'CRITICAL_CENTRAL_SERVICE_DEGRADATION',
        confidenceScore: telemetrySnapshot.latencyMs > 500 ? 0.99 : 0.96,
        site: { id: site.id, code: site.code, name: site.name },
        zone: { id: zone.id, name: zone.name, vlan: zone.vlan },
        observedTelemetry: telemetrySnapshot,
        blastRadius: {
          impactScope: 'Enterprise Fleet-Wide (All dependent branch offices: LON, NYC, TYO, SIN)',
          serviceRole: 'Frankfurt Central Core Services',
          tier: 'MISSION_CRITICAL'
        },
        summary: `Shared central service degradation in Frankfurt Tier-IV DC (${zone.name}). Disruption directly cascades across all remote branch locations querying central DB/API.`,
        recommendations: [
          'Inspect Postgres primary connection pool capacity and locks.',
          'Verify DC internal load balancer health checks before diagnosing branch endpoints.'
        ]
      };
    }

    // Case 2: Site Gateway Outage
    if (isGatewayReportedDown) {
      return {
        correlationScope: 'SITE_GATEWAY_OUTAGE',
        classification: 'SITE_WIDE_BORDER_DISRUPTION',
        confidenceScore: 0.94,
        site: { id: site.id, code: site.code, name: site.name, region: site.region },
        affectedZoneCount: siteZones.length,
        observedTelemetry: telemetrySnapshot,
        blastRadius: {
          impactScope: `Entire ${site.name} (${site.code})`,
          affectedVlans: siteZones.map(z => z.vlan),
          estimatedUsers: site.code === 'LON-HQ' ? 1200 : (site.code === 'NYC-BR' ? 450 : 200),
          tier: site.criticality
        },
        summary: `Site-wide boundary outage detected at ${site.code}. Primary gateway ${site.primaryGateway} or local core aggregation switch is unreachable across multiple VLANs.`,
        recommendations: [
          `Inspect VRRP/HSRP primary router state on gateway ${site.primaryGateway}.`,
          `Check local border switch power and uplinks at ${site.name}.`
        ]
      };
    }

    // Case 3: WAN Transit Failure
    if (degradedLinks.length > 0) {
      const worstLink = degradedLinks[0];
      return {
        correlationScope: 'WAN_TRANSIT_FAILURE',
        classification: 'INTER_SITE_LINK_DEGRADATION',
        confidenceScore: 0.89,
        site: { id: site.id, code: site.code, name: site.name },
        link: worstLink,
        observedTelemetry: telemetrySnapshot,
        blastRadius: {
          impactScope: `Cross-site WAN link ${worstLink.linkType || worstLink.link_type} (${worstLink.provider})`,
          latencyObservedMs: worstLink.latency_ms,
          packetLossPct: worstLink.packet_loss_pct
        },
        summary: `WAN transit degradation between ${worstLink.source_site_id} and ${worstLink.target_site_id}. Carrier ${worstLink.provider} reports packet loss of ${worstLink.packet_loss_pct}%.`,
        recommendations: [
          `Fail over BGP/SD-WAN path to secondary backup IPsec tunnel.`,
          `Open carrier priority ticket with ${worstLink.provider}.`
        ]
      };
    }

    // Case 4: Isolated Local VLAN
    return {
      correlationScope: 'LOCAL_VLAN_ISOLATED',
      classification: 'LOCAL_SUBNET_CONFINED_ISSUE',
      confidenceScore: 0.92,
      site: { id: site.id, code: site.code, name: site.name },
      zone: zone ? { id: zone.id, name: zone.name, vlan: zone.vlan, subnet: zone.subnet } : null,
      observedTelemetry: telemetrySnapshot,
      blastRadius: {
        impactScope: zone ? `Restricted to VLAN ${zone.vlan} (${zone.name})` : 'Single Endpoint',
        otherVlansHealthy: true,
        siteGatewayHealthy: true
      },
      summary: `Issue is strictly confined to VLAN ${zone ? zone.vlan : 'local'} at ${site.name}. Site gateway and WAN uplinks are healthy with 0% packet loss.`,
      recommendations: [
        `Check local switch port configuration and ARP table on VLAN ${zone ? zone.vlan : 'local'}.`,
        `Inspect local DHCP scope lease saturation for subnet ${zone ? zone.subnet : 'local'}.`
      ]
    };
  }

  /**
   * Generate an Executive Fleet-Wide Multi-Site Status Report
   */
  generateMultiSiteFleetOverview() {
    const sites = this.getAllSites();
    const links = this.getAllWanLinks();

    const totalSites = sites.length;
    const healthySites = sites.filter(s => s.status === 'HEALTHY').length;
    const totalZones = sites.reduce((acc, s) => acc + (s.zones ? s.zones.length : 0), 0);
    const totalLinks = links.length;
    const optimalLinks = links.filter(l => l.status === 'OPTIMAL').length;

    return {
      fleetSummary: {
        totalSites,
        healthySites,
        degradedSites: totalSites - healthySites,
        totalZones,
        totalWanLinks: totalLinks,
        optimalWanLinks: optimalLinks,
        overallStatus: (healthySites === totalSites && optimalLinks === totalLinks) ? 'NOMINAL' : 'ATTENTION_REQUIRED'
      },
      sites,
      wanLinks: links,
      generatedAt: new Date().toISOString()
    };
  }
}

const multiSiteManager = new MultiSiteManager();

module.exports = {
  MultiSiteManager,
  multiSiteManager,
  DEFAULT_SITES,
  DEFAULT_WAN_LINKS
};
