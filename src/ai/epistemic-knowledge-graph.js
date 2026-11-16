/**
 * EJII Epistemic Knowledge Graph & Wire Distillation Engine
 * Phase 20.0 Autonomous Operating Fabric
 *
 * Dual-Maintenance CommonJS Implementation.
 */

'use strict';

const crypto = require('node:crypto');
const { db } = require('../db/database');

class EpistemicKnowledgeGraph {
  constructor() {
    this.inMemoryTriples = [];
    this.inMemoryEntities = new Map();
    this.ensureSchema();
    this.prepareStatements();
  }

  ensureSchema() {
    try {
      db.exec(`
        CREATE TABLE IF NOT EXISTS knowledge_entities (
          entity_id TEXT PRIMARY KEY,
          entity_type TEXT NOT NULL,
          canonical_name TEXT NOT NULL,
          metadata_json TEXT DEFAULT '{}',
          first_seen_ms INTEGER NOT NULL,
          last_seen_ms INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS knowledge_triples (
          triple_id TEXT PRIMARY KEY,
          subject_id TEXT NOT NULL,
          predicate TEXT NOT NULL,
          object_id TEXT NOT NULL,
          confidence REAL NOT NULL DEFAULT 1.0,
          evidence_hash TEXT NOT NULL,
          observed_at_ms INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_kt_subject ON knowledge_triples(subject_id);
        CREATE INDEX IF NOT EXISTS idx_kt_object ON knowledge_triples(object_id);
      `);
    } catch (_) {
      // In-memory fallback
    }
  }

  prepareStatements() {
    try {
      this.stmtInsertEntity = db.prepare(`
        INSERT INTO knowledge_entities (entity_id, entity_type, canonical_name, metadata_json, first_seen_ms, last_seen_ms)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(entity_id) DO UPDATE SET
          last_seen_ms = excluded.last_seen_ms,
          metadata_json = excluded.metadata_json;
      `);
      this.stmtInsertTriple = db.prepare(`
        INSERT INTO knowledge_triples (triple_id, subject_id, predicate, object_id, confidence, evidence_hash, observed_at_ms)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(triple_id) DO UPDATE SET
          confidence = excluded.confidence,
          observed_at_ms = excluded.observed_at_ms;
      `);
    } catch (_) {
      // Fallback
    }
  }

  addEntity(entity) {
    const now = Date.now();
    const ent = {
      entityId: entity.entityId,
      entityType: entity.entityType,
      canonicalName: entity.canonicalName || entity.entityId,
      metadataJson: entity.metadataJson || '{}',
      firstSeenMs: entity.firstSeenMs || now,
      lastSeenMs: entity.lastSeenMs || now
    };
    this.inMemoryEntities.set(ent.entityId, ent);

    if (this.stmtInsertEntity) {
      try {
        this.stmtInsertEntity.run(
          ent.entityId,
          ent.entityType,
          ent.canonicalName,
          ent.metadataJson,
          ent.firstSeenMs,
          ent.lastSeenMs
        );
      } catch (_) {}
    }
  }

  addTriple(triple) {
    this.inMemoryTriples.push(triple);
    if (this.stmtInsertTriple) {
      try {
        this.stmtInsertTriple.run(
          triple.tripleId,
          triple.subjectId,
          triple.predicate,
          triple.objectId,
          triple.confidence,
          triple.evidenceHash,
          triple.observedAtMs
        );
      } catch (_) {}
    }
  }

  distillWireFrame(frame) {
    const now = Date.now();
    const srcEntity = `ip:${frame.srcIp}`;
    const dstEntity = `ip:${frame.dstIp}`;
    const srcPortEntity = `port:${frame.srcIp}:${frame.srcPort}`;
    const dstPortEntity = `port:${frame.dstIp}:${frame.dstPort}`;

    this.addEntity({ entityId: srcEntity, entityType: 'IP', canonicalName: frame.srcIp });
    this.addEntity({ entityId: dstEntity, entityType: 'IP', canonicalName: frame.dstIp });
    this.addEntity({ entityId: srcPortEntity, entityType: 'PORT', canonicalName: `${frame.srcIp}:${frame.srcPort}` });
    this.addEntity({ entityId: dstPortEntity, entityType: 'PORT', canonicalName: `${frame.dstIp}:${frame.dstPort}` });

    const hash = crypto.createHash('sha256')
      .update(`${frame.srcIp}:${frame.srcPort}->${frame.dstIp}:${frame.dstPort}@${now}`)
      .digest('hex');

    this.addTriple({
      tripleId: `trip_comm_${hash.substring(0, 16)}`,
      subjectId: srcEntity,
      predicate: 'COMMUNICATES_WITH',
      objectId: dstEntity,
      confidence: 1.0,
      evidenceHash: hash,
      observedAtMs: now
    });

    this.addTriple({
      tripleId: `trip_bind_${dstPortEntity}`,
      subjectId: dstEntity,
      predicate: 'BINDS_PORT',
      objectId: dstPortEntity,
      confidence: 0.99,
      evidenceHash: hash,
      observedAtMs: now
    });

    if (frame.tcpFlags && (frame.tcpFlags & 0x04)) {
      this.addTriple({
        tripleId: `trip_rst_${hash.substring(0, 16)}`,
        subjectId: srcEntity,
        predicate: 'RESETS_CONNECTION',
        objectId: dstEntity,
        confidence: 0.98,
        evidenceHash: hash,
        observedAtMs: now
      });
    }
  }

  distillSocketBinding(binding) {
    const now = Date.now();
    const ipEntity = `ip:${binding.ip}`;
    const portEntity = `port:${binding.ip}:${binding.port}`;
    const procEntity = `process:${binding.pid}:${binding.processName}`;

    this.addEntity({ entityId: ipEntity, entityType: 'IP', canonicalName: binding.ip });
    this.addEntity({ entityId: portEntity, entityType: 'PORT', canonicalName: `${binding.ip}:${binding.port}` });
    this.addEntity({ entityId: procEntity, entityType: 'PROCESS', canonicalName: `${binding.processName} (PID ${binding.pid})` });

    const hash = crypto.createHash('sha256')
      .update(`${binding.processName}:${binding.pid}->${binding.ip}:${binding.port}`)
      .digest('hex');

    this.addTriple({
      tripleId: `trip_proc_bind_${portEntity}`,
      subjectId: procEntity,
      predicate: 'BINDS_PORT',
      objectId: portEntity,
      confidence: 1.0,
      evidenceHash: hash,
      observedAtMs: now
    });

    this.addTriple({
      tripleId: `trip_ip_proc_${portEntity}`,
      subjectId: ipEntity,
      predicate: 'OWNED_BY_PID',
      objectId: procEntity,
      confidence: 1.0,
      evidenceHash: hash,
      observedAtMs: now
    });
  }

  queryTriples(filter = {}) {
    let results = [];

    try {
      const conditions = [];
      const params = [];
      if (filter.subjectId) {
        conditions.push('subject_id = ?');
        params.push(filter.subjectId);
      }
      if (filter.predicate) {
        conditions.push('predicate = ?');
        params.push(filter.predicate);
      }
      if (filter.objectId) {
        conditions.push('object_id = ?');
        params.push(filter.objectId);
      }

      const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
      const stmt = db.prepare(`
        SELECT triple_id, subject_id, predicate, object_id, confidence, evidence_hash, observed_at_ms
        FROM knowledge_triples ${whereClause}
        ORDER BY observed_at_ms DESC LIMIT 100
      `);
      const rows = stmt.all(...params);
      results = rows.map((r) => ({
        tripleId: r.triple_id,
        subjectId: r.subject_id,
        predicate: r.predicate,
        objectId: r.object_id,
        confidence: Number(r.confidence),
        evidenceHash: r.evidence_hash,
        observedAtMs: Number(r.observed_at_ms)
      }));
    } catch (_) {
      results = this.inMemoryTriples.filter(t => {
        if (filter.subjectId && t.subjectId !== filter.subjectId) return false;
        if (filter.predicate && t.predicate !== filter.predicate) return false;
        if (filter.objectId && t.objectId !== filter.objectId) return false;
        return true;
      });
    }

    return results;
  }

  queryCausalPath(sourceId, targetId, maxHops = 4) {
    if (sourceId === targetId) {
      return { pathFound: true, sourceId, targetId, hops: [], entities: [sourceId] };
    }

    const queue = [
      { currentId: sourceId, hops: [], visited: new Set([sourceId]) }
    ];

    while (queue.length > 0) {
      const item = queue.shift();
      if (item.hops.length >= maxHops) continue;

      const outgoingTriples = this.queryTriples({ subjectId: item.currentId });
      for (const t of outgoingTriples) {
        const nextId = t.objectId;
        if (nextId === targetId) {
          const hops = [...item.hops, t];
          const entities = [sourceId, ...hops.map(h => h.objectId)];
          return {
            pathFound: true,
            sourceId,
            targetId,
            hops,
            entities
          };
        }
        if (!item.visited.has(nextId)) {
          const nextVisited = new Set(item.visited);
          nextVisited.add(nextId);
          queue.push({
            currentId: nextId,
            hops: [...item.hops, t],
            visited: nextVisited
          });
        }
      }
    }

    return {
      pathFound: false,
      sourceId,
      targetId,
      hops: [],
      entities: [sourceId]
    };
  }

  getGraphSummary() {
    let totalEntities = this.inMemoryEntities.size;
    let totalTriples = this.inMemoryTriples.length;
    try {
      const entRow = db.prepare('SELECT COUNT(*) as c FROM knowledge_entities').get();
      const tripRow = db.prepare('SELECT COUNT(*) as c FROM knowledge_triples').get();
      if (entRow && entRow.c) totalEntities = Number(entRow.c);
      if (tripRow && tripRow.c) totalTriples = Number(tripRow.c);
    } catch (_) {}

    return {
      totalEntities,
      totalTriples,
      totalHyperedges: 0
    };
  }
}

const epistemicKnowledgeGraph = new EpistemicKnowledgeGraph();

module.exports = {
  EpistemicKnowledgeGraph,
  epistemicKnowledgeGraph
};
