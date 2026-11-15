/**
 * EJII Tree-of-Thought (ToT) Conversational Working Memory & Socratic Disambiguator
 *
 * Implements a branchable, evaluate-and-prune reasoning graph persisted in SQLite WAL
 * for long-horizon incident diagnosis and interactive Socratic disambiguation.
 * CommonJS Dual-Parity Implementation.
 */

'use strict';

const path = require('path');

class TotWorkingMemory {
  constructor(customDbPath) {
    this.db = null;
    this.dbPath = customDbPath || path.resolve(process.cwd(), 'database.sqlite');
    this.initialized = false;
  }

  ensureDatabaseTable() {
    if (this.initialized && this.db) return;

    try {
      const sqlite = require('node:sqlite');
      if (sqlite && typeof sqlite.DatabaseSync === 'function') {
        this.db = new sqlite.DatabaseSync(this.dbPath);
        this.db.exec(`
          PRAGMA journal_mode = WAL;
          PRAGMA synchronous = NORMAL;
          CREATE TABLE IF NOT EXISTS ejii_chat_tot_nodes (
            node_id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL,
            parent_id TEXT,
            thought_type TEXT NOT NULL,
            content TEXT NOT NULL,
            eval_score REAL NOT NULL,
            contradiction_detected INTEGER NOT NULL DEFAULT 0,
            is_active_branch INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
          );
          CREATE INDEX IF NOT EXISTS idx_ejii_chat_tot_session ON ejii_chat_tot_nodes(session_id, is_active_branch);
        `);
        this.initialized = true;
      }
    } catch (err) {
      this.initialized = true;
    }
  }

  addThoughtNode(sessionId, parentId, thoughtType, content, evalScore = 0.5) {
    this.ensureDatabaseTable();
    const nodeId = `tot_${Date.now()}_${Math.floor(Math.random() * 100000)}`;
    const createdAt = new Date().toISOString();
    const clampedScore = Math.max(0.0, Math.min(1.0, evalScore));

    const node = {
      nodeId,
      sessionId,
      parentId,
      thoughtType,
      content,
      evalScore: clampedScore,
      contradictionDetected: false,
      isActiveBranch: true,
      createdAt
    };

    if (this.db) {
      try {
        const stmt = this.db.prepare(`
          INSERT INTO ejii_chat_tot_nodes (
            node_id, session_id, parent_id, thought_type, content, eval_score, contradiction_detected, is_active_branch, created_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);
        stmt.run(
          nodeId,
          sessionId,
          parentId,
          thoughtType,
          content,
          clampedScore,
          0,
          1,
          createdAt
        );
      } catch (e) {}
    }

    return node;
  }

  getActiveBranches(sessionId) {
    this.ensureDatabaseTable();
    if (!this.db) return [];

    try {
      const stmt = this.db.prepare(`
        SELECT node_id, session_id, parent_id, thought_type, content, eval_score, contradiction_detected, is_active_branch, created_at
        FROM ejii_chat_tot_nodes
        WHERE session_id = ? AND is_active_branch = 1
        ORDER BY eval_score DESC
      `);
      const rows = stmt.all(sessionId);
      return rows.map((r) => ({
        nodeId: r.node_id,
        sessionId: r.session_id,
        parentId: r.parent_id,
        thoughtType: r.thought_type,
        content: r.content,
        evalScore: r.eval_score,
        contradictionDetected: Boolean(r.contradiction_detected),
        isActiveBranch: Boolean(r.is_active_branch),
        createdAt: r.created_at
      }));
    } catch (e) {
      return [];
    }
  }

  evaluateBranch(nodeId, newScore, contradictionDetected = false) {
    this.ensureDatabaseTable();
    if (!this.db) return;

    try {
      const clampedScore = Math.max(0.0, Math.min(1.0, newScore));
      const stmt = this.db.prepare(`
        UPDATE ejii_chat_tot_nodes
        SET eval_score = ?, contradiction_detected = ?
        WHERE node_id = ?
      `);
      stmt.run(clampedScore, contradictionDetected ? 1 : 0, nodeId);
    } catch (e) {}
  }

  pruneLowScoringBranches(sessionId, threshold = 0.25) {
    this.ensureDatabaseTable();
    if (!this.db) return 0;

    try {
      const stmt = this.db.prepare(`
        UPDATE ejii_chat_tot_nodes
        SET is_active_branch = 0
        WHERE session_id = ? AND is_active_branch = 1 AND (eval_score < ? OR contradiction_detected = 1)
      `);
      const res = stmt.run(sessionId, threshold);
      return res?.changes || 0;
    } catch (e) {
      return 0;
    }
  }

  getBestThoughtPath(sessionId) {
    const active = this.getActiveBranches(sessionId);
    if (active.length === 0) return [];

    const bestNode = active[0];
    const pathList = [bestNode];

    let currentParentId = bestNode.parentId;
    while (currentParentId) {
      try {
        const stmt = this.db.prepare(`
          SELECT node_id, session_id, parent_id, thought_type, content, eval_score, contradiction_detected, is_active_branch, created_at
          FROM ejii_chat_tot_nodes
          WHERE node_id = ?
        `);
        const r = stmt.get(currentParentId);
        if (!r) break;
        const parentNode = {
          nodeId: r.node_id,
          sessionId: r.session_id,
          parentId: r.parent_id,
          thoughtType: r.thought_type,
          content: r.content,
          evalScore: r.eval_score,
          contradictionDetected: Boolean(r.contradiction_detected),
          isActiveBranch: Boolean(r.is_active_branch),
          createdAt: r.created_at
        };
        pathList.unshift(parentNode);
        currentParentId = parentNode.parentId;
      } catch (e) {
        break;
      }
    }

    return pathList;
  }

  generateSocraticClarification(intent, targetParam, riskLevel = 'HIGH') {
    const clarificationId = `socratic_${Date.now()}`;

    if (!targetParam || targetParam === 'undefined') {
      return {
        clarificationId,
        intent,
        ambiguityType: 'TARGET_UNSPECIFIED',
        promptQuestion: 'Target infrastructure node is unspecified. Which domain scope would you like to target?',
        options: [
          {
            optionId: 'opt_core_gw',
            label: 'Edge Gateway Fleet (border-gw-01)',
            description: 'Apply diagnostics/remediation to perimeter peering routers.',
            blastRadiusPct: 15.0,
            expectedLatencyImpactMs: 2.5,
            isRecommended: true
          },
          {
            optionId: 'opt_agg_switch',
            label: 'Aggregation Switch Layer (agg-sw-01)',
            description: 'Target internal spine-leaf interconnects.',
            blastRadiusPct: 35.0,
            expectedLatencyImpactMs: 0.8,
            isRecommended: false
          },
          {
            optionId: 'opt_sim_sandbox',
            label: 'Isolated Digital Twin Sandbox',
            description: 'Simulate effects first before executing in production.',
            blastRadiusPct: 0.0,
            expectedLatencyImpactMs: 0.0,
            isRecommended: false
          }
        ]
      };
    }

    return {
      clarificationId,
      intent,
      ambiguityType: riskLevel === 'HIGH' ? 'HIGH_BLAST_RADIUS' : 'CONFLICTING_EVIDENCE',
      promptQuestion: `Operation on target [${targetParam}] has a high estimated blast radius. Select authorization level:`,
      options: [
        {
          optionId: 'opt_bounded_clamp',
          label: 'Bounded Graceful Remediation (Conservative)',
          description: 'Clamp TCP window to 32KB and rate-limit non-essential ICMP.',
          blastRadiusPct: 5.0,
          expectedLatencyImpactMs: 1.2,
          isRecommended: true
        },
        {
          optionId: 'opt_full_divert',
          label: 'Full BGP Traffic Shedding (Aggressive)',
          description: 'Withdraw BGP routes to drain all transit traffic from target.',
          blastRadiusPct: 50.0,
          expectedLatencyImpactMs: 14.5,
          isRecommended: false
        }
      ]
    };
  }
}

const totWorkingMemory = new TotWorkingMemory();

module.exports = {
  TotWorkingMemory,
  totWorkingMemory
};
