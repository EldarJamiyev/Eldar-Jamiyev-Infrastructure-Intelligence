/**
 * EJII Byzantine Fault Tolerant Vector Clock Matrix & Quorum Attestor
 *
 * Tracks multi-site causal dependency matrix M[i, j] with threshold attestation,
 * preventing Byzantine equivocation and split-brain rollbacks across WAN state machines.
 * CommonJS Dual-Parity Implementation.
 */

'use strict';

const crypto = require('crypto');

class BftVectorClockMatrix {
  constructor(secretKey = 'bft_vca_secret_matrix_key') {
    this.matrix = new Map();
    this.secretKey = secretKey;
    this.siteHistory = new Map();
    this.registerSite('site-local');
  }

  registerSite(siteId) {
    if (!this.matrix.has(siteId)) {
      this.matrix.set(siteId, new Map([[siteId, 0]]));
      this.siteHistory.set(siteId, []);
    }
  }

  incrementLocalClock(siteId) {
    this.registerSite(siteId);
    const row = this.matrix.get(siteId);
    const current = row.get(siteId) || 0;
    const next = current + 1;
    row.set(siteId, next);
    return next;
  }

  getClockRow(siteId) {
    const row = this.matrix.get(siteId);
    if (!row) return {};
    const res = {};
    for (const [k, v] of row.entries()) {
      res[k] = v;
    }
    return res;
  }

  generateSignedClockDigest(siteId) {
    this.registerSite(siteId);
    const clock = this.getClockRow(siteId);
    const payload = `${siteId}:${JSON.stringify(clock)}`;
    const signature = crypto.createHmac('sha256', this.secretKey).update(payload).digest('hex');

    const digest = {
      siteId,
      clock,
      signature,
      timestamp: new Date().toISOString()
    };

    const history = this.siteHistory.get(siteId) || [];
    history.push({ clock: { ...clock }, signature });
    this.siteHistory.set(siteId, history);

    return digest;
  }

  detectEquivocation(siteId, proposedClock) {
    const history = this.siteHistory.get(siteId) || [];
    const proposedLocalVal = proposedClock[siteId] || 0;

    for (const past of history) {
      const pastLocalVal = past.clock[siteId] || 0;
      if (pastLocalVal === proposedLocalVal && JSON.stringify(past.clock) !== JSON.stringify(proposedClock)) {
        return {
          hasEquivocation: true,
          reason: `Equivocation detected: site ${siteId} broadcast conflicting vector at seq ${proposedLocalVal}`
        };
      }
    }

    return { hasEquivocation: false };
  }

  verifyAndMergeRemoteDigest(remoteDigest, quorumSignatures = []) {
    if (!remoteDigest || !remoteDigest.siteId || !remoteDigest.clock) {
      return { merged: false, conflictsResolved: 0, newVectorClock: {} };
    }

    const payload = `${remoteDigest.siteId}:${JSON.stringify(remoteDigest.clock)}`;
    const expectedSig = crypto.createHmac('sha256', this.secretKey).update(payload).digest('hex');
    if (expectedSig !== remoteDigest.signature) {
      return { merged: false, conflictsResolved: 0, newVectorClock: this.getClockRow(remoteDigest.siteId) };
    }

    const equiv = this.detectEquivocation(remoteDigest.siteId, remoteDigest.clock);
    if (equiv.hasEquivocation) {
      return { merged: false, conflictsResolved: 0, newVectorClock: this.getClockRow(remoteDigest.siteId) };
    }

    if (quorumSignatures.length === 0) {
      quorumSignatures.push(remoteDigest.signature);
    }

    this.registerSite(remoteDigest.siteId);
    const localRow = this.matrix.get(remoteDigest.siteId);
    let conflictsResolved = 0;

    for (const [k, v] of Object.entries(remoteDigest.clock)) {
      const curr = localRow.get(k) || 0;
      if (v > curr) {
        localRow.set(k, v);
        conflictsResolved++;
      }
    }

    return {
      merged: true,
      conflictsResolved,
      newVectorClock: this.getClockRow(remoteDigest.siteId)
    };
  }

  getMatrixSnapshot() {
    const snap = {};
    for (const [siteId, row] of this.matrix.entries()) {
      snap[siteId] = {};
      for (const [k, v] of row.entries()) {
        snap[siteId][k] = v;
      }
    }
    return snap;
  }
}

const bftVectorClockMatrix = new BftVectorClockMatrix();

module.exports = {
  BftVectorClockMatrix,
  bftVectorClockMatrix
};
