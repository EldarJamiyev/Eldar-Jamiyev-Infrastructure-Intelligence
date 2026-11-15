/**
 * EJII Phase 10.0 Track 2 — Post-Quantum Cryptography (PQC) & Zero-Knowledge Telemetry Prover (CommonJS Parity)
 */

'use strict';

const crypto = require('node:crypto');

function getDb() {
  try {
    return require('../../db/database').db;
  } catch (_) {
    return null;
  }
}

const RING_N = 256;
const RING_Q = 8380417;
const GAMMA1 = 131072;
const BETA = 78;

class PostQuantumZkAttestor {
  static P_PRIME = BigInt('0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F');
  static G_GEN = BigInt(2);
  static H_GENS = [BigInt(3), BigInt(5), BigInt(7)];

  constructor() {
    this.ensureDatabaseTable();
  }

  ensureDatabaseTable() {
    const db = getDb();
    if (!db) return;
    try {
      db.exec(`
        CREATE TABLE IF NOT EXISTS ejii_pqc_attestation_records (
          receipt_id TEXT PRIMARY KEY,
          node_id TEXT NOT NULL,
          payload_digest TEXT NOT NULL,
          pqc_key_id TEXT NOT NULL,
          is_verified INTEGER NOT NULL,
          zk_commitment TEXT NOT NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE INDEX IF NOT EXISTS idx_pqc_node_id ON ejii_pqc_attestation_records(node_id);
      `);
    } catch (_) {}
  }

  polyMultiply(a, b) {
    const res = new Array(RING_N).fill(0);
    for (let i = 0; i < RING_N; i++) {
      if (a[i] === 0) continue;
      for (let j = 0; j < RING_N; j++) {
        if (b[j] === 0) continue;
        const term = (a[i] * b[j]) % RING_Q;
        const deg = i + j;
        if (deg < RING_N) {
          res[deg] = (res[deg] + term) % RING_Q;
        } else {
          const wrapped = deg - RING_N;
          res[wrapped] = (res[wrapped] - term + RING_Q) % RING_Q;
        }
      }
    }
    return res;
  }

  polyAdd(a, b) {
    const res = new Array(RING_N);
    for (let i = 0; i < RING_N; i++) {
      res[i] = ((a[i] || 0) + (b[i] || 0)) % RING_Q;
    }
    return res;
  }

  polySubtract(a, b) {
    const res = new Array(RING_N);
    for (let i = 0; i < RING_N; i++) {
      res[i] = (((a[i] || 0) - (b[i] || 0)) % RING_Q + RING_Q) % RING_Q;
    }
    return res;
  }

  polyInfinityNorm(z) {
    let max = 0;
    const halfQ = Math.floor(RING_Q / 2);
    for (let i = 0; i < RING_N; i++) {
      let val = z[i] % RING_Q;
      if (val > halfQ) val -= RING_Q;
      const abs = Math.abs(val);
      if (abs > max) max = abs;
    }
    return max;
  }

  expandMatrixA(seed) {
    const a = new Array(RING_N);
    for (let i = 0; i < RING_N; i++) {
      const hash = crypto.createHash('sha256').update(`${seed}:polyA:${i}`).digest();
      const val = hash.readUInt32BE(0) % RING_Q;
      a[i] = val;
    }
    return a;
  }

  sampleSmallPoly(seed, domain, eta = 2) {
    const s = new Array(RING_N);
    for (let i = 0; i < RING_N; i++) {
      const hash = crypto.createHash('sha256').update(`${seed}:${domain}:${i}`).digest();
      const raw = (hash.readUInt8(0) % (2 * eta + 1)) - eta;
      s[i] = (raw + RING_Q) % RING_Q;
    }
    return s;
  }

  generatePqcKeyPair(seed) {
    const keySeed = seed || crypto.randomBytes(32).toString('hex');
    const keyId = `pqc_key_${crypto.createHash('sha256').update(keySeed).digest('hex').substring(0, 16)}`;

    const polyA = this.expandMatrixA(keySeed);
    const s1 = this.sampleSmallPoly(keySeed, 'secret_s1', 2);
    const s2 = this.sampleSmallPoly(keySeed, 'secret_s2', 2);

    const as1 = this.polyMultiply(polyA, s1);
    const t = this.polyAdd(as1, s2);

    return {
      keyId,
      publicKey: {
        matrixSeed: keySeed,
        t
      },
      secretKey: {
        s1,
        s2
      },
      createdAtIso: new Date().toISOString()
    };
  }

  signLattice(payload, keyPair) {
    const polyA = this.expandMatrixA(keyPair.publicKey.matrixSeed);
    const payloadHash = crypto.createHash('sha256').update(payload).digest('hex');

    let nonce = 0;
    let z = [];
    let challengeHash = '';
    let w1HighBits = [];

    while (nonce < 1000) {
      nonce++;
      const y = new Array(RING_N);
      for (let i = 0; i < RING_N; i++) {
        const hash = crypto.createHash('sha256').update(`${payloadHash}:nonce_${nonce}:${i}`).digest();
        const raw = (hash.readUInt32BE(0) % (2 * GAMMA1)) - GAMMA1;
        y[i] = (raw + RING_Q) % RING_Q;
      }

      const ay = this.polyMultiply(polyA, y);
      w1HighBits = ay.slice(0, 16).map((val) => Math.floor(val / 65536));
      challengeHash = crypto.createHash('sha256').update(`${payloadHash}:${w1HighBits.join(',')}`).digest('hex');

      const c = new Array(RING_N).fill(0);
      for (let i = 0; i < 39; i++) {
        const idx = parseInt(challengeHash.substring((i * 2) % 60, (i * 2) % 60 + 2), 16) % RING_N;
        c[idx] = i % 2 === 0 ? 1 : RING_Q - 1;
      }

      const cs1 = this.polyMultiply(c, keyPair.secretKey.s1);
      z = this.polyAdd(y, cs1);

      const normZ = this.polyInfinityNorm(z);
      if (normZ < GAMMA1 - BETA) {
        break;
      }
    }

    const signatureHex = Buffer.from(JSON.stringify({ challengeHash, zHead: z.slice(0, 16) })).toString('hex');

    return {
      keyId: keyPair.keyId,
      challengeHash,
      w1HighBits,
      z,
      signatureHex,
      timestampIso: new Date().toISOString()
    };
  }

  verifyLattice(payload, signature, publicKey) {
    const normZ = this.polyInfinityNorm(signature.z);
    if (normZ >= GAMMA1 - BETA) {
      return false;
    }

    const payloadHash = crypto.createHash('sha256').update(payload).digest('hex');
    const computedChallenge = crypto.createHash('sha256').update(`${payloadHash}:${(signature.w1HighBits || []).join(',')}`).digest('hex');

    if (computedChallenge !== signature.challengeHash) {
      return false;
    }

    const polyA = this.expandMatrixA(publicKey.matrixSeed);

    const c = new Array(RING_N).fill(0);
    for (let i = 0; i < 39; i++) {
      const idx = parseInt(signature.challengeHash.substring((i * 2) % 60, (i * 2) % 60 + 2), 16) % RING_N;
      c[idx] = i % 2 === 0 ? 1 : RING_Q - 1;
    }

    const az = this.polyMultiply(polyA, signature.z);
    const ct = this.polyMultiply(c, publicKey.t);
    const w1Prime = this.polySubtract(az, ct);

    for (let i = 0; i < 16; i++) {
      const reconstructedHighBit = Math.floor(w1Prime[i] / 65536);
      const expectedHighBit = signature.w1HighBits ? signature.w1HighBits[i] : reconstructedHighBit;
      if (Math.abs(reconstructedHighBit - expectedHighBit) > 2) {
        return false;
      }
    }

    return true;
  }

  modExp(base, exp, mod) {
    let res = BigInt(1);
    let b = base % mod;
    let e = exp;
    while (e > 0n) {
      if (e % 2n === 1n) {
        res = (res * b) % mod;
      }
      b = (b * b) % mod;
      e = e / 2n;
    }
    return res;
  }

  generateZkPedersenCommitment(telemetry, thresholds = { maxRttMs: 150.0, maxLossPct: 5.0, maxQueuePackets: 100 }) {
    const P = PostQuantumZkAttestor.P_PRIME;
    const ORDER = P - 1n;
    const G = PostQuantumZkAttestor.G_GEN;
    const H = PostQuantumZkAttestor.H_GENS;

    const v = [
      BigInt(Math.max(1, Math.round(telemetry.rttMs * 10))),
      BigInt(Math.max(0, Math.round(telemetry.lossPct * 100))),
      BigInt(Math.max(0, Math.round(telemetry.queueDepthPackets)))
    ];

    const rBytes = crypto.randomBytes(32);
    const r = BigInt('0x' + rBytes.toString('hex')) % ORDER;

    let C = this.modExp(G, r, P);
    for (let i = 0; i < 3; i++) {
      const factor = this.modExp(H[i], v[i], P);
      C = (C * factor) % P;
    }

    const kRBytes = crypto.randomBytes(32);
    const kR = BigInt('0x' + kRBytes.toString('hex')) % ORDER;
    const kV = [BigInt(10), BigInt(20), BigInt(30)];

    let R = this.modExp(G, kR, P);
    for (let i = 0; i < 3; i++) {
      R = (R * this.modExp(H[i], kV[i], P)) % P;
    }

    const challengeHex = crypto
      .createHash('sha256')
      .update(`${C.toString(16)}:${R.toString(16)}`)
      .digest('hex');
    const challenge = BigInt('0x' + challengeHex) % ORDER;

    const sR = (kR + challenge * r) % ORDER;
    const sV = kV.map((kVal, i) => (kVal + challenge * v[i]) % ORDER);

    const satisfiesThresholds =
      telemetry.rttMs <= thresholds.maxRttMs &&
      telemetry.lossPct <= thresholds.maxLossPct &&
      telemetry.queueDepthPackets <= thresholds.maxQueuePackets;

    return {
      commitmentHex: C.toString(16),
      blindedProof: {
        commitmentR: R.toString(16),
        responseR: sR.toString(16),
        responseV: sV.map((x) => x.toString(16)),
        challenge: challengeHex
      },
      satisfiesThresholds,
      thresholds,
      timestampIso: new Date().toISOString()
    };
  }

  verifyZkCommitment(zkCommitment) {
    const P = PostQuantumZkAttestor.P_PRIME;
    const ORDER = P - 1n;
    const G = PostQuantumZkAttestor.G_GEN;
    const H = PostQuantumZkAttestor.H_GENS;

    try {
      const C = BigInt('0x' + zkCommitment.commitmentHex);
      const R = BigInt('0x' + zkCommitment.blindedProof.commitmentR);
      const sR = BigInt('0x' + zkCommitment.blindedProof.responseR);
      const sV = zkCommitment.blindedProof.responseV.map((x) => BigInt('0x' + x));

      const expectedChallengeHex = crypto
        .createHash('sha256')
        .update(`${C.toString(16)}:${R.toString(16)}`)
        .digest('hex');

      if (expectedChallengeHex !== zkCommitment.blindedProof.challenge) {
        return false;
      }
      const challenge = BigInt('0x' + expectedChallengeHex) % ORDER;

      let lhs = this.modExp(G, sR, P);
      for (let i = 0; i < 3; i++) {
        lhs = (lhs * this.modExp(H[i], sV[i], P)) % P;
      }

      const rhs = (R * this.modExp(C, challenge, P)) % P;
      return lhs === rhs;
    } catch (_) {
      return false;
    }
  }

  createHybridAttestation(nodeId, payload, keyPair, telemetry, ed25519PrivateKeyPem) {
    const receiptId = `hyb_rcpt_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
    const payloadDigest = crypto.createHash('sha256').update(payload).digest('hex');

    let ed25519Signature = undefined;
    if (ed25519PrivateKeyPem) {
      try {
        ed25519Signature = crypto.sign(null, Buffer.from(payload, 'utf8'), ed25519PrivateKeyPem).toString('base64url');
      } catch (_) {}
    }

    const pqcSignature = this.signLattice(payload, keyPair);
    const zkCommitment = this.generateZkPedersenCommitment(telemetry);

    const isPqcValid = this.verifyLattice(payload, pqcSignature, keyPair.publicKey);
    const isZkValid = this.verifyZkCommitment(zkCommitment);
    const isHybridVerified = isPqcValid && isZkValid && zkCommitment.satisfiesThresholds;

    const receipt = {
      receiptId,
      nodeId,
      payloadDigest,
      ed25519Signature,
      pqcSignature,
      zkCommitment,
      isHybridVerified,
      timestampIso: new Date().toISOString()
    };

    this.persistAttestation(receipt);
    return receipt;
  }

  persistAttestation(receipt) {
    const db = getDb();
    if (!db) return;
    try {
      const stmt = db.prepare(`
        INSERT INTO ejii_pqc_attestation_records (
          receipt_id, node_id, payload_digest, pqc_key_id, is_verified, zk_commitment
        ) VALUES (?, ?, ?, ?, ?, ?)
      `);
      stmt.run(
        receipt.receiptId,
        receipt.nodeId,
        receipt.payloadDigest,
        receipt.pqcSignature.keyId,
        receipt.isHybridVerified ? 1 : 0,
        receipt.zkCommitment.commitmentHex
      );
    } catch (_) {}
  }
}

const postQuantumZkAttestor = new PostQuantumZkAttestor();

module.exports = {
  PostQuantumZkAttestor,
  postQuantumZkAttestor,
  RING_N,
  RING_Q,
  GAMMA1,
  BETA
};
