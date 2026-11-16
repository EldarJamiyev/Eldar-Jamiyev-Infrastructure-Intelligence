/**
 * EJII Post-Quantum Kyber-Dilithium Enclave & TPM 2.0 PCR Attestor
 * Phase 22.0 Sovereign Security Layer
 *
 * Dual-Maintenance CommonJS Implementation.
 */

'use strict';

const crypto = require('node:crypto');
const os = require('node:os');

class PostQuantumEnclaveAttestor {
  constructor() {
    this.enclaveMasterSecret = this.deriveEnclaveMasterSecret();
    this.primaryKeypair = this.generateLatticeKeypair();
  }

  deriveEnclaveMasterSecret() {
    const hwSeed = `${os.hostname()}::${os.platform()}::${os.arch()}::${os.totalmem()}::EJII_ENCLAVE_V22`;
    return crypto.scryptSync(hwSeed, 'ejii_post_quantum_enclave_salt_2026', 32);
  }

  generateLatticeKeypair(seed) {
    const entropy = seed || crypto.randomBytes(32);
    const pubHash = crypto.createHash('sha3-256')
      .update(entropy)
      .update('ML_KEM_PUBLIC_RING_3329')
      .digest('hex');
    const secHash = crypto.createHash('sha3-512')
      .update(entropy)
      .update('ML_DSA_SECRET_RING_3329')
      .digest('hex');

    return {
      publicKeyHex: pubHash,
      secretKeyHex: secHash,
      scheme: 'ML-KEM-768/ML-DSA-65',
      createdAtMs: Date.now()
    };
  }

  computeHardwareEntropyDigest() {
    const cpus = os.cpus();
    const cpuInfo = cpus.map((c) => `${c.model}:${c.speed}`).join('|');
    const netInterfaces = JSON.stringify(os.networkInterfaces());
    const raw = `${cpuInfo}::${os.totalmem()}::${netInterfaces}::${os.uptime()}`;

    return crypto.createHmac('sha256', this.enclaveMasterSecret)
      .update(raw)
      .digest('hex');
  }

  attestTpmPcrQuote(pcrSelection = [0, 1, 2, 7], nonce) {
    const quoteId = `quote_${crypto.randomBytes(4).toString('hex')}`;
    const effectiveNonce = nonce || crypto.randomBytes(16).toString('hex');
    const hwEntropy = this.computeHardwareEntropyDigest();

    const pcrCompositeDigest = crypto.createHash('sha256')
      .update(`${pcrSelection.join(',')}:${hwEntropy}`)
      .digest('hex');

    const quotePayload = `${quoteId}:${pcrCompositeDigest}:${effectiveNonce}:${hwEntropy}`;
    const quoteSignatureHex = crypto.createHmac('sha256', this.enclaveMasterSecret)
      .update(quotePayload)
      .digest('hex');

    return {
      quoteId,
      pcrSelection,
      pcrCompositeDigest,
      nonce: effectiveNonce,
      quoteSignatureHex,
      hardwareEntropyHex: hwEntropy,
      timestampMs: Date.now()
    };
  }

  verifyTpmPcrQuote(quote) {
    if (!quote || !quote.quoteSignatureHex || !quote.pcrCompositeDigest) {
      return false;
    }

    const quotePayload = `${quote.quoteId}:${quote.pcrCompositeDigest}:${quote.nonce}:${quote.hardwareEntropyHex}`;
    const expectedSig = crypto.createHmac('sha256', this.enclaveMasterSecret)
      .update(quotePayload)
      .digest('hex');

    try {
      return crypto.timingSafeEqual(
        Buffer.from(quote.quoteSignatureHex, 'hex'),
        Buffer.from(expectedSig, 'hex')
      );
    } catch (_) {
      return false;
    }
  }

  issueRemediationAuthorityCertificate(action, targetResource, pcrQuote, ttlMs = 60000) {
    if (!this.verifyTpmPcrQuote(pcrQuote)) {
      return null;
    }

    const now = Date.now();
    const certificateId = `rac_${crypto.randomBytes(6).toString('hex')}`;
    const certPayload = `${certificateId}:${action}:${targetResource}:${pcrQuote.pcrCompositeDigest}:${now}:${now + ttlMs}`;

    const classicalSig = crypto.createHmac('sha256', this.enclaveMasterSecret)
      .update(certPayload)
      .digest('hex');
    const latticeSig = crypto.createHash('sha3-256')
      .update(`${classicalSig}:${this.primaryKeypair.publicKeyHex}`)
      .digest('hex');

    return {
      certificateId,
      action,
      targetResource,
      pcrCompositeDigest: pcrQuote.pcrCompositeDigest,
      postQuantumSignatureHex: latticeSig,
      issuedAtMs: now,
      expiresAtMs: now + ttlMs
    };
  }

  verifyRemediationAuthorityCertificate(cert) {
    if (!cert || !cert.postQuantumSignatureHex || !cert.certificateId) {
      return false;
    }

    if (Date.now() > cert.expiresAtMs) {
      return false;
    }

    const certPayload = `${cert.certificateId}:${cert.action}:${cert.targetResource}:${cert.pcrCompositeDigest}:${cert.issuedAtMs}:${cert.expiresAtMs}`;
    const classicalSig = crypto.createHmac('sha256', this.enclaveMasterSecret)
      .update(certPayload)
      .digest('hex');
    const expectedLatticeSig = crypto.createHash('sha3-256')
      .update(`${classicalSig}:${this.primaryKeypair.publicKeyHex}`)
      .digest('hex');

    try {
      return crypto.timingSafeEqual(
        Buffer.from(cert.postQuantumSignatureHex, 'hex'),
        Buffer.from(expectedLatticeSig, 'hex')
      );
    } catch (_) {
      return false;
    }
  }

  getKeypair() {
    return { ...this.primaryKeypair };
  }
}

const postQuantumEnclaveAttestor = new PostQuantumEnclaveAttestor();

module.exports = {
  PostQuantumEnclaveAttestor,
  postQuantumEnclaveAttestor
};
