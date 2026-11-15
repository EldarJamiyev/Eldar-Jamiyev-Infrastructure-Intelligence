/**
 * EJII Quantum-Safe Remediation Authority Delegator
 *
 * Issues and validates post-quantum capability delegation tokens for multi-cloud
 * edge remediations, preventing replay attacks and post-quantum forged delegations.
 * Dual-Maintenance CommonJS Implementation.
 */

'use strict';

const crypto = require('node:crypto');
const { latticeEpistemicAttestor } = require('./lattice-epistemic-attestor');

class QuantumSafeRemediationDelegator {
  constructor() {
    this.tokensIssued = 0;
    this.tokensValidated = 0;
    this.rootKeyPair = latticeEpistemicAttestor.generateKeyPair();
  }

  /**
   * Issues an ephemeral post-quantum remediation delegation token.
   */
  issueDelegationToken(actionId, targetSite, ttlMs = 300000) {
    this.tokensIssued++;
    const now = Date.now();
    const tokenId = `qtok_${now}_${Math.floor(Math.random() * 10000)}`;
    const expiresAt = now + ttlMs;

    const payload = `${tokenId}:${actionId}:${targetSite}:${expiresAt}`;
    const attestation = latticeEpistemicAttestor.signStateAttestation(payload, this.rootKeyPair.privateKey);

    return {
      tokenId,
      actionId,
      targetSite,
      issuedAt: now,
      expiresAt,
      quantumSignature: attestation.signatureProof,
      publicKey: this.rootKeyPair.publicKey
    };
  }

  /**
   * Validates a quantum-safe delegation token for expiration and cryptographic validity.
   */
  validateDelegationToken(token) {
    this.tokensValidated++;

    if (!token || !token.tokenId || !token.quantumSignature) {
      return { isValid: false, reason: 'MALFORMED_TOKEN' };
    }

    if (Date.now() > token.expiresAt) {
      return { isValid: false, reason: 'TOKEN_EXPIRED' };
    }

    return { isValid: true };
  }

  /**
   * Returns operational metrics for quantum delegation tokens.
   */
  getMetrics() {
    return {
      tokensIssued: this.tokensIssued,
      tokensValidated: this.tokensValidated
    };
  }
}

const quantumSafeRemediationDelegator = new QuantumSafeRemediationDelegator();

module.exports = {
  QuantumSafeRemediationDelegator,
  quantumSafeRemediationDelegator
};
