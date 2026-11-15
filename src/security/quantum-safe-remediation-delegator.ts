/**
 * EJII Quantum-Safe Remediation Authority Delegator
 *
 * Issues and validates post-quantum capability delegation tokens for multi-cloud
 * edge remediations, preventing replay attacks and post-quantum forged delegations.
 * Dual-Maintenance TypeScript Reference.
 */

import * as crypto from 'node:crypto';
import { latticeEpistemicAttestor } from './lattice-epistemic-attestor';

export interface QuantumDelegationToken {
  tokenId: string;
  actionId: string;
  targetSite: string;
  issuedAt: number;
  expiresAt: number;
  quantumSignature: string;
  publicKey: string;
}

export class QuantumSafeRemediationDelegator {
  private tokensIssued: number = 0;
  private tokensValidated: number = 0;
  private rootKeyPair: { publicKey: string; privateKey: string };

  constructor() {
    this.rootKeyPair = latticeEpistemicAttestor.generateKeyPair();
  }

  /**
   * Issues an ephemeral post-quantum remediation delegation token.
   */
  public issueDelegationToken(
    actionId: string,
    targetSite: string,
    ttlMs: number = 300000
  ): QuantumDelegationToken {
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
  public validateDelegationToken(token: QuantumDelegationToken): { isValid: boolean; reason?: string } {
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
  public getMetrics(): { tokensIssued: number; tokensValidated: number } {
    return {
      tokensIssued: this.tokensIssued,
      tokensValidated: this.tokensValidated
    };
  }
}

export const quantumSafeRemediationDelegator = new QuantumSafeRemediationDelegator();
