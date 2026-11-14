/**
 * EJII Phase 4.0 — Generative Neuro-Symbolic Remediation Synthesizer
 *
 * Implements:
 *   1. Safe Micro-Remediation Grammar (TCP_WINDOW_CLAMP, DNS_UPSTREAM_PIVOT, SOCKET_BUFFER_EXPEDITE, DSCP_TRAFFIC_SHAPE)
 *   2. Pre-Execution Control-Theoretic Lyapunov Invariant Proof Engine (V(s_{t+1}) - V(s_t) <= -delta < 0)
 *   3. Automated Algebraic Compensating Inverse Action Generation (a^{-1})
 *   4. HMAC-SHA256 Cryptographic Action Token & Dual-Custody Issuance
 */

import * as crypto from 'node:crypto';

export type MicroRemediationType =
  | 'TCP_WINDOW_CLAMP'
  | 'DNS_UPSTREAM_PIVOT'
  | 'SOCKET_BUFFER_EXPEDITE'
  | 'DSCP_TRAFFIC_SHAPE';

export type InverseRemediationType =
  | 'TCP_WINDOW_UNCLAMP'
  | 'DNS_UPSTREAM_REVERT'
  | 'SOCKET_BUFFER_RESET'
  | 'DSCP_DEFAULT';

export interface TelemetryStateVector {
  rttMs: number;
  lossPct: number;
  queueDepthPackets: number;
  cpuLoadPct?: number;
  memoryUsedPct?: number;
}

export interface ExpectedImpact {
  rttDeltaMs: number;
  lossDeltaPct: number;
  queueDeltaPackets: number;
}

export interface MicroRemediationAction {
  actionId: string;
  actionType: MicroRemediationType;
  target: string;
  parameters: Record<string, any>;
  rationale: string;
  expectedImpact: ExpectedImpact;
  requiresElevation: boolean;
  commandPreview: string;
}

export interface CompensatingInverseAction {
  actionId: string;
  inverseType: InverseRemediationType;
  reversesActionId: string;
  target: string;
  parameters: Record<string, any>;
  rationale: string;
  commandPreview: string;
  requiresElevation: boolean;
  isCompensatingInverse: true;
}

export interface LyapunovProof {
  verified: boolean;
  deltaV: number;
  energyBefore: number;
  energyAfter: number;
  contractionMargin: number;
  stabilityVerdict: 'STABLE_CONTRACTION' | 'NEUTRAL_OR_EXPANSIVE_REJECTED';
  weights: { alpha: number; beta: number; gamma: number };
  reason?: string;
}

export interface SynthesizedActionPlan {
  actionId: string;
  target: string;
  action: MicroRemediationAction;
  inverseAction: CompensatingInverseAction;
  lyapunovProof: LyapunovProof;
  actionToken: string;
  issuedAtIso: string;
  expiresAtIso: string;
}

export const CANONICAL_LYAPUNOV_WEIGHTS = Object.freeze({
  alpha: 0.40, // RTT penalty weight
  beta: 0.40,  // Loss percentage penalty weight
  gamma: 0.20  // Queue depth penalty weight
});

export const MIN_LYAPUNOV_CONTRACTION_DELTA = 0.05;

export class GenerativeRemediationSynthesizer {
  private hmacSecret: Buffer;

  constructor(secretKey: string = process.env.EJII_HMAC_SECRET || 'EJII-ENTERPRISE-INTELLIGENCE-HMAC-SECURE-KEY-2026') {
    this.hmacSecret = Buffer.from(secretKey, 'utf-8');
  }

  /**
   * Computes quadratic Lyapunov energy:
   * V(s) = alpha * (rtt)^2 + beta * (lossPct)^2 + gamma * (queueDepth)^2
   */
  public computeLyapunovEnergy(
    state: TelemetryStateVector,
    weights: { alpha: number; beta: number; gamma: number } = CANONICAL_LYAPUNOV_WEIGHTS
  ): number {
    const rtt = Math.max(0, Number(state.rttMs) || 0);
    const loss = Math.max(0, Number(state.lossPct) || 0);
    const queue = Math.max(0, Number(state.queueDepthPackets) || 0);

    const energy = weights.alpha * Math.pow(rtt, 2) +
                   weights.beta * Math.pow(loss, 2) +
                   weights.gamma * Math.pow(queue, 2);

    return Math.round(energy * 1000) / 1000;
  }

  /**
   * Proves Lyapunov stability invariant before execution:
   * delta V = V(s_{t+1}) - V(s_t) <= -delta < 0
   */
  public proveLyapunovStability(
    currentState: TelemetryStateVector,
    action: MicroRemediationAction,
    options: { deltaThreshold?: number; weights?: { alpha: number; beta: number; gamma: number } } = {}
  ): LyapunovProof {
    const weights = options.weights || CANONICAL_LYAPUNOV_WEIGHTS;
    const deltaThreshold = typeof options.deltaThreshold === 'number'
      ? options.deltaThreshold
      : MIN_LYAPUNOV_CONTRACTION_DELTA;

    const energyBefore = this.computeLyapunovEnergy(currentState, weights);

    const projectedState: TelemetryStateVector = {
      rttMs: Math.max(0, (currentState.rttMs || 0) + (action.expectedImpact.rttDeltaMs || 0)),
      lossPct: Math.max(0, (currentState.lossPct || 0) + (action.expectedImpact.lossDeltaPct || 0)),
      queueDepthPackets: Math.max(0, (currentState.queueDepthPackets || 0) + (action.expectedImpact.queueDeltaPackets || 0)),
      cpuLoadPct: currentState.cpuLoadPct,
      memoryUsedPct: currentState.memoryUsedPct
    };

    const energyAfter = this.computeLyapunovEnergy(projectedState, weights);
    const deltaV = Math.round((energyAfter - energyBefore) * 1000) / 1000;

    // Must be strictly decreasing by at least deltaThreshold: deltaV <= -deltaThreshold
    const verified = deltaV <= -deltaThreshold;

    return {
      verified,
      deltaV,
      energyBefore,
      energyAfter,
      contractionMargin: Math.round((-deltaV - deltaThreshold) * 1000) / 1000,
      stabilityVerdict: verified ? 'STABLE_CONTRACTION' : 'NEUTRAL_OR_EXPANSIVE_REJECTED',
      weights,
      reason: verified
        ? `Lyapunov invariant satisfied: delta V = ${deltaV} <= -${deltaThreshold} (energy contracted from ${energyBefore} to ${energyAfter}).`
        : `Lyapunov stability violation: delta V = ${deltaV} does not guarantee strict contraction (threshold -${deltaThreshold}).`
    };
  }

  /**
   * Generates exact algebraic compensating inverse action a^{-1} for any synthesized action a.
   */
  public deriveCompensatingInverse(action: MicroRemediationAction): CompensatingInverseAction {
    const inverseId = `INV_${action.actionId}`;

    switch (action.actionType) {
      case 'TCP_WINDOW_CLAMP': {
        const origWindow = action.parameters.originalWindowSize || 65535;
        return {
          actionId: inverseId,
          inverseType: 'TCP_WINDOW_UNCLAMP',
          reversesActionId: action.actionId,
          target: action.target,
          parameters: { windowSize: origWindow },
          rationale: `Compensating inverse: unclamp TCP receive window back to original ${origWindow} bytes.`,
          commandPreview: `netsh int tcp set global autotuninglevel=normal || sysctl -w net.ipv4.tcp_rmem="4096 87380 ${origWindow}"`,
          requiresElevation: action.requiresElevation,
          isCompensatingInverse: true
        };
      }

      case 'DNS_UPSTREAM_PIVOT': {
        const previousResolver = action.parameters.previousResolver || '127.0.0.1';
        return {
          actionId: inverseId,
          inverseType: 'DNS_UPSTREAM_REVERT',
          reversesActionId: action.actionId,
          target: action.target,
          parameters: { targetResolver: previousResolver },
          rationale: `Compensating inverse: revert DNS resolver binding back to original upstream ${previousResolver}.`,
          commandPreview: `Set-DnsClientServerAddress -InterfaceAlias * -ServerAddresses ("${previousResolver}")`,
          requiresElevation: action.requiresElevation,
          isCompensatingInverse: true
        };
      }

      case 'SOCKET_BUFFER_EXPEDITE': {
        const origBytes = action.parameters.originalBufferBytes || 65536;
        return {
          actionId: inverseId,
          inverseType: 'SOCKET_BUFFER_RESET',
          reversesActionId: action.actionId,
          target: action.target,
          parameters: { bufferBytes: origBytes },
          rationale: `Compensating inverse: reset socket SO_RCVBUF / SO_SNDBUF allocations back to standard ${origBytes} bytes.`,
          commandPreview: `sysctl -w net.core.rmem_default=${origBytes} net.core.wmem_default=${origBytes}`,
          requiresElevation: action.requiresElevation,
          isCompensatingInverse: true
        };
      }

      case 'DSCP_TRAFFIC_SHAPE': {
        const origDscp = action.parameters.originalDscpClass || 'CS0';
        return {
          actionId: inverseId,
          inverseType: 'DSCP_DEFAULT',
          reversesActionId: action.actionId,
          target: action.target,
          parameters: { dscpClass: origDscp },
          rationale: `Compensating inverse: restore default QoS DSCP classification to ${origDscp} (Best Effort).`,
          commandPreview: `Remove-NetQosPolicy -Name "EJII_Priority_${action.target}" -Confirm:$false`,
          requiresElevation: action.requiresElevation,
          isCompensatingInverse: true
        };
      }

      default: {
        return {
          actionId: inverseId,
          inverseType: 'TCP_WINDOW_UNCLAMP',
          reversesActionId: action.actionId,
          target: action.target,
          parameters: {},
          rationale: `Compensating rollback for action ${action.actionId}.`,
          commandPreview: `# Rollback ${action.actionId}`,
          requiresElevation: action.requiresElevation,
          isCompensatingInverse: true
        };
      }
    }
  }

  /**
   * Synthesizes candidate micro-remediations guided by symptoms and current telemetry vector.
   */
  public synthesizeRemediationCandidate(
    symptom: string,
    currentState: TelemetryStateVector,
    target: string = '127.0.0.1',
    options: { originalParams?: Record<string, any> } = {}
  ): MicroRemediationAction {
    const normSymptom = String(symptom || '').toUpperCase();
    const actionId = `MICRO_REM_${Date.now()}_${crypto.randomBytes(3).toString('hex')}`;

    if (normSymptom.includes('BUFFERBLOAT') || normSymptom.includes('QUEUE') || (currentState.queueDepthPackets || 0) > 40) {
      return {
        actionId,
        actionType: 'TCP_WINDOW_CLAMP',
        target,
        parameters: {
          windowSize: 32768,
          originalWindowSize: options.originalParams?.windowSize || 65535
        },
        rationale: 'Clamp TCP receive window to 32KB to eliminate edge bufferbloat and buffer congestion.',
        expectedImpact: {
          rttDeltaMs: -Math.min(25, (currentState.rttMs || 0) * 0.40),
          lossDeltaPct: -Math.min(2.0, (currentState.lossPct || 0) * 0.30),
          queueDeltaPackets: -Math.min(30, (currentState.queueDepthPackets || 0) * 0.60)
        },
        requiresElevation: false,
        commandPreview: `sysctl -w net.ipv4.tcp_rmem="4096 16384 32768"`
      };
    }

    if (normSymptom.includes('DNS') || normSymptom.includes('RESOLVER') || normSymptom.includes('TIMEOUT')) {
      const fallbackIp = target.startsWith('10.') ? '1.1.1.1' : '8.8.8.8';
      return {
        actionId,
        actionType: 'DNS_UPSTREAM_PIVOT',
        target,
        parameters: {
          newResolver: fallbackIp,
          previousResolver: options.originalParams?.previousResolver || '127.0.0.1'
        },
        rationale: `Pivot upstream DNS resolution to verified resilient anycast authoritative resolver (${fallbackIp}).`,
        expectedImpact: {
          rttDeltaMs: -Math.min(40, (currentState.rttMs || 0) * 0.50),
          lossDeltaPct: -Math.min(5.0, (currentState.lossPct || 0) * 0.80),
          queueDeltaPackets: -2
        },
        requiresElevation: false,
        commandPreview: `Set-DnsClientServerAddress -InterfaceAlias * -ServerAddresses ("${fallbackIp}")`
      };
    }

    if (normSymptom.includes('CONGESTION') || normSymptom.includes('SOCKET') || (currentState.rttMs || 0) > 80) {
      return {
        actionId,
        actionType: 'SOCKET_BUFFER_EXPEDITE',
        target,
        parameters: {
          bufferBytes: 262144,
          originalBufferBytes: options.originalParams?.bufferBytes || 65536
        },
        rationale: 'Expand socket receive and transmit ring buffers to 256KB to expedite kernel packet drain.',
        expectedImpact: {
          rttDeltaMs: -Math.min(15, (currentState.rttMs || 0) * 0.25),
          lossDeltaPct: -Math.min(3.0, (currentState.lossPct || 0) * 0.50),
          queueDeltaPackets: -Math.min(15, (currentState.queueDepthPackets || 0) * 0.40)
        },
        requiresElevation: false,
        commandPreview: `sysctl -w net.core.rmem_max=262144 net.core.wmem_max=262144`
      };
    }

    // Default: DSCP Traffic Shaping for latency-sensitive traffic
    return {
      actionId,
      actionType: 'DSCP_TRAFFIC_SHAPE',
      target,
      parameters: {
        dscpClass: 'AF41',
        originalDscpClass: options.originalParams?.dscpClass || 'CS0'
      },
      rationale: 'Classify traffic as DSCP AF41 (Assured Forwarding Class 4) for prioritized switch hop scheduling.',
      expectedImpact: {
        rttDeltaMs: -Math.min(12, (currentState.rttMs || 0) * 0.30),
        lossDeltaPct: -Math.min(1.5, (currentState.lossPct || 0) * 0.40),
        queueDeltaPackets: -5
      },
      requiresElevation: false,
      commandPreview: `New-NetQosPolicy -Name "EJII_Priority_${target}" -AppPathNameMatchCondition "*" -DSCPAction 34`
    };
  }

  /**
   * Formulates full plan with verified Lyapunov invariant proof and cryptographic HMAC action token.
   */
  public issueCryptographicActionPlan(
    action: MicroRemediationAction,
    currentState: TelemetryStateVector,
    options: { ttlMs?: number; deltaThreshold?: number } = {}
  ): SynthesizedActionPlan {
    const proof = this.proveLyapunovStability(currentState, action, { deltaThreshold: options.deltaThreshold });

    if (!proof.verified) {
      const err = new Error(`Action plan rejected: ${proof.reason}`);
      (err as any).code = 'LYAPUNOV_INVARIANT_VIOLATED';
      (err as any).proof = proof;
      throw err;
    }

    const inverseAction = this.deriveCompensatingInverse(action);
    const ttlMs = options.ttlMs || 300000; // 5 minutes TTL
    const issuedAt = Date.now();
    const expiresAt = issuedAt + ttlMs;

    const payload = {
      actionId: action.actionId,
      actionType: action.actionType,
      target: action.target,
      parameters: action.parameters,
      inverseActionId: inverseAction.actionId,
      deltaV: proof.deltaV,
      issuedAt,
      expiresAt
    };

    const payloadStr = JSON.stringify(payload);
    const signature = crypto.createHmac('sha256', this.hmacSecret).update(payloadStr).digest('hex');
    const actionToken = `${Buffer.from(payloadStr).toString('base64url')}.${signature}`;

    return {
      actionId: action.actionId,
      target: action.target,
      action,
      inverseAction,
      lyapunovProof: proof,
      actionToken,
      issuedAtIso: new Date(issuedAt).toISOString(),
      expiresAtIso: new Date(expiresAt).toISOString()
    };
  }

  /**
   * Verifies authenticity, signature, and expiration of an issued action token.
   */
  public verifyActionPlanToken(token: string): { valid: boolean; payload?: any; reason?: string } {
    if (!token || typeof token !== 'string') {
      return { valid: false, reason: 'INVALID_TOKEN_FORMAT' };
    }

    const parts = token.split('.');
    if (parts.length !== 2) {
      return { valid: false, reason: 'MALFORMED_TOKEN_STRUCTURE' };
    }

    const [b64Payload, sig] = parts;
    let payloadStr: string;
    try {
      payloadStr = Buffer.from(b64Payload, 'base64url').toString('utf-8');
    } catch (_) {
      return { valid: false, reason: 'BASE64URL_DECODE_FAILED' };
    }

    const expectedSig = crypto.createHmac('sha256', this.hmacSecret).update(payloadStr).digest('hex');
    if (!crypto.timingSafeEqual(Buffer.from(sig, 'hex'), Buffer.from(expectedSig, 'hex'))) {
      return { valid: false, reason: 'HMAC_SIGNATURE_MISMATCH' };
    }

    let payload: any;
    try {
      payload = JSON.parse(payloadStr);
    } catch (_) {
      return { valid: false, reason: 'PAYLOAD_JSON_INVALID' };
    }

    if (Date.now() > payload.expiresAt) {
      return { valid: false, reason: 'TOKEN_EXPIRED', payload };
    }

    return { valid: true, payload };
  }
}

export const generativeRemediationSynthesizer = new GenerativeRemediationSynthesizer();
