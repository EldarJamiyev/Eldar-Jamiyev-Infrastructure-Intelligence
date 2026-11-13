'use strict';

/**
 * EJII Project Atlas V — Statistically Sound Indirect Cross-Layer Inference Engine
 *
 * Synthesizes fault-domain hypotheses when direct single-layer probes are unavailable or inconclusive,
 * while strictly enforcing epistemic and statistical integrity (Cycle 5):
 *   1. Never fabricates a 6-domain posterior when observations are absent (`inferenceMode: 'INSUFFICIENT_EVIDENCE'`,
 *      `confidenceType: 'INSUFFICIENT_DATA'`).
 *   2. Never assigns `DIRECT_L7_OBSERVATION` when `httpLatencyMs` is missing or `DIRECT_DNS_OBSERVATION`
 *      when `dnsLatencyMs` is missing, and never invents `HOST_KERNEL_SOCKET` without host telemetry.
 *   3. Explicitly separates `measuredMetrics` from `inferredEstimates` (`inferredPacketLossRatio`,
 *      never reported as measured packet loss) and keeps historical memory strictly labeled as
 *      `HISTORICAL_EPISODIC_PRIOR`.
 *   4. Separates true Bayesian log-likelihood posterior inference (`BAYESIAN_LIKELIHOOD_POSTERIOR`)
 *      from normalized rule-based heuristic scores (`RULE_HEURISTIC`), reporting explicit `confidenceType`:
 *        - `BAYESIAN_LIKELIHOOD_POSTERIOR`
 *        - `RULE_HEURISTIC`
 *        - `EMPIRICALLY_CALIBRATED`
 *        - `INSUFFICIENT_DATA`
 *   5. Detects cross-layer contradictory observations (`contradictoryObservations`), such as healthy/fast
 *      L7 HTTP response time contradicting severe L3/L4 loss claims, or healthy TCP RTT contradicting
 *      inflated ICMP loss due to control-plane ICMP rate limiting.
 *   6. Computes Shannon Expected Information Gain (`expectedInformationGainBits`) across candidate probes
 *      and supports historical Brier score / calibration evaluation (`evaluateCalibrationAgainstSettledIncidents`)
 *      without fabricating training data.
 */

class IndirectCrossLayerInferencer {
  constructor() {
    this.minimumCalibrationSampleSize = 10;
    this.minimumCalibrationDistinctDomains = 2;
    this.domainMetadata = {
      DNS_CONTROL_PLANE: {
        defaultProbe: 'DNS_SOA_AND_UDP53_TRACE',
        priorProb: 0.14,
        disambiguationPower: 0.86,
        probeSensitivity: 0.91,
        probeFalsePositiveRate: 0.07,
        probeCostWeight: 1.0,
        operationalRiskWeight: 1.0
      },
      L3_NETWORK_PATH: {
        defaultProbe: 'ICMP_MTR_HOP_DIVERGENCE_PROBE',
        priorProb: 0.24,
        disambiguationPower: 0.82,
        probeSensitivity: 0.86,
        probeFalsePositiveRate: 0.10,
        probeCostWeight: 1.05,
        operationalRiskWeight: 1.0
      },
      L4_TRANSPORT_CONGESTION: {
        defaultProbe: 'TCP_SYN_RTT_AND_RETRANSMIT_SAMPLE',
        priorProb: 0.26,
        disambiguationPower: 0.85,
        probeSensitivity: 0.89,
        probeFalsePositiveRate: 0.08,
        probeCostWeight: 1.0,
        operationalRiskWeight: 1.0
      },
      TLS_CRYPTO_HANDSHAKE: {
        defaultProbe: 'TLS_1_3_HANDSHAKE_TIMING_AUDIT',
        priorProb: 0.12,
        disambiguationPower: 0.88,
        probeSensitivity: 0.92,
        probeFalsePositiveRate: 0.06,
        probeCostWeight: 1.08,
        operationalRiskWeight: 1.0
      },
      L7_UPSTREAM_APPLICATION: {
        defaultProbe: 'HTTP_HEAD_TTFB_ISOLATION_PROBE',
        priorProb: 0.16,
        disambiguationPower: 0.90,
        probeSensitivity: 0.93,
        probeFalsePositiveRate: 0.06,
        probeCostWeight: 1.05,
        operationalRiskWeight: 1.0
      },
      HOST_KERNEL_SOCKET: {
        defaultProbe: 'LOCAL_PROC_NET_SNMP_SOCKET_AUDIT',
        priorProb: 0.08,
        disambiguationPower: 0.84,
        probeSensitivity: 0.90,
        probeFalsePositiveRate: 0.07,
        probeCostWeight: 1.0,
        operationalRiskWeight: 1.0
      }
    };
  }

  /**
   * Computes Shannon entropy H(P) in bits for a probability distribution array (values in [0, 1]).
   */
  _computeShannonEntropyBits(probs = []) {
    let h = 0;
    for (const p of probs) {
      if (typeof p === 'number' && p > 1e-9 && p <= 1) {
        h -= p * Math.log2(p);
      }
    }
    return Number(Math.max(0, h).toFixed(4));
  }

  /**
   * Computes genuine Expected Information Gain (EIG) in bits for a candidate probe targeting `targetDomain`
   * over the current discrete hypothesis distribution `domainProbs` ({ domain, prob, isDirectObservation }):
   *   EIG(O; D) = H(D) - [ P(O=pos) * H(D | O=pos) + P(O=neg) * H(D | O=neg) ]
   * where P(O=pos | D=targetDomain) = sensitivity and P(O=pos | D!=targetDomain) = falsePositiveRate.
   * Never applies an artificial positive floor: an uninformative probe (sensitivity === falsePositiveRate)
   * or a degenerate distribution yields exactly 0 bits of Expected Information Gain.
   */
  _computeProbeExpectedInformationGain(arg1 = [], arg2, arg3, probeOptions = {}) {
    let domainProbs = [];
    let targetDomain = '';
    let currentEntropyBits = null;
    let opts = probeOptions && typeof probeOptions === 'object' ? probeOptions : {};

    if (Array.isArray(arg1)) {
      domainProbs = arg1;
      targetDomain = typeof arg2 === 'string' ? arg2 : '';
      if (typeof arg3 === 'number') {
        currentEntropyBits = arg3;
      } else if (arg3 && typeof arg3 === 'object') {
        opts = arg3;
      }
    } else if (typeof arg1 === 'string') {
      targetDomain = arg1;
      if (Array.isArray(arg2)) {
        domainProbs = arg2;
        if (typeof arg3 === 'number') {
          currentEntropyBits = arg3;
        } else if (arg3 && typeof arg3 === 'object') {
          opts = arg3;
        }
      } else if (Array.isArray(arg3)) {
        currentEntropyBits = typeof arg2 === 'number' ? arg2 : null;
        domainProbs = arg3;
      }
    }

    const baseMeta = this.domainMetadata[targetDomain] || {
      defaultProbe: 'TCP_SYN_RTT_AND_RETRANSMIT_SAMPLE',
      probeSensitivity: 0.88,
      probeFalsePositiveRate: 0.09,
      probeCostWeight: 1.0,
      operationalRiskWeight: 1.0
    };
    const meta = {
      ...baseMeta,
      ...(opts.probeMetadataOverride || {})
    };

    let empiricalSensitivity = null;
    let empiricalFalsePositiveRate = null;
    let confusionMatrixRejectReason = null;
    let empiricalObservationCount = 0;

    if (opts.empiricalConfusionMatrix && typeof opts.empiricalConfusionMatrix === 'object') {
      const rawTp = opts.empiricalConfusionMatrix.truePositives;
      const rawFn = opts.empiricalConfusionMatrix.falseNegatives;
      const rawFp = opts.empiricalConfusionMatrix.falsePositives;
      const rawTn = opts.empiricalConfusionMatrix.trueNegatives;
      const minObs = Math.max(4, Number(opts.minEmpiricalConfusionObservations ?? 10));
      const minClassObs = Math.max(2, Number(opts.minEmpiricalClassObservations ?? 3));

      const allFiniteNonNegative =
        typeof rawTp === 'number' && Number.isFinite(rawTp) && rawTp >= 0 &&
        typeof rawFn === 'number' && Number.isFinite(rawFn) && rawFn >= 0 &&
        typeof rawFp === 'number' && Number.isFinite(rawFp) && rawFp >= 0 &&
        typeof rawTn === 'number' && Number.isFinite(rawTn) && rawTn >= 0;

      if (!allFiniteNonNegative) {
        confusionMatrixRejectReason = 'INVALID_CONFUSION_MATRIX_FALLBACK_PRIOR';
      } else {
        const totalObs = rawTp + rawFn + rawFp + rawTn;
        empiricalObservationCount = totalObs;
        if (totalObs >= minObs && rawTp + rawFn >= minClassObs && rawFp + rawTn >= minClassObs) {
          empiricalSensitivity = rawTp / (rawTp + rawFn);
          empiricalFalsePositiveRate = rawFp / (rawFp + rawTn);
        } else {
          confusionMatrixRejectReason = 'INSUFFICIENT_EMPIRICAL_OBSERVATIONS_FALLBACK_PRIOR';
        }
      }
    }

    const probeCharacteristicSource =
      empiricalSensitivity !== null && empiricalFalsePositiveRate !== null
        ? 'EMPIRICAL_HISTORICAL_CONFUSION_MATRIX'
        : confusionMatrixRejectReason
          ? confusionMatrixRejectReason
          : opts.probeSensitivity !== undefined || opts.probeFalsePositiveRate !== undefined
            ? 'CALLER_SPECIFIED_CHARACTERISTICS'
            : 'CONFIGURED_HEURISTIC_PRIOR';

    const sensRaw =
      empiricalSensitivity !== null
        ? empiricalSensitivity
        : opts.probeSensitivity !== undefined
          ? Number(opts.probeSensitivity)
          : Number(meta.probeSensitivity ?? 0.88);
    const fprRaw =
      empiricalFalsePositiveRate !== null
        ? empiricalFalsePositiveRate
        : opts.probeFalsePositiveRate !== undefined
          ? Number(opts.probeFalsePositiveRate)
          : Number(meta.probeFalsePositiveRate ?? 0.09);
    const sens = Math.max(0, Math.min(1, Number.isFinite(sensRaw) ? sensRaw : 0.88));
    const fpr = Math.max(0, Math.min(1, Number.isFinite(fprRaw) ? fprRaw : 0.09));
    const probeCostWeight = Math.max(0.1, Number(opts.probeCostWeight ?? meta.probeCostWeight ?? 1.0));
    const operationalRiskWeight = Math.max(0.1, Number(opts.operationalRiskWeight ?? meta.operationalRiskWeight ?? 1.0));
    const probeAvailability = opts.probeAvailable === false ? 'UNAVAILABLE' : 'AVAILABLE';

    const normalizedCandidates = (Array.isArray(domainProbs) ? domainProbs : []).map((d) => {
      const domainName = d.domain || d.layer || 'UNKNOWN';
      const prob =
        d.prob !== undefined
          ? Number(d.prob)
          : d.probabilityPct !== undefined
            ? Number(d.probabilityPct) / 100
            : 0;
      return {
        ...d,
        domain: domainName,
        prob: Math.max(0, Number.isFinite(prob) ? prob : 0)
      };
    }).filter((d) => d.prob > 0);

    if (normalizedCandidates.length === 0 || probeAvailability === 'UNAVAILABLE') {
      return {
        probeType: meta.defaultProbe,
        targetLayer: targetDomain,
        expectedInformationGainBits: 0,
        rawMutualInformationBits: 0,
        utilityAdjustedEigBits: 0,
        diagnosticUsefulnessScore: 0,
        expectedPosteriorEntropyBits: 0,
        positiveOutcomeProbability: 0,
        probeSensitivity: sens,
        probeFalsePositiveRate: fpr,
        probeCharacteristicSource,
        operationalUtilityMultiplier: 0,
        executionCostPenalty: probeCostWeight,
        operationalRiskPenalty: operationalRiskWeight,
        probeCostWeight,
        operationalRiskWeight,
        probeAvailability,
        observationFreshnessState: 'UNAVAILABLE',
        eigCalculationMethod: 'INSUFFICIENT_PRIOR_DISTRIBUTION'
      };
    }

    // If sensitivity equals falsePositiveRate, the probe outcome is statistically independent of the hypothesis -> EIG = 0
    if (Math.abs(sens - fpr) < 1e-9) {
      const totalP = normalizedCandidates.reduce((acc, d) => acc + d.prob, 0) || 1;
      const priorH = this._computeShannonEntropyBits(normalizedCandidates.map((d) => d.prob / totalP));
      return {
        probeType: meta.defaultProbe,
        targetLayer: targetDomain,
        expectedInformationGainBits: 0,
        rawMutualInformationBits: 0,
        utilityAdjustedEigBits: 0,
        diagnosticUsefulnessScore: 0,
        expectedPosteriorEntropyBits: priorH,
        positiveOutcomeProbability: Number(sens.toFixed(4)),
        probeSensitivity: sens,
        probeFalsePositiveRate: fpr,
        probeCharacteristicSource,
        operationalUtilityMultiplier: 1.0,
        executionCostPenalty: probeCostWeight,
        operationalRiskPenalty: operationalRiskWeight,
        probeCostWeight,
        operationalRiskWeight,
        probeAvailability,
        observationFreshnessState: 'UNINFORMATIVE_PROBE',
        eigCalculationMethod: 'BAYESIAN_POSTERIOR_ENTROPY_REDUCTION'
      };
    }

    if (normalizedCandidates.length === 1) {
      // Single-candidate distribution: evaluate binary hypothesis uncertainty against its complement only if 0 < p < 1
      const pSingle = Math.max(0, Math.min(1, normalizedCandidates[0].prob));
      if (pSingle <= 1e-6 || pSingle >= 1 - 1e-6) {
        return {
          probeType: meta.defaultProbe,
          targetLayer: targetDomain,
          expectedInformationGainBits: 0,
          rawMutualInformationBits: 0,
          utilityAdjustedEigBits: 0,
          diagnosticUsefulnessScore: 0,
          expectedPosteriorEntropyBits: 0,
          positiveOutcomeProbability: Number((pSingle * sens + (1 - pSingle) * fpr).toFixed(4)),
          probeSensitivity: sens,
          probeFalsePositiveRate: fpr,
          probeCharacteristicSource,
          operationalUtilityMultiplier: 1.0,
          executionCostPenalty: probeCostWeight,
          operationalRiskPenalty: operationalRiskWeight,
          probeCostWeight,
          operationalRiskWeight,
          probeAvailability,
          observationFreshnessState: normalizedCandidates[0].isDirectObservation ? 'RECENTLY_MEASURED' : 'UNMEASURED_HIGH_VALUE',
          eigCalculationMethod: 'BAYESIAN_POSTERIOR_ENTROPY_REDUCTION'
        };
      }
      const binaryPriorEntropy = this._computeShannonEntropyBits([pSingle, 1 - pSingle]);
      const pPos = pSingle * sens + (1 - pSingle) * fpr;
      const pNeg = 1 - pPos;
      const postPos = pPos > 1e-9 ? (pSingle * sens) / pPos : pSingle;
      const postNeg = pNeg > 1e-9 ? (pSingle * (1 - sens)) / pNeg : pSingle;
      const hPos = this._computeShannonEntropyBits([postPos, 1 - postPos]);
      const hNeg = this._computeShannonEntropyBits([postNeg, 1 - postNeg]);
      const expectedPostH = pPos * hPos + pNeg * hNeg;
      const rawMi = Math.max(0, binaryPriorEntropy - expectedPostH);
      const freshnessFactor = normalizedCandidates[0].isDirectObservation ? 0.92 : 1.15;
      const costRiskDivisor = Math.max(0.25, probeCostWeight * operationalRiskWeight);
      const utilityAdjusted = Number(((rawMi * freshnessFactor) / costRiskDivisor).toFixed(4));
      return {
        probeType: meta.defaultProbe,
        targetLayer: targetDomain,
        expectedInformationGainBits: Number(rawMi.toFixed(4)),
        rawMutualInformationBits: Number(rawMi.toFixed(4)),
        utilityAdjustedEigBits: utilityAdjusted,
        diagnosticUsefulnessScore: utilityAdjusted,
        expectedPosteriorEntropyBits: Number(expectedPostH.toFixed(4)),
        positiveOutcomeProbability: Number(pPos.toFixed(4)),
        probeSensitivity: sens,
        probeFalsePositiveRate: fpr,
        probeCharacteristicSource,
        operationalUtilityMultiplier: freshnessFactor,
        executionCostPenalty: probeCostWeight,
        operationalRiskPenalty: operationalRiskWeight,
        probeCostWeight,
        operationalRiskWeight,
        probeAvailability,
        observationFreshnessState: normalizedCandidates[0].isDirectObservation ? 'RECENTLY_MEASURED' : 'UNMEASURED_HIGH_VALUE',
        eigCalculationMethod: 'BAYESIAN_POSTERIOR_ENTROPY_REDUCTION'
      };
    }

    // Normalize prior probabilities across candidate domains
    const totalP = normalizedCandidates.reduce((acc, d) => acc + d.prob, 0) || 1;
    const normProbs = normalizedCandidates.map((d) => ({
      ...d,
      p: d.prob / totalP
    }));

    // Marginal probe outcome probabilities P(O = pos) and P(O = neg)
    let pPos = 0;
    for (const d of normProbs) {
      const likelihoodPos = d.domain === targetDomain ? sens : fpr;
      pPos += d.p * likelihoodPos;
    }
    const pNeg = 1 - pPos;
    if (pPos <= 1e-9 || pNeg <= 1e-9) {
      const priorH = this._computeShannonEntropyBits(normProbs.map((d) => d.p));
      return {
        probeType: meta.defaultProbe,
        targetLayer: targetDomain,
        expectedInformationGainBits: 0,
        rawMutualInformationBits: 0,
        utilityAdjustedEigBits: 0,
        diagnosticUsefulnessScore: 0,
        expectedPosteriorEntropyBits: priorH,
        positiveOutcomeProbability: Number(Math.max(0, Math.min(1, pPos)).toFixed(4)),
        probeSensitivity: sens,
        probeFalsePositiveRate: fpr,
        probeCharacteristicSource,
        operationalUtilityMultiplier: 1.0,
        executionCostPenalty: probeCostWeight,
        operationalRiskPenalty: operationalRiskWeight,
        probeCostWeight,
        operationalRiskWeight,
        probeAvailability,
        observationFreshnessState: 'DEGENERATE_OUTCOME',
        eigCalculationMethod: 'BAYESIAN_POSTERIOR_ENTROPY_REDUCTION'
      };
    }

    // Posterior distribution given O = pos and given O = neg
    const postGivenPos = normProbs.map((d) => {
      const likelihoodPos = d.domain === targetDomain ? sens : fpr;
      return (d.p * likelihoodPos) / pPos;
    });
    const postGivenNeg = normProbs.map((d) => {
      const likelihoodNeg = d.domain === targetDomain ? 1 - sens : 1 - fpr;
      return (d.p * likelihoodNeg) / pNeg;
    });

    const hGivenPos = this._computeShannonEntropyBits(postGivenPos);
    const hGivenNeg = this._computeShannonEntropyBits(postGivenNeg);
    const expectedPosteriorEntropyBits = pPos * hGivenPos + pNeg * hGivenNeg;
    const computedPriorH = this._computeShannonEntropyBits(normProbs.map((d) => d.p));
    const priorH =
      typeof currentEntropyBits === 'number' && currentEntropyBits > 0 && Math.abs(currentEntropyBits - computedPriorH) < 0.05
        ? currentEntropyBits
        : computedPriorH;

    const rawMiBits = Math.max(0, priorH - expectedPosteriorEntropyBits);
    const targetEntry = normProbs.find((d) => d.domain === targetDomain);
    const observationFreshnessState = targetEntry && !targetEntry.isDirectObservation ? 'UNMEASURED_HIGH_VALUE' : 'RECENTLY_MEASURED';
    const freshnessFactor = observationFreshnessState === 'UNMEASURED_HIGH_VALUE' ? 1.15 : 0.92;
    const costRiskDivisor = Math.max(0.25, probeCostWeight * operationalRiskWeight);
    const utilityAdjustedEigBits = Number(((rawMiBits * freshnessFactor) / costRiskDivisor).toFixed(4));

    return {
      probeType: meta.defaultProbe,
      targetLayer: targetDomain,
      expectedInformationGainBits: Number(rawMiBits.toFixed(4)),
      rawMutualInformationBits: Number(rawMiBits.toFixed(4)),
      utilityAdjustedEigBits,
      diagnosticUsefulnessScore: utilityAdjustedEigBits,
      expectedPosteriorEntropyBits: Number(expectedPosteriorEntropyBits.toFixed(4)),
      positiveOutcomeProbability: Number(pPos.toFixed(4)),
      probeSensitivity: sens,
      probeFalsePositiveRate: fpr,
      probeCharacteristicSource,
      operationalUtilityMultiplier: freshnessFactor,
      executionCostPenalty: probeCostWeight,
      operationalRiskPenalty: operationalRiskWeight,
      probeCostWeight,
      operationalRiskWeight,
      probeAvailability,
      observationFreshnessState,
      eigCalculationMethod: 'BAYESIAN_POSTERIOR_ENTROPY_REDUCTION'
    };
  }

  /**
   * Computes an indirect estimate of L3/L4 packet loss ratio from TCP handshake RTT inflation
   * and jitter using an inverted Mathis-style bound (`RTT_ratio` & `jitter_ratio`).
   * Strictly labeled as `INFERRED_FROM_TCP_JITTER` and never reported as a measured counter.
   */
  estimatePacketLossFromTcpTiming(tcpRttMs, baselineRttMs = 15, tcpJitterMs = 0) {
    if (typeof tcpRttMs !== 'number' || !Number.isFinite(tcpRttMs) || tcpRttMs <= 0) {
      return {
        inferredPacketLossRatio: null,
        evidenceType: 'UNAVAILABLE_METRIC',
        confidence: 0,
        confidenceType: 'INSUFFICIENT_DATA'
      };
    }
    const safeBase = Math.max(1, Number(baselineRttMs) || 15);
    const safeJitter = Math.max(0, Number(tcpJitterMs) || 0);
    const inflationRatio = Math.max(1, tcpRttMs / safeBase);
    const jitterFactor = safeJitter / Math.max(10, tcpRttMs);

    if (inflationRatio <= 1.25 && jitterFactor <= 0.15) {
      return {
        inferredPacketLossRatio: 0,
        evidenceType: 'INFERRED_FROM_TCP_JITTER',
        confidence: 0.72,
        confidenceType: 'RULE_HEURISTIC'
      };
    }

    const rawLoss = Math.min(0.45, (inflationRatio - 1) * 0.035 + jitterFactor * 0.18);
    return {
      inferredPacketLossRatio: Number(rawLoss.toFixed(4)),
      evidenceType: 'INFERRED_FROM_TCP_JITTER',
      confidence: Number(Math.min(0.84, 0.45 + jitterFactor * 0.4).toFixed(2)),
      confidenceType: 'RULE_HEURISTIC'
    };
  }

  /**
   * Detects cross-layer contradictory observations and computes penalty adjustments.
   */
  detectContradictoryObservations(measuredMetrics = {}, lossInference = {}) {
    const contradictions = [];
    const domainMultipliers = new Map();

    // Contradiction 1: Fast L7 HTTP response time (< 45ms) contradicts severe L3/L4 transport congestion or packet loss
    if (
      measuredMetrics.httpLatencyMs !== null &&
      measuredMetrics.httpLatencyMs <= 45 &&
      ((measuredMetrics.icmpLossPct !== null && measuredMetrics.icmpLossPct >= 15) ||
        (measuredMetrics.tcpRttMs !== null && measuredMetrics.tcpRttMs >= 140))
    ) {
      contradictions.push({
        code: 'CONTRADICTION_FAST_L7_VS_SEVERE_LOWER_LAYER_DEGRADATION',
        layersInvolved: ['L7_UPSTREAM_APPLICATION', 'L3_NETWORK_PATH', 'L4_TRANSPORT_CONGESTION'],
        description: `Measured HTTP L7 response time (${measuredMetrics.httpLatencyMs} ms) is fast and healthy, which contradicts severe lower-layer degradation (tcpRttMs=${measuredMetrics.tcpRttMs ?? 'N/A'}, icmpLossPct=${measuredMetrics.icmpLossPct ?? 'N/A'}%). This indicates measurement path divergence, cached L7 edge responder, or ICMP control-plane policing.`,
        adjustmentApplied: 'Attenuated L3/L4 posterior confidence by 0.65x due to healthy end-to-end L7 completion.'
      });
      domainMultipliers.set('L3_NETWORK_PATH', 0.65);
      domainMultipliers.set('L4_TRANSPORT_CONGESTION', 0.70);
    }

    // Contradiction 2: High ICMP packet loss (> 20%) while TCP handshake RTT (< 25ms) and jitter (< 5ms) are healthy
    if (
      measuredMetrics.icmpLossPct !== null &&
      measuredMetrics.icmpLossPct >= 20 &&
      measuredMetrics.tcpRttMs !== null &&
      measuredMetrics.tcpRttMs <= 25 &&
      (measuredMetrics.tcpJitterMs === null || measuredMetrics.tcpJitterMs <= 5)
    ) {
      contradictions.push({
        code: 'CONTRADICTION_HIGH_ICMP_LOSS_VS_HEALTHY_TCP_TRANSPORT',
        layersInvolved: ['L3_NETWORK_PATH', 'L4_TRANSPORT_CONGESTION'],
        description: `Measured ICMP loss is elevated (${measuredMetrics.icmpLossPct}%) while TCP handshake RTT (${measuredMetrics.tcpRttMs} ms) and jitter (${measuredMetrics.tcpJitterMs ?? 0} ms) are nominal, strongly indicating router ICMP rate-limiting rather than true L3 data-plane packet loss.`,
        adjustmentApplied: 'Attenuated L3_NETWORK_PATH score by 0.55x (router ICMP control-plane deprioritization).'
      });
      domainMultipliers.set('L3_NETWORK_PATH', 0.55);
    }

    // Contradiction 3: Fast TLS handshake (< 20ms) while TCP RTT is reported as > 120ms
    if (
      measuredMetrics.tlsHandshakeMs !== null &&
      measuredMetrics.tlsHandshakeMs > 0 &&
      measuredMetrics.tlsHandshakeMs < 20 &&
      measuredMetrics.tcpRttMs !== null &&
      measuredMetrics.tcpRttMs > 120
    ) {
      contradictions.push({
        code: 'CONTRADICTION_TLS_FASTER_THAN_SINGLE_TCP_RTT',
        layersInvolved: ['TLS_CRYPTO_HANDSHAKE', 'L4_TRANSPORT_CONGESTION'],
        description: `Measured TLS handshake (${measuredMetrics.tlsHandshakeMs} ms) completed faster than a single measured TCP RTT (${measuredMetrics.tcpRttMs} ms), indicating local TLS termination or split-TCP proxy interception.`,
        adjustmentApplied: 'Flagged split-TCP / local proxy termination anomaly.'
      });
    }

    return {
      contradictions,
      domainMultipliers
    };
  }

  /**
   * Deduplicates settled incidents so repeated synthetic template clones (identical root cause,
   * observations, and predictedDomains, even when assigned different synthetic incidentIds or timestamps)
   * cannot artificially inflate the >= 10 independent incident calibration gate (Cycle 4).
   */
  _deduplicateSettledIncidents(settledIncidents = []) {
    const allSupplied = Array.isArray(settledIncidents) ? settledIncidents : [];
    let missingGroundTruthCount = 0;
    let untrustedProvenanceCount = 0;
    let invalidTimestampIncidentsCount = 0;
    let invalidDistributionIncidentsCount = 0;

    const rawList = [];
    for (const inc of allSupplied) {
      if (!inc || typeof inc !== 'object') {
        missingGroundTruthCount += 1;
        continue;
      }
      if (typeof inc.actualRootCauseDomain !== 'string' || !inc.actualRootCauseDomain.trim()) {
        missingGroundTruthCount += 1;
        continue;
      }
      if (
        inc.synthetic === true ||
        inc.groundTruthVerified === false ||
        String(inc.provenance || '').toUpperCase() === 'SYNTHETIC_CLONE' ||
        String(inc.provenance || '').toUpperCase() === 'UNVERIFIED_SYNTHETIC'
      ) {
        untrustedProvenanceCount += 1;
        continue;
      }
      if (inc.settledAtMs !== undefined || inc.timestamp !== undefined) {
        const parsedTs =
          typeof inc.settledAtMs === 'number'
            ? inc.settledAtMs
            : Date.parse(String(inc.settledAtMs || inc.timestamp || ''));
        if (!Number.isFinite(parsedTs) || parsedTs <= 0) {
          invalidTimestampIncidentsCount += 1;
          continue;
        }
      }
      if (Array.isArray(inc.predictedDomains) && inc.predictedDomains.length > 0) {
        const seenDomainsInEntry = new Set();
        let probSumPct = 0;
        let hasInvalidEntry = false;
        for (const d of inc.predictedDomains) {
          if (!d || typeof d !== 'object') {
            hasInvalidEntry = true;
            break;
          }
          const domName = String(d.domain || d.layer || '').trim();
          const rawP = d.probabilityPct !== undefined ? Number(d.probabilityPct) : Number(d.prob) * 100;
          if (!domName || !Number.isFinite(rawP) || rawP < 0 || rawP > 100) {
            hasInvalidEntry = true;
            break;
          }
          if (seenDomainsInEntry.has(domName)) {
            hasInvalidEntry = true;
            break;
          }
          seenDomainsInEntry.add(domName);
          probSumPct += rawP;
        }
        if (hasInvalidEntry || probSumPct > 105 || probSumPct <= 0) {
          invalidDistributionIncidentsCount += 1;
          continue;
        }
      }
      rawList.push(inc);
    }

    const seenIds = new Set();
    const seenCanonicalKeys = new Set();
    const seenContentSignatures = new Set();
    const deduplicated = [];

    for (const inc of rawList) {
      const explicitId = inc.incidentId ? String(inc.incidentId).trim() : '';
      if (explicitId) {
        if (seenIds.has(explicitId)) continue;
      }

      const canonicalKey = String(inc.canonicalIncidentKey || inc.rootEventRef || '').trim();
      if (canonicalKey) {
        if (seenCanonicalKeys.has(canonicalKey)) continue;
      }

      const obsSig = inc.observations && typeof inc.observations === 'object'
        ? JSON.stringify(Object.keys(inc.observations).sort().map((k) => [k, inc.observations[k]]))
        : '';
      const predSig = Array.isArray(inc.predictedDomains)
        ? JSON.stringify(
            inc.predictedDomains.map((d) => [d.domain || d.layer || '', Number(d.probabilityPct ?? d.prob ?? 0)])
          )
        : '';

      // Content-based signature independent of synthetic incidentId or timestamp so cloned incidents with mutated IDs/timestamps are still deduplicated
      const contentSig = `${inc.actualRootCauseDomain.trim()}|${obsSig}|${predSig}`;
      if (seenContentSignatures.has(contentSig)) {
        continue;
      }

      if (explicitId) seenIds.add(explicitId);
      if (canonicalKey) seenCanonicalKeys.add(canonicalKey);
      seenContentSignatures.add(contentSig);
      deduplicated.push(inc);
    }

    return {
      totalSuppliedCount: allSupplied.length,
      rawSuppliedCount: rawList.length,
      deduplicated,
      duplicatesRemovedCount: rawList.length - deduplicated.length,
      missingGroundTruthCount,
      untrustedProvenanceCount,
      invalidTimestampIncidentsCount,
      invalidDistributionIncidentsCount
    };
  }

  /**
   * Estimates empirical prior probabilities from settled historical incidents ONLY when
   * minimum independent deduplicated sample size (>= 10) and distinct domain coverage (>= 2) are satisfied.
   */
  _computeEmpiricalPriorsFromSettledIncidents(settledIncidents = []) {
    const { deduplicated: valid } = this._deduplicateSettledIncidents(settledIncidents);
    const distinct = new Set(valid.map((inc) => inc.actualRootCauseDomain.trim()));
    if (valid.length < this.minimumCalibrationSampleSize || distinct.size < this.minimumCalibrationDistinctDomains) {
      return {
        hasEmpiricalPriors: false,
        priorSource: 'CONFIGURED_DOMAIN_PRIORS',
        priorsByDomain: {}
      };
    }
    const counts = {};
    const domainKeys = Object.keys(this.domainMetadata);
    for (const k of domainKeys) counts[k] = 1; // Laplace smoothing alpha=1
    for (const inc of valid) {
      const dom = inc.actualRootCauseDomain.trim();
      counts[dom] = (counts[dom] || 1) + 1;
    }
    const total = Object.values(counts).reduce((a, b) => a + b, 0) || 1;
    const priorsByDomain = {};
    for (const [k, c] of Object.entries(counts)) {
      priorsByDomain[k] = Number((c / total).toFixed(4));
    }
    return {
      hasEmpiricalPriors: true,
      priorSource: 'EMPIRICAL_LAPLACE_SMOOTHED_PRIORS',
      priorsByDomain
    };
  }

  /**
   * Synthesizes fault-domain hypotheses from whatever direct, cross-layer, or historical
   * signals are genuinely present, without inventing observations for missing layers.
   */
  synthesizeIndirectDomains(observations = {}, episodicMatches = [], options = {}) {
    const obs = observations && typeof observations === 'object' ? observations : {};
    const safeMatches = Array.isArray(episodicMatches) ? episodicMatches : [];

    const hasNumeric = (v) => typeof v === 'number' && Number.isFinite(v) && v >= 0;

    const measuredMetrics = {
      tcpRttMs: hasNumeric(obs.tcpRttMs) ? Number(obs.tcpRttMs) : null,
      tcpJitterMs: hasNumeric(obs.tcpJitterMs) ? Number(obs.tcpJitterMs) : null,
      tlsHandshakeMs: hasNumeric(obs.tlsHandshakeMs) ? Number(obs.tlsHandshakeMs) : null,
      httpLatencyMs: hasNumeric(obs.httpLatencyMs) ? Number(obs.httpLatencyMs) : null,
      dnsLatencyMs: hasNumeric(obs.dnsLatencyMs) ? Number(obs.dnsLatencyMs) : null,
      icmpLossPct: hasNumeric(obs.icmpLossPct) ? Number(obs.icmpLossPct) : null,
      hostSocketQueueDepth: hasNumeric(obs.hostSocketQueueDepth) ? Number(obs.hostSocketQueueDepth) : null
    };

    const measuredLayerCount = Object.values(measuredMetrics).filter((v) => v !== null).length;

    const unmeasuredLayers = [];
    if (measuredMetrics.dnsLatencyMs === null) unmeasuredLayers.push('DNS_CONTROL_PLANE');
    if (measuredMetrics.icmpLossPct === null) unmeasuredLayers.push('L3_ICMP_DIRECT');
    if (measuredMetrics.tcpRttMs === null) unmeasuredLayers.push('L4_TCP_DIRECT');
    if (measuredMetrics.tlsHandshakeMs === null) unmeasuredLayers.push('TLS_CRYPTO_HANDSHAKE');
    if (measuredMetrics.httpLatencyMs === null) unmeasuredLayers.push('L7_UPSTREAM_APPLICATION');
    if (measuredMetrics.hostSocketQueueDepth === null) unmeasuredLayers.push('HOST_KERNEL_SOCKET');

    // Evaluate empirical calibration status if settledIncidents were supplied
    const calibrationStatus = Array.isArray(options.settledIncidents) && options.settledIncidents.length > 0
      ? this.evaluateCalibrationAgainstSettledIncidents(options.settledIncidents, { _skipAutoSynthesize: true })
      : { calibrated: false, confidenceType: 'INSUFFICIENT_DATA', sampleSize: 0, calibrationTemperature: 1.0 };

    // Only apply empirical priors from settled incidents if holdout calibration also succeeded (or use training slice priors)
    const empiricalPriorsInfo = calibrationStatus.calibrated
      ? this._computeEmpiricalPriorsFromSettledIncidents(options.settledIncidents)
      : { hasEmpiricalPriors: false, priorSource: 'CONFIGURED_DOMAIN_PRIORS', priorsByDomain: {} };

    // Candidate map: domain -> { rawScore, configuredPriorProb, empiricalPriorProb, priorProb, logLikelihood, evidenceSources, reasons }
    const candidates = new Map();
    const addCandidate = (domain, ruleScoreDelta, logLikelihoodDelta, sourceType, reason) => {
      if (ruleScoreDelta <= 0) return;
      let entry = candidates.get(domain);
      if (!entry) {
        const meta = this.domainMetadata[domain] || { priorProb: 0.15 };
        const configuredPriorProb = meta.priorProb;
        const empiricalPriorProb = empiricalPriorsInfo.hasEmpiricalPriors
          ? empiricalPriorsInfo.priorsByDomain[domain] ?? configuredPriorProb
          : null;
        entry = {
          domain,
          rawScore: 0,
          configuredPriorProb,
          empiricalPriorProb,
          priorProb: empiricalPriorProb !== null ? empiricalPriorProb : configuredPriorProb,
          priorSource: empiricalPriorProb !== null ? 'EMPIRICAL_PRIOR' : 'CONFIGURED_PRIOR',
          logLikelihood: 0,
          evidenceSources: new Set(),
          reasons: []
        };
        candidates.set(domain, entry);
      }
      entry.rawScore += ruleScoreDelta;
      entry.logLikelihood += logLikelihoodDelta;
      entry.evidenceSources.add(sourceType);
      if (reason) entry.reasons.push(reason);
    };

    const lossInference = this.estimatePacketLossFromTcpTiming(
      measuredMetrics.tcpRttMs,
      obs.baselineRttMs || 15,
      measuredMetrics.tcpJitterMs || 0
    );

    // 1. Direct DNS observation (ONLY when dnsLatencyMs is actually measured)
    if (measuredMetrics.dnsLatencyMs !== null) {
      if (measuredMetrics.dnsLatencyMs > 80) {
        const delta = 0.45 + Math.min(0.4, (measuredMetrics.dnsLatencyMs - 80) / 300);
        addCandidate(
          'DNS_CONTROL_PLANE',
          delta,
          Math.log(1.8 + (measuredMetrics.dnsLatencyMs - 80) / 100),
          'DIRECT_DNS_OBSERVATION',
          `Measured DNS resolution latency is elevated (${measuredMetrics.dnsLatencyMs} ms).`
        );
      } else {
        addCandidate(
          'DNS_CONTROL_PLANE',
          0.04,
          -1.2,
          'DIRECT_DNS_OBSERVATION',
          `Measured DNS resolution latency is nominal (${measuredMetrics.dnsLatencyMs} ms).`
        );
      }
    }

    // 2. Direct L3 ICMP observation OR Indirect Cross-Layer L3 inference from TCP RTT + jitter
    if (measuredMetrics.icmpLossPct !== null) {
      if (measuredMetrics.icmpLossPct > 1.0) {
        const delta = 0.5 + Math.min(0.45, measuredMetrics.icmpLossPct / 40);
        addCandidate(
          'L3_NETWORK_PATH',
          delta,
          Math.log(2.0 + measuredMetrics.icmpLossPct / 10),
          'DIRECT_L3_ICMP_OBSERVATION',
          `Measured ICMP packet loss is ${measuredMetrics.icmpLossPct}%.`
        );
      }
    } else if (
      lossInference.inferredPacketLossRatio !== null &&
      lossInference.inferredPacketLossRatio > 0
    ) {
      const delta = 0.35 + lossInference.inferredPacketLossRatio * 1.2;
      addCandidate(
        'L3_NETWORK_PATH',
        delta,
        Math.log(1.4 + lossInference.inferredPacketLossRatio * 4),
        'INDIRECT_TCP_RTT_JITTER_COVARIANCE',
        `Direct ICMP is unavailable; TCP RTT (${measuredMetrics.tcpRttMs} ms) and jitter (${measuredMetrics.tcpJitterMs ?? 0} ms) indicate indirect L3 path degradation (inferred loss ratio=${lossInference.inferredPacketLossRatio}).`
      );
    }

    // 3. L4 Transport observation from TCP RTT & jitter
    if (measuredMetrics.tcpRttMs !== null) {
      const jitter = measuredMetrics.tcpJitterMs || 0;
      if (measuredMetrics.tcpRttMs > 60 || jitter > 15) {
        const delta = 0.42 + Math.min(0.45, measuredMetrics.tcpRttMs / 400 + jitter / 100);
        addCandidate(
          'L4_TRANSPORT_CONGESTION',
          delta,
          Math.log(1.75 + measuredMetrics.tcpRttMs / 150 + jitter / 40),
          'DIRECT_L4_TCP_OBSERVATION',
          `Measured TCP handshake RTT (${measuredMetrics.tcpRttMs} ms) and jitter (${jitter} ms) show transport queueing or retransmission delay.`
        );
      } else {
        addCandidate(
          'L4_TRANSPORT_CONGESTION',
          0.08,
          -0.9,
          'DIRECT_L4_TCP_OBSERVATION',
          `Measured TCP RTT (${measuredMetrics.tcpRttMs} ms) is within baseline bounds.`
        );
      }
    }

    // 4. TLS Handshake observation / Cross-Layer TLS residual delta (TLS handshake > 2.2x TCP RTT)
    if (measuredMetrics.tlsHandshakeMs !== null) {
      const expectedTlsOverhead = measuredMetrics.tcpRttMs !== null ? measuredMetrics.tcpRttMs * 2.2 : 60;
      const tlsExcessMs = measuredMetrics.tlsHandshakeMs - expectedTlsOverhead;
      if (tlsExcessMs > 40) {
        const sourceTag =
          measuredMetrics.tcpRttMs !== null
            ? 'INDIRECT_TLS_MINUS_TCP_RESIDUAL'
            : 'DIRECT_TLS_OBSERVATION';
        const delta = 0.38 + Math.min(0.45, tlsExcessMs / 250);
        addCandidate(
          'TLS_CRYPTO_HANDSHAKE',
          delta,
          Math.log(1.6 + tlsExcessMs / 100),
          sourceTag,
          `TLS handshake duration (${measuredMetrics.tlsHandshakeMs} ms) exceeds expected transport RTT multiple by ${tlsExcessMs.toFixed(1)} ms.`
        );
      }
    }

    // 5. Direct L7 HTTP observation (ONLY when httpLatencyMs is actually measured)
    if (measuredMetrics.httpLatencyMs !== null) {
      const transportBaseline =
        (measuredMetrics.tcpRttMs || 0) + (measuredMetrics.tlsHandshakeMs || 0);
      const appResidualMs = measuredMetrics.httpLatencyMs - transportBaseline;
      if (appResidualMs > 100 || measuredMetrics.httpLatencyMs > 250) {
        const delta = 0.48 + Math.min(0.4, Math.max(0, appResidualMs) / 500);
        addCandidate(
          'L7_UPSTREAM_APPLICATION',
          delta,
          Math.log(2.1 + Math.max(0, appResidualMs) / 150),
          'DIRECT_L7_OBSERVATION',
          `Measured HTTP L7 response time (${measuredMetrics.httpLatencyMs} ms) exhibits upstream application processing delay.`
        );
      } else {
        addCandidate(
          'L7_UPSTREAM_APPLICATION',
          0.06,
          -1.1,
          'DIRECT_L7_OBSERVATION',
          `Measured HTTP L7 response time (${measuredMetrics.httpLatencyMs} ms) is healthy.`
        );
      }
    }

    // 6. Host Kernel Socket observation (ONLY when hostSocketQueueDepth is actually measured)
    if (measuredMetrics.hostSocketQueueDepth !== null && measuredMetrics.hostSocketQueueDepth > 0) {
      const delta = 0.3 + Math.min(0.45, measuredMetrics.hostSocketQueueDepth / 128);
      addCandidate(
        'HOST_KERNEL_SOCKET',
        delta,
        Math.log(1.5 + measuredMetrics.hostSocketQueueDepth / 64),
        'DIRECT_HOST_SOCKET_OBSERVATION',
        `Measured local socket queue depth is ${measuredMetrics.hostSocketQueueDepth}.`
      );
    }

    // 7. Historical Episodic Memory Priors (strictly labeled HISTORICAL_EPISODIC_PRIOR)
    const episodicPriors = [];
    for (const match of safeMatches) {
      if (!match || typeof match !== 'object') continue;
      const dom = String(match.rootCauseDomain || match.domain || '').trim();
      const sim = Math.max(0, Math.min(1, Number(match.similarityScore ?? 0.5)));
      if (dom && sim > 0.2) {
        const priorBoost = Number((sim * 0.22).toFixed(4));
        episodicPriors.push({
          domain: dom,
          similarityScore: sim,
          priorBoost,
          incidentId: match.incidentId || null,
          evidenceClass: 'HISTORICAL_EPISODIC_PRIOR'
        });
        addCandidate(
          dom,
          priorBoost,
          Math.log(1 + sim * 0.5),
          'HISTORICAL_EPISODIC_PRIOR',
          `Historical episodic memory prior (similarity=${sim.toFixed(2)}) suggests ${dom}.`
        );
      }
    }

    // Evaluate cross-layer contradictions
    const { contradictions: contradictoryObservations, domainMultipliers } =
      this.detectContradictoryObservations(measuredMetrics, lossInference);

    for (const [dom, mult] of domainMultipliers.entries()) {
      const entry = candidates.get(dom);
      if (entry) {
        entry.rawScore = Number((entry.rawScore * mult).toFixed(4));
        entry.logLikelihood += Math.log(mult);
      }
    }

    // Check if we have any usable evidence at all
    if (candidates.size === 0) {
      return {
        abstentionPrevented: false,
        inferenceMode: 'INSUFFICIENT_EVIDENCE',
        confidenceType: 'INSUFFICIENT_DATA',
        statisticalMethodology: 'ABSTAINED_NO_TELEMETRY_OBSERVATIONS',
        priorDistributionSource: empiricalPriorsInfo.priorSource,
        calibrationSummary: calibrationStatus,
        inferredPacketLossRatio: null,
        measuredMetrics,
        inferredEstimates: {
          inferredPacketLossRatio: null,
          evidenceType: 'UNAVAILABLE_METRIC',
          confidenceType: 'INSUFFICIENT_DATA'
        },
        episodicPriors: [],
        contradictoryObservations: [],
        unmeasuredLayers,
        domains: [],
        dominantIndirectHypothesis: null,
        posteriorEntropyBits: 0,
        explanatoryReasoning:
          'Insufficient direct or cross-layer telemetry observations to form a grounded fault-domain posterior.',
        recommendedNextProbe: {
          probeType: 'TCP_SYN_RTT_AND_RETRANSMIT_SAMPLE',
          targetLayer: 'L4_TRANSPORT_CONGESTION',
          expectedInformationGainBits: 0,
          eigCalculationMethod: 'INSUFFICIENT_PRIOR_DISTRIBUTION',
          candidateProbesRankedByEig: [],
          rationale: 'Collect baseline L4 TCP handshake RTT and jitter before inferring cross-layer faults.'
        }
      };
    }

    const entries = Array.from(candidates.values());

    // Determine whether we have multi-signal likelihood data for Bayesian posterior or single-rule heuristic
    const useBayesianPosterior = measuredLayerCount >= 2 || (measuredLayerCount >= 1 && episodicPriors.length > 0);
    // Strictly require verified calibrationStatus.calibrated === true (deduplicated sampleSize >= 10, distinctDomains >= 2, and holdout verified)
    const hasEmpiricalCalibration = Boolean(calibrationStatus && calibrationStatus.calibrated === true);
    const calibrationTemp = Number(calibrationStatus?.calibrationTemperature) || 1.0;

    const confidenceType = hasEmpiricalCalibration
      ? 'EMPIRICALLY_CALIBRATED'
      : useBayesianPosterior
        ? 'BAYESIAN_LIKELIHOOD_POSTERIOR'
        : 'RULE_HEURISTIC';

    const totalRuleScore = entries.reduce((acc, item) => acc + item.rawScore, 0) || 1;

    // Compute unnormalized Bayesian posterior weights: P(D) * exp(logLikelihood)
    const bayesWeights = entries.map((item) => {
      const w = Math.max(1e-6, item.priorProb * Math.exp(Math.max(-4, Math.min(4, item.logLikelihood))));
      return w;
    });
    const totalBayesWeight = bayesWeights.reduce((a, b) => a + b, 0) || 1;

    // Temperature-calibrated weights when empirically calibrated
    const calibratedWeights = entries.map((item) => {
      const scaledLogL = Math.max(-4, Math.min(4, item.logLikelihood)) / Math.max(0.25, calibrationTemp);
      return Math.max(1e-6, item.priorProb * Math.exp(scaledLogL));
    });
    const totalCalibratedWeight = calibratedWeights.reduce((a, b) => a + b, 0) || 1;

    const domains = entries
      .map((item, idx) => {
        const sources = Array.from(item.evidenceSources);
        const primaryEvidenceType = sources.find((s) => s.startsWith('DIRECT_')) || sources[0];
        const ruleHeuristicScorePct = Number(((item.rawScore / totalRuleScore) * 100).toFixed(1));
        const bayesianPosteriorPct = Number(((bayesWeights[idx] / totalBayesWeight) * 100).toFixed(1));
        const calibratedPosteriorPct = hasEmpiricalCalibration
          ? Number(((calibratedWeights[idx] / totalCalibratedWeight) * 100).toFixed(1))
          : null;
        const probabilityPct = hasEmpiricalCalibration
          ? calibratedPosteriorPct
          : useBayesianPosterior
            ? bayesianPosteriorPct
            : ruleHeuristicScorePct;

        return {
          domain: item.domain,
          probabilityPct,
          ruleHeuristicScorePct,
          bayesianPosteriorPct,
          calibratedPosteriorPct,
          configuredPriorProb: item.configuredPriorProb,
          empiricalPriorProb: item.empiricalPriorProb,
          priorSource: item.priorSource,
          logLikelihood: Number(item.logLikelihood.toFixed(4)),
          confidenceType,
          evidenceType: primaryEvidenceType,
          evidenceSources: sources,
          isDirectObservation: sources.some((s) => s.startsWith('DIRECT_')),
          isHistoricalPriorOnly:
            sources.length === 1 && sources[0] === 'HISTORICAL_EPISODIC_PRIOR',
          supportingReasons: item.reasons
        };
      })
      .sort((a, b) => b.probabilityPct - a.probabilityPct);

    const dominant = domains[0] || null;
    const hasDirect = domains.some((d) => d.isDirectObservation);
    const hasIndirect = domains.some((d) =>
      d.evidenceSources.some((s) => s.startsWith('INDIRECT_'))
    );

    const inferenceMode = hasIndirect
      ? 'INDIRECT_CROSS_LAYER_BAYESIAN_SYNTHESIS'
      : hasDirect
        ? 'DIRECT_AND_PRIOR_GROUNDED_SYNTHESIS'
        : 'HISTORICAL_EPISODIC_PRIOR_ONLY';

    // Compute Shannon entropy of current posterior distribution and genuine Expected Information Gain (EIG) in bits
    const probDist = domains.map((d) => d.probabilityPct / 100);
    const currentEntropyBits = this._computeShannonEntropyBits(probDist);
    const domainProbsForEig = domains.map((d) => ({
      domain: d.domain,
      prob: d.probabilityPct / 100,
      isDirectObservation: d.isDirectObservation
    }));

    // Evaluate candidate probes via true Bayesian posterior entropy reduction H(D) - E_O[H(D|O)]
    const candidateProbes = domains.map((d) =>
      this._computeProbeExpectedInformationGain(domainProbsForEig, d.domain, currentEntropyBits)
    );
    candidateProbes.sort(
      (a, b) =>
        b.diagnosticUsefulnessScore - a.diagnosticUsefulnessScore ||
        b.expectedInformationGainBits - a.expectedInformationGainBits
    );

    const bestProbe = candidateProbes[0] || {
      probeType:
        (dominant &&
          this.domainMetadata[dominant.domain] &&
          this.domainMetadata[dominant.domain].defaultProbe) ||
        'TCP_SYN_RTT_AND_RETRANSMIT_SAMPLE',
      targetLayer: dominant ? dominant.domain : 'L4_TRANSPORT_CONGESTION',
      expectedInformationGainBits: 0,
      utilityAdjustedEigBits: 0,
      diagnosticUsefulnessScore: 0,
      eigCalculationMethod: 'HEURISTIC_PROBE_PRIORITY'
    };

    return {
      abstentionPrevented: true,
      inferenceMode,
      confidenceType,
      statisticalMethodology: hasEmpiricalCalibration
        ? 'EMPIRICALLY_CALIBRATED_BAYESIAN_POSTERIOR_HOLDOUT_VERIFIED'
        : useBayesianPosterior
          ? 'LOG_LIKELIHOOD_BAYESIAN_POSTERIOR_WITH_CONTRADICTION_PENALTY'
          : 'NORMALIZED_RULE_HEURISTIC_SCORE',
      priorDistributionSource: empiricalPriorsInfo.priorSource,
      calibrationSummary: {
        calibrated: calibrationStatus.calibrated,
        confidenceType: calibrationStatus.confidenceType,
        sampleSize: calibrationStatus.sampleSize,
        calibrationTemperature: calibrationTemp
      },
      inferredPacketLossRatio: lossInference.inferredPacketLossRatio,
      measuredMetrics,
      inferredEstimates: lossInference,
      episodicPriors,
      contradictoryObservations,
      unmeasuredLayers,
      domains,
      dominantIndirectHypothesis: dominant,
      posteriorEntropyBits: currentEntropyBits,
      explanatoryReasoning: dominant
        ? `Top suspected layer is ${dominant.domain} (${dominant.probabilityPct}%, confidenceType=${confidenceType}, source=${dominant.evidenceType}): ${dominant.supportingReasons.join(' ')}${contradictoryObservations.length > 0 ? ` [Contradictions noted: ${contradictoryObservations.map((c) => c.code).join(', ')}]` : ''}`
        : 'No dominant hypothesis identified.',
      recommendedNextProbe: {
        probeType: bestProbe.probeType,
        targetLayer: bestProbe.targetLayer,
        expectedInformationGainBits: bestProbe.expectedInformationGainBits,
        rawMutualInformationBits: bestProbe.rawMutualInformationBits ?? bestProbe.expectedInformationGainBits,
        utilityAdjustedEigBits: bestProbe.utilityAdjustedEigBits,
        diagnosticUsefulnessScore: bestProbe.diagnosticUsefulnessScore,
        expectedPosteriorEntropyBits: bestProbe.expectedPosteriorEntropyBits,
        probeCostWeight: bestProbe.probeCostWeight,
        operationalRiskWeight: bestProbe.operationalRiskWeight,
        probeCharacteristicSource: bestProbe.probeCharacteristicSource || 'CONFIGURED_HEURISTIC_PRIOR',
        probeAvailability: bestProbe.probeAvailability,
        observationFreshnessState: bestProbe.observationFreshnessState,
        eigCalculationMethod: bestProbe.eigCalculationMethod || 'BAYESIAN_POSTERIOR_ENTROPY_REDUCTION',
        candidateProbesRankedByEig: candidateProbes,
        rationale: `Execute ${bestProbe.probeType} (EIG=${bestProbe.expectedInformationGainBits} bits, diagnosticUsefulness=${bestProbe.diagnosticUsefulnessScore}, method=${bestProbe.eigCalculationMethod}) to directly disambiguate ${bestProbe.targetLayer} and reduce posterior entropy from ${currentEntropyBits} bits.`
      }
    };
  }

  /**
   * Evaluates empirical calibration (proper multiclass Brier score, Expected Calibration Error, and out-of-sample holdout validation)
   * against real settled historical incidents without fabricating synthetic training data (Cycle 4).
   */
  evaluateCalibrationAgainstSettledIncidents(settledIncidents = [], options = {}) {
    const minSampleSize = Math.max(10, Number(options.minSampleSize) || this.minimumCalibrationSampleSize);
    const minDistinctDomains = Math.max(2, Number(options.minDistinctDomains) || this.minimumCalibrationDistinctDomains);
    const maxAcceptableHoldoutBrier = Number(options.maxAcceptableHoldoutBrier) || 0.35;
    const maxAcceptableHoldoutEce = Number(options.maxAcceptableHoldoutEce) || 0.35;

    const {
      totalSuppliedCount,
      rawSuppliedCount,
      deduplicated,
      duplicatesRemovedCount,
      missingGroundTruthCount,
      untrustedProvenanceCount,
      invalidTimestampIncidentsCount,
      invalidDistributionIncidentsCount
    } = this._deduplicateSettledIncidents(settledIncidents);

    if (deduplicated.length === 0) {
      const hasInvalidData =
        untrustedProvenanceCount > 0 ||
        invalidTimestampIncidentsCount > 0 ||
        invalidDistributionIncidentsCount > 0;
      const onlyMissingGroundTruth =
        totalSuppliedCount > 0 && missingGroundTruthCount === totalSuppliedCount;

      return {
        calibrated: false,
        confidenceType: hasInvalidData
          ? 'INVALID_INCIDENT_DATA'
          : onlyMissingGroundTruth && options.strictGroundTruthState === true
            ? 'UNAVAILABLE_GROUND_TRUTH'
            : 'INSUFFICIENT_DATA',
        groundTruthState: onlyMissingGroundTruth ? 'UNAVAILABLE_GROUND_TRUTH' : 'INSUFFICIENT_OR_INVALID',
        totalSuppliedIncidentCount: totalSuppliedCount,
        rawSuppliedIncidentCount: rawSuppliedCount,
        duplicatesRemovedCount,
        missingGroundTruthCount,
        untrustedProvenanceCount,
        invalidTimestampIncidentsCount,
        invalidDistributionIncidentsCount,
        sampleSize: 0,
        distinctRootCauseDomainsCount: 0,
        minimumRequiredSampleSize: minSampleSize,
        minimumRequiredDistinctDomains: minDistinctDomains,
        brierScore: null,
        multiclassBrierScoreSum: null,
        validationBrierScore: null,
        holdoutBrierScore: null,
        expectedCalibrationError: null,
        top1AccuracyPct: null,
        calibrationTemperature: 1.0,
        note: 'No settled incidents with verified actualRootCauseDomain were supplied; refusing to fabricate calibration metrics.'
      };
    }

    // Sort chronologically if settledAtMs or timestamp is provided
    const ordered = [...deduplicated].sort((a, b) => {
      const ta = Number(a.settledAtMs || Date.parse(a.timestamp || '') || 0);
      const tb = Number(b.settledAtMs || Date.parse(b.timestamp || '') || 0);
      return ta - tb;
    });

    const distinctDomains = new Set(ordered.map((inc) => inc.actualRootCauseDomain.trim()));

    const evaluateSlice = (slice, temperature = 1.0) => {
      let halfMulticlassBrierSum = 0;
      let fullMulticlassBrierSum = 0;
      let correctTop1 = 0;
      const bins = Array.from({ length: 5 }, () => ({ count: 0, confSum: 0, accSum: 0 }));

      for (const inc of slice) {
        const actual = inc.actualRootCauseDomain.trim();
        const rawDomains = Array.isArray(inc.predictedDomains)
          ? inc.predictedDomains
          : options._skipAutoSynthesize
            ? []
            : this.synthesizeIndirectDomains(inc.observations || {}, inc.episodicMatches || [], { _skipAutoSynthesize: true }).domains;

        if (!Array.isArray(rawDomains) || rawDomains.length === 0) {
          halfMulticlassBrierSum += 1.0;
          fullMulticlassBrierSum += 2.0;
          continue;
        }

        // Preserve unassigned probability mass in a complement bucket if caller supplied only top-1 or partial predictions
        const rawEntries = rawDomains.map((d) => ({
          domain: String(d.domain || d.layer || '').trim(),
          prob: Math.max(0, Math.min(1, Number(d.probabilityPct !== undefined ? d.probabilityPct / 100 : d.prob || 0)))
        })).filter((d) => d.domain && d.prob > 0);

        const rawProbSum = rawEntries.reduce((acc, d) => acc + d.prob, 0);
        const hasSubstantialUnassignedMass = rawProbSum < 0.999 && rawEntries.length > 0;
        if (hasSubstantialUnassignedMass) {
          rawEntries.push({
            domain: '__UNASSIGNED_COMPLEMENT__',
            prob: Math.max(1e-4, 1 - rawProbSum)
          });
        }

        // Apply temperature scaling to domain log-probabilities: p_k(T) \propto p_k^(1/T)
        const invT = 1 / Math.max(0.25, temperature);
        const scaled = rawEntries.map((d) => {
          const pClamped = Math.max(1e-6, Math.min(0.999999, d.prob));
          const pScaled = Math.pow(pClamped, invT);
          return { domain: d.domain, pScaled };
        });
        const totalScaled = scaled.reduce((acc, s) => acc + s.pScaled, 0) || 1;
        const normDomains = scaled
          .map((s) => ({ domain: s.domain, prob: s.pScaled / totalScaled }))
          .sort((a, b) => b.prob - a.prob);

        // Do NOT exclude __UNASSIGNED_COMPLEMENT__ when it dominates all named classes (e.g., partial 10% prediction where 90% is unassigned)
        const overallTop = normDomains[0];
        const realRanked = normDomains.filter((d) => d.domain !== '__UNASSIGNED_COMPLEMENT__');
        const topNamed = realRanked[0] || overallTop;
        const complementDominates =
          overallTop && overallTop.domain === '__UNASSIGNED_COMPLEMENT__' && (!topNamed || overallTop.prob > topNamed.prob);
        const top = complementDominates ? overallTop : topNamed;
        const topConf = top ? top.prob : 0;
        const isTopCorrect = top && top.domain === actual ? 1 : 0;
        if (isTopCorrect) correctTop1 += 1;

        // Proper multiclass Brier score: sum_{k=1}^K (p_{i,k} - y_{i,k})^2 across ALL classes k
        let sampleSquaredErrorSum = 0;
        let seenActualInDistribution = false;
        for (const d of normDomains) {
          const yk = d.domain === actual ? 1 : 0;
          if (yk === 1) seenActualInDistribution = true;
          sampleSquaredErrorSum += Math.pow(d.prob - yk, 2);
        }
        if (!seenActualInDistribution) {
          // True class received 0 predicted probability: add (0 - 1)^2 = 1.0
          sampleSquaredErrorSum += 1.0;
        }

        fullMulticlassBrierSum += sampleSquaredErrorSum;
        halfMulticlassBrierSum += 0.5 * sampleSquaredErrorSum;

        const binIdx = Math.min(4, Math.floor(topConf * 5));
        bins[binIdx].count += 1;
        bins[binIdx].confSum += topConf;
        bins[binIdx].accSum += isTopCorrect;
      }

      const n = slice.length || 1;
      const brierScore = Number((halfMulticlassBrierSum / n).toFixed(4));
      const multiclassBrierScoreSum = Number((fullMulticlassBrierSum / n).toFixed(4));
      let ece = 0;
      for (const b of bins) {
        if (b.count > 0) {
          const avgConf = b.confSum / b.count;
          const avgAcc = b.accSum / b.count;
          ece += (b.count / n) * Math.abs(avgAcc - avgConf);
        }
      }
      return {
        brierScore,
        multiclassBrierScoreSum,
        expectedCalibrationError: Number(ece.toFixed(4)),
        top1AccuracyPct: Number(((correctTop1 / n) * 100).toFixed(1))
      };
    };

    const overallUncalibrated = evaluateSlice(ordered, 1.0);
    const n = ordered.length;
    const meetsSampleSize = n >= minSampleSize;
    const meetsDomainDiversity = distinctDomains.size >= minDistinctDomains;

    if (!meetsSampleSize || !meetsDomainDiversity) {
      return {
        calibrated: false,
        confidenceType: 'INSUFFICIENT_DATA',
        totalSuppliedIncidentCount: totalSuppliedCount,
        rawSuppliedIncidentCount: rawSuppliedCount,
        duplicatesRemovedCount,
        missingGroundTruthCount,
        untrustedProvenanceCount,
        invalidTimestampIncidentsCount,
        invalidDistributionIncidentsCount,
        sampleSize: n,
        distinctRootCauseDomainsCount: distinctDomains.size,
        minimumRequiredSampleSize: minSampleSize,
        minimumRequiredDistinctDomains: minDistinctDomains,
        brierScore: overallUncalibrated.brierScore,
        multiclassBrierScoreSum: overallUncalibrated.multiclassBrierScoreSum,
        uncalibratedBrierScore: overallUncalibrated.brierScore,
        validationBrierScore: null,
        holdoutBrierScore: null,
        expectedCalibrationError: overallUncalibrated.expectedCalibrationError,
        top1AccuracyPct: overallUncalibrated.top1AccuracyPct,
        calibrationTemperature: 1.0,
        note: `Insufficient settled incidents: Insufficient independent settled incidents for empirical calibration (deduplicated sampleSize=${n}, duplicatesRemoved=${duplicatesRemovedCount}, required>=${minSampleSize}; distinctDomains=${distinctDomains.size}, required>=${minDistinctDomains}). Returning descriptive uncalibrated metrics.`
      };
    }

    // Chronological 70/30 train/holdout split: fit temperature parameter T strictly on the 70% training slice
    const trainCount = Math.max(6, Math.floor(n * 0.7));
    const trainSlice = ordered.slice(0, trainCount);
    const valSlice = ordered.slice(trainCount);

    const candidateTemps = [0.6, 0.8, 1.0, 1.25, 1.5, 2.0];
    let bestTemp = 1.0;
    let bestTrainEval = evaluateSlice(trainSlice, 1.0);
    for (const t of candidateTemps) {
      const res = evaluateSlice(trainSlice, t);
      if (res.brierScore < bestTrainEval.brierScore) {
        bestTrainEval = res;
        bestTemp = t;
      }
    }

    const calibratedOverall = evaluateSlice(ordered, bestTemp);
    const validationMetrics = valSlice.length > 0 ? evaluateSlice(valSlice, bestTemp) : calibratedOverall;
    const holdoutPassed =
      validationMetrics.brierScore <= maxAcceptableHoldoutBrier &&
      validationMetrics.expectedCalibrationError <= maxAcceptableHoldoutEce;

    // Compute per-domain calibration & diagnostic accuracy metrics (Phase Atlas IX — Cycle 1)
    const perDomainCalibrationMetrics = {};
    for (const domainName of distinctDomains) {
      let supportCount = 0;
      let truePositives = 0;
      let falsePositives = 0;
      let falseNegatives = 0;
      let domainBrierSum = 0;

      for (const inc of ordered) {
        const rawDomains = Array.isArray(inc.predictedDomains) ? inc.predictedDomains : [];
        const rawEntries = rawDomains.map((d) => ({
          domain: String(d.domain || d.layer || '').trim(),
          prob: Math.max(0, Math.min(1, Number(d.probabilityPct !== undefined ? d.probabilityPct / 100 : d.prob || 0)))
        })).filter((d) => d.domain && d.prob > 0);
        const invT = 1 / Math.max(0.25, bestTemp);
        const scaled = rawEntries.map((d) => ({
          domain: d.domain,
          pScaled: Math.pow(Math.max(1e-6, Math.min(0.999999, d.prob)), invT)
        }));
        const totalScaled = scaled.reduce((acc, s) => acc + s.pScaled, 0) || 1;
        const normDomains = scaled
          .map((s) => ({ domain: s.domain, prob: s.pScaled / totalScaled }))
          .sort((a, b) => b.prob - a.prob);

        const matchEntry = normDomains.find((d) => d.domain === domainName);
        const pDomain = matchEntry ? matchEntry.prob : 0;
        const isActual = inc.actualRootCauseDomain === domainName ? 1 : 0;
        domainBrierSum += Math.pow(pDomain - isActual, 2);

        const topPredicted = normDomains[0]?.domain || null;
        if (isActual === 1) {
          supportCount += 1;
          if (topPredicted === domainName) {
            truePositives += 1;
          } else {
            falseNegatives += 1;
          }
        } else if (topPredicted === domainName) {
          falsePositives += 1;
        }
      }

      perDomainCalibrationMetrics[domainName] = {
        domain: domainName,
        supportCount,
        truePositives,
        falsePositives,
        falseNegatives,
        precision:
          truePositives + falsePositives > 0
            ? Number((truePositives / (truePositives + falsePositives)).toFixed(4))
            : null,
        recall: supportCount > 0 ? Number((truePositives / supportCount).toFixed(4)) : null,
        binaryBrierScore: Number((domainBrierSum / Math.max(1, ordered.length)).toFixed(4))
      };
    }

    return {
      calibrated: holdoutPassed,
      confidenceType: holdoutPassed ? 'EMPIRICALLY_CALIBRATED' : 'POORLY_CALIBRATED_ON_HOLDOUT',
      totalSuppliedIncidentCount: totalSuppliedCount,
      rawSuppliedIncidentCount: rawSuppliedCount,
      duplicatesRemovedCount,
      missingGroundTruthCount,
      untrustedProvenanceCount,
      invalidTimestampIncidentsCount,
      invalidDistributionIncidentsCount,
      sampleSize: n,
      distinctRootCauseDomainsCount: distinctDomains.size,
      minimumRequiredSampleSize: minSampleSize,
      minimumRequiredDistinctDomains: minDistinctDomains,
      trainSampleSize: trainSlice.length,
      validationSampleSize: valSlice.length,
      calibrationTemperature: bestTemp,
      uncalibratedBrierScore: overallUncalibrated.brierScore,
      trainBrierScore: bestTrainEval.brierScore,
      inSampleBrierScore: bestTrainEval.brierScore,
      brierScore: calibratedOverall.brierScore,
      multiclassBrierScoreSum: calibratedOverall.multiclassBrierScoreSum,
      validationBrierScore: validationMetrics.brierScore,
      holdoutBrierScore: validationMetrics.brierScore,
      expectedCalibrationError: calibratedOverall.expectedCalibrationError,
      validationExpectedCalibrationError: validationMetrics.expectedCalibrationError,
      holdoutExpectedCalibrationError: validationMetrics.expectedCalibrationError,
      top1AccuracyPct: calibratedOverall.top1AccuracyPct,
      holdoutTop1AccuracyPct: validationMetrics.top1AccuracyPct,
      perDomainCalibrationMetrics,
      note: holdoutPassed
        ? `Empirically calibrated on ${trainSlice.length} training incidents and verified on ${valSlice.length} out-of-sample holdout incidents (holdoutBrier=${validationMetrics.brierScore}).`
        : `Sufficient sample size (${n}), but out-of-sample holdout validation failed quality thresholds (holdoutBrier=${validationMetrics.brierScore} > ${maxAcceptableHoldoutBrier} or holdoutECE=${validationMetrics.expectedCalibrationError} > ${maxAcceptableHoldoutEce}).`
    };
  }
}

const indirectCrossLayerInferencer = new IndirectCrossLayerInferencer();

module.exports = {
  IndirectCrossLayerInferencer,
  indirectCrossLayerInferencer
};
