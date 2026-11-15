/**
 * EJII Continuous Stochastic Differential Equation (SDE) Degradation Engine
 *
 * Implements:
 *   1. Continuous Ornstein-Uhlenbeck (OU) Mean-Reverting Process with Geometric Volatility:
 *      ds_t = \theta (\mu - s_t) dt + \sigma \sqrt{s_t} dW_t
 *      where:
 *        - \theta: mean-reversion rate / elasticity
 *        - \mu: long-term asymptotic baseline
 *        - \sigma: diffusion volatility
 *        - W_t: standard Wiener process (Brownian motion)
 *
 *   2. Euler-Maruyama Numerical Discretization:
 *      s_{t+\Delta t} = s_t + \theta (\mu - s_t) \Delta t + \sigma \sqrt{\max(0, s_t \Delta t)} \cdot Z_t,
 *      Z_t \sim \mathcal{N}(0, 1)
 *
 *   3. Analytical & Monte Carlo First-Passage Time (FPT) Distribution:
 *      Calculates cumulative survival curve S(t) = P(T > t) to critical failure barrier B.
 *      Computes Value-at-Risk (VaR) Time-to-Failure at 95% and 99% confidence horizons:
 *      TTF_{95%} = \inf \{ t : S(t) \le 0.05 \},  TTF_{99%} = \inf \{ t : S(t) \le 0.01 \}
 */

'use strict';

export interface SdeParameters {
  theta: number; // Mean-reversion speed (>= 0)
  mu: number; // Asymptotic equilibrium baseline
  sigma: number; // Volatility / diffusion scaling
  s0?: number; // Starting state value
}

export interface SimulationOptions {
  dt?: number; // Discretization step delta in seconds (default: 0.1)
  steps?: number; // Number of steps per path (default: 200)
  numPaths?: number; // Number of Monte Carlo trajectories (default: 100)
  seed?: number; // Optional seed for deterministic pseudo-random sequence
  thresholdB?: number; // Barrier threshold for first-passage calculation
}

export interface SdeTrajectory {
  timePoints: number[];
  states: number[];
  breached: boolean;
  firstPassageTime: number | null;
}

export interface FirstPassageTimeResult {
  thresholdB: number;
  initialState: number;
  expectedHittingTimeSeconds: number | null;
  medianHittingTimeSeconds: number | null;
  var95TimeToFailureSeconds: number | null;
  var99TimeToFailureSeconds: number | null;
  survivalProbabilityAtHorizon: number;
  survivalCurve: Array<{ t: number; survivalProb: number }>;
  pathsSimulated: number;
  breachFraction: number;
  riskTier: 'CRITICAL_IMMINENT' | 'HIGH_DRIFT' | 'ELEVATED' | 'NOMINAL_STABLE';
  summary: string;
}

/**
 * Deterministic pseudo-random standard normal generator.
 * Supports optional seed or cryptographic/system random.
 */
class GaussianSampler {
  private state: number;

  constructor(seed?: number) {
    this.state = typeof seed === 'number' && Number.isFinite(seed) ? Math.floor(Math.abs(seed)) % 2147483647 : 0;
  }

  private nextUniform(): number {
    if (this.state === 0) {
      return Math.random();
    }
    // Park-Miller / Lehmer LCG
    this.state = (this.state * 48271) % 2147483647;
    return this.state / 2147483647;
  }

  nextStandardNormal(): number {
    let u = 0;
    let v = 0;
    while (u <= 1e-9) {
      u = this.nextUniform();
    }
    while (v <= 1e-9) {
      v = this.nextUniform();
    }
    // Box-Muller transform
    return Math.sqrt(-2.0 * Math.log(u)) * Math.cos(2.0 * Math.PI * v);
  }
}

/**
 * Calibrates continuous SDE parameters (\theta, \mu, \sigma) from historical discrete observations.
 * Uses Ordinary Least Squares (OLS) AR(1) transition regression.
 */
export function estimateSdeParameters(series: number[], dt: number = 1.0): SdeParameters {
  const clean = (series || []).filter((v) => typeof v === 'number' && Number.isFinite(v));
  const N = clean.length;

  if (N < 3) {
    const defaultVal = clean[clean.length - 1] ?? 20.0;
    return { theta: 0.1, mu: defaultVal, sigma: 0.2, s0: defaultVal };
  }

  const s0 = clean[clean.length - 1];

  // AR(1) regression: y_{i} = a + b * y_{i-1} + e_i
  let sumX = 0;
  let sumY = 0;
  let sumXY = 0;
  let sumXX = 0;
  const count = N - 1;

  for (let i = 0; i < count; i++) {
    const x = clean[i];
    const y = clean[i + 1];
    sumX += x;
    sumY += y;
    sumXY += x * y;
    sumXX += x * x;
  }

  const denom = count * sumXX - sumX * sumX;
  const b = Math.abs(denom) > 1e-12 ? (count * sumXY - sumX * sumY) / denom : 0.95;
  const a = (sumY - b * sumX) / count;

  let theta = 0.1;
  let mu = s0;

  if (b > 0 && b < 0.999) {
    theta = -Math.log(b) / Math.max(1e-4, dt);
    mu = a / (1 - b);
  } else if (b >= 0.999) {
    // Non-reverting upward/downward drift
    theta = 0.01;
    mu = Math.max(s0, clean.reduce((max, v) => Math.max(max, v), s0) * 1.5);
  } else {
    theta = 0.5;
    mu = sumY / count;
  }

  // Calculate residual variance for volatility \sigma
  let resSumSq = 0;
  for (let i = 0; i < count; i++) {
    const expectedY = a + b * clean[i];
    const diff = clean[i + 1] - expectedY;
    resSumSq += diff * diff;
  }
  const resVar = resSumSq / Math.max(1, count - 2);

  // For geometric diffusion ds_t = \theta(\mu - s)dt + \sigma \sqrt{s} dW
  const avgS = Math.max(1e-3, clean.reduce((sum, v) => sum + Math.abs(v), 0) / N);
  const sigma = Math.max(0.01, Math.sqrt(resVar / (avgS * Math.max(1e-4, dt))));

  return {
    theta: Number(Math.max(0.001, theta).toFixed(4)),
    mu: Number(mu.toFixed(2)),
    sigma: Number(sigma.toFixed(4)),
    s0: Number(s0.toFixed(2))
  };
}

/**
 * Simulates a single Euler-Maruyama sample trajectory for the Ornstein-Uhlenbeck SDE:
 * s_{t+\Delta t} = s_t + \theta (\mu - s_t) \Delta t + \sigma \sqrt{\max(0, s_t \Delta t)} \cdot Z_t
 */
export function simulateEulerMaruyamaPath(
  params: SdeParameters,
  options: SimulationOptions = {},
  sampler?: GaussianSampler
): SdeTrajectory {
  const dt = Math.max(1e-4, options.dt ?? 0.1);
  const steps = Math.max(1, options.steps ?? 200);
  const thresholdB = options.thresholdB ?? Infinity;
  const localSampler = sampler ?? new GaussianSampler(options.seed);

  const { theta, mu, sigma } = params;
  let current = params.s0 ?? mu;

  const timePoints: number[] = [0];
  const states: number[] = [current];
  let breached = current >= thresholdB;
  let firstPassageTime: number | null = breached ? 0 : null;

  for (let step = 1; step <= steps; step++) {
    const t = Number((step * dt).toFixed(4));
    const z = localSampler.nextStandardNormal();

    // Euler-Maruyama discretization step
    const drift = theta * (mu - current) * dt;
    const diffusionScale = sigma * Math.sqrt(Math.max(0, current * dt));
    const diffusion = diffusionScale * z;

    current = Math.max(0, current + drift + diffusion);

    timePoints.push(t);
    states.push(Number(current.toFixed(4)));

    if (!breached && current >= thresholdB) {
      breached = true;
      firstPassageTime = t;
    }
  }

  return {
    timePoints,
    states,
    breached,
    firstPassageTime
  };
}

/**
 * Solves First-Passage Time (FPT) distribution to failure barrier B via high-fidelity Monte Carlo ensemble.
 */
export function calculateFirstPassageTime(
  params: SdeParameters,
  thresholdB: number,
  options: SimulationOptions = {}
): FirstPassageTimeResult {
  const dt = Math.max(1e-4, options.dt ?? 0.1);
  const steps = Math.max(1, options.steps ?? 200);
  const numPaths = Math.max(10, options.numPaths ?? 100);
  const sampler = new GaussianSampler(options.seed);

  const initial = params.s0 ?? params.mu;
  const maxTime = steps * dt;

  if (initial >= thresholdB) {
    return {
      thresholdB,
      initialState: initial,
      expectedHittingTimeSeconds: 0,
      medianHittingTimeSeconds: 0,
      var95TimeToFailureSeconds: 0,
      var99TimeToFailureSeconds: 0,
      survivalProbabilityAtHorizon: 0,
      survivalCurve: [{ t: 0, survivalProb: 0 }],
      pathsSimulated: numPaths,
      breachFraction: 1.0,
      riskTier: 'CRITICAL_IMMINENT',
      summary: `Immediate breach: Current state (${initial}) already meets or exceeds critical barrier (${thresholdB}).`
    };
  }

  const fptTimes: number[] = [];
  let breachCount = 0;

  // Track survival count at discrete checkpoint intervals (20 slices)
  const numCheckpoints = 20;
  const checkpointInterval = Math.max(1, Math.floor(steps / numCheckpoints));
  const checkpointSurvivals: number[] = new Array(numCheckpoints + 1).fill(numPaths);
  const checkpointTimes: number[] = [];

  for (let c = 0; c <= numCheckpoints; c++) {
    checkpointTimes.push(Number((c * checkpointInterval * dt).toFixed(2)));
  }

  for (let p = 0; p < numPaths; p++) {
    const trajectory = simulateEulerMaruyamaPath(
      params,
      { dt, steps, thresholdB },
      sampler
    );

    if (trajectory.breached && trajectory.firstPassageTime !== null) {
      breachCount++;
      fptTimes.push(trajectory.firstPassageTime);

      // Decrement survival for all checkpoints after breach
      for (let c = 1; c <= numCheckpoints; c++) {
        if (checkpointTimes[c] >= trajectory.firstPassageTime) {
          checkpointSurvivals[c]--;
        }
      }
    }
  }

  // Construct survival curve S(t) = P(T > t)
  const survivalCurve = checkpointTimes.map((t, idx) => ({
    t,
    survivalProb: Number((checkpointSurvivals[idx] / numPaths).toFixed(4))
  }));

  const breachFraction = Number((breachCount / numPaths).toFixed(4));
  const survivalProbabilityAtHorizon = survivalCurve[survivalCurve.length - 1]?.survivalProb ?? 1.0;

  // Hitting time statistics over paths that breached
  fptTimes.sort((a, b) => a - b);

  let expectedHittingTimeSeconds: number | null = null;
  let medianHittingTimeSeconds: number | null = null;
  let var95TimeToFailureSeconds: number | null = null;
  let var99TimeToFailureSeconds: number | null = null;

  if (fptTimes.length > 0) {
    const sum = fptTimes.reduce((acc, t) => acc + t, 0);
    expectedHittingTimeSeconds = Number((sum / fptTimes.length).toFixed(2));
    medianHittingTimeSeconds = fptTimes[Math.floor(fptTimes.length * 0.5)];

    // VaR 95%: Time where 5% of all paths have breached (or 5th percentile of breach times)
    const p95Idx = Math.floor(numPaths * 0.05);
    if (fptTimes.length > p95Idx) {
      var95TimeToFailureSeconds = fptTimes[p95Idx];
    }

    // VaR 99%: Time where 1% of all paths have breached
    const p99Idx = Math.floor(numPaths * 0.01);
    if (fptTimes.length > p99Idx) {
      var99TimeToFailureSeconds = fptTimes[p99Idx];
    }
  }

  // Classify risk tier
  let riskTier: FirstPassageTimeResult['riskTier'] = 'NOMINAL_STABLE';
  if (breachFraction >= 0.50 || (var95TimeToFailureSeconds !== null && var95TimeToFailureSeconds <= 30)) {
    riskTier = 'CRITICAL_IMMINENT';
  } else if (breachFraction >= 0.20 || (var95TimeToFailureSeconds !== null && var95TimeToFailureSeconds <= 120)) {
    riskTier = 'HIGH_DRIFT';
  } else if (breachFraction > 0.05) {
    riskTier = 'ELEVATED';
  }

  const summary = `FPT SDE Evaluation (barrier=${thresholdB}, breach=${(breachFraction * 100).toFixed(1)}%, ` +
    `S(${maxTime.toFixed(1)}s)=${(survivalProbabilityAtHorizon * 100).toFixed(1)}%): ` +
    (var95TimeToFailureSeconds !== null
      ? `95% VaR TTF horizon is ${var95TimeToFailureSeconds}s.`
      : 'No 95% breach horizon within simulation time.');

  return {
    thresholdB,
    initialState: initial,
    expectedHittingTimeSeconds,
    medianHittingTimeSeconds,
    var95TimeToFailureSeconds,
    var99TimeToFailureSeconds,
    survivalProbabilityAtHorizon,
    survivalCurve,
    pathsSimulated: numPaths,
    breachFraction,
    riskTier,
    summary
  };
}

export class StochasticDifferentialEngine {
  public estimateParameters(series: number[], dt?: number): SdeParameters {
    return estimateSdeParameters(series, dt);
  }

  public simulatePath(params: SdeParameters, options?: SimulationOptions): SdeTrajectory {
    return simulateEulerMaruyamaPath(params, options);
  }

  public calculateFirstPassageTime(
    params: SdeParameters,
    thresholdB: number,
    options?: SimulationOptions
  ): FirstPassageTimeResult {
    return calculateFirstPassageTime(params, thresholdB, options);
  }
}

export const stochasticDifferentialEngine = new StochasticDifferentialEngine();
