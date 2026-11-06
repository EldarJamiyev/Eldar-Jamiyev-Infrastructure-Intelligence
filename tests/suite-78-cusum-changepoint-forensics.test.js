"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.runSuite78CusumChangepointForensics = runSuite78CusumChangepointForensics;
// tests/suite-78-cusum-changepoint-forensics.test.ts
const assert = __importStar(require("node:assert"));
const cusum_changepoint_engine_1 = require("../src/ai/cusum-changepoint-engine");
async function runSuite78CusumChangepointForensics() {
    console.log('=== [SUITE 78] PAGE\'S CUSUM CHANGEPOINT FORENSICS & CAUSAL PRECEDENCE VERIFICATION ===');
    // 1. Two-Sided Tabular Page's CUSUM on Step Change Telemetry
    console.log('[78.1] Verifying two-sided CUSUM shift detection and retrospective onset pinpointing...');
    const engine = new cusum_changepoint_engine_1.CusumChangepointEngine(0.5, 4.0); // k = 0.5, h = 4.0
    // Generate 40 samples:
    // t = 0..19: baseline ~20.0ms (Gaussian noise +/- 0.5)
    // t = 20..39: sudden step change to ~80.0ms (shift of +60ms / ~120 sigmas!)
    const sampleCount = 40;
    const rttValues = new Float64Array(sampleCount);
    const timestamps = [];
    for (let t = 0; t < 20; t++) {
        rttValues[t] = 20.0 + ((t % 3) - 1) * 0.2;
        timestamps.push(1000 + t * 1000);
    }
    for (let t = 20; t < 40; t++) {
        rttValues[t] = 80.0 + ((t % 3) - 1) * 0.3;
        timestamps.push(1000 + t * 1000);
    }
    const changepoint = engine.evaluateSeriesCusum(rttValues, timestamps, 'rttMs', 15);
    assert.strictEqual(changepoint.shiftDetected, true, 'CUSUM must detect step shift');
    assert.strictEqual(changepoint.direction, 'INCREASE', 'Direction must be INCREASE');
    assert.ok(changepoint.changepointIndex !== null, 'Changepoint onset index must be determined');
    // Retrospective onset index should be exactly at or near t=20
    assert.ok(changepoint.changepointIndex >= 19 && changepoint.changepointIndex <= 21, `Retrospective onset index should be ~20, got ${changepoint.changepointIndex}`);
    assert.strictEqual(changepoint.onsetTimestampMs, timestamps[changepoint.changepointIndex], 'Onset timestamp must match timestamps[index]');
    assert.ok(changepoint.triggerTimestampMs !== null && changepoint.triggerTimestampMs >= changepoint.onsetTimestampMs, 'Trigger timestamp must follow onset');
    assert.ok(changepoint.shiftMagnitudeSigmas > 10, `Shift magnitude in sigmas should be huge, got ${changepoint.shiftMagnitudeSigmas}`);
    assert.ok(changepoint.maxCusumStatistic > 4.0, `Max CUSUM statistic must exceed threshold h=4.0, got ${changepoint.maxCusumStatistic}`);
    // Test Stationary / Equilibrated Series (Zero false positives)
    console.log('[78.2] Verifying zero false positives on equilibrated stationary noise...');
    const stationaryValues = new Float64Array(40);
    for (let t = 0; t < 40; t++) {
        stationaryValues[t] = 25.0 + Math.sin(t) * 0.3;
    }
    const stationaryRes = engine.evaluateSeriesCusum(stationaryValues, timestamps, 'stationaryRtt', 15);
    assert.strictEqual(stationaryRes.shiftDetected, false, 'No shift should be detected on stationary series');
    assert.strictEqual(stationaryRes.direction, 'NONE', 'Direction must be NONE');
    assert.strictEqual(stationaryRes.changepointIndex, null, 'Index must be null');
    // 2. Multi-Metric Granger-Style Temporal Precedence Ordering
    console.log('[78.3] Verifying Granger-style temporal causal precedence ranking...');
    // Scenario:
    // t = 10: CPU spikes from 20% to 95% (The root cause / driver)
    // t = 15: TCP Retransmit Rate spikes from 0.01 to 0.40 (Cascading symptom 1)
    // t = 18: RTT jumps from 15ms to 180ms (Cascading symptom 2)
    const multiSeries = [];
    for (let t = 0; t < 30; t++) {
        const time = 1000 + t * 1000;
        const cpu = t >= 10 ? 95.0 + ((t % 2) * 1) : 20.0 + ((t % 2) * 0.5);
        const tcpRetrans = t >= 15 ? 0.40 : 0.01;
        const rtt = t >= 18 ? 180.0 : 15.0;
        multiSeries.push({
            timestampMs: time,
            cpuSaturationPct: cpu,
            tcpRetransmitRate: tcpRetrans,
            rttMs: rtt
        });
    }
    const precedenceReport = engine.evaluateMultiMetricPrecedence(multiSeries, ['cpuSaturationPct', 'tcpRetransmitRate', 'rttMs'], 8);
    assert.strictEqual(precedenceReport.primaryTemporalDriver, 'cpuSaturationPct', 'Primary temporal driver must be cpuSaturationPct');
    assert.strictEqual(precedenceReport.causalChainOrder.length, 3, 'All 3 metrics must be ranked in causal chain');
    // Rank 1: cpuSaturationPct
    assert.strictEqual(precedenceReport.causalChainOrder[0].metricName, 'cpuSaturationPct');
    assert.strictEqual(precedenceReport.causalChainOrder[0].role, 'PRIMARY_DRIVER');
    assert.strictEqual(precedenceReport.causalChainOrder[0].delayAfterDriverMs, 0);
    // Rank 2: tcpRetransmitRate (delay: 5000ms after CPU spike)
    assert.strictEqual(precedenceReport.causalChainOrder[1].metricName, 'tcpRetransmitRate');
    assert.strictEqual(precedenceReport.causalChainOrder[1].role, 'CASCADING_SYMPTOM');
    assert.ok(precedenceReport.causalChainOrder[1].delayAfterDriverMs >= 4000, 'Delay must be ~5000ms');
    // Rank 3: rttMs (delay: 8000ms after CPU spike)
    assert.strictEqual(precedenceReport.causalChainOrder[2].metricName, 'rttMs');
    assert.strictEqual(precedenceReport.causalChainOrder[2].role, 'CASCADING_SYMPTOM');
    assert.ok(precedenceReport.causalChainOrder[2].delayAfterDriverMs >= 7000, 'Delay must be ~8000ms');
    console.log(`  ✓ Primary driver identified: ${precedenceReport.primaryTemporalDriver} (onset t = ${precedenceReport.driverOnsetTimestampMs}ms).`);
    console.log('✓ Suite 78 passed: CUSUM Changepoint Forensics 100% verified.\n');
}
if (require.main === module) {
    runSuite78CusumChangepointForensics().then(() => process.exit(0)).catch(err => {
        console.error(err);
        process.exit(1);
    });
}
//# sourceMappingURL=suite-78-cusum-changepoint-forensics.test.js.map