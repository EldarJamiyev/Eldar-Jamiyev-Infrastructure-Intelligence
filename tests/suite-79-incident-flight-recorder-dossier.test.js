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
exports.runSuite79IncidentFlightRecorderDossier = runSuite79IncidentFlightRecorderDossier;
// tests/suite-79-incident-flight-recorder-dossier.test.ts
const assert = __importStar(require("node:assert"));
const incident_flight_recorder_1 = require("../src/observability/incident-flight-recorder");
async function runSuite79IncidentFlightRecorderDossier() {
    console.log('=== [SUITE 79] BLACK-BOX INCIDENT FLIGHT RECORDER & SIGNED DOSSIER VERIFICATION ===');
    const testSecret = 'TEST-HMAC-SECRET-APEX-ENTERPRISE-2026-KEY';
    const recorder = new incident_flight_recorder_1.IncidentFlightRecorder(testSecret);
    // 1. Unified 5-Pillar Snapshot Assembly
    console.log('[79.1] Verifying 5-pillar unified flight snapshot aggregation...');
    const snapshot = recorder.assembleFlightSnapshot({
        incidentId: 'INC-20261026-NOC01',
        topologySpectral: {
            lambda2: 0.12,
            partitionRisk: 'ELEVATED',
            criticalCutCount: 2,
            routingAnomaliesCount: 1
        },
        wireDissection: {
            recentPacketsCaptured: 1540,
            tlsJa4Sample: 't13d1516h2_8daaf6152771_b4b604b34b3e',
            dnsEntropyMax: 4.12,
            dgaSuspected: true
        },
        hostSocketMatrix: {
            cpuLoadPct: 88.5,
            memoryUsedPct: 76.2,
            ephemeralSaturationPct: 62.4,
            topProcessName: 'leak_worker.exe'
        },
        aiCusumForensics: {
            smoothRobustnessRho: -12.4,
            estimatedTtvSec: 45,
            primaryTemporalDriver: 'cpuLoadPct',
            topHypothesis: 'PROCESS_RESOURCE_EXHAUSTION',
            confidencePct: 96.8
        },
        dsrlLyapunovAudit: {
            lastRemediationVerdict: 'QUARANTINE_PROCESS',
            lyapunovDeltaEnergy: -28.6,
            merkleRootHex: 'abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890'
        }
    });
    assert.strictEqual(snapshot.incidentId, 'INC-20261026-NOC01');
    assert.strictEqual(snapshot.topologySpectral.partitionRisk, 'ELEVATED');
    assert.strictEqual(snapshot.wireDissection.dgaSuspected, true);
    assert.strictEqual(snapshot.hostSocketMatrix.topProcessName, 'leak_worker.exe');
    assert.strictEqual(snapshot.aiCusumForensics.primaryTemporalDriver, 'cpuLoadPct');
    assert.strictEqual(snapshot.dsrlLyapunovAudit.lyapunovDeltaEnergy, -28.6);
    // 2. Executive Markdown Post-Mortem Synthesis
    console.log('[79.2] Verifying executive markdown synthesis across all 5 architectural pillars...');
    const markdown = recorder.generateMarkdownDossier(snapshot);
    assert.ok(markdown.includes('# 📋 EJII EXECUTIVE INCIDENT POST-MORTEM DOSSIER'), 'Must contain header');
    assert.ok(markdown.includes('INC-20261026-NOC01'), 'Must include incident ID');
    assert.ok(markdown.includes('Spectral Graph Topology'), 'Must include Pillar 1');
    assert.ok(markdown.includes('Wire & Network Telemetry'), 'Must include Pillar 2');
    assert.ok(markdown.includes('Host Socket & Process Attribution'), 'Must include Pillar 3');
    assert.ok(markdown.includes('Neuro-Symbolic & CUSUM Changepoint Forensics'), 'Must include Pillar 4');
    assert.ok(markdown.includes('Lyapunov Stability & Audit Provenance'), 'Must include Pillar 5');
    assert.ok(markdown.includes('Eldar Jamiyev Infrastructure Intelligence'), 'Must include sovereign branding');
    // 3. HMAC-SHA256 Cryptographic Signing & Tamper Verification
    console.log('[79.3] Verifying HMAC-SHA256 cryptographic signature and tamper-proofing...');
    const signedDossier = recorder.signDossier(snapshot);
    assert.strictEqual(signedDossier.dossierVersion, '3.0.0-sovereign-enterprise');
    assert.ok(signedDossier.snapshotSha256.length === 64, 'SHA-256 hash must be 64 hex characters');
    assert.ok(signedDossier.dossierSignatureHmac.length === 64, 'HMAC-SHA256 signature must be 64 hex characters');
    // Verify authentic dossier
    const isValid = recorder.verifyDossierSignature(signedDossier);
    assert.strictEqual(isValid, true, 'Original signed dossier must verify cleanly');
    // Tamper Case A: Modify snapshot data
    const tamperedSnapshotDossier = {
        ...signedDossier,
        snapshot: {
            ...signedDossier.snapshot,
            hostSocketMatrix: {
                ...signedDossier.snapshot.hostSocketMatrix,
                cpuLoadPct: 10.0 // Tampered from 88.5%
            }
        }
    };
    assert.strictEqual(recorder.verifyDossierSignature(tamperedSnapshotDossier), false, 'Tampered snapshot payload must fail signature verification');
    // Tamper Case B: Modify executive markdown
    const tamperedMarkdownDossier = {
        ...signedDossier,
        executiveMarkdown: signedDossier.executiveMarkdown + '\n<!-- Tampered Injection -->'
    };
    assert.strictEqual(recorder.verifyDossierSignature(tamperedMarkdownDossier), false, 'Tampered executive markdown must fail signature verification');
    // Tamper Case C: Corrupted HMAC Signature
    const tamperedSigDossier = {
        ...signedDossier,
        dossierSignatureHmac: '0000000000000000000000000000000000000000000000000000000000000000'
    };
    assert.strictEqual(recorder.verifyDossierSignature(tamperedSigDossier), false, 'Invalid signature hex must be rejected');
    console.log(`  ✓ Generated and verified HMAC signature: ${signedDossier.dossierSignatureHmac.slice(0, 16)}...`);
    console.log('✓ Suite 79 passed: Incident Flight Recorder 100% verified.\n');
}
if (require.main === module) {
    runSuite79IncidentFlightRecorderDossier().then(() => process.exit(0)).catch(err => {
        console.error(err);
        process.exit(1);
    });
}
//# sourceMappingURL=suite-79-incident-flight-recorder-dossier.test.js.map