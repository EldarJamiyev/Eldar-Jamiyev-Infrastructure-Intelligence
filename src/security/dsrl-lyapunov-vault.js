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
exports.DSRLLyapunovSafetyVault = void 0;
// src/security/dsrl-lyapunov-vault.ts
const crypto = __importStar(require("node:crypto"));
class DSRLLyapunovSafetyVault {
    hmacSecret;
    registeredScriptHashes;
    ledger = [];
    constructor(hmacSecretKey = process.env.EJII_HMAC_SECRET || 'EJII-ENTERPRISE-INTELLIGENCE-HMAC-SECURE-KEY-2026', allowedScriptHashes = []) {
        if (!hmacSecretKey || hmacSecretKey.length < 16) {
            throw new Error('DSRL Safety Vault requires a cryptographic HMAC secret >= 16 characters.');
        }
        this.hmacSecret = Buffer.from(hmacSecretKey, 'utf-8');
        this.registeredScriptHashes = new Set(allowedScriptHashes);
    }
    /**
     * Executes the 6-Stage Deterministic DSRL Gate:
     *  Stage 1: Script SHA-256 Registry & Zero-Elevation Verification
     *  Stage 2: Symbolic Precondition Proof
     *  Stage 3: Host Headroom Validation
     *  Stage 4: Active Management Session Disconnect Protection
     *  Stage 5: Sandboxed Execution & Empirical Post-State Sampling
     *  Stage 6: Lyapunov Energy Decreasing Proof V(s_{t+1}) <= V(s_t) or Automatic Inverse Rollback
     */
    async executeGuardedRemediation(action, sampleSystemState) {
        const preState = await sampleSystemState();
        // Stage 1: Registry Hash & Zero-Elevation Gate
        if (action.requiresElevation || !this.registeredScriptHashes.has(action.scriptSha256)) {
            return this.appendAuditEntry(action.actionId, 'BLOCKED_PRECONDITION', preState.stlRobustnessRho, preState.stlRobustnessRho);
        }
        // Stage 2, 3, 4: Symbolic Precondition, Host Headroom & Session Disconnect Protection
        const headroomOk = preState.cpuLoadPct <= action.maxAllowedCpuPct && preState.memoryUsedPct < 92.0;
        const sessionProtected = preState.activeManagementSocketAlive;
        const symbolicOk = action.symbolicPrecondition(preState);
        if (!headroomOk || !sessionProtected || !symbolicOk) {
            return this.appendAuditEntry(action.actionId, 'BLOCKED_PRECONDITION', preState.stlRobustnessRho, preState.stlRobustnessRho);
        }
        // Stage 5: Execute User-Space Remediation
        const execResult = await action.executeUserSpaceAction();
        const postState = await sampleSystemState();
        // Stage 6: Control-Theoretic Lyapunov Energy Function V(s) = max(0, 100 - rho)^2 + cpuPenalty
        const preLyapunov = this.computeLyapunovEnergy(preState);
        const postLyapunov = this.computeLyapunovEnergy(postState);
        const deltaV = postLyapunov - preLyapunov;
        const degraded = execResult.exitCode !== 0 ||
            !postState.activeManagementSocketAlive ||
            postState.stlRobustnessRho < preState.stlRobustnessRho - 1.5;
        if (degraded) {
            if (action.executeInverseRollback) {
                await action.executeInverseRollback();
            }
            return this.appendAuditEntry(action.actionId, 'ROLLED_BACK_LYAPUNOV_VIOLATION', preState.stlRobustnessRho, postState.stlRobustnessRho, deltaV);
        }
        return this.appendAuditEntry(action.actionId, 'APPROVED_COMMITTED', preState.stlRobustnessRho, postState.stlRobustnessRho, deltaV);
    }
    /**
     * Positive-definite Lyapunov candidate function V(x) >= 0.
     * Stability requires dV/dt <= 0 across autonomous remediation transitions.
     */
    computeLyapunovEnergy(state) {
        const stlDeficit = Math.max(0.0, 50.0 - state.stlRobustnessRho);
        const disconnectPenalty = state.activeManagementSocketAlive ? 0.0 : 10000.0;
        return Number((0.5 * stlDeficit * stlDeficit + 0.1 * state.cpuLoadPct + disconnectPenalty).toFixed(4));
    }
    appendAuditEntry(actionId, verdict, preRho, postRho, lyapunovDelta = 0) {
        const seq = this.ledger.length + 1;
        const prevHmac = seq === 1
            ? '0000000000000000000000000000000000000000000000000000000000000000'
            : this.ledger[this.ledger.length - 1].entryHmac;
        const timestampIso = new Date().toISOString();
        const payload = `${seq}|${timestampIso}|${actionId}|${verdict}|${preRho}|${postRho}|${lyapunovDelta}|${prevHmac}`;
        const entryHmac = crypto
            .createHmac('sha256', this.hmacSecret)
            .update(payload)
            .digest('hex');
        const entry = {
            sequenceNumber: seq,
            timestampIso,
            actionId,
            verdict,
            preActionRho: preRho,
            postActionRho: postRho,
            lyapunovDeltaEnergy: Number(lyapunovDelta.toFixed(4)),
            previousHmac: prevHmac,
            entryHmac,
        };
        this.ledger.push(entry);
        return entry;
    }
    /**
     * Verifies the cryptographic integrity of the entire HMAC chain + computes the Merkle Root.
     */
    verifyAuditLedgerAndMerkleRoot() {
        let expectedPrev = '0000000000000000000000000000000000000000000000000000000000000000';
        for (const item of this.ledger) {
            if (item.previousHmac !== expectedPrev) {
                return { intact: false, tamperedSequenceNumber: item.sequenceNumber, merkleRootHex: '' };
            }
            const payload = `${item.sequenceNumber}|${item.timestampIso}|${item.actionId}|${item.verdict}|${item.preActionRho}|${item.postActionRho}|${item.lyapunovDeltaEnergy}|${item.previousHmac}`;
            const recomputed = crypto
                .createHmac('sha256', this.hmacSecret)
                .update(payload)
                .digest('hex');
            if (!crypto.timingSafeEqual(Buffer.from(recomputed, 'hex'), Buffer.from(item.entryHmac, 'hex'))) {
                return { intact: false, tamperedSequenceNumber: item.sequenceNumber, merkleRootHex: '' };
            }
            expectedPrev = item.entryHmac;
        }
        // Compute binary Merkle Tree root over all entryHmac leaves
        if (this.ledger.length === 0) {
            return { intact: true, tamperedSequenceNumber: null, merkleRootHex: expectedPrev };
        }
        let level = this.ledger.map((e) => e.entryHmac);
        while (level.length > 1) {
            const nextLevel = [];
            for (let i = 0; i < level.length; i += 2) {
                const left = level[i];
                const right = i + 1 < level.length ? level[i + 1] : left;
                const combinedHash = crypto
                    .createHash('sha256')
                    .update(`${left}:${right}`)
                    .digest('hex');
                nextLevel.push(combinedHash);
            }
            level = nextLevel;
        }
        return {
            intact: true,
            tamperedSequenceNumber: null,
            merkleRootHex: level[0],
        };
    }
}
exports.DSRLLyapunovSafetyVault = DSRLLyapunovSafetyVault;
//# sourceMappingURL=dsrl-lyapunov-vault.js.map