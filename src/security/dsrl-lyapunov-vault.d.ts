export interface SystemStateVector {
    readonly timestampMs: number;
    readonly stlRobustnessRho: number;
    readonly cpuLoadPct: number;
    readonly memoryUsedPct: number;
    readonly activeManagementSocketAlive: boolean;
    readonly gatewayReachable: boolean;
}
export interface RemediationActionDescriptor {
    readonly actionId: string;
    readonly scriptSha256: string;
    readonly requiresElevation: boolean;
    readonly inverseRollbackActionId: string | null;
    readonly maxAllowedCpuPct: number;
    readonly symbolicPrecondition: (state: SystemStateVector) => boolean;
    readonly executeUserSpaceAction: () => Promise<{
        exitCode: number;
        stdout: string;
    }>;
    readonly executeInverseRollback?: () => Promise<{
        exitCode: number;
        stdout: string;
    }>;
}
export interface AuditChainEntry {
    readonly sequenceNumber: number;
    readonly timestampIso: string;
    readonly actionId: string;
    readonly verdict: 'APPROVED_COMMITTED' | 'BLOCKED_PRECONDITION' | 'ROLLED_BACK_LYAPUNOV_VIOLATION';
    readonly preActionRho: number;
    readonly postActionRho: number;
    readonly lyapunovDeltaEnergy: number;
    readonly previousHmac: string;
    readonly entryHmac: string;
}
export declare class DSRLLyapunovSafetyVault {
    private readonly hmacSecret;
    private readonly registeredScriptHashes;
    private readonly ledger;
    constructor(hmacSecretKey?: string, allowedScriptHashes?: readonly string[]);
    /**
     * Executes the 6-Stage Deterministic DSRL Gate:
     *  Stage 1: Script SHA-256 Registry & Zero-Elevation Verification
     *  Stage 2: Symbolic Precondition Proof
     *  Stage 3: Host Headroom Validation
     *  Stage 4: Active Management Session Disconnect Protection
     *  Stage 5: Sandboxed Execution & Empirical Post-State Sampling
     *  Stage 6: Lyapunov Energy Decreasing Proof V(s_{t+1}) <= V(s_t) or Automatic Inverse Rollback
     */
    executeGuardedRemediation(action: RemediationActionDescriptor, sampleSystemState: () => Promise<SystemStateVector>): Promise<AuditChainEntry>;
    /**
     * Positive-definite Lyapunov candidate function V(x) >= 0.
     * Stability requires dV/dt <= 0 across autonomous remediation transitions.
     */
    computeLyapunovEnergy(state: SystemStateVector): number;
    private appendAuditEntry;
    /**
     * Verifies the cryptographic integrity of the entire HMAC chain + computes the Merkle Root.
     */
    verifyAuditLedgerAndMerkleRoot(): {
        readonly intact: boolean;
        readonly tamperedSequenceNumber: number | null;
        readonly merkleRootHex: string;
    };
}
