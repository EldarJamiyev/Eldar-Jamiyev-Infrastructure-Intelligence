/**
 * Cryptographic Zero-Trust X.509 & TLS Posture Auditor
 * 100% Unprivileged, Native Node.js tls.connect implementation.
 * Supports:
 *  - X.509 Certificate Chain Inspection & Expiration Telemetry
 *  - Ephemeral Key Exchange & Forward Secrecy Analysis
 *  - NIST SP 800-52r2 & Post-Quantum Readiness Scoring (0..100 & A+..F)
 */
export interface X509CertDetails {
    readonly subject: Record<string, string>;
    readonly subjectRaw: string;
    readonly issuer: Record<string, string>;
    readonly issuerRaw: string;
    readonly validFrom: string;
    readonly validTo: string;
    readonly daysRemaining: number;
    readonly isExpired: boolean;
    readonly isSelfSigned: boolean;
    readonly serialNumber: string;
    readonly fingerprint256: string;
    readonly subjectAltNames: readonly string[];
}
export interface TlsPostureFinding {
    readonly ruleId: string;
    readonly category: 'PROTOCOL' | 'CIPHER' | 'CERTIFICATE' | 'FORWARD_SECRECY';
    readonly scoreDelta: number;
    readonly description: string;
}
export interface TlsPostureReport {
    readonly host: string;
    readonly port: number;
    readonly connected: boolean;
    readonly handshakeLatencyMs: number;
    readonly tlsVersion: string | null;
    readonly cipherSuite: string | null;
    readonly alpnProtocol: string | null;
    readonly ephemeralKeyInfo: Record<string, unknown> | null;
    readonly certificate: X509CertDetails | null;
    readonly nistScore: number;
    readonly letterGrade: 'A+' | 'A' | 'B' | 'C' | 'F';
    readonly postQuantumReady: boolean;
    readonly findings: readonly TlsPostureFinding[];
    readonly error?: string;
    readonly timestampIso: string;
}
export declare class TlsPostureAuditor {
    /**
     * Deterministic NIST SP 800-52r2 & Post-Quantum Readiness Scorer
     */
    static computeTlsPostureScore(tlsVersion: string | null, cipherSuite: string | null, cert: X509CertDetails | null, ephemeralKeyInfo: Record<string, unknown> | null): {
        nistScore: number;
        letterGrade: 'A+' | 'A' | 'B' | 'C' | 'F';
        postQuantumReady: boolean;
        findings: TlsPostureFinding[];
    };
    /**
     * Alias for auditing TLS endpoint.
     */
    static auditEndpoint(host: string, port?: number, timeoutMs?: number, rejectUnauthorized?: boolean): Promise<TlsPostureReport>;
    /**
     * Performs a real unprivileged TLS handshake against an endpoint.
     */
    static auditTlsEndpoint(host: string, port?: number, timeoutMs?: number): Promise<TlsPostureReport>;
}
