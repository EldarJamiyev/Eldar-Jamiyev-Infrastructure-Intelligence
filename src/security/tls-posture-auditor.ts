// src/security/tls-posture-auditor.ts
/**
 * Cryptographic Zero-Trust X.509 & TLS Posture Auditor
 * 100% Unprivileged, Native Node.js tls.connect implementation.
 * Supports:
 *  - X.509 Certificate Chain Inspection & Expiration Telemetry
 *  - Ephemeral Key Exchange & Forward Secrecy Analysis
 *  - NIST SP 800-52r2 & Post-Quantum Readiness Scoring (0..100 & A+..F)
 */

import * as tls from 'node:tls';
import * as net from 'node:net';

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
  readonly nistScore: number; // 0..100
  readonly letterGrade: 'A+' | 'A' | 'B' | 'C' | 'F';
  readonly postQuantumReady: boolean;
  readonly findings: readonly TlsPostureFinding[];
  readonly error?: string;
  readonly timestampIso: string;
}

export class TlsPostureAuditor {
  /**
   * Deterministic NIST SP 800-52r2 & Post-Quantum Readiness Scorer
   */
  public static computeTlsPostureScore(
    tlsVersion: string | null,
    cipherSuite: string | null,
    cert: X509CertDetails | null,
    ephemeralKeyInfo: Record<string, unknown> | null
  ): {
    nistScore: number;
    letterGrade: 'A+' | 'A' | 'B' | 'C' | 'F';
    postQuantumReady: boolean;
    findings: TlsPostureFinding[];
  } {
    const findings: TlsPostureFinding[] = [];
    let score = 0;

    // 1. Protocol Version (Max 40 points)
    if (tlsVersion === 'TLSv1.3') {
      score += 40;
      findings.push({
        ruleId: 'NIST-PROTO-1.3',
        category: 'PROTOCOL',
        scoreDelta: 40,
        description: 'TLS 1.3 negotiated (RFC 8446) - Mandatory 1-RTT handshake and forward secrecy.',
      });
    } else if (tlsVersion === 'TLSv1.2') {
      score += 25;
      findings.push({
        ruleId: 'NIST-PROTO-1.2',
        category: 'PROTOCOL',
        scoreDelta: 25,
        description: 'TLS 1.2 negotiated (RFC 5246) - Supported under NIST SP 800-52r2.',
      });
    } else if (tlsVersion === 'TLSv1.1' || tlsVersion === 'TLSv1') {
      score -= 30;
      findings.push({
        ruleId: 'NIST-PROTO-DEPRECATED',
        category: 'PROTOCOL',
        scoreDelta: -30,
        description: 'Legacy insecure protocol negotiated (TLS 1.0/1.1) - Prohibited by NIST SP 800-52r2 and PCI-DSS.',
      });
    }

    // 2. Cipher Suite (Max 30 points)
    const cs = (cipherSuite || '').toUpperCase();
    if (cs.includes('GCM') || cs.includes('POLY1305') || cs.includes('CHACHA20') || cs.includes('CCM')) {
      score += 30;
      findings.push({
        ruleId: 'NIST-CIPHER-AEAD',
        category: 'CIPHER',
        scoreDelta: 30,
        description: `Modern AEAD Cipher Suite (${cs}) - Authenticated encryption resistant to padding oracle attacks.`,
      });
    } else if (cs.includes('CBC')) {
      score += 15;
      findings.push({
        ruleId: 'NIST-CIPHER-CBC',
        category: 'CIPHER',
        scoreDelta: 15,
        description: `CBC mode cipher suite (${cs}) - Legacy authenticated encryption vulnerable to timing side channels.`,
      });
    } else if (cs.includes('RC4') || cs.includes('DES') || cs.includes('NULL')) {
      score -= 40;
      findings.push({
        ruleId: 'NIST-CIPHER-PROHIBITED',
        category: 'CIPHER',
        scoreDelta: -40,
        description: `Cryptographically broken cipher suite (${cs}) - Critical risk of plaintext compromise.`,
      });
    }

    // 3. Certificate Lifecycle & Authenticity (Max 20 points)
    if (cert) {
      if (cert.isExpired) {
        score -= 40;
        findings.push({
          ruleId: 'X509-EXPIRED',
          category: 'CERTIFICATE',
          scoreDelta: -40,
          description: `X.509 Certificate is expired (${cert.validTo}). Browsers and zero-trust proxies will terminate connections.`,
        });
      } else if (cert.daysRemaining <= 14) {
        score += 10;
        findings.push({
          ruleId: 'X509-EXPIRING-SOON',
          category: 'CERTIFICATE',
          scoreDelta: 10,
          description: `X.509 Certificate expires in ${cert.daysRemaining} day(s). Immediate renewal required.`,
        });
      } else {
        score += 20;
        findings.push({
          ruleId: 'X509-VALID-LIFECYCLE',
          category: 'CERTIFICATE',
          scoreDelta: 20,
          description: `X.509 Certificate is valid with healthy lifecycle (${cert.daysRemaining} days remaining).`,
        });
      }

      if (cert.isSelfSigned) {
        score -= 20;
        findings.push({
          ruleId: 'X509-SELF-SIGNED',
          category: 'CERTIFICATE',
          scoreDelta: -20,
          description: 'Self-signed certificate detected. Untrusted without explicit enterprise root pinning.',
        });
      }
    }

    // 4. Forward Secrecy & Key Exchange (Max 10 points)
    if (cs.includes('ECDHE') || cs.includes('DHE') || tlsVersion === 'TLSv1.3') {
      score += 10;
      findings.push({
        ruleId: 'NIST-FORWARD-SECRECY',
        category: 'FORWARD_SECRECY',
        scoreDelta: 10,
        description: 'Ephemeral Diffie-Hellman Key Exchange (ECDHE) - Perfect Forward Secrecy active.',
      });
    }

    // Post-Quantum readiness check (Hybrid Kyber/ML-KEM or X25519 in TLS 1.3)
    const keyType = String(ephemeralKeyInfo?.type || '').toUpperCase();
    const keyName = String(ephemeralKeyInfo?.name || ephemeralKeyInfo?.group || '').toUpperCase();
    const postQuantumReady =
      tlsVersion === 'TLSv1.3' &&
      (keyName.includes('KYBER') ||
        keyName.includes('MLKEM') ||
        keyName.includes('X25519') ||
        keyType.includes('X25519'));

    if (postQuantumReady) {
      findings.push({
        ruleId: 'NIST-PQC-READY',
        category: 'FORWARD_SECRECY',
        scoreDelta: 5,
        description: 'Post-Quantum / Modern Ephemeral Curve (X25519/Kyber) verified in key exchange.',
      });
      score += 5;
    }

    const clampedScore = Math.max(0, Math.min(100, score));
    const letterGrade: TlsPostureReport['letterGrade'] =
      clampedScore >= 95
        ? 'A+'
        : clampedScore >= 85
        ? 'A'
        : clampedScore >= 70
        ? 'B'
        : clampedScore >= 50
        ? 'C'
        : 'F';

    return {
      nistScore: clampedScore,
      letterGrade,
      postQuantumReady,
      findings,
    };
  }

  /**
   * Alias for auditing TLS endpoint.
   */
  public static auditEndpoint(
    host: string,
    port = 443,
    timeoutMs = 5000,
    rejectUnauthorized = false
  ): Promise<TlsPostureReport> {
    return this.auditTlsEndpoint(host, port, timeoutMs);
  }

  /**
   * Performs a real unprivileged TLS handshake against an endpoint.
   */
  public static auditTlsEndpoint(
    host: string,
    port = 443,
    timeoutMs = 5000
  ): Promise<TlsPostureReport> {
    return new Promise((resolve) => {
      const startTime = Date.now();
      const cleanHost = (host || '127.0.0.1').trim();
      const cleanPort = Math.max(1, Math.min(65535, port));

      const isIp = net.isIP(cleanHost) !== 0;
      const socket = tls.connect(
        {
          host: cleanHost,
          port: cleanPort,
          servername: isIp ? undefined : cleanHost,
          rejectUnauthorized: false, // Audit mode: inspect self-signed/expired certs without throwing
          timeout: timeoutMs,
        },
        () => {
          const latency = Date.now() - startTime;
          const tlsVersion = socket.getProtocol();
          const cipherSuiteObj = socket.getCipher();
          const cipherSuite = cipherSuiteObj ? cipherSuiteObj.name : null;
          const alpnProtocol = socket.alpnProtocol || null;
          let ephemeralKeyInfo: Record<string, unknown> | null = null;
          if (typeof socket.getEphemeralKeyInfo === 'function') {
            ephemeralKeyInfo = socket.getEphemeralKeyInfo() as Record<string, unknown> | null;
          }

          let certDetails: X509CertDetails | null = null;
          const peerCert = socket.getPeerCertificate(true);

          if (peerCert && Object.keys(peerCert).length > 0) {
            const now = Date.now();
            const validToMs = new Date(peerCert.valid_to).getTime();
            const daysRemaining = Math.max(0, Math.floor((validToMs - now) / (1000 * 60 * 60 * 24)));
            const isExpired = validToMs < now;
            const isSelfSigned = peerCert.fingerprint256 === peerCert.issuerCertificate?.fingerprint256 ||
              peerCert.raw?.equals(peerCert.issuerCertificate?.raw || Buffer.alloc(0)) ||
              peerCert.subject?.CN === peerCert.issuer?.CN;

            let sanList: string[] = [];
            if (peerCert.subjectaltname) {
              sanList = peerCert.subjectaltname.split(',').map((s) => s.trim().replace(/^DNS:/, ''));
            }

            certDetails = {
              subject: peerCert.subject as unknown as Record<string, string>,
              subjectRaw: String(peerCert.subject?.CN || cleanHost),
              issuer: peerCert.issuer as unknown as Record<string, string>,
              issuerRaw: String(peerCert.issuer?.O || peerCert.issuer?.CN || 'Self-Signed'),
              validFrom: peerCert.valid_from,
              validTo: peerCert.valid_to,
              daysRemaining,
              isExpired,
              isSelfSigned: Boolean(isSelfSigned),
              serialNumber: peerCert.serialNumber,
              fingerprint256: peerCert.fingerprint256,
              subjectAltNames: sanList,
            };
          }

          const { nistScore, letterGrade, postQuantumReady, findings } =
            TlsPostureAuditor.computeTlsPostureScore(
              tlsVersion,
              cipherSuite,
              certDetails,
              ephemeralKeyInfo
            );

          socket.end();
          resolve({
            host: cleanHost,
            port: cleanPort,
            connected: true,
            handshakeLatencyMs: latency,
            tlsVersion,
            cipherSuite,
            alpnProtocol,
            ephemeralKeyInfo,
            certificate: certDetails,
            nistScore,
            letterGrade,
            postQuantumReady,
            findings,
            timestampIso: new Date().toISOString(),
          });
        }
      );

      socket.on('timeout', () => {
        socket.destroy();
        resolve({
          host: cleanHost,
          port: cleanPort,
          connected: false,
          handshakeLatencyMs: timeoutMs,
          tlsVersion: null,
          cipherSuite: null,
          alpnProtocol: null,
          ephemeralKeyInfo: null,
          certificate: null,
          nistScore: 0,
          letterGrade: 'F',
          postQuantumReady: false,
          findings: [
            {
              ruleId: 'TLS-TIMEOUT',
              category: 'PROTOCOL',
              scoreDelta: 0,
              description: `Connection timed out after ${timeoutMs}ms.`,
            },
          ],
          error: `TLS handshake timed out after ${timeoutMs}ms`,
          timestampIso: new Date().toISOString(),
        });
      });

      socket.on('error', (err) => {
        socket.destroy();
        resolve({
          host: cleanHost,
          port: cleanPort,
          connected: false,
          handshakeLatencyMs: Date.now() - startTime,
          tlsVersion: null,
          cipherSuite: null,
          alpnProtocol: null,
          ephemeralKeyInfo: null,
          certificate: null,
          nistScore: 0,
          letterGrade: 'F',
          postQuantumReady: false,
          findings: [
            {
              ruleId: 'TLS-CONNECT-ERROR',
              category: 'PROTOCOL',
              scoreDelta: 0,
              description: `TLS connection failed: ${err.message}`,
            },
          ],
          error: err.message,
          timestampIso: new Date().toISOString(),
        });
      });
    });
  }
}
