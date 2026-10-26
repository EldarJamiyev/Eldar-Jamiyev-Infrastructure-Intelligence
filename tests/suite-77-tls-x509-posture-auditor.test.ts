// tests/suite-77-tls-x509-posture-auditor.test.ts
import * as assert from 'node:assert';
import * as tls from 'node:tls';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { TlsPostureAuditor, X509CertDetails } from '../src/security/tls-posture-auditor';

const TEST_CERT_PEM = `-----BEGIN CERTIFICATE-----
MIIDMTCCAhmgAwIBAgIUNTVwCcGTbPitt4hGWRskCFtEzFswDQYJKoZIhvcNAQEL
BQAwKDESMBAGA1UEAwwJMTI3LjAuMC4xMRIwEAYDVQQKDAlFSklJLVRlc3QwHhcN
MjYxMDI2MTgwNTQ1WhcNMjcxMDI2MTgwNTQ1WjAoMRIwEAYDVQQDDAkxMjcuMC4w
LjExEjAQBgNVBAoMCUVKSUktVGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAJxRlpfTg9MwV5ahe/PnN4hbh3ceUS0Zg5DEwZv6etZRaJOJvwvGQARf
zP/ct5ozPLmCMAT3bg/tI5MDT1ayaBaB3SwALe+4eoI7MiB8FhSMRkRlibz24+DA
as4CDg/WShILNT4qF1wn2grw6ZaTlNsevTQVqNVmvxEw4Nyj9Hjem03r3TsP76SV
YoEYCUuiV63gAzdnmTZh0+f8+ljIiIyFCAup6ZOlDTt/GVuIY7gU9TJon7RWcosU
bjjEtCAWlxGB0svwQc04AhNXML4QsTFDKVuiM4kudgry/kXTqqqkyNv69Eu+sfmT
yrwFoYBA/hP7ytBvy9/oIM4s6KWuVI0CAwEAAaNTMFEwHQYDVR0OBBYEFOLnJ45a
BNJcT6kgsdupqtTs/f4eMB8GA1UdIwQYMBaAFOLnJ45aBNJcT6kgsdupqtTs/f4e
MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBADzPl2ORLMxiPdrr
TATHg7q8V/Z1pnxgWiGIiZZrJlNL1HoLQe9usv/QZAN/YqdYrmwxHJxgNXuxJuJY
RR3K9dfm97dkPqVFkK2x9qZEK1xybb42tcApxUm5F4GQx8QsUtPFyloCSFAvF76K
K5C06Z8DYDrlokeV2Su29rfwVU76eh5xdVVPUrnvPddg+53M0YCc7mzSfW4FDijf
qHrNHcMwO4e2btvbsGLK7Necpdy6vMRGAXOdXRSoVI5SZ2FYV59ny1o63sC6L0Py
oxu85UKuJjGm0mFSRJIrTqUfoc8DVdmx70mzDpRk+Rb/lGnaHLx89ONOr0v5aT8b
MgiRaq8=
-----END CERTIFICATE-----`;

const TEST_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCcUZaX04PTMFeW
oXvz5zeIW4d3HlEtGYOQxMGb+nrWUWiTib8LxkAEX8z/3LeaMzy5gjAE924P7SOT
A09WsmgWgd0sAC3vuHqCOzIgfBYUjEZEZYm89uPgwGrOAg4P1koSCzU+KhdcJ9oK
8OmWk5TbHr00FajVZr8RMODco/R43ptN6907D++klWKBGAlLolet4AM3Z5k2YdPn
/PpYyIiMhQgLqemTpQ07fxlbiGO4FPUyaJ+0VnKLFG44xLQgFpcRgdLL8EHNOAIT
VzC+ELExQylbojOJLnYK8v5F06qqpMjb+vRLvrH5k8q8BaGAQP4T+8rQb8vf6CDO
LOilrlSNAgMBAAECggEAGjYAB1M7HnVTqnlHXH1frWiTjWCzAdnuWp7zS+EzKa6a
12pYc3P5lgIuUJTE4IFI5F41CRAoD1mXBnaeng3qMCP0XwVkrnaDbETaweGsniNr
QNq5vsqzKSN6hTKJAxTOdLoWYmcSZax0/jKpKEt0wU0lMo+TML06uno0qip/uqht
oF7WZ54uFJ0bFSgmLyshuPZaRVbJZRnfyh/e5pTUgaR/XqSs2w53QX/nbq6yGLfv
1RGjx8KYCrUIhfQwPLoxUhbC6KOolnf52YDBb5tV8fKWq1I7SCjwEUHMj5njo15Y
e08itNufzPV98MmVOsKRf8QWlOqGkxGNpe5gm3p5AQKBgQDX2UogMq/oP68FJ9kQ
a5+S0XFZ1IkMqAsHHwX9cV8YMFaaOEhImvU3rxrhi3AslR5PXJ8eUzElXKtWgXvQ
Zyk/mggAHdwr1XFxCi7HNCL5l8JviNNfYeFsthox0BqvjrnRt0e/u7iKbNgr8wZC
rwW8P+d2prsnO0CnkvCv5YbTzQKBgQC5ZXqDXUx9lGVnqaKZ77R5PW9m1i7tMMal
jfbBHaa6jAIMv3ZTzEbyvTdZ+Xcg5wuZ9DlaZVqDo+/stjhGaAKQL5sRAsUDiape
9iJbUdxBb4LO4prdUrJAm71iLJAFWnHaVY+J61wr3oS2wBAerOT2b0mBZ1grd3rw
K2qpUgJDwQKBgC7OzChXVZZD2SyBC61n6V7pVG9qi53XAy00KRRg9YJFWUJwWhyE
nhDJREcM+fJxE/WZ3FezKsEza2SDB9qVxHgqavm7f/dxffxJfQNt5vfBVUTioxPY
Ig51HxEWU/MmPF2iJUkK6GX8XJSLSxxC4DeGlCdC2OsVClxMnS1H1QkxAoGAPLJM
edWBxVtgF6Ah6+PeYhMK9dAJbP4bCvh/YJoki85qnWHRi33FfJMWHA7gQZVi5vRe
Eoo8J/zz/7tokSRcMnhjfB48AfyAGrbaaKtUQNgRK0plCTCZyy0xw4JzZE1IGQMK
C01Sz8n6CRq4LFLOYx/sIMGEzDZBuX99XBHNTAECgYEArdQPl26M12IJtoHWfL1s
Cl4BdxXD5NHO4z7/NEHjJ+gxtkQgZZ84SgeH9i2D0yZg0KBFlx1QaXSWJUxW0dWw
PThdjpCAsquEuK3gWlHlm30uj9VdXWGD5cLlD8IpgK4JhtKaksdxVfAE8flFpph2
VZxteS0qFSAXwC9Hqq9v4Pc=
-----END PRIVATE KEY-----`;

export async function runSuite77TlsX509PostureAuditor(): Promise<void> {
  console.log('=== [SUITE 77] CRYPTOGRAPHIC ZERO-TRUST TLS & X.509 POSTURE AUDITOR VERIFICATION ===');

  // 1. Deterministic NIST SP 800-52r2 Rule Engine Scoring
  console.log('[77.1] Verifying NIST SP 800-52r2 scoring, letter grade mapping, and findings...');
  const validMockCert: X509CertDetails = {
    subject: { CN: 'ejii.enterprise.local' },
    subjectRaw: 'ejii.enterprise.local',
    issuer: { O: 'DigiCert Sovereign CA' },
    issuerRaw: 'DigiCert Sovereign CA',
    validFrom: 'Jan 1 00:00:00 2026 GMT',
    validTo: 'Jan 1 00:00:00 2027 GMT',
    daysRemaining: 180,
    isExpired: false,
    isSelfSigned: false,
    serialNumber: 'ABCDEF123456',
    fingerprint256: 'FA:FA:FA:FA:FA',
    subjectAltNames: ['ejii.enterprise.local', 'api.ejii.local']
  };

  // Test Case A: Optimal TLS 1.3 + AEAD + Valid Cert + Forward Secrecy
  const resA = TlsPostureAuditor.computeTlsPostureScore(
    'TLSv1.3',
    'TLS_AES_256_GCM_SHA384',
    validMockCert,
    { group: 'X25519MLKEM768' }
  );
  assert.strictEqual(resA.letterGrade, 'A+', 'Optimal TLS 1.3 + ML-KEM must achieve grade A+');
  assert.ok(resA.nistScore >= 95, `NIST score must be >= 95, got ${resA.nistScore}`);
  assert.strictEqual(resA.postQuantumReady, true, 'Hybrid MLKEM key exchange must be recognized as post-quantum ready');

  // Test Case B: Deprecated TLS 1.0 + Broken Cipher
  const resB = TlsPostureAuditor.computeTlsPostureScore(
    'TLSv1',
    'TLS_RSA_WITH_RC4_128_MD5',
    null,
    null
  );
  assert.strictEqual(resB.letterGrade, 'F', 'TLS 1.0 + RC4 must yield failing grade F');
  assert.ok(resB.nistScore <= 30, `NIST score must be heavily penalized, got ${resB.nistScore}`);
  assert.ok(resB.findings.some(f => f.ruleId === 'NIST-PROTO-DEPRECATED'), 'Must flag deprecated protocol');
  assert.ok(resB.findings.some(f => f.ruleId === 'NIST-CIPHER-PROHIBITED'), 'Must flag prohibited cipher');

  // 2. Real In-Process TLS Server Handshake & X.509 Extraction
  console.log('[77.2] Starting local in-process TLS server with test X.509 certificate...');
  const server = tls.createServer({
    key: TEST_KEY_PEM,
    cert: TEST_CERT_PEM,
    minVersion: 'TLSv1.2'
  }, (socket) => {
    socket.write('EJII TLS WORKBENCH READY\n');
  });

  await new Promise<void>((resolve, reject) => {
    server.listen(0, '127.0.0.1', () => resolve());
    server.once('error', reject);
  });

  const address = server.address() as { port: number; address: string };
  const port = address.port;
  console.log(`  Local TLS server listening on 127.0.0.1:${port}`);

  try {
    console.log('[77.3] Auditing local TLS endpoint using TlsPostureAuditor.auditEndpoint()...');
    const auditRes = await TlsPostureAuditor.auditEndpoint('127.0.0.1', port, 4000, false);
    
    assert.strictEqual(auditRes.connected, true, 'Must connect successfully to TLS server');
    assert.ok(auditRes.handshakeLatencyMs >= 0, 'Handshake latency ms must be recorded');
    assert.ok(auditRes.tlsVersion?.startsWith('TLSv1.'), `TLS version must be 1.2 or 1.3, got ${auditRes.tlsVersion}`);
    assert.ok(auditRes.cipherSuite !== null, 'Cipher suite must be extracted');
    assert.ok(auditRes.certificate !== null, 'Certificate must be extracted');
    assert.strictEqual(auditRes.certificate?.subjectRaw, '127.0.0.1', 'Subject CN must match 127.0.0.1');
    assert.strictEqual(auditRes.certificate?.issuerRaw, 'EJII-Test', 'Issuer Organization must match EJII-Test');
    assert.strictEqual(auditRes.certificate?.isExpired, false, 'Freshly generated cert must not be expired');
    assert.ok(auditRes.certificate?.daysRemaining && auditRes.certificate.daysRemaining > 300, 'Days remaining should be ~365');
    assert.strictEqual(auditRes.certificate?.isSelfSigned, true, 'Self-signed certificate must be flagged as isSelfSigned');
    assert.ok(auditRes.nistScore > 50, `Score for clean local TLS should be reasonable, got ${auditRes.nistScore}`);

    console.log(`  ✓ Successfully audited local TLS endpoint (${auditRes.tlsVersion}, ${auditRes.cipherSuite}, score: ${auditRes.nistScore}, grade: ${auditRes.letterGrade})`);

    // 3. Error handling on non-existent port
    console.log('[77.4] Verifying connection error handling on dead port...');
    const deadRes = await TlsPostureAuditor.auditEndpoint('127.0.0.1', 1, 1000, false);
    assert.strictEqual(deadRes.connected, false, 'Must report connected: false on closed port');
    assert.ok(deadRes.error !== undefined, 'Error message must be present');
    assert.strictEqual(deadRes.letterGrade, 'F', 'Unreachable host must receive grade F');
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }

  console.log('✓ Suite 77 passed: TLS X.509 Posture Auditor 100% verified.\n');
}

if (require.main === module) {
  runSuite77TlsX509PostureAuditor().then(() => process.exit(0)).catch(err => {
    console.error(err);
    process.exit(1);
  });
}
