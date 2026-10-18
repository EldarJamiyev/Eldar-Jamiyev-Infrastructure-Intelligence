# Runbook RB-05: TLS 1.3 Handshake Alerts, Certificate Chain Validation, and SNI Audit

## Objective
Detect and resolve cryptographic negotiation failures, TLS fatal alert codes (e.g. Alert 48 `unknown_ca`, Alert 46 `certificate_unknown`, Alert 40 `handshake_failure`, Alert 80 `internal_error`), missing or mismatched Server Name Indication (SNI) extensions, and expired or untrusted x509 leaf/intermediate certificates.

## Step-by-Step Procedure in EJII
1. **Isolate TLS Handshakes in Live Wire Sniffer:**
   - In Section 2, switch to `⭐ Important` or use Display Filter: `tls || tcp.port == 443`.
   - Natural Language query: `tls handshakes` or `tls alerts`.
2. **Inspect ClientHello and ServerHello Extensions:**
   - Examine `server_name` (SNI) extension in `ClientHello` frame (RFC 6066).
   - Check supported cipher suites (`TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`) and supported TLS versions (TLS 1.2 vs TLS 1.3 RFC 8446).
3. **Analyze Server Certificate Chain & Alerts:**
   - If a TLS Alert frame (ContentType 21) is captured, note the alert level (`2 = Fatal`) and alert description number.
   - Cross-reference with Stage 4 in Endpoint Troubleshooter: verify validity start/end timestamps, Common Name (CN), and Subject Alternative Name (SAN) wildcards.
4. **Remediation & Trusted Root Verification:**
   - Verify whether local Windows Certificate Store (`certmgr.msc` / `certlm.msc`) contains the root CA or if enterprise proxy MITM decryption certificate is missing.
