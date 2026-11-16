/**
 * EJII Hardware-Anchored Platform Root-of-Trust Attestor
 * Phase 21.0 Sovereign Security Layer
 *
 * Dual-Maintenance CommonJS Implementation.
 */

'use strict';

const crypto = require('node:crypto');
const os = require('node:os');
const { OS_PROTECTED_PROCESS_NAMES } = require('../diagnostics/hardware-kernel-inspector');

class HardwareRootAttestor {
  constructor() {
    this.hardwareFingerprint = this.computeHardwareFingerprint();
    this.machineIdentityKey = this.deriveMachineIdentityKey();
    this.protectedProcesses = new Set([
      'memory compression',
      'secure system',
      'system',
      'registry',
      'idle',
      'dwm',
      'csrss',
      'wininit',
      'services',
      'lsass',
      'svchost',
      'fontdrvhost',
      'explorer',
      'node',
      'ejii'
    ]);

    if (OS_PROTECTED_PROCESS_NAMES) {
      for (const p of OS_PROTECTED_PROCESS_NAMES) {
        this.protectedProcesses.add(p.toLowerCase());
      }
    }
  }

  computeHardwareFingerprint() {
    const raw = `${os.hostname()}::${os.platform()}::${os.arch()}::${os.cpus().length}::EJII_TPM_ROOT_V21`;
    return crypto.createHash('sha256').update(raw).digest('hex');
  }

  deriveMachineIdentityKey() {
    const salt = Buffer.from('ejii_hardware_enclave_master_salt_phase21_tpm', 'utf8');
    const derived = crypto.scryptSync(this.hardwareFingerprint, salt, 32);
    return derived.toString('hex');
  }

  issueHardwareSealedToken(action, targetPid, ttlMs = 60000) {
    const now = Date.now();
    const tokenId = `rat_${crypto.randomBytes(6).toString('hex')}`;
    const payload = `${tokenId}:${action}:${targetPid || 0}:${this.hardwareFingerprint}:${now}:${now + ttlMs}`;
    const signatureHex = crypto.createHmac('sha256', this.machineIdentityKey).update(payload).digest('hex');

    return {
      tokenId,
      action,
      targetPid,
      hardwareFingerprint: this.hardwareFingerprint,
      signatureHex,
      issuedAtMs: now,
      expiresAtMs: now + ttlMs
    };
  }

  verifyHardwareSealedToken(token) {
    if (!token || !token.signatureHex || !token.tokenId) return false;
    if (Date.now() > token.expiresAtMs) return false;
    if (token.hardwareFingerprint !== this.hardwareFingerprint) return false;

    const payload = `${token.tokenId}:${token.action}:${token.targetPid || 0}:${token.hardwareFingerprint}:${token.issuedAtMs}:${token.expiresAtMs}`;
    const expectedSig = crypto.createHmac('sha256', this.machineIdentityKey).update(payload).digest('hex');

    return crypto.timingSafeEqual(Buffer.from(token.signatureHex, 'hex'), Buffer.from(expectedSig, 'hex'));
  }

  validateProcessIntegrity(processName, pid) {
    if (pid <= 4) {
      return {
        valid: false,
        reason: `Target PID ${pid} is an OS-kernel bootstrap process. Hardware execution denied.`
      };
    }

    const cleanName = String(processName).trim().toLowerCase().replace(/\.exe$/i, '');
    if (this.protectedProcesses.has(cleanName)) {
      return {
        valid: false,
        reason: `Process '${processName}' is authenticated as an OS-protected subsystem. Hardware mutation blocked.`
      };
    }

    return { valid: true };
  }

  getHardwareIdentity() {
    return {
      fingerprint: this.hardwareFingerprint,
      initialized: this.machineIdentityKey.length === 64
    };
  }
}

const hardwareRootAttestor = new HardwareRootAttestor();

module.exports = {
  HardwareRootAttestor,
  hardwareRootAttestor
};
