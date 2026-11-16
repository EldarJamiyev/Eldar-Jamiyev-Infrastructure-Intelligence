/**
 * EJII Local Authenticated Secret Vault (AES-256-GCM)
 * Phase 20.0 Sovereign Security Layer
 *
 * Dual-Maintenance CommonJS Implementation.
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const os = require('node:os');

class LocalSecretVault {
  constructor(customFilePath) {
    const rootDir = path.resolve(__dirname, '..', '..');
    this.vaultFilePath = customFilePath || path.join(rootDir, 'test-smoke-data', 'security', '.local_instance_secrets.json');
    this.masterKey = this.deriveMasterKey();
    this.inMemorySecrets = new Map();
    this.loadVault();
  }

  deriveMasterKey() {
    const machineId = `${os.hostname()}::${os.platform()}::${os.arch()}::EJII_SOVEREIGN_V20`;
    const salt = Buffer.from('ejii_master_salt_phase20_singularity_999', 'utf8');
    return crypto.scryptSync(machineId, salt, 32);
  }

  loadVault() {
    try {
      if (fs.existsSync(this.vaultFilePath)) {
        const raw = fs.readFileSync(this.vaultFilePath, 'utf8');
        const data = JSON.parse(raw);
        if (data && typeof data === 'object') {
          if (data.hmacSecret && typeof data.hmacSecret === 'string') {
            this.inMemorySecrets.set('hmacSecret', data.hmacSecret);
          }
          if (data.jwtSecret && typeof data.jwtSecret === 'string') {
            this.inMemorySecrets.set('jwtSecret', data.jwtSecret);
          }
          if (data.googleAiStudioApiKey && typeof data.googleAiStudioApiKey === 'string') {
            this.inMemorySecrets.set('googleAiStudioApiKey', data.googleAiStudioApiKey);
          }
          if (data.encryptedVault && typeof data.encryptedVault === 'object') {
            for (const [k, enc] of Object.entries(data.encryptedVault)) {
              try {
                const dec = this.decryptSecret(enc);
                this.inMemorySecrets.set(k, dec);
              } catch (_) {
                // Silently ignore corrupted or mismatched keys
              }
            }
          }
        }
      }
    } catch (_) {
      // Fallback
    }
  }

  encryptSecret(plaintext, keyId = 'v1') {
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.masterKey, iv);
    let ciphertext = cipher.update(plaintext, 'utf8', 'hex');
    ciphertext += cipher.final('hex');
    const tag = cipher.getAuthTag();

    return {
      ivHex: iv.toString('hex'),
      tagHex: tag.toString('hex'),
      ciphertextHex: ciphertext,
      keyId,
      updatedAtIso: new Date().toISOString()
    };
  }

  decryptSecret(payload) {
    if (!payload || !payload.ivHex || !payload.tagHex || !payload.ciphertextHex) {
      throw new Error('Invalid EncryptedSecretPayload format');
    }
    const iv = Buffer.from(payload.ivHex, 'hex');
    const tag = Buffer.from(payload.tagHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', this.masterKey, iv);
    decipher.setAuthTag(tag);
    let decrypted = decipher.update(payload.ciphertextHex, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  }

  setSecret(keyName, secretValue, persistToDisk = false) {
    this.inMemorySecrets.set(keyName, secretValue);

    if (persistToDisk) {
      try {
        let existing = {};
        if (fs.existsSync(this.vaultFilePath)) {
          existing = JSON.parse(fs.readFileSync(this.vaultFilePath, 'utf8'));
        }
        if (!existing.encryptedVault) {
          existing.encryptedVault = {};
        }
        existing.encryptedVault[keyName] = this.encryptSecret(secretValue);
        fs.writeFileSync(this.vaultFilePath, JSON.stringify(existing, null, 2), 'utf8');
      } catch (_) {
        // Safe write error suppression
      }
    }
  }

  getSecret(keyName) {
    if (keyName === 'googleAiStudioApiKey' || keyName === 'geminiApiKey') {
      if (process.env.GEMINI_API_KEY) return process.env.GEMINI_API_KEY;
      if (process.env.GOOGLE_AI_STUDIO_KEY) return process.env.GOOGLE_AI_STUDIO_KEY;
      if (process.env.GOOGLE_API_KEY) return process.env.GOOGLE_API_KEY;
    }
    if (this.inMemorySecrets.has(keyName)) {
      return this.inMemorySecrets.get(keyName);
    }
    return null;
  }

  hasSecret(keyName) {
    return this.getSecret(keyName) !== null;
  }

  getSanitizedRoster() {
    const result = {};
    for (const [k, v] of this.inMemorySecrets.entries()) {
      result[k] = {
        configured: true,
        length: v.length,
        masked: v.length > 8 ? `${v.substring(0, 4)}...${v.substring(v.length - 4)}` : '****'
      };
    }
    return result;
  }
}

const localSecretVault = new LocalSecretVault();

module.exports = {
  LocalSecretVault,
  localSecretVault
};
