/**
 * EJI Enterprise TOTP Engine (RFC 6238 / RFC 4226)
 * Pure native crypto implementation of Time-based One-Time Passwords.
 * Compatible with Google Authenticator, Microsoft Authenticator, and YubiKey.
 */

const crypto = require('crypto');

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Encode buffer into Base32 RFC 4648 string (without padding)
 * @param {Buffer} buffer 
 * @returns {string}
 */
function base32Encode(buffer) {
  let bits = 0;
  let value = 0;
  let output = '';

  for (let i = 0; i < buffer.length; i++) {
    value = (value << 8) | buffer[i];
    bits += 8;

    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  }

  return output;
}

/**
 * Decode Base32 RFC 4648 string into Buffer
 * @param {string} str 
 * @returns {Buffer}
 */
function base32Decode(str) {
  const cleanStr = (str || '').toUpperCase().replace(/[\s=-]/g, '');
  let bits = 0;
  let value = 0;
  const bytes = [];

  for (let i = 0; i < cleanStr.length; i++) {
    const idx = BASE32_ALPHABET.indexOf(cleanStr[i]);
    if (idx === -1) {
      throw new Error(`Invalid Base32 character encountered: [${cleanStr[i]}]`);
    }

    value = (value << 5) | idx;
    bits += 5;

    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }

  return Buffer.from(bytes);
}

/**
 * Generate a cryptographically secure random base32 secret
 * @param {number} byteLength Default 20 bytes (160 bits)
 * @returns {string}
 */
function generateSecret(byteLength = 20) {
  const buf = crypto.randomBytes(byteLength);
  return base32Encode(buf);
}

/**
 * Generate HMAC-Based One-Time Password (RFC 4226)
 * @param {string} secret Base32 encoded secret
 * @param {number} counter 64-bit integer counter
 * @param {number} digits Token length (default 6)
 * @returns {string}
 */
function generateHOTP(secret, counter, digits = 6) {
  const key = base32Decode(secret);
  const counterBuffer = Buffer.alloc(8);
  
  // High 32 bits and Low 32 bits for standard 64-bit integer
  const high = Math.floor(counter / 0x100000000);
  const low = counter >>> 0;
  counterBuffer.writeUInt32BE(high, 0);
  counterBuffer.writeUInt32BE(low, 4);

  const hmac = crypto.createHmac('sha1', key).update(counterBuffer).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;

  const code = (
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff)
  ) % (10 ** digits);

  return code.toString().padStart(digits, '0');
}

/**
 * Generate Time-Based One-Time Password (RFC 6238)
 * @param {string} secret Base32 encoded secret
 * @param {number} timestampMs Timestamp in ms (default Date.now())
 * @param {number} stepSeconds Step duration (default 30 seconds)
 * @param {number} digits Token length (default 6)
 * @returns {string}
 */
function generateTOTP(secret, timestampMs = Date.now(), stepSeconds = 30, digits = 6) {
  const counter = Math.floor(timestampMs / 1000 / stepSeconds);
  return generateHOTP(secret, counter, digits);
}

/**
 * Verify TOTP Token with clock drift tolerance
 * @param {string} secret Base32 encoded secret
 * @param {string} token 6-digit string
 * @param {number} window Number of 30-second steps to tolerate before/after (default 1)
 * @param {number} timestampMs 
 * @param {number} stepSeconds 
 * @returns {boolean}
 */
function verifyTOTP(secret, token, window = 1, timestampMs = Date.now(), stepSeconds = 30) {
  if (!secret || !token) return false;
  const cleanToken = token.toString().trim();
  if (!/^\d{6}$/.test(cleanToken)) return false;

  const currentCounter = Math.floor(timestampMs / 1000 / stepSeconds);

  for (let i = -window; i <= window; i++) {
    const candidate = generateHOTP(secret, currentCounter + i, 6);
    if (crypto.timingSafeEqual(Buffer.from(candidate), Buffer.from(cleanToken))) {
      return true;
    }
  }

  return false;
}

/**
 * Generate standard otpauth URI for QR codes and authenticator apps
 * @param {string} issuer e.g. "EJI Security"
 * @param {string} accountName e.g. "eldar.jamiyev@caspel.az"
 * @param {string} secret Base32 secret
 * @returns {string}
 */
function getOtpAuthUrl(issuer, accountName, secret) {
  const cleanIssuer = encodeURIComponent(issuer || 'EJI');
  const cleanAccount = encodeURIComponent(accountName || 'admin');
  return `otpauth://totp/${cleanIssuer}:${cleanAccount}?secret=${secret}&issuer=${cleanIssuer}&algorithm=SHA1&digits=6&period=30`;
}

module.exports = {
  base32Encode,
  base32Decode,
  generateSecret,
  generateHOTP,
  generateTOTP,
  verifyTOTP,
  getOtpAuthUrl
};
