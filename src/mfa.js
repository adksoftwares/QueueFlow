const crypto = require("crypto");

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Encode(buffer) {
  let bits = 0;
  let value = 0;
  let output = "";

  for (const byte of buffer) {
    value = (value << 8) | byte;
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

function base32Decode(str) {
  const clean = String(str || "")
    .toUpperCase()
    .replace(/=+$/, "")
    .replace(/[^A-Z2-7]/g, "");
  let bits = 0;
  let value = 0;
  const bytes = [];

  for (const char of clean) {
    const idx = BASE32_ALPHABET.indexOf(char);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bytes.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Buffer.from(bytes);
}

function generateTotpSecret(byteLength = 20) {
  return base32Encode(crypto.randomBytes(byteLength));
}

function generateHotp(secretBase32, counter) {
  const key = base32Decode(secretBase32);
  const msg = Buffer.alloc(8);
  const big = BigInt(counter);
  msg.writeBigUInt64BE(big, 0);

  const hmac = crypto.createHmac("sha1", key).update(msg).digest();
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  return String(binary % 1000000).padStart(6, "0");
}

function generateTotp(secretBase32, timestampMs = Date.now(), stepSeconds = 30) {
  const counter = Math.floor(timestampMs / 1000 / stepSeconds);
  return generateHotp(secretBase32, counter);
}

function verifyTotp(secretBase32, token, timestampMs = Date.now(), window = 1, stepSeconds = 30) {
  const clean = String(token || "").replace(/\s+/g, "");
  if (!/^\d{6}$/.test(clean) || !secretBase32) return false;

  const counter = Math.floor(timestampMs / 1000 / stepSeconds);
  for (let offset = -window; offset <= window; offset++) {
    const expected = generateHotp(secretBase32, counter + offset);
    if (crypto.timingSafeEqual(Buffer.from(clean), Buffer.from(expected))) {
      return true;
    }
  }
  return false;
}

function buildOtpAuthUri({ secret, email, issuer = "QueueFlow" }) {
  const label = encodeURIComponent(`${issuer}:${email}`);
  return `otpauth://totp/${label}?secret=${encodeURIComponent(secret)}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;
}

function hashRecoveryCode(code) {
  const clean = String(code || "").trim().toUpperCase();
  return crypto.createHash("sha256").update(`qf-recovery:${clean}`).digest("hex");
}

function generateRecoveryCodes(count = 8) {
  const codes = [];
  const hashes = [];
  for (let i = 0; i < count; i++) {
    const raw = crypto.randomBytes(4).toString("hex").toUpperCase();
    const formatted = `${raw.slice(0, 4)}-${raw.slice(4, 8)}`;
    codes.push(formatted);
    hashes.push(hashRecoveryCode(formatted));
  }
  return { codes, hashes };
}

function consumeRecoveryCode(storedHashesJson, candidateCode) {
  let hashes = [];
  try {
    hashes = JSON.parse(storedHashesJson || "[]");
  } catch {
    return { matched: false, remainingJson: storedHashesJson };
  }
  if (!Array.isArray(hashes) || !hashes.length) {
    return { matched: false, remainingJson: storedHashesJson };
  }

  const candidateHash = hashRecoveryCode(candidateCode);
  const idx = hashes.findIndex((h) => {
    if (typeof h !== "string" || h.length !== candidateHash.length) return false;
    return crypto.timingSafeEqual(Buffer.from(h), Buffer.from(candidateHash));
  });
  if (idx === -1) {
    return { matched: false, remainingJson: storedHashesJson };
  }

  hashes.splice(idx, 1);
  return { matched: true, remainingJson: JSON.stringify(hashes) };
}

module.exports = {
  generateTotpSecret,
  generateTotp,
  verifyTotp,
  buildOtpAuthUri,
  generateRecoveryCodes,
  consumeRecoveryCode
};
