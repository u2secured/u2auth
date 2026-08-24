import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function toBase32(buf: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = "";

  for (let i = 0; i < buf.length; i++) {
    value = (value << 8) | buf[i];
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

export interface QRCodeOptions {
  algorithm?: string;
  digits?: number;
  period?: number;
}

/**
 * Generate a cryptographically random base32-encoded TOTP secret.
 */
export function generateSecret(byteLen = 20): string {
  const buf = randomBytes(byteLen);
  return toBase32(buf);
}

/**
 * Build an otpauth://totp/... URI for QR code display.
 */
export function generateQRCodeURI(
  issuer: string,
  account: string,
  secret: string,
  opts?: QRCodeOptions
): string {
  const algorithm = opts?.algorithm ?? "SHA1";
  const digits = opts?.digits ?? 6;
  const period = opts?.period ?? 30;

  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(account)}`;
  const params = new URLSearchParams({
    secret,
    issuer,
    algorithm,
    digits: String(digits),
    period: String(period),
  });

  return `otpauth://totp/${label}?${params.toString()}`;
}

/**
 * Generate count random 8-character alphanumeric recovery codes.
 */
export function generateRecoveryCodes(count = 10): string[] {
  const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const codes: string[] = [];

  for (let i = 0; i < count; i++) {
    const buf = randomBytes(8);
    let code = "";
    for (let j = 0; j < 8; j++) {
      code += charset[buf[j] % charset.length];
    }
    codes.push(code);
  }
  return codes;
}

function fromBase32(s: string): Buffer {
  const clean = s.toUpperCase().trim().replace(/=+$/, "");
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/**
 * Compute the TOTP code for a secret at a given instant (RFC 6238).
 * Exposed mainly so tests can drive a fixed clock; most callers want
 * {@link validateTOTP}.
 */
export function generateTOTP(secret: string, atMs = Date.now(), digits = 6, periodSec = 30): string {
  const counter = Math.floor(atMs / 1000 / periodSec);
  const counterBytes = Buffer.alloc(8);
  counterBytes.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  counterBytes.writeUInt32BE(counter >>> 0, 4);

  const mac = createHmac("sha1", fromBase32(secret)).update(counterBytes).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const truncated = mac.readUInt32BE(offset) & 0x7fffffff;
  return String(truncated % 10 ** digits).padStart(digits, "0");
}

/**
 * Verify a TOTP code locally, without a network call.
 *
 * This runs the same RFC 6238 check the U2 Secured Authenticator backend runs,
 * including the ±1 window tolerance for clock drift, and returns the same
 * answer. Prefer it when a login must not depend on a third party being
 * reachable: the developer's backend already holds the secret, so no round trip
 * is required to check a code.
 *
 * What it does NOT provide, and `client.verifyTOTP()` does:
 *   - the shared brute-force lockout, which spans all of your backend instances
 *   - an entry in the Activity feed of the developer portal
 *
 * Neither call protects against replay on its own — a code stays valid for its
 * whole window. Bind a successful check to a single login attempt.
 */
export function validateTOTP(secret: string, code: string, atMs = Date.now(), digits = 6, periodSec = 30): boolean {
  const supplied = Buffer.from(code.trim());
  let ok = false;
  for (let delta = -1; delta <= 1; delta++) {
    const candidate = Buffer.from(generateTOTP(secret, atMs + delta * periodSec * 1000, digits, periodSec));
    // Compare every window rather than short-circuiting, and use a
    // length-checked constant-time compare, so neither the matching window nor
    // the number of correct digits is observable through timing.
    if (candidate.length === supplied.length && timingSafeEqual(candidate, supplied)) ok = true;
  }
  return ok;
}
