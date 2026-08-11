import { randomBytes, scryptSync, createHmac, createCipheriv, createDecipheriv, timingSafeEqual } from 'node:crypto';

const ALG = 'aes-256-gcm';
const KEY_BYTES = 32;
const IV_BYTES = 12;
const SALT_BYTES = 16;
const SCRYPT_N = 2 ** 15;

export interface Sealed {
  ciphertext: Buffer;
  iv: Buffer;
  authTag: Buffer;
}

export function generateNoteKey(): Buffer {
  return randomBytes(KEY_BYTES);
}

export function generateSalt(): Buffer {
  return randomBytes(SALT_BYTES);
}

export function deriveFromPassword(password: string, salt: Buffer): Buffer {
  // scrypt's memory footprint is ~128 * N * r bytes; give it headroom above
  // Node's 32MB default maxmem so N=2^15, r=8 doesn't get rejected.
  return scryptSync(password, salt, KEY_BYTES, { N: SCRYPT_N, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
}

/**
 * For client-side-encrypted notes the server never holds a decryption key,
 * so a password gate has to be checked explicitly via a stored verifier
 * instead of relying on AEAD tag failure.
 */
export function verifyPassword(password: string, salt: Buffer, verifier: Buffer): boolean {
  const candidate = deriveFromPassword(password, salt);
  return candidate.length === verifier.length && timingSafeEqual(candidate, verifier);
}

/**
 * Combines the random per-note key with a password-derived value so that
 * decryption is impossible without both. Nothing password-derived is ever
 * stored — only `salt` (public, required to re-derive on read).
 */
export function combineKey(noteKey: Buffer, password: string | undefined, salt: Buffer | null): Buffer {
  if (!password || !salt) return noteKey;
  const fromPassword = deriveFromPassword(password, salt);
  return createHmac('sha256', fromPassword).update(noteKey).digest();
}

export function seal(plaintext: Buffer, key: Buffer): Sealed {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ALG, key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return { ciphertext, iv, authTag };
}

/** Throws if the key/password is wrong — GCM auth tag verification is the check. */
export function unseal(sealed: Sealed, key: Buffer): Buffer {
  const decipher = createDecipheriv(ALG, key, sealed.iv);
  decipher.setAuthTag(sealed.authTag);
  return Buffer.concat([decipher.update(sealed.ciphertext), decipher.final()]);
}

export function keyToBase64Url(key: Buffer): string {
  return key.toString('base64url');
}

export function keyFromBase64Url(s: string): Buffer {
  const buf = Buffer.from(s, 'base64url');
  if (buf.length !== KEY_BYTES) throw new Error('invalid key length');
  return buf;
}

export const alg = ALG;

/**
 * Packs filename + content-type into the plaintext before it's sealed, so
 * that metadata is encrypted along with the body instead of sitting next to
 * the ciphertext in cleartext store fields. Only used for the server-side
 * encryption path; client-encrypted notes are opaque to us entirely.
 */
export function buildEnvelope(filename: string | null, contentType: string, payload: Buffer): Buffer {
  const filenameBuf = Buffer.from(filename ?? '', 'utf8');
  const contentTypeBuf = Buffer.from(contentType || 'application/octet-stream', 'utf8');
  const header = Buffer.alloc(4);
  header.writeUInt16BE(filenameBuf.length, 0);
  header.writeUInt16BE(contentTypeBuf.length, 2);
  return Buffer.concat([header, filenameBuf, contentTypeBuf, payload]);
}

export function parseEnvelope(buf: Buffer): { filename: string | null; contentType: string; payload: Buffer } {
  if (buf.length < 4) throw new Error('malformed envelope');
  const filenameLen = buf.readUInt16BE(0);
  const contentTypeLen = buf.readUInt16BE(2);
  let offset = 4;
  const filenameBuf = buf.subarray(offset, offset + filenameLen);
  offset += filenameLen;
  const contentTypeBuf = buf.subarray(offset, offset + contentTypeLen);
  offset += contentTypeLen;
  const payload = buf.subarray(offset);
  return {
    filename: filenameBuf.length > 0 ? filenameBuf.toString('utf8') : null,
    contentType: contentTypeBuf.toString('utf8') || 'application/octet-stream',
    payload: Buffer.from(payload)
  };
}
