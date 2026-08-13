import { describe, expect, it } from 'vitest';
import {
  buildEnvelope,
  combineKey,
  deriveFromPassword,
  generateNoteKey,
  generateSalt,
  keyFromBase64Url,
  keyToBase64Url,
  parseEnvelope,
  seal,
  unseal,
  verifyPassword
} from './crypto.js';

describe('deriveFromPassword', () => {
  it('is deterministic for the same password and salt', () => {
    const salt = generateSalt();
    const a = deriveFromPassword('hunter2', salt);
    const b = deriveFromPassword('hunter2', salt);
    expect(a.equals(b)).toBe(true);
  });

  it('differs for different salts', () => {
    const a = deriveFromPassword('hunter2', generateSalt());
    const b = deriveFromPassword('hunter2', generateSalt());
    expect(a.equals(b)).toBe(false);
  });
});

describe('verifyPassword', () => {
  it('accepts the correct password', () => {
    const salt = generateSalt();
    const verifier = deriveFromPassword('hunter2', salt);
    expect(verifyPassword('hunter2', salt, verifier)).toBe(true);
  });

  it('rejects the wrong password', () => {
    const salt = generateSalt();
    const verifier = deriveFromPassword('hunter2', salt);
    expect(verifyPassword('wrong', salt, verifier)).toBe(false);
  });

  it('rejects a verifier of the wrong length without throwing', () => {
    const salt = generateSalt();
    const corruptVerifier = Buffer.alloc(16);
    expect(verifyPassword('hunter2', salt, corruptVerifier)).toBe(false);
  });
});

describe('combineKey', () => {
  it('passes the note key through unchanged when there is no password', () => {
    const noteKey = generateNoteKey();
    expect(combineKey(noteKey, undefined, null).equals(noteKey)).toBe(true);
  });

  it('mixes in the password so the combined key differs from the raw note key', () => {
    const noteKey = generateNoteKey();
    const salt = generateSalt();
    const combined = combineKey(noteKey, 'hunter2', salt);
    expect(combined.equals(noteKey)).toBe(false);
  });

  it('is deterministic for the same note key, password, and salt', () => {
    const noteKey = generateNoteKey();
    const salt = generateSalt();
    const a = combineKey(noteKey, 'hunter2', salt);
    const b = combineKey(noteKey, 'hunter2', salt);
    expect(a.equals(b)).toBe(true);
  });
});

describe('seal/unseal', () => {
  it('round-trips plaintext through the same key', () => {
    const key = generateNoteKey();
    const plaintext = Buffer.from('the launch code is 1234', 'utf8');
    const sealed = seal(plaintext, key);
    const opened = unseal(sealed, key);
    expect(opened.equals(plaintext)).toBe(true);
  });

  it('throws (auth tag failure) when unsealing with the wrong key', () => {
    const plaintext = Buffer.from('secret', 'utf8');
    const sealed = seal(plaintext, generateNoteKey());
    expect(() => unseal(sealed, generateNoteKey())).toThrow();
  });

  it('throws when the ciphertext has been tampered with', () => {
    const key = generateNoteKey();
    const sealed = seal(Buffer.from('secret', 'utf8'), key);
    sealed.ciphertext[0] = (sealed.ciphertext[0] ?? 0) ^ 0xff;
    expect(() => unseal(sealed, key)).toThrow();
  });
});

describe('key base64url encoding', () => {
  it('round-trips through keyToBase64Url/keyFromBase64Url', () => {
    const key = generateNoteKey();
    expect(keyFromBase64Url(keyToBase64Url(key)).equals(key)).toBe(true);
  });

  it('rejects a key of the wrong length', () => {
    const shortKey = Buffer.alloc(8).toString('base64url');
    expect(() => keyFromBase64Url(shortKey)).toThrow('invalid key length');
  });
});

describe('buildEnvelope/parseEnvelope', () => {
  it('round-trips filename, content type, and payload', () => {
    const payload = Buffer.from('file bytes', 'utf8');
    const envelope = buildEnvelope('contract.pdf', 'application/pdf', payload);
    const parsed = parseEnvelope(envelope);
    expect(parsed.filename).toBe('contract.pdf');
    expect(parsed.contentType).toBe('application/pdf');
    expect(parsed.payload.equals(payload)).toBe(true);
  });

  it('represents a missing filename as null and defaults an empty content type', () => {
    const payload = Buffer.from('plain text', 'utf8');
    const envelope = buildEnvelope(null, '', payload);
    const parsed = parseEnvelope(envelope);
    expect(parsed.filename).toBeNull();
    expect(parsed.contentType).toBe('application/octet-stream');
    expect(parsed.payload.equals(payload)).toBe(true);
  });

  it('throws on a truncated envelope', () => {
    expect(() => parseEnvelope(Buffer.alloc(2))).toThrow('malformed envelope');
  });
});
