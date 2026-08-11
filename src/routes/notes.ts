import { Hono } from 'hono';
import { bodyLimit } from 'hono/body-limit';
import { config } from '../config.js';
import { store } from '../store.js';
import { getClientIp, ipAllowed } from '../ip.js';
import {
  generateNoteKey,
  generateSalt,
  combineKey,
  seal,
  unseal,
  keyToBase64Url,
  keyFromBase64Url,
  buildEnvelope,
  parseEnvelope,
  deriveFromPassword,
  verifyPassword
} from '../crypto.js';
import type { NoteRecord } from '../types.js';

export const notes = new Hono();

const MAX_VIEWS = 1_000_000;

function parsePositiveInt(raw: string | undefined, fallback: number): number {
  if (!raw) return fallback;
  const n = Number.parseInt(raw, 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

notes.post(
  '/',
  bodyLimit({
    maxSize: config.maxItemBytes,
    onError: (c) => c.json({ error: `payload exceeds max size of ${config.maxItemBytes} bytes` }, 413)
  }),
  async (c) => {
    const rawBody = Buffer.from(await c.req.arrayBuffer());
    if (rawBody.length === 0) {
      return c.json({ error: 'empty body' }, 400);
    }

    const password = c.req.header('x-password') || undefined;
    const filename = c.req.header('x-filename') || null;
    const contentType = c.req.header('content-type') || 'application/octet-stream';
    const allowedIp = c.req.header('x-allowed-ip') || null;
    const clientEncrypted = (c.req.header('x-encrypted') || '').toLowerCase() === 'client';

    const viewsHeader = c.req.header('x-views');
    const ttlHeader = c.req.header('x-ttl-minutes');
    const views = viewsHeader ? parsePositiveInt(viewsHeader, 1) : ttlHeader ? MAX_VIEWS : 1;
    const ttlMinutes = ttlHeader ? parsePositiveInt(ttlHeader, config.defaultTtlMinutes) : null;
    const expiresAt = Date.now() + (ttlMinutes ?? config.defaultTtlMinutes) * 60_000;

    const id = store.generateId();
    let record: NoteRecord;
    let responseKey: string | null = null;

    if (clientEncrypted) {
      let passwordVerifier: Buffer | null = null;
      let salt: Buffer | null = null;
      if (password) {
        salt = generateSalt();
        passwordVerifier = deriveFromPassword(password, salt);
      }
      record = {
        id,
        ciphertext: rawBody,
        iv: Buffer.alloc(0),
        authTag: Buffer.alloc(0),
        salt,
        hasPassword: Boolean(password),
        passwordVerifier,
        clientEncrypted: true,
        allowedIp,
        filename,
        contentType,
        createdAt: Date.now(),
        expiresAt,
        viewsRemaining: views
      };
    } else {
      const noteKey = generateNoteKey();
      const salt = password ? generateSalt() : null;
      const finalKey = combineKey(noteKey, password, salt);
      const envelope = buildEnvelope(filename, contentType, rawBody);
      const sealed = seal(envelope, finalKey);
      record = {
        id,
        ciphertext: sealed.ciphertext,
        iv: sealed.iv,
        authTag: sealed.authTag,
        salt,
        hasPassword: Boolean(password),
        passwordVerifier: null,
        clientEncrypted: false,
        allowedIp,
        filename: null,
        contentType: 'application/octet-stream',
        createdAt: Date.now(),
        expiresAt,
        viewsRemaining: views
      };
      responseKey = keyToBase64Url(noteKey);
    }

    await store.put(record);

    const origin = new URL(c.req.url).origin;
    return c.json(
      {
        id,
        key: responseKey,
        has_password: record.hasPassword,
        client_encrypted: clientEncrypted,
        views_remaining: record.viewsRemaining,
        expires_at: new Date(record.expiresAt).toISOString(),
        url_raw: `${origin}/api/notes/${id}`,
        url_decrypted: responseKey ? `${origin}/api/notes/${id}?key=${responseKey}` : null
      },
      201
    );
  }
);

notes.get('/:id', async (c) => {
  const id = c.req.param('id');
  const record = await store.get(id);
  if (!record) {
    return c.json({ error: 'not found or expired' }, 404);
  }

  if (record.allowedIp) {
    const clientIp = getClientIp(c);
    if (!ipAllowed(clientIp, record.allowedIp)) {
      return c.json({ error: 'forbidden: source ip not allowed' }, 403);
    }
  }

  const password = c.req.header('x-password') || undefined;
  const key = c.req.query('key');

  // Everything below only checks whether the request *would* be servable;
  // the actual view is burned atomically, right before each response body
  // is written, so a losing race never gets to see content.

  if (record.clientEncrypted) {
    if (record.hasPassword) {
      if (!password) return c.json({ error: 'password required' }, 401);
      if (!verifyPassword(password, record.salt!, record.passwordVerifier!)) {
        return c.json({ error: 'invalid password' }, 401);
      }
    }
    const remaining = await store.burnView(id);
    if (remaining === null) return c.json({ error: 'not found or expired' }, 404);
    c.header('content-type', record.contentType);
    if (record.filename) c.header('content-disposition', `attachment; filename="${sanitizeFilename(record.filename)}"`);
    c.header('x-views-remaining', String(remaining));
    return c.body(Uint8Array.from(record.ciphertext));
  }

  if (!key) {
    // Raw ciphertext fetch: caller decrypts locally (openssl / Web Crypto),
    // so the key/password never has to travel to the server on read.
    const remaining = await store.burnView(id);
    if (remaining === null) return c.json({ error: 'not found or expired' }, 404);
    c.header('content-type', 'application/octet-stream');
    c.header('x-alg', 'aes-256-gcm');
    c.header('x-iv', record.iv.toString('base64url'));
    c.header('x-auth-tag', record.authTag.toString('base64url'));
    if (record.salt) c.header('x-salt', record.salt.toString('base64url'));
    c.header('x-has-password', String(record.hasPassword));
    c.header('x-views-remaining', String(remaining));
    return c.body(Uint8Array.from(record.ciphertext));
  }

  if (record.hasPassword && !password) {
    return c.json({ error: 'password required' }, 401);
  }

  let noteKey: Buffer;
  try {
    noteKey = keyFromBase64Url(key);
  } catch {
    return c.json({ error: 'malformed key' }, 400);
  }

  const finalKey = combineKey(noteKey, password, record.salt);
  let envelope: Buffer;
  try {
    envelope = unseal({ ciphertext: record.ciphertext, iv: record.iv, authTag: record.authTag }, finalKey);
  } catch {
    return c.json({ error: 'decryption failed: wrong key and/or password' }, 400);
  }

  const remaining = await store.burnView(id);
  if (remaining === null) return c.json({ error: 'not found or expired' }, 404);
  const { filename, contentType, payload } = parseEnvelope(envelope);
  c.header('content-type', contentType);
  if (filename) c.header('content-disposition', `attachment; filename="${sanitizeFilename(filename)}"`);
  c.header('x-views-remaining', String(remaining));
  return c.body(Uint8Array.from(payload));
});

function sanitizeFilename(name: string): string {
  return name.replace(/["\r\n]/g, '_');
}
