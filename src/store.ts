import { randomBytes } from 'node:crypto';
import { sql } from './db.js';
import type { NoteRecord } from './types.js';

export class TooLargeError extends Error {}

function toBuf(v: unknown): Buffer {
  // node-postgres/neon return bytea columns as Buffer already under node runtime
  return Buffer.isBuffer(v) ? v : Buffer.from(v as ArrayBuffer);
}

function rowToRecord(row: Record<string, unknown>): NoteRecord {
  return {
    id: row.id as string,
    ciphertext: toBuf(row.ciphertext),
    iv: toBuf(row.iv),
    authTag: toBuf(row.auth_tag),
    salt: row.salt ? toBuf(row.salt) : null,
    hasPassword: row.has_password as boolean,
    passwordVerifier: row.password_verifier ? toBuf(row.password_verifier) : null,
    clientEncrypted: row.client_encrypted as boolean,
    allowedIp: row.allowed_ip as string | null,
    filename: row.filename as string | null,
    contentType: row.content_type as string,
    createdAt: new Date(row.created_at as string).getTime(),
    expiresAt: new Date(row.expires_at as string).getTime(),
    viewsRemaining: row.views_remaining as number
  };
}

function generateId(): string {
  return randomBytes(9).toString('base64url');
}

async function put(record: NoteRecord): Promise<void> {
  await sql`
    insert into notes (
      id, ciphertext, iv, auth_tag, salt, has_password, password_verifier,
      client_encrypted, allowed_ip, filename, content_type, expires_at, views_remaining
    ) values (
      ${record.id}, ${record.ciphertext}, ${record.iv}, ${record.authTag}, ${record.salt},
      ${record.hasPassword}, ${record.passwordVerifier}, ${record.clientEncrypted},
      ${record.allowedIp}, ${record.filename}, ${record.contentType},
      to_timestamp(${record.expiresAt / 1000}), ${record.viewsRemaining}
    )
  `;
}

/** Fetches a note for gate-checks (IP/password) without consuming a view. */
async function get(id: string): Promise<NoteRecord | undefined> {
  const rows = await sql`
    select * from notes where id = ${id} and expires_at > now()
  `;
  return rows[0] ? rowToRecord(rows[0] as Record<string, unknown>) : undefined;
}

/**
 * Atomically consumes one view right before content is actually sent.
 * Returns the remaining view count, or null if there was nothing left to
 * consume (already exhausted/expired) — the caller must not serve content
 * in that case, even if an earlier `get()` succeeded.
 */
async function burnView(id: string): Promise<number | null> {
  const rows = await sql`
    update notes
    set views_remaining = views_remaining - 1
    where id = ${id} and views_remaining > 0 and expires_at > now()
    returning views_remaining
  `;
  const row = rows[0] as { views_remaining: number } | undefined;
  if (!row) return null;
  if (row.views_remaining <= 0) {
    await sql`delete from notes where id = ${id}`;
  }
  return row.views_remaining;
}

async function del(id: string): Promise<void> {
  await sql`delete from notes where id = ${id}`;
}

async function stats(): Promise<{ ok: true; count: number }> {
  const rows = await sql`select count(*)::int as count from notes where expires_at > now()`;
  return { ok: true, count: (rows[0] as { count: number }).count };
}

export const store = { generateId, put, get, burnView, delete: del, stats };
