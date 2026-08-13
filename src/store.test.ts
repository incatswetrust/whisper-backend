import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { NoteRecord } from './types.js';

// store.ts only issues four distinct query shapes (insert/select/update/
// delete on `notes`), so a tiny in-memory fake standing in for `sql` is
// enough to exercise burnView's logic — real Postgres row-locking isn't
// meaningfully testable in-process anyway (Node is single-threaded).
const fakeRows = vi.hoisted(() => new Map<string, Record<string, unknown>>());

vi.mock('./db.js', () => {
  function sql(strings: TemplateStringsArray, ...values: unknown[]): Promise<Record<string, unknown>[]> {
    const text = strings.join(' ').trim().toLowerCase();

    if (text.startsWith('insert into notes')) {
      const [
        id,
        ciphertext,
        iv,
        authTag,
        salt,
        hasPassword,
        passwordVerifier,
        clientEncrypted,
        allowedIp,
        filename,
        contentType,
        expiresAtSeconds,
        viewsRemaining
      ] = values;
      fakeRows.set(id as string, {
        id,
        ciphertext,
        iv,
        auth_tag: authTag,
        salt,
        has_password: hasPassword,
        password_verifier: passwordVerifier,
        client_encrypted: clientEncrypted,
        allowed_ip: allowedIp,
        filename,
        content_type: contentType,
        created_at: new Date().toISOString(),
        expires_at: new Date((expiresAtSeconds as number) * 1000).toISOString(),
        views_remaining: viewsRemaining
      });
      return Promise.resolve([]);
    }

    if (text.startsWith('select * from notes')) {
      const row = fakeRows.get(values[0] as string);
      if (!row || new Date(row.expires_at as string).getTime() <= Date.now()) return Promise.resolve([]);
      return Promise.resolve([row]);
    }

    if (text.startsWith('update notes')) {
      const row = fakeRows.get(values[0] as string);
      const expired = !row || new Date(row.expires_at as string).getTime() <= Date.now();
      if (!row || expired || (row.views_remaining as number) <= 0) return Promise.resolve([]);
      row.views_remaining = (row.views_remaining as number) - 1;
      return Promise.resolve([{ views_remaining: row.views_remaining }]);
    }

    if (text.startsWith('delete from notes')) {
      fakeRows.delete(values[0] as string);
      return Promise.resolve([]);
    }

    throw new Error(`fake sql: unhandled query: ${text}`);
  }

  return { sql };
});

const { store } = await import('./store.js');

function baseRecord(overrides: Partial<NoteRecord> = {}): NoteRecord {
  return {
    id: 'test-id',
    ciphertext: Buffer.from('secret'),
    iv: Buffer.alloc(12),
    authTag: Buffer.alloc(16),
    salt: null,
    hasPassword: false,
    passwordVerifier: null,
    clientEncrypted: false,
    allowedIp: null,
    filename: null,
    contentType: 'text/plain',
    createdAt: Date.now(),
    expiresAt: Date.now() + 60_000,
    viewsRemaining: 1,
    ...overrides
  };
}

beforeEach(() => {
  fakeRows.clear();
});

describe('store.burnView', () => {
  it('decrements and returns the remaining view count', async () => {
    await store.put(baseRecord({ id: 'a', viewsRemaining: 3 }));
    await expect(store.burnView('a')).resolves.toBe(2);
  });

  it('deletes the row once views are exhausted', async () => {
    await store.put(baseRecord({ id: 'b', viewsRemaining: 1 }));
    await expect(store.burnView('b')).resolves.toBe(0);
    await expect(store.get('b')).resolves.toBeUndefined();
  });

  it('returns null for an already-exhausted note', async () => {
    await store.put(baseRecord({ id: 'c', viewsRemaining: 1 }));
    await store.burnView('c');
    await expect(store.burnView('c')).resolves.toBeNull();
  });

  it('returns null for a nonexistent note', async () => {
    await expect(store.burnView('does-not-exist')).resolves.toBeNull();
  });

  it('returns null for an expired note, and excludes it from get() too', async () => {
    await store.put(baseRecord({ id: 'd', expiresAt: Date.now() - 1000 }));
    await expect(store.burnView('d')).resolves.toBeNull();
    await expect(store.get('d')).resolves.toBeUndefined();
  });
});
