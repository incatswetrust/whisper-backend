# whisper-backend

Open HTTP API for anonymous, self-destructing, end-to-end-encryptable notes
and files. Companion backend for `whisper-frontend`. Storage is Postgres
(Neon) — notes are deleted the moment their view count or TTL runs out, so
in practice the table stays close to empty; nothing sits around longer than
its expiry.

## Run it

```bash
npm install
# DATABASE_URL must point at a Neon (or any) Postgres instance
npm run db:migrate   # applies migrations/*.sql
npm run dev           # tsx watch, http://localhost:8787
npm run build && npm start   # production (long-running Node process)
```

Config is via env vars (see `src/config.ts`): `DATABASE_URL` (or
`POSTGRES_URL`), `PORT`, `FRONTEND_ORIGIN` (comma-separated CORS allowlist),
`TRUST_PROXY`, `MAX_ITEM_BYTES`, `DEFAULT_TTL_MINUTES`.

## Deploying to Vercel

The app's own routes (`/health`, `/notes`, `/notes/:id`) have no `/api`
prefix — `api.whisper.beer/notes`, not `api.whisper.beer/api/notes`, since
the subdomain already says "this is the API." Vercel functions can only
live under `/api` though, so `api/[[...route]].ts` mounts the app under
`/api` internally (`new Hono().route('/api', app)`), and `vercel.json`
rewrites every public path to its `/api/...` counterpart so that internal
prefix never shows up outside this repo. It also forces the Node.js runtime
(not Edge — password hashing needs `node:crypto`'s `scryptSync`, which
Edge's Web Crypto subset doesn't have) and restricts Vercel's function
detection to `api/**/*.ts` — without that, Vercel's zero-config detection
also builds `src/index.ts` (the local dev entry, which just starts a
long-running `@hono/node-server` listener) as a second, broken function,
and traffic randomly hitting it either hangs or crashes with
`FUNCTION_INVOCATION_FAILED`.

1. Connect a Neon Postgres database to the project (Vercel Marketplace →
   Neon) — this sets `DATABASE_URL` automatically.
2. Run `npm run db:migrate` once (locally, pointed at that same
   `DATABASE_URL`, or via Vercel's shell) to create the `notes` table.
3. Set `FRONTEND_ORIGIN` to your deployed frontend's origin.
4. Deploy. `src/index.ts` / `@hono/node-server` are only used for local
   `npm run dev` — Vercel never touches them.

**Why files live in the same Postgres `bytea` column as text notes, not in
object storage:** Vercel serverless functions cap request/response bodies at
roughly 4.5MB regardless of backend, so `MAX_ITEM_BYTES` (default 4MB) was
always going to be small. Neon handles a few-MB `bytea` value fine, so a
second storage service (Vercel Blob/S3) would be pure overhead for no
benefit at this size. If you raise the size ceiling a lot later (self-hosted,
no Vercel body limit), that's the point to move ciphertext into object
storage and keep only metadata + a reference in Postgres.

## Encryption model

Every note is AES-256-GCM encrypted with a random 256-bit key that the
**server never stores**. There are two ways to get a note in:

1. **Server-encrypted** (default, what curl uses): you POST plaintext, the
   server generates a key, encrypts, discards the plaintext, and returns the
   key to you once in the response. If you never save that key, nobody —
   including us — can ever recover the note.
2. **Client-encrypted** (`X-Encrypted: client`): you encrypt before sending
   (e.g. browser Web Crypto). The server stores your ciphertext as an opaque
   blob and never sees a key at all.

If you set a password, it's mixed into the encryption key via scrypt + HMAC
(server-encrypted mode) — decryption simply fails if the password is wrong,
there's no separate password hash to attack. `allowed_ip` is a separate,
non-cryptographic network gate checked before any content is served.

## Creating a note — `POST /notes`

Body is the raw payload (text or file bytes). Everything else is headers so
the whole thing works cleanly with `curl --data-binary`.

| Header           | Meaning                                                  |
|-------------------|-----------------------------------------------------------|
| `Content-Type`     | real MIME type of the payload                             |
| `X-Password`       | optional password; required again to read                 |
| `X-Views`          | max number of reads (default 1, or unlimited-ish if `X-TTL-Minutes` given without this) |
| `X-TTL-Minutes`    | expire after N minutes regardless of views                |
| `X-Allowed-IP`     | exact IP, IPv4 CIDR (`10.0.0.0/8`), or comma-separated list |
| `X-Filename`       | original filename, for downloads                          |
| `X-Encrypted: client` | payload is already encrypted by the caller; server stores it opaquely |

```bash
# simplest: one-shot secret text
curl -X POST http://localhost:8787/notes \
  -H "Content-Type: text/plain" \
  --data-binary "the launch code is 1234"
# => { "id": "...", "key": "...", "url_decrypted": "http://.../notes/ID?key=KEY", ... }

# a file, password-protected, 5 views, expires in 60 minutes
curl -X POST http://localhost:8787/notes \
  -H "Content-Type: application/pdf" \
  -H "X-Filename: contract.pdf" \
  -H "X-Password: hunter2" \
  -H "X-Views: 5" \
  -H "X-TTL-Minutes: 60" \
  --data-binary @contract.pdf

# restrict who can ever fetch it
curl -X POST http://localhost:8787/notes \
  -H "Content-Type: text/plain" \
  -H "X-Allowed-IP: 203.0.113.4,198.51.100.0/24" \
  --data-binary "only for the office network"
```

## Reading a note — `GET /notes/:id`

```bash
# the easy way: server decrypts for you, streams the content back
curl "http://localhost:8787/notes/ID?key=KEY" -o downloaded_file
curl "http://localhost:8787/notes/ID?key=KEY" -H "X-Password: hunter2"

# the paranoid way: fetch raw ciphertext, decrypt locally, key never
# touches the network at read time
curl -D headers.txt -o note.enc "http://localhost:8787/notes/ID"
# headers.txt now has X-Iv / X-Auth-Tag / X-Salt (if a password was set) / X-Alg
# decrypt with openssl (password case needs the same scrypt+HMAC combine —
# see src/crypto.ts combineKey — a plain openssl one-liner only covers the
# no-password case):
# keys/iv/tag are base64url — convert to hex first (portable across openssl versions)
HEX_KEY=$(echo -n "KEY" | tr '_-' '/+' | base64 -d | xxd -p -c256)
openssl enc -d -aes-256-gcm -K "$HEX_KEY" \
  -iv $(grep -i x-iv headers.txt | cut -d' ' -f2 | tr -d '\r' | tr '_-' '/+' | base64 -d | xxd -p -c256) \
  -in note.enc -out note.txt
```

Each successful read (content actually returned, whether or not it later
turns out to be decryptable) burns one view. Wrong key/password (400) or a
blocked IP (403) never consumes a view, so a guesser can't burn the real
recipient's read. Once views hit 0 or the TTL passes, the note is gone —
`GET` returns 404.

## Notes / current limitations

- IP allowlist: exact match or IPv4 CIDR only (no IPv6 CIDR yet).
- No auth, no rate limiting — it's an anonymous public API by design; put a
  reverse proxy in front if you want rate limits, and set `TRUST_PROXY=true`
  + review `X-Forwarded-For` handling in `src/ip.ts` if you do.
- Expired rows aren't proactively swept — they're filtered out of every read
  (`expires_at > now()`) and deleted the moment a note's last view is burned,
  so an unread-but-expired note just sits inert until its next read attempt
  deletes it. Add a Vercel Cron hitting a small cleanup query if you want
  guaranteed prompt deletion regardless of reads.
- Not yet wired into `whisper-frontend` — the UI's create/view forms don't
  call this API yet, that's the next step.
