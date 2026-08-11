create table if not exists notes (
  id text primary key,
  ciphertext bytea not null,
  iv bytea not null,
  auth_tag bytea not null,
  salt bytea,
  has_password boolean not null default false,
  password_verifier bytea,
  client_encrypted boolean not null default false,
  allowed_ip text,
  filename text,
  content_type text not null default 'application/octet-stream',
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  views_remaining integer not null
);

-- reads always filter on expires_at; the burn-view update additionally
-- filters on views_remaining, so both are worth indexing.
create index if not exists notes_expires_at_idx on notes (expires_at);
