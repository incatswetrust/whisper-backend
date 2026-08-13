-- Fixed-window counters keyed by an arbitrary bucket string (ip + route +
-- window start, see src/rateLimit.ts). One row per (key, window); rows from
-- past windows are harmless dead weight until swept, not incorrect.
create table if not exists rate_limits (
  bucket_key text primary key,
  count integer not null default 1,
  window_start timestamptz not null default now()
);

create index if not exists rate_limits_window_start_idx on rate_limits (window_start);
