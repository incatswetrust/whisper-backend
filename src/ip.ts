import type { Context } from 'hono';
import { getConnInfo } from '@hono/node-server/conninfo';
import { config } from './config.js';

export function getClientIp(c: Context): string {
  if (config.trustProxy) {
    const xff = c.req.header('x-forwarded-for');
    if (xff) {
      const first = xff.split(',')[0]?.trim();
      if (first) return normalize(first);
    }
  }
  // Only meaningful for local dev via @hono/node-server — Vercel's own
  // Hono hosting doesn't provide the connection info this expects, so it
  // throws there. Always trustProxy=true on Vercel (see config.ts) means
  // this fallback is local-dev-only in practice, but keep it defensive.
  try {
    const info = getConnInfo(c);
    return normalize(info.remote.address ?? 'unknown');
  } catch {
    return 'unknown';
  }
}

function normalize(ip: string): string {
  // strip IPv4-mapped IPv6 prefix, e.g. ::ffff:127.0.0.1
  return ip.startsWith('::ffff:') ? ip.slice(7) : ip;
}

function ipv4ToInt(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const part of parts) {
    const octet = Number(part);
    if (!Number.isInteger(octet) || octet < 0 || octet > 255) return null;
    n = (n << 8) | octet;
  }
  return n >>> 0;
}

function matchesRule(ip: string, rule: string): boolean {
  rule = rule.trim();
  if (!rule) return false;
  if (rule === ip) return true;

  if (rule.includes('/')) {
    const [base, prefixStr] = rule.split('/');
    const prefix = Number(prefixStr);
    const ipInt = ipv4ToInt(ip);
    const baseInt = base ? ipv4ToInt(base) : null;
    if (ipInt === null || baseInt === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
      return false;
    }
    const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
    return (ipInt & mask) === (baseInt & mask);
  }

  return false;
}

/** `allowRule` may be a single IP, a CIDR block, or a comma-separated list of either. */
export function ipAllowed(clientIp: string, allowRule: string): boolean {
  return allowRule
    .split(',')
    .some((rule) => matchesRule(clientIp, rule));
}
