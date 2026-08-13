import type { Context } from 'hono';
import { getConnInfo } from '@hono/node-server/conninfo';
import net from 'node:net';
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

// IPv6 has 128 bits — plain JS numbers (53 usable bits) can't hold that, so
// this path uses BigInt throughout, unlike the IPv4 helpers above.
function ipv6ToBigInt(ip: string): bigint | null {
  if (!net.isIPv6(ip)) return null;

  const halves = ip.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - head.length - tail.length;
  if (missing < 0) return null;
  const groups = [...head, ...Array(missing).fill('0'), ...tail];
  if (groups.length !== 8) return null;

  let result = 0n;
  for (const group of groups) {
    const n = Number.parseInt(group, 16);
    if (!Number.isInteger(n) || n < 0 || n > 0xffff) return null;
    result = (result << 16n) | BigInt(n);
  }
  return result;
}

function matchesIpv6Rule(ip: string, rule: string): boolean {
  const [base, prefixStr] = rule.split('/');
  const ipBig = ipv6ToBigInt(ip);
  const baseBig = base ? ipv6ToBigInt(base) : null;
  const prefix = prefixStr === undefined ? 128 : Number(prefixStr);
  if (ipBig === null || baseBig === null || !Number.isInteger(prefix) || prefix < 0 || prefix > 128) {
    return false;
  }
  const fullMask = (1n << 128n) - 1n;
  const mask = prefix === 0 ? 0n : (fullMask << BigInt(128 - prefix)) & fullMask;
  return (ipBig & mask) === (baseBig & mask);
}

function matchesRule(ip: string, rule: string): boolean {
  rule = rule.trim();
  if (!rule) return false;
  if (rule === ip) return true;

  // Not supporting embedded-IPv4-in-IPv6 CIDR *rules* like
  // `::ffff:192.0.2.0/120` — normalize() already strips that form from
  // client IPs, so this only matters for a rule written that way, an edge
  // case not worth the added parsing complexity.
  if (ip.includes(':') || rule.includes(':')) {
    return matchesIpv6Rule(ip, rule);
  }

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

/**
 * `allowRule` may be a single IPv4/IPv6 address, an IPv4/IPv6 CIDR block, or
 * a comma-separated list of either.
 */
export function ipAllowed(clientIp: string, allowRule: string): boolean {
  return allowRule
    .split(',')
    .some((rule) => matchesRule(clientIp, rule));
}
