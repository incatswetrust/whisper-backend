import { describe, expect, it } from 'vitest';
import { ipAllowed } from './ip.js';

describe('ipAllowed — IPv4', () => {
  it('matches an exact IP', () => {
    expect(ipAllowed('203.0.113.4', '203.0.113.4')).toBe(true);
    expect(ipAllowed('203.0.113.5', '203.0.113.4')).toBe(false);
  });

  it('matches a CIDR block', () => {
    expect(ipAllowed('10.1.2.3', '10.0.0.0/8')).toBe(true);
    expect(ipAllowed('11.1.2.3', '10.0.0.0/8')).toBe(false);
  });

  it('matches any of a comma-separated list', () => {
    expect(ipAllowed('198.51.100.5', '203.0.113.4,198.51.100.0/24')).toBe(true);
    expect(ipAllowed('1.2.3.4', '203.0.113.4,198.51.100.0/24')).toBe(false);
  });
});

describe('ipAllowed — IPv6', () => {
  it('matches an exact address', () => {
    expect(ipAllowed('2001:db8::1', '2001:db8::1')).toBe(true);
    expect(ipAllowed('2001:db8::2', '2001:db8::1')).toBe(false);
  });

  it('matches an exact address written differently (compressed vs expanded)', () => {
    expect(ipAllowed('2001:0db8:0000:0000:0000:0000:0000:0001', '2001:db8::1')).toBe(true);
  });

  it('matches a CIDR block', () => {
    expect(ipAllowed('2001:db8::1234', '2001:db8::/32')).toBe(true);
    expect(ipAllowed('2001:db9::1234', '2001:db8::/32')).toBe(false);
  });

  it('rejects a malformed address or out-of-range prefix', () => {
    expect(ipAllowed('not-an-ip', '2001:db8::/32')).toBe(false);
    expect(ipAllowed('2001:db8::1', '2001:db8::/200')).toBe(false);
  });

  it('mixes IPv4 and IPv6 rules in one comma-separated list', () => {
    const rule = '203.0.113.4,2001:db8::/32';
    expect(ipAllowed('203.0.113.4', rule)).toBe(true);
    expect(ipAllowed('2001:db8::5', rule)).toBe(true);
    expect(ipAllowed('2001:dead::5', rule)).toBe(false);
  });
});
