// Data handling rules (section 9): identifiers are keyed hashes by default and
// sensors never send passwords, tokens, OTPs, card numbers or raw bodies.
// The hash matches ivar_core::redact::keyed_hash, so ids line up everywhere.

import { createHmac } from 'node:crypto';

export function keyedHash(keyHex: string, value: string): string {
  if (!value || value.startsWith('kh_')) return value;
  const mac = createHmac('sha256', Buffer.from(keyHex, 'hex')).update(value).digest('hex');
  return `kh_${mac.slice(0, 24)}`;
}

const FORBIDDEN = /(pass(word|wd)?|secret|token|otp|one_time|pin$|cvv|cvc|card(_?number)?|pan$|authorization|cookie|api_?key|private_?key)/i;

/** Field names only, never values, and never names of secret fields' values. */
export function bodyKeys(body: unknown): string[] {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return [];
  return Object.keys(body as Record<string, unknown>).slice(0, 64);
}

export function safeAttributes(attrs: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(attrs)) {
    if (!FORBIDDEN.test(k)) out[k] = String(v).slice(0, 512);
  }
  return out;
}
