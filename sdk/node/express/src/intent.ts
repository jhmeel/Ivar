// Intent origins mint the token; each later step attests with its own key.
// Each step can narrow it and none can widen it (section 6.2).

import * as core from '@ivar/core-wasm';

function unwrap(json: string): { token: string; root_public_key?: string; step_public_key?: string } {
  const v = JSON.parse(json);
  if (v.error) throw new Error(v.error);
  return v;
}

export interface Narrowing {
  max?: Record<string, number>;
  expiry_ms?: number;
}

export function mintIntent(rootSeedHex: string, intentId: string, action: string, subject: string, limits: Record<string, number>, ttlMs = 5 * 60_000): { token: string; rootPublicKey: string } {
  const v = unwrap(core.mintIntent(rootSeedHex, intentId, action, subject, JSON.stringify(limits), Date.now() + ttlMs));
  return { token: v.token, rootPublicKey: v.root_public_key ?? '' };
}

export function attestStep(stepSeedHex: string, step: string, token: string, rootPublicKey: string, narrowing: Narrowing = {}): string {
  return unwrap(core.attestStep(stepSeedHex, step, token, rootPublicKey, JSON.stringify(narrowing))).token;
}

export function narrowIntent(token: string, rootPublicKey: string, narrowing: Narrowing): string {
  return unwrap(core.narrowIntent(token, rootPublicKey, JSON.stringify(narrowing))).token;
}

export function stepPublicKey(stepSeedHex: string): string {
  return core.stepPublicKey(stepSeedHex);
}

/** Header that carries the intent token from origin to sink. */
export const INTENT_HEADER = 'ivar-intent';
