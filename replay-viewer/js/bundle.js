// Loading and verifying ReplayBundles in the browser.
//
// The viewer never trusts a server's rendering: it checks the bundle
// signature and the evidence chain, then re executes the evidence with the
// pinned policy inside the same engine build (compiled to WebAssembly), and
// renders only when every recorded verdict is reproduced (section 13).

import init, { reverifyBundle, engineVersion } from '../pkg/ivar_wasm.js';

let started;

export function ready() {
  started ??= init();
  return started;
}

export class VerificationError extends Error {}

/**
 * Verify one bundle. `text` must be the bundle file exactly as received,
 * because the signature covers its serialized form.
 */
export async function verifyBundle(text, keyringText, redactionKeyHex) {
  await ready();
  const result = reverifyBundle(text, keyringText ?? '', (redactionKeyHex ?? '').trim());
  let parsed;
  try {
    parsed = JSON.parse(result);
  } catch {
    throw new VerificationError(result);
  }
  if (parsed?.error) throw new VerificationError(parsed.error);
  if (!parsed || parsed.matched !== true) {
    throw new VerificationError(`replay does not reproduce the live verdicts: ${(parsed?.mismatches ?? []).join('; ')}`);
  }
  return { bundle: JSON.parse(text), reExecution: parsed, engine: engineVersion() };
}

/** Index sealed evidence by id for the inspector. */
export function evidenceIndex(bundle) {
  return new Map((bundle.evidence ?? []).map((r) => [r.evidence_id, r]));
}
