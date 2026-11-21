// Signed policy bundles for tests, in the format ivar-control writes: a tar
// archive holding policy.json and signatures.json, each signature an
// Ed25519 signature over the exact policy.json bytes.

import { createPrivateKey, createPublicKey, sign } from 'node:crypto';
import * as core from '@ivar/core-wasm';

export interface TestKey {
  id: string;
  seedHex: string;
}

function privateKey(seedHex: string) {
  return createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(seedHex, 'hex')]), format: 'der', type: 'pkcs8' });
}

export function publicHex(seedHex: string): string {
  const der = createPublicKey(privateKey(seedHex)).export({ format: 'der', type: 'spki' }) as Buffer;
  return der.subarray(der.length - 32).toString('hex');
}

export function keyring(keys: TestKey[]): Record<string, unknown> {
  return { keys: Object.fromEntries(keys.map((k) => [k.id, [{ key_id: k.id, alg: 'ed25519', bytes: publicHex(k.seedHex) }, ['policy']]])) };
}

function tarEntry(name: string, data: Buffer): Buffer {
  const h = Buffer.alloc(512);
  h.write(name, 0, 'utf8');
  h.write('0000644\0', 100);
  h.write('0000000\0', 108);
  h.write('0000000\0', 116);
  h.write(data.length.toString(8).padStart(11, '0') + '\0', 124);
  h.write('00000000000\0', 136);
  h.write('        ', 148);
  h.write('0', 156);
  h.write('ustar\0', 257);
  h.write('00', 263);
  let sum = 0;
  for (const b of h) sum += b;
  h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148);
  const pad = Buffer.alloc((512 - (data.length % 512)) % 512);
  return Buffer.concat([h, data, pad]);
}

/** A policy derived from the spec default with the given changes. */
export function policy(version: number, edit: (p: any) => void = () => {}): any {
  const p = JSON.parse(core.defaultPolicy(Date.now()));
  p.version = version;
  p.policy_version = `test-${version}`;
  p.expires_at = Date.now() + 86_400_000;
  edit(p);
  return p;
}

/** Sign a policy with the given keys and return the base64 archive. */
export function signBundle(p: unknown, keys: TestKey[]): string {
  const content = Buffer.from(JSON.stringify(p, null, 2));
  const sigs = keys.map((k) => ({ alg: 'ed25519', key_id: k.id, sig: sign(null, content, privateKey(k.seedHex)).toString('base64') }));
  return Buffer.concat([tarEntry('policy.json', content), tarEntry('signatures.json', Buffer.from(JSON.stringify(sigs))), Buffer.alloc(1024)]).toString('base64');
}
