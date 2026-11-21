// One test per verified configuration defect (Appendix A, section 21.1),
// each with the test input the review used.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign, KeyObject } from 'node:crypto';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { resolve, safePattern, FlagClient, SignedFlag, FlagBackend, ConfigError, durationSeconds } from '../src/security.config';

const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const keys: Record<string, KeyObject> = { 'flags-1': publicKey };
function signed(name: string, value: string, version: number): SignedFlag {
  const f: SignedFlag = { name, value, version, issued_at: 1, signature: null };
  const sig = sign(null, Buffer.from(`ivar.flag.v1\n${name}\n${value}\n${version}\n1`), privateKey).toString('base64');
  return { ...f, signature: { alg: 'ed25519', key_id: 'flags-1', sig } };
}
class FakeRedis implements FlagBackend {
  up = true;
  data: Record<string, SignedFlag> = {};
  async get(n: string) {
    if (!this.up) throw new Error('ECONNREFUSED');
    return this.data[n] ?? null;
  }
}

test('F1 payouts off and registration closed survive a restart while Redis is down', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'ivar-f1-'));
  const redis = new FakeRedis();
  redis.data.PAYOUTS_ENABLED = signed('PAYOUTS_ENABLED', 'false', 4);
  redis.data.REGISTRATION_MODE = signed('REGISTRATION_MODE', 'closed', 4);
  const c = new FlagClient(redis, keys, join(dir, 'flags.json'));
  assert.equal((await c.get('PAYOUTS_ENABLED')).value, 'false');
  assert.equal((await c.get('REGISTRATION_MODE')).value, 'closed');
  redis.up = false;
  const restarted = new FlagClient(redis, keys, join(dir, 'flags.json'));
  assert.deepEqual(await restarted.get('PAYOUTS_ENABLED'), { value: 'false', source: 'local_disk' });
  assert.deepEqual(await restarted.get('REGISTRATION_MODE'), { value: 'closed', source: 'local_disk' });
  const fresh = new FlagClient(redis, keys, join(dir, 'none.json'));
  assert.deepEqual(await fresh.get('PAYOUTS_ENABLED'), { value: 'false', source: 'safest_default' });
});

test('F2 ABUSE_EXEMPT_CIDRS=0.0.0.0/0,::/0 is rejected in production', () => {
  assert.throws(() => resolve('payments', 'production', { ABUSE_EXEMPT_CIDRS: '0.0.0.0/0,::/0' }), ConfigError);
  assert.doesNotThrow(() => resolve('payments', 'production', { ABUSE_EXEMPT_CIDRS: '203.0.113.0/24' }));
});

test('F3 a value written directly to the flag key is refused', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'ivar-f3-'));
  const redis = new FakeRedis();
  redis.data.PAYOUTS_ENABLED = signed('PAYOUTS_ENABLED', 'false', 2);
  const alerts: string[] = [];
  const c = new FlagClient(redis, keys, join(dir, 'f.json'), (m) => alerts.push(m));
  await c.get('PAYOUTS_ENABLED');
  redis.data.PAYOUTS_ENABLED = { name: 'PAYOUTS_ENABLED', value: 'true', version: 99, issued_at: 1, signature: null };
  assert.equal((await c.get('PAYOUTS_ENABLED')).value, 'false');
  assert.ok(alerts.some((a) => a.includes('unsigned')));
});

test('F4 lockdown is reachable at runtime through the signed posture', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'ivar-f4-'));
  const redis = new FakeRedis();
  redis.data.RUNTIME_POSTURE = signed('RUNTIME_POSTURE', 'lockdown', 1);
  const c = new FlagClient(redis, keys, join(dir, 'f.json'));
  const cfg = resolve('standard', 'production', {}, await c.runtime());
  assert.equal(cfg.RUNTIME_POSTURE, 'lockdown');
});

test('F5 standard profile with 2FA, rotation and verified email off is blocked for money services', () => {
  assert.throws(() => resolve('standard', 'production', { HANDLES_MONEY: 'true' }), /standard profile/);
  assert.doesNotThrow(() => resolve('payments', 'production', { HANDLES_MONEY: 'true' }));
  assert.doesNotThrow(() => resolve('standard', 'development', { HANDLES_MONEY: 'true' }));
});

test('F6 ^(a+)+$ is rejected, and safe patterns still work', () => {
  assert.throws(() => safePattern('^(a+)+$'), /nested quantifiers/);
  assert.throws(() => safePattern('^(a|aa)*$'), /nested quantifiers/);
  assert.throws(() => safePattern('(x)\\1'), /backreferences/);
  const ok = safePattern('^[a-z]{3,8}[0-9]+@example\\.com$');
  const start = performance.now();
  ok.test('a'.repeat(29) + '!');
  assert.ok(performance.now() - start < 50);
});

test('F7 a public signup role outside the allowlist is rejected', () => {
  assert.throws(() => resolve('payments', 'production', { PUBLIC_SIGNUP_ROLES: 'customer,manager,finance,operator' }), /allowlist/);
});

test('F8 patterns with commas load whole from a structured file', () => {
  const dir = mkdtempSync(join(tmpdir(), 'ivar-f8-'));
  const f = join(dir, 'patterns.json');
  writeFileSync(f, JSON.stringify(['^[a-z]{3,8}[0-9]+$']));
  const cfg = resolve('payments', 'production', { BLOCKED_EMAIL_PATTERNS_FILE: f });
  assert.equal(cfg.BLOCKED_EMAIL_PATTERNS.length, 1);
  assert.ok(cfg.BLOCKED_EMAIL_PATTERNS[0].test('abc123'));
  assert.throws(() => resolve('payments', 'production', { BLOCKED_EMAIL_PATTERNS: '^[a-z]{3,8}[0-9]+$' }), /FILE/);
});

test('F9 forever is limited to the two ban settings', () => {
  assert.throws(() => resolve('payments', 'production', { PIN_LOCK_DURATION: 'forever' }), /forever/);
  assert.throws(() => resolve('payments', 'production', { PURGE_GRACE_PERIOD: 'forever' }), /forever/);
  assert.throws(() => resolve('payments', 'production', { AUDIT_RETENTION: 'forever' }), /forever/);
  assert.equal(durationSeconds('BAN_DURATION', 'forever'), Number.POSITIVE_INFINITY);
  assert.doesNotThrow(() => resolve('payments', 'production', { BAN_DURATION: 'forever', REPEAT_BAN_DURATION: 'forever' }));
});

test('IVAR settings table defaults and resolve order', () => {
  const c = resolve('payments', 'staging', { INTENT_BINDING: 'observe,payout=enforce' });
  assert.equal(c.DETECTION_MODE, 'observe');
  assert.equal(c.AUTO_CONTAIN_MAX_USERS_PCT, 0.5);
  assert.equal(c.AI_AUTONOMY, 'advise');
  assert.equal(c.EVIDENCE_RETENTION, '400d');
  assert.equal(c.FAIL_OPEN_BUDGET_PCT, 0.1);
  assert.deepEqual(c.RISK_HALF_LIVES, { fast: '30m', slow: '7d' });
  assert.equal(c.INTENT_BINDING.perAction.payout, 'enforce');
  assert.deepEqual(c.SHARED_NETWORK_CIDRS, ['100.64.0.0/10'], 'shared networks protection carries over');
});
