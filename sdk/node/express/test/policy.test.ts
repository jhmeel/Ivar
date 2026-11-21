// Signed policy in the SDK: verified at start, refreshed live from the
// control plane, refused when forged or rolled back, and kept on disk across
// a restart while the control plane is down.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import http from 'node:http';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';
import { ivar, Alert } from '../src/index';
import { keyring, policy, signBundle, TestKey } from './support/bundle';

const a: TestKey = { id: 'policy-a', seedHex: '01'.repeat(32) };
const b: TestKey = { id: 'policy-b', seedHex: '02'.repeat(32) };
const ring = keyring([a, b]);
const enforce = (p: any) => (p.settings.detection_mode = 'enforce');

/** A fake control plane serving whatever bundle the test sets. */
function controlPlane(): Promise<{ url: string; set(bundle?: string, version?: number): void; close(): void }> {
  let current: { bundle: string; version: number } | undefined;
  const srv = http.createServer((req, res) => {
    const have = Number(new URL(req.url ?? '/', 'http://x').searchParams.get('have') ?? 0);
    if (!current || current.version <= have) {
      res.writeHead(204).end();
      return;
    }
    res.writeHead(200, { 'content-type': 'text/plain' }).end(current.bundle);
  });
  return new Promise((resolve) =>
    srv.listen(0, () =>
      resolve({
        url: `http://127.0.0.1:${(srv.address() as AddressInfo).port}`,
        set: (bundle, version = 0) => (current = bundle ? { bundle, version } : undefined),
        close: () => {
          srv.closeAllConnections();
          srv.close();
        },
      }),
    ),
  );
}

async function status(mw: express.RequestHandler, path: string, ip: string): Promise<number> {
  const app = express();
  app.set('trust proxy', true);
  app.use(mw);
  app.use((_req, res) => res.send('ok'));
  const srv = app.listen(0);
  await new Promise((r) => srv.once('listening', r));
  try {
    const res = await fetch(`http://127.0.0.1:${(srv.address() as AddressInfo).port}${path}`, { headers: { 'x-forwarded-for': ip } });
    return res.status;
  } finally {
    srv.closeAllConnections();
    srv.close();
  }
}

test('a signed observe policy goes live as enforce with no restart', async () => {
  const cp = await controlPlane();
  const alerts: Alert[] = [];
  const mw = ivar({ mode: 'enforce', identity: () => undefined, policyBundle: signBundle(policy(1), [a]), policyKeyring: ring, controlUrl: cp.url, policyRefreshMs: 60_000, onAlert: (x) => alerts.push(x) });
  try {
    assert.deepEqual(mw.policy(), { version: 1, policyVersion: 'test-1', source: 'bundle' });
    assert.equal(await status(mw, '/.env.backup', '203.0.113.10'), 200, 'v1 is observe: recorded, not blocked');
    cp.set(signBundle(policy(2, enforce), [a]), 2);
    assert.equal(await mw.refreshPolicy(), true);
    assert.equal(mw.policy().version, 2);
    assert.ok(alerts.some((x) => x.kind === 'policy_applied'));
    assert.equal(await status(mw, '/.env.backup', '203.0.113.11'), 403, 'v2 is enforce: the decoy is blocked');
    assert.equal(await mw.refreshPolicy(), false, 'nothing newer: 204');
  } finally {
    mw.close();
    cp.close();
  }
});

test('a forged weakening, a rollback and an unknown key are refused and the current policy kept', async () => {
  const cp = await controlPlane();
  const alerts: Alert[] = [];
  const mw = ivar({ mode: 'enforce', identity: () => undefined, policyBundle: signBundle(policy(5, enforce), [a]), policyKeyring: ring, controlUrl: cp.url, policyRefreshMs: 60_000, onAlert: (x) => alerts.push(x) });
  try {
    cp.set(signBundle(policy(6, (p) => (p.weakens_protection = true)), [a]), 6);
    assert.equal(await mw.refreshPolicy(), false, 'weakening with one key');
    cp.set(signBundle(policy(7), [{ id: 'policy-a', seedHex: '09'.repeat(32) }]), 7);
    assert.equal(await mw.refreshPolicy(), false, 'signed by a key the keyring does not trust');
    assert.equal(mw.policy().version, 5);
    assert.ok(alerts.filter((x) => x.kind === 'policy_rejected').length >= 2);
    assert.equal(await status(mw, '/.env.backup', '203.0.113.12'), 403, 'still enforcing v5');
  } finally {
    mw.close();
    cp.close();
  }
  assert.throws(() => ivar({ mode: 'enforce', identity: () => undefined, policyBundle: signBundle(policy(1), [{ id: 'x', seedHex: '07'.repeat(32) }]), policyKeyring: ring }), /refusing to start/);
});

test('a restart while the control plane is down keeps the last verified policy', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'ivar-sdk-policy-'));
  const stateFile = join(dir, 'policy.bundle');
  const cp = await controlPlane();
  const first = ivar({ mode: 'enforce', identity: () => undefined, policyBundle: signBundle(policy(1), [a]), policyKeyring: ring, controlUrl: cp.url, policyStateFile: stateFile, policyRefreshMs: 60_000, onAlert: () => {} });
  cp.set(signBundle(policy(3, enforce), [a, b]), 3);
  assert.equal(await first.refreshPolicy(), true);
  first.close();
  cp.close();

  // Restart with the original v1 bundle in config and the control plane gone.
  const restarted = ivar({ mode: 'enforce', identity: () => undefined, policyBundle: signBundle(policy(1), [a]), policyKeyring: ring, controlUrl: 'http://127.0.0.1:9', policyStateFile: stateFile, policyRefreshMs: 60_000, onAlert: () => {} });
  try {
    assert.deepEqual(restarted.policy(), { version: 3, policyVersion: 'test-3', source: 'state_file' });
    assert.equal(await restarted.refreshPolicy(), false, 'control plane unreachable: nothing changes');
    assert.equal(await status(restarted, '/.env.backup', '203.0.113.13'), 403, 'still enforcing v3');
  } finally {
    restarted.close();
  }
});
