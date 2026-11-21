import { test } from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import type { AddressInfo } from 'node:net';
import http from 'node:http';
import * as core from '@ivar/core-wasm';
import { ivar, mintIntent, attestStep, stepPublicKey, INTENT_HEADER, Alert } from '../src/index';

/** The spec default policy with DETECTION_MODE enforce. */
function enforcePolicy(): unknown {
  const p = JSON.parse(core.defaultPolicy(Date.now()));
  p.settings.detection_mode = 'enforce';
  return p;
}

/** Run a test body against a served app, always closing the server and the SDK. */
async function withServer(app: express.Express, mw: { close(): void }, body: (url: string) => Promise<void>): Promise<void> {
  const s = await serve(app);
  try {
    await body(s.url);
  } finally {
    s.close();
    mw.close();
  }
}

function serve(app: express.Express): Promise<{ url: string; close: () => void }> {
  return new Promise((resolve) => {
    const s = app.listen(0, () => resolve({ url: `http://127.0.0.1:${(s.address() as AddressInfo).port}`, close: () => { s.closeAllConnections(); s.close(); } }));
  });
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

test('the spec usage line works in observe mode and never affects requests', async () => {
  const app = express();
  const mw = ivar({ mode: 'observe', identity: (req) => (req as any).user?.id, onAlert: () => {} });
  app.use(mw);
  app.get('/.env.backup', (_req, res) => res.status(404).send('no'));
  app.get('/hello', (_req, res) => res.send('hi'));
  const s = await serve(app);
  assert.equal((await fetch(`${s.url}/hello`)).status, 200);
  assert.equal((await fetch(`${s.url}/.env.backup`)).status, 404, 'decoy hit is recorded, not blocked');
  await sleep(50);
  assert.ok(mw.engine.evidence().length > 0, 'observe mode records evidence');
  s.close();
  mw.close();
});

test('enforce mode blocks a decoy route in the SDK, then contains the source', async () => {
  const app = express();
  const mw = ivar({ mode: 'enforce', policy: enforcePolicy(), identity: () => undefined, onAlert: () => {} });
  app.use(mw);
  app.get('/hello', (_req, res) => res.send('hi'));
  await withServer(app, mw, async (url) => {
    assert.equal((await fetch(`${url}/.env.backup`)).status, 403);
    await sleep(50);
    assert.equal((await fetch(`${url}/hello`)).status, 403, 'the source IP is now contained by the core verdict');
  });
});

test('a signed observe policy never blocks, even with the SDK in enforce', async () => {
  const app = express();
  const mw = ivar({ mode: 'enforce', identity: () => undefined, onAlert: () => {} });
  app.use(mw);
  app.get('/.env.backup', (_req, res) => res.status(404).send('no'));
  await withServer(app, mw, async (url) => {
    assert.equal((await fetch(`${url}/.env.backup`)).status, 404, 'DETECTION_MODE observe in the signed policy wins');
  });
});

test('payout guard: stolen credential refused, full chain executes, large payout held', async () => {
  const root = '11'.repeat(32);
  const steps = { authenticated_session: '22'.repeat(32), ledger_entry: '33'.repeat(32), payout_instruction: '44'.repeat(32) };
  const stepKeys = Object.fromEntries(Object.entries(steps).map(([k, seed]) => [k, stepPublicKey(seed)]));
  const alerts: string[] = [];
  const app = express();
  app.use(express.json());
  const mw = ivar({ mode: 'enforce', identity: () => 'svc-payouts', session: (req) => req.headers['x-session'] as string, onAlert: (a) => alerts.push(a.kind) });
  app.use(mw);
  let rootPublicKey = '';
  const chain = (id: string, limit: number) => {
    const m = mintIntent(root, id, 'payout', 'ses_1', { amount: limit });
    rootPublicKey = m.rootPublicKey;
    let t = m.token;
    for (const [step, seed] of Object.entries(steps)) t = attestStep(seed, step, t, rootPublicKey);
    return t;
  };
  const first = chain('int_0', 1);
  app.post('/payouts', mw.guard('payout', { rootPublicKey, stepKeys }, { intentBinding: 'enforce', value: (req) => req.body.amount }), (_req, res) => res.json({ sent: true }));
  const s = await serve(app);
  try {
  const pay = (amount: number, token?: string) =>
    fetch(`${s.url}/payouts`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-session': 'ses_1', ...(token ? { [INTENT_HEADER]: token } : {}) }, body: JSON.stringify({ amount }) });

  assert.equal((await pay(100)).status, 403, 'valid login, no intent chain');
  assert.equal((await pay(1, first)).status, 200);
  assert.equal((await pay(100, chain('int_1', 5000))).status, 200);
  const held = await pay(60_000, chain('int_2', 100_000));
  assert.equal(held.status, 202);
  assert.ok((await held.json()).lock_id);
  assert.equal((await pay(100, chain('int_1', 5000))).status, 403, 'an intent is used once');
  assert.ok(alerts.includes('action_refused') && alerts.includes('time_lock'));
  } finally {
    s.close();
    mw.close();
  }
});

test('local decision stays inside the latency budget', async () => {
  const mw = ivar({ mode: 'enforce', identity: () => 'u1', onAlert: () => {} });
  const req: any = { method: 'GET', originalUrl: '/x', path: '/x', headers: {}, ip: '203.0.113.1', socket: {}, body: undefined };
  const times: number[] = [];
  for (let i = 0; i < 2000; i++) {
    const t = performance.now();
    mw.engine.decide({ activity_name: 'http.request', http_request: { http_method: 'GET', url_path: '/x' }, src_endpoint: { ip: req.ip }, ivar: { sensor_id: 's', sensor_seq: i } }, Date.now());
    times.push(performance.now() - t);
  }
  times.sort((a, b) => a - b);
  const p99 = times[Math.floor(times.length * 0.99)];
  console.log(`local decision p99 ${p99.toFixed(3)} ms`);
  assert.ok(p99 < 1, `p99 ${p99}`);
  mw.close();
});

test('an unverified client IP raises an alert once', async () => {
  const alerts: Alert[] = [];
  const app = express();
  const mw = ivar({ mode: 'observe', identity: () => 'u1', onAlert: (a) => alerts.push(a) });
  app.use(mw);
  app.get('/hello', (_req, res) => res.send('hi'));
  await withServer(app, mw, async (url) => {
    await fetch(`${url}/hello`, { headers: { 'x-forwarded-for': '203.0.113.5' } });
    await fetch(`${url}/hello`, { headers: { 'x-forwarded-for': '203.0.113.6' } });
  });
  assert.equal(alerts.filter((a) => a.kind === 'client_ip_unverified').length, 1);

  const crowded: Alert[] = [];
  const app2 = express();
  app2.set('trust proxy', 'loopback');
  let n = 0;
  const mw2 = ivar({ mode: 'observe', identity: () => `user${n++}`, onAlert: (a) => crowded.push(a) });
  app2.use(mw2);
  app2.get('/hello', (_req, res) => res.send('hi'));
  await withServer(app2, mw2, async (url) => {
    for (let i = 0; i < 12; i++) await fetch(`${url}/hello`, { headers: { 'x-forwarded-for': '192.0.2.2' } });
  });
  assert.ok(crowded.some((a) => a.kind === 'client_ip_unverified' && /192\.0\.2\.2/.test(a.message)), 'many identities behind one address');
});

test('verdicts caused by other sensors reach the app through the feed', async () => {
  const contain = { verdict_id: 'vrd_feed', decision: 'contain', entity: { type: 'ip', id: '198.51.100.31', role: 0 }, risk: 1, reasons: ['deception'], sources: ['edge'], policy_version: 'x', expires_at: 0, mode: 'enforce', ladder_level: 4 };
  let polls = 0;
  const core = http.createServer((req, res) => {
    if (req.url?.startsWith('/v1/verdicts')) {
      polls += 1;
      res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ verdicts: [contain], verdict_cursor: 7 }));
      return;
    }
    req.resume();
    req.on('end', () => res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify({ accepted: 0, verdicts: [], verdict_cursor: 7 })));
  });
  await new Promise<void>((r) => core.listen(0, () => r()));
  const app = express();
  app.set('trust proxy', 'loopback');
  const mw = ivar({ mode: 'enforce', policy: enforcePolicy(), coreUrl: `http://127.0.0.1:${(core.address() as AddressInfo).port}`, identity: () => undefined, onAlert: () => {} });
  app.use(mw);
  app.get('/hello', (_req, res) => res.send('hi'));
  try {
    await withServer(app, mw, async (url) => {
      await sleep(1300);
      assert.ok(polls >= 1, 'the idle SDK polled the feed');
      assert.equal((await fetch(`${url}/hello`, { headers: { 'x-forwarded-for': '198.51.100.31' } })).status, 403, 'contained by a verdict another sensor caused');
      assert.equal((await fetch(`${url}/hello`, { headers: { 'x-forwarded-for': '198.51.100.32' } })).status, 200);
    });
  } finally {
    core.closeAllConnections();
    core.close();
  }
});
