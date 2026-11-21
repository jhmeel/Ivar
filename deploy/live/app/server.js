// A small payments API protected by the IVAR Express SDK, used by the live
// test. It is an ordinary Express app: the IVAR parts are the middleware,
// the login and action reports, and the payout guard.
//
//   IVAR_CORE_URL, IVAR_CONTROL_URL, IVAR_POLICY_BUNDLE (file), IVAR_KEYRING (file),
//   IVAR_REDACTION_KEY (file), IVAR_STATE_DIR, PORT

'use strict';
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const express = require('express');
const { ivar, mintIntent, attestStep, stepPublicKey, INTENT_HEADER } = require('@ivar/express');

const env = (k, d) => process.env[k] ?? d;
const read = (f) => fs.readFileSync(f, 'utf8').trim();
const stateDir = env('IVAR_STATE_DIR', '/tmp/ivar-demo');
fs.mkdirSync(stateDir, { recursive: true });

// Demo users. Passwords are hashed; roles drive positive security.
const hash = (p) => crypto.createHash('sha256').update(p).digest('hex');
const users = new Map([
  ['alice@bank.test', { id: 'u_alice', password: hash('correct horse'), roles: ['customer'], balance: 250_000 }],
  ['bob@bank.test', { id: 'u_bob', password: hash('battery staple'), roles: ['customer'], balance: 90_000 }],
  ['ceo@bank.test', { id: 'u_ceo', password: hash('exec-only'), roles: ['customer'], balance: 1_000_000 }],
  ['ops@bank.test', { id: 'u_ops', password: hash('ops-secret'), roles: ['customer', 'admin'], balance: 0 }],
]);
for (let i = 0; i < 40; i++) users.set(`user${i}@bank.test`, { id: `u_${i}`, password: hash(`pw-${i}`), roles: ['customer'], balance: 10_000 });
const sessions = new Map(); // session id to user

// Intent issuer and the three steps a payout chain needs (section 6.2). In
// production each step key sits in its own service; here one process holds
// them so the demo is self contained.
const seed = () => crypto.randomBytes(32).toString('hex');
const rootSeed = seed();
const stepSeeds = { authenticated_session: seed(), ledger_entry: seed(), payout_instruction: seed() };
const stepKeys = Object.fromEntries(Object.entries(stepSeeds).map(([k, s]) => [k, stepPublicKey(s)]));
const rootPublicKey = mintIntent(rootSeed, 'boot', 'payout', 'boot', { amount: 1 }).rootPublicKey;

const mw = ivar({
  mode: env('IVAR_MODE', 'enforce'),
  identity: (req) => sessions.get(req.headers['x-session'])?.id,
  session: (req) => req.headers['x-session'],
  roles: (req) => sessions.get(req.headers['x-session'])?.roles,
  coreUrl: env('IVAR_CORE_URL'),
  controlUrl: env('IVAR_CONTROL_URL'),
  policyBundle: read(env('IVAR_POLICY_BUNDLE')),
  policyKeyring: read(env('IVAR_KEYRING')),
  policyStateFile: path.join(stateDir, 'policy.bundle'),
  policyRefreshMs: Number(env('IVAR_POLICY_REFRESH_MS', '2000')),
  redactionKey: read(env('IVAR_REDACTION_KEY')),
  sensorId: 'payments-api',
  onAlert: (a) => console.log(JSON.stringify({ ivar_alert: a.kind, message: a.message })),
});

const app = express();
// Trust exactly the gateway hops, so req.ip is the real client (phase 1
// exit test). Envoy appends its own address for loopback clients, so the
// live test passes the host address here.
app.set('trust proxy', env('IVAR_TRUSTED_PROXIES', 'loopback').split(',').map((s) => s.trim()));
app.use(express.json({ limit: '64kb' }));
app.use(mw);

const authed = (req, res, next) => (sessions.has(req.headers['x-session']) ? next() : res.status(401).json({ error: 'login required' }));

app.get('/healthz', (_req, res) => res.send('ok'));
app.get('/ivar/policy', (_req, res) => res.json(mw.policy()));

app.post('/login', (req, res) => {
  const { email, password } = req.body ?? {};
  const u = users.get(String(email));
  const ok = !!u && u.password === hash(String(password ?? ''));
  req.ivar.login({ success: ok, account: String(email ?? '') });
  if (!ok) return res.status(401).json({ error: 'invalid credentials' });
  const sid = `ses_${crypto.randomBytes(12).toString('hex')}`;
  sessions.set(sid, u);
  res.json({ session: sid });
});

app.get('/accounts/:id', authed, (req, res) => {
  const u = sessions.get(req.headers['x-session']);
  if (u.id !== req.params.id) return res.status(403).json({ error: 'not your account' });
  res.json({ id: u.id, balance: u.balance });
});

app.patch('/users/:id', authed, (req, res) => {
  const u = sessions.get(req.headers['x-session']);
  if (req.body.role) u.roles = [...new Set([...u.roles, req.body.role])];
  if (req.body.name) u.name = req.body.name;
  res.json({ id: u.id, roles: u.roles });
});

// The customer request handler mints the intent and each step attests it.
app.post('/payouts/intent', authed, (req, res) => {
  const amount = Number(req.body.amount);
  const sid = req.headers['x-session'];
  let token = mintIntent(rootSeed, `int_${crypto.randomBytes(8).toString('hex')}`, 'payout', sid, { amount }).token;
  for (const [step, s] of Object.entries(stepSeeds)) token = attestStep(s, step, token, rootPublicKey);
  res.json({ intent: token, header: INTENT_HEADER });
});

app.post('/payouts', authed, mw.guard('payout', { rootPublicKey, stepKeys }, { value: (req) => Number(req.body.amount) }), (req, res) => {
  const u = sessions.get(req.headers['x-session']);
  u.balance -= Number(req.body.amount);
  res.json({ sent: true, balance: u.balance });
});

app.get('/admin/users', authed, (req, res) => {
  const u = sessions.get(req.headers['x-session']);
  if (!u.roles.includes('admin')) return res.status(403).json({ error: 'admins only' });
  res.json([...users.keys()]);
});

const port = Number(env('PORT', '3000'));
app.listen(port, '127.0.0.1', () => console.log(JSON.stringify({ listening: port, policy: mw.policy() })));
