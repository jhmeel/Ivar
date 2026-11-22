// The test shop API in Node.js with Express and @ivar/express.
const crypto = require('node:crypto');
const fs = require('node:fs');
const express = require('express');
const { ivar, mintIntent, attestStep, stepPublicKey, INTENT_HEADER } = require('@ivar/express');

const env = (k, d) => process.env[k] ?? d;
const dir = env('IVAR_DIR');
const read = (f) => fs.readFileSync(`${dir}/${f}`, 'utf8');

const hash = (s) => crypto.createHash('sha256').update(s).digest('hex');
const users = new Map();
for (let i = 1; i <= 200; i++) users.set(`user${i}@corp.test`, { id: `u${i}`, password: hash(`pw${i}`), roles: i === 1 ? ['admin'] : ['customer'], balance: 100000 });
const sessions = new Map();
const userOf = (req) => sessions.get(req.headers['x-session']);

const steps = { authenticated_session: env('IVAR_STEP_SESSION'), ledger_entry: env('IVAR_STEP_LEDGER'), payout_instruction: env('IVAR_STEP_PAYOUT') };
const stepKeys = Object.fromEntries(Object.entries(steps).map(([k, s]) => [k, stepPublicKey(s)]));
const rootPublicKey = mintIntent(env('IVAR_ROOT_SEED'), 'boot', 'payout', 'boot', { amount: 1 }).rootPublicKey;

const mw = ivar({
  mode: env('IVAR_MODE', 'enforce'),
  identity: (req) => userOf(req)?.id,
  session: (req) => req.headers['x-session'],
  roles: (req) => userOf(req)?.roles ?? [],
  coreUrl: env('IVAR_CORE_URL'),
  coreToken: process.env.IVAR_CORE_TOKEN,
  policyBundle: read('policy.bundle'),
  policyKeyring: JSON.parse(read('keyring.json')),
  controlUrl: process.env.IVAR_CONTROL_URL,
  policyRefreshMs: 2000,
  policyStateFile: `${process.env.IVAR_DIR}/policy.state`,
  redactionKey: read('keys/redaction.hex').trim(),
  sensorId: env('SENSOR_ID', 'shop-node'),
  onAlert: (a) => console.log(JSON.stringify({ ivar_alert: a.kind, message: a.message })),
});

const app = express();
app.set('trust proxy', 'loopback');
app.use(express.json({ limit: '64kb' }));
app.use(mw);
const authed = (req, res, next) => (userOf(req) ? next() : res.status(401).json({ error: 'login required' }));

app.get('/healthz', (_q, r) => r.send('ok'));
app.post('/login', (req, res) => {
  const u = users.get(String(req.body?.email));
  const ok = !!u && u.password === hash(String(req.body?.password ?? ''));
  req.ivar.login({ success: ok, account: String(req.body?.email ?? '') });
  if (!ok) return res.status(401).json({ error: 'invalid credentials' });
  const sid = `ses_${crypto.randomBytes(12).toString('hex')}`;
  sessions.set(sid, u);
  res.json({ session: sid });
});
app.get('/accounts/:id', authed, (req, res) => (userOf(req).id === req.params.id ? res.json({ id: req.params.id, balance: userOf(req).balance }) : res.status(403).json({ error: 'not your account' })));
app.patch('/users/:id', authed, (req, res) => {
  const u = userOf(req);
  if (req.body.role) u.roles.push(req.body.role);
  res.json({ id: u.id, roles: u.roles });
});
app.post('/payouts/intent', authed, (req, res) => {
  let t = mintIntent(env('IVAR_ROOT_SEED'), `int_${crypto.randomBytes(6).toString('hex')}`, 'payout', req.headers['x-session'], { amount: Number(req.body.amount) }).token;
  for (const [k, s] of Object.entries(steps)) t = attestStep(s, k, t, rootPublicKey);
  res.json({ intent: t, header: INTENT_HEADER });
});
app.post('/payouts', authed, mw.guard('payout', { rootPublicKey, stepKeys }, { value: (req) => Number(req.body.amount) }), (req, res) => {
  userOf(req).balance -= Number(req.body.amount);
  res.json({ sent: true });
});
app.get('/admin/users', authed, (req, res) => (userOf(req).roles.includes('admin') ? res.json({ users: users.size }) : res.status(403).json({ error: 'admins only' })));
app.listen(Number(env('PORT', '3101')), '127.0.0.1');
