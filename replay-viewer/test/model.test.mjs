// The dashboard model against a sample bundle: run with
//   node --test replay-viewer/test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { buildModel, causalChain, filterRows, fieldReport, toCsv, summarize } from '../js/model.js';

const bundle = JSON.parse(readFileSync(fileURLToPath(new URL('../samples/bundle.json', import.meta.url)), 'utf8'));
const m = buildModel(bundle);

test('totals and indexes cover every frame', () => {
  assert.equal(m.totals.frames, bundle.frames.length);
  assert.equal(m.rows.length, bundle.frames.length);
  const verdicts = bundle.frames.filter((f) => f.kind === 'verdict').length;
  assert.equal(m.totals.verdicts, verdicts);
  assert.ok(m.entities.length > 0 && m.entities[0].maxRisk >= m.entities[m.entities.length - 1].maxRisk, 'entities ranked by risk');
  assert.equal(m.buckets.reduce((a, b) => a + b.events, 0), m.totals.events, 'every event lands in one bucket');
});

test('the causal chain links an event to what it caused', () => {
  const contain = m.rows.find((r) => r.kind === 'verdict' && r.outcome === 'contain');
  assert.ok(contain, 'sample has a containment');
  const chain = causalChain(m, contain.i).map((i) => m.rows[i].kind);
  assert.ok(chain.includes('event') && chain.includes('verdict'), `chain ${chain}`);
  assert.ok(chain.indexOf('event') < chain.indexOf('verdict'), 'ordered cause first');
  assert.ok(chain.includes('action_request'), 'the verdict leads to its action');
});

test('sessions group requests and carry the decisions about them', () => {
  assert.ok(m.sessions.length > 0);
  const total = m.sessions.reduce((a, s) => a + s.events.length, 0);
  assert.equal(total, m.rows.filter((r) => r.kind === 'event' && r.f.payload.activity_name !== 'sensor.heartbeat').length);
  assert.ok(m.sessions.some((s) => Object.keys(s.decisions).length > 0), 'decisions attached to sessions');
});

test('filters combine text, kind, decision and entity', () => {
  const all = filterRows(m, {});
  assert.equal(all.length, m.rows.length);
  const verdicts = filterRows(m, { kinds: new Set(['verdict']) });
  assert.ok(verdicts.every((r) => r.kind === 'verdict'));
  const contained = filterRows(m, { decision: 'contain' });
  assert.ok(contained.length > 0 && contained.every((r) => r.outcome === 'contain'));
  const ent = m.entities[0].key;
  assert.ok(filterRows(m, { entity: ent }).every((r) => r.entities.includes(ent)));
  assert.ok(filterRows(m, { text: 'db.query' }).length > 0);
  assert.ok(filterRows(m, { securityOnly: true }).every((r) => r.kind !== 'event'));
});

test('field report checks body fields against the declared route', () => {
  const declared = { routes: [{ method: 'PATCH', template: '/users/{id}', allowed_properties: ['name', 'role'], privileged_properties: ['role'] }] };
  const f = { payload: { http_request: { http_method: 'PATCH', url_path: '/users/7', body_keys: ['name', 'role', 'is_admin'] } } };
  assert.deepEqual(fieldReport(f, declared).fields.map((x) => x.status), ['declared', 'privileged', 'undeclared']);
  assert.equal(fieldReport({ payload: { http_request: { http_method: 'GET', url_path: '/x', body_keys: ['a'] } } }, declared).fields[0].status, 'undeclared_route');
});

test('csv export quotes and covers the rows', () => {
  const csv = toCsv(m.rows.slice(0, 5)).split('\n');
  assert.equal(csv.length, 6);
  assert.ok(csv[0].startsWith('frame,utc,elapsed_ms'));
  assert.equal(summarize({ kind: 'gap', payload: { unobserved: 'x' } }), 'x');
});
