// The dashboard's data model: one pass over a verified ReplayBundle (or the
// evidence a live core streams) that indexes frames by evidence, entity,
// session and sensor, so every view answers "what happened, to whom, and
// why" without rescanning. Pure functions with no DOM, tested under Node.

export const DECISIONS = ['record', 'throttle', 'challenge', 'block', 'contain', 'refuse'];
const ENFORCING = new Set(['throttle', 'challenge', 'block', 'contain', 'refuse']);

export function entityKey(e) {
  return e && e.type ? `${e.type}:${e.id}` : '';
}

export function outcome(f) {
  if (f.kind === 'verdict') return f.payload?.decision ?? 'record';
  if (f.kind === 'action_receipt') return f.payload?.result ?? 'receipt';
  return f.kind;
}

/** Everything a frame is about, as entity keys. */
export function entitiesOf(f) {
  const p = f.payload ?? {};
  const out = new Set();
  const add = (k) => k && !k.endsWith(':') && out.add(k);
  switch (f.kind) {
    case 'event':
      if (p.src_endpoint?.ip) add(`ip:${p.src_endpoint.ip}`);
      if (p.actor?.user?.uid) add(`${p.actor.user.type === 'service' ? 'service' : 'user'}:${p.actor.user.uid}`);
      if (p.actor?.session?.uid) add(`session:${p.actor.session.uid}`);
      if (p.device?.hostname) add(`host:${p.device.hostname}`);
      if (p.ivar?.target_entity) add(p.ivar.target_entity);
      break;
    case 'finding':
      for (const e of p.entities ?? []) add(entityKey(e));
      break;
    case 'risk':
    case 'verdict':
      add(entityKey(p.entity));
      break;
    case 'action_request':
      add(entityKey(p.request?.target));
      break;
    default:
      break;
  }
  return [...out];
}

/** One line a person can read for any frame. */
export function summarize(f) {
  const p = f.payload ?? {};
  switch (f.kind) {
    case 'event': {
      const h = p.http_request;
      if (h) return `${h.http_method} ${h.url_path}${p.http_response?.code ? ` → ${p.http_response.code}` : ''}`;
      if (p.activity_name?.startsWith('auth.')) return `${p.activity_name} ${p.status_id === 1 ? 'succeeded' : p.status_id === 2 ? 'failed' : ''}`.trim();
      return p.activity_name || 'event';
    }
    case 'finding':
      return `${p.rule} (${p.rule_family})`;
    case 'risk':
      return `risk ${fmt(p.score)} · fast ${fmt(p.fast_score)} · slow ${fmt(p.slow_score)}`;
    case 'verdict':
      return `${p.decision}: ${(p.reasons ?? []).slice(0, 2).join('; ')}`;
    case 'action_request':
      return `${p.request?.action} on ${entityKey(p.request?.target)} · ${p.review ?? ''}`;
    case 'action_receipt':
      return `${p.result}: ${p.verification ?? ''}`;
    case 'gap':
      return p.unobserved ?? 'unobserved interval';
    case 'policy':
      return `policy ${p.policy_version} applied`;
    case 'edge_change':
      return `trust edge ${p.change ?? ''} ${p.from ?? ''} → ${p.to ?? ''}`;
    default:
      return f.kind;
  }
}

function fmt(n) {
  return typeof n === 'number' ? n.toFixed(2) : '?';
}

export function riskOf(f) {
  const p = f.payload ?? {};
  if (f.kind === 'risk') return p.score;
  if (f.kind === 'verdict') return p.risk;
  return undefined;
}

/** Field names a request sent, checked against the declared route. */
export function fieldReport(f, declared) {
  const h = f.payload?.http_request;
  if (!h) return null;
  const route = matchRoute(declared, h.http_method, h.url_path);
  const fields = (h.body_keys ?? []).map((name) => {
    let status = 'undeclared_route';
    if (route) {
      if ((route.privileged_properties ?? []).includes(name)) status = 'privileged';
      else if ((route.allowed_properties ?? []).includes(name)) status = 'declared';
      else status = 'undeclared';
    }
    return { name, status };
  });
  return { route, fields };
}

export function matchRoute(declared, method, path) {
  const routes = declared?.routes ?? [];
  const clean = String(path ?? '').split('?')[0];
  return routes.find((r) => r.method === method && templateMatches(r.template, clean)) ?? null;
}

function templateMatches(template, path) {
  const t = template.split('/');
  const p = path.split('/');
  return t.length === p.length && t.every((seg, i) => (seg.startsWith('{') && seg.endsWith('}') ? p[i] !== '' : seg === p[i]));
}

/** Build the indexes every view uses. */
export function buildModel(bundle, options = {}) {
  const frames = bundle.frames ?? [];
  const span = Math.max(1, frames.length ? frames[frames.length - 1].elapsed_ms : 1);
  const byEvidence = new Map();
  const byEntity = new Map();
  // Actions cite their verdict by id and receipts cite their request.
  const actionsByVerdict = new Map();
  const receiptsByRequest = new Map();
  const sensors = new Map();
  const rules = new Map();
  const decisions = Object.fromEntries(DECISIONS.map((d) => [d, 0]));
  const kinds = {};
  const rows = frames.map((f, i) => {
    const ents = entitiesOf(f);
    const row = { i, f, kind: f.kind, outcome: outcome(f), entities: ents, summary: summarize(f), risk: riskOf(f), sensor: f.sensor_id, layer: f.payload?.ivar?.sensor_type ?? '' };
    row.text = `${row.summary} ${ents.join(' ')} ${f.sensor_id} ${f.evidence_ids?.join(' ') ?? ''} ${f.kind} ${row.outcome}`.toLowerCase();
    return row;
  });

  for (const r of rows) {
    const f = r.f;
    kinds[f.kind] = (kinds[f.kind] ?? 0) + 1;
    if (f.kind === 'action_request' && f.payload?.request?.verdict_id) {
      const k = f.payload.request.verdict_id;
      if (!actionsByVerdict.has(k)) actionsByVerdict.set(k, []);
      actionsByVerdict.get(k).push(r.i);
    }
    if (f.kind === 'action_receipt' && f.payload?.action_request_id) {
      const k = f.payload.action_request_id;
      if (!receiptsByRequest.has(k)) receiptsByRequest.set(k, []);
      receiptsByRequest.get(k).push(r.i);
    }
    for (const id of f.evidence_ids ?? []) {
      if (!byEvidence.has(id)) byEvidence.set(id, []);
      byEvidence.get(id).push(r.i);
    }
    for (const k of r.entities) {
      if (!byEntity.has(k)) byEntity.set(k, newEntity(k));
      const e = byEntity.get(k);
      e.frames.push(r.i);
      e.first = Math.min(e.first, f.elapsed_ms);
      e.last = Math.max(e.last, f.elapsed_ms);
      if (f.kind === 'event') e.events += 1;
      if (f.kind === 'finding') e.findings += 1;
      if (f.kind === 'verdict') {
        e.decisions[f.payload.decision] = (e.decisions[f.payload.decision] ?? 0) + 1;
        e.lastDecision = f.payload.decision;
      }
      if (r.risk !== undefined && (f.kind === 'risk' || !e.risk.length)) {
        e.risk.push({ t: f.elapsed_ms, score: r.risk, fast: f.payload.fast_score ?? r.risk, slow: f.payload.slow_score ?? r.risk, i: r.i });
        e.maxRisk = Math.max(e.maxRisk, r.risk);
      }
    }
    if (f.kind === 'verdict') decisions[f.payload.decision] = (decisions[f.payload.decision] ?? 0) + 1;
    if (f.kind === 'finding') {
      const key = f.payload.rule;
      const x = rules.get(key) ?? { rule: key, family: f.payload.rule_family, technique: f.payload.technique, count: 0, frames: [] };
      x.count += 1;
      x.frames.push(r.i);
      rules.set(key, x);
    }
    if (f.sensor_id) {
      const s = sensors.get(f.sensor_id) ?? { id: f.sensor_id, layer: '', events: 0, gaps: 0, skew: 0, first: f.elapsed_ms, last: f.elapsed_ms, hops: [] };
      if (f.kind === 'event') {
        s.events += 1;
        s.layer = f.payload?.ivar?.sensor_type ?? s.layer;
        s.skew = f.clock_skew_ms;
        const total = Object.values(f.hops_us ?? {}).reduce((a, b) => a + b, 0);
        if (total) s.hops.push(total);
      }
      if (f.kind === 'gap') s.gaps += 1;
      s.last = Math.max(s.last, f.elapsed_ms);
      sensors.set(f.sensor_id, s);
    }
  }

  const sessions = buildSessions(rows, byEntity);
  const buckets = bucketize(rows, span, options.buckets ?? 60);
  const enforced = DECISIONS.filter((d) => ENFORCING.has(d)).reduce((a, d) => a + (decisions[d] ?? 0), 0);
  const verdicts = Object.values(decisions).reduce((a, b) => a + b, 0);
  return {
    bundle,
    rows,
    span,
    byEvidence,
    byEntity,
    actionsByVerdict,
    receiptsByRequest,
    entities: [...byEntity.values()].sort((a, b) => b.maxRisk - a.maxRisk || b.frames.length - a.frames.length),
    sensors: [...sensors.values()],
    rules: [...rules.values()].sort((a, b) => b.count - a.count),
    sessions,
    buckets,
    decisions,
    kinds,
    totals: {
      frames: rows.length,
      events: kinds.event ?? 0,
      findings: kinds.finding ?? 0,
      verdicts,
      enforced,
      actions: kinds.action_request ?? 0,
      gaps: kinds.gap ?? 0,
      sources: [...byEntity.keys()].filter((k) => k.startsWith('ip:')).length,
      sessions: sessions.length,
    },
    declared: bundle.policy?.declared ?? null,
  };
}

function newEntity(key) {
  const [type, ...rest] = key.split(':');
  return { key, type, id: rest.join(':'), frames: [], events: 0, findings: 0, decisions: {}, lastDecision: '', risk: [], maxRisk: 0, first: Infinity, last: -Infinity };
}

/**
 * Sessions: requests grouped by session id, or by source and identity when
 * a request carries no session. Each keeps its own transcript and the IVAR
 * decisions about any entity it touched while it was active.
 */
function buildSessions(rows, byEntity) {
  const map = new Map();
  for (const r of rows) {
    if (r.kind !== 'event') continue;
    const p = r.f.payload ?? {};
    if (p.activity_name === 'sensor.heartbeat') continue;
    const sid = p.actor?.session?.uid;
    const ip = p.src_endpoint?.ip ?? '';
    const uid = p.actor?.user?.uid ?? '';
    const key = sid ? `session:${sid}` : `source:${ip}${uid ? `|${uid}` : ''}`;
    const s = map.get(key) ?? { key, session: sid ?? '', ip, user: uid, events: [], routes: new Set(), statuses: {}, sensors: new Set(), first: r.f.elapsed_ms, last: r.f.elapsed_ms, entities: new Set() };
    s.events.push(r.i);
    s.last = Math.max(s.last, r.f.elapsed_ms);
    if (uid && !s.user) s.user = uid;
    if (ip && !s.ip) s.ip = ip;
    s.routes.add(p.http_request ? `${p.http_request.http_method} ${p.http_request.url_path}` : p.activity_name || 'event');
    const code = p.http_response?.code;
    if (code) s.statuses[code] = (s.statuses[code] ?? 0) + 1;
    s.sensors.add(r.f.sensor_id);
    for (const k of r.entities) s.entities.add(k);
    map.set(key, s);
  }
  const out = [];
  for (const s of map.values()) {
    const decisions = {};
    let maxRisk = 0;
    const related = new Set();
    for (const k of s.entities) {
      const e = byEntity.get(k);
      if (!e) continue;
      for (const i of e.frames) {
        const f = rows[i].f;
        if (f.elapsed_ms < s.first || f.elapsed_ms > s.last + 60_000) continue;
        if (f.kind === 'verdict' || f.kind === 'finding' || f.kind === 'action_request') related.add(i);
        if (f.kind === 'verdict') decisions[f.payload.decision] = (decisions[f.payload.decision] ?? 0) + 1;
      }
      maxRisk = Math.max(maxRisk, e.maxRisk);
    }
    out.push({ ...s, routes: [...s.routes], sensors: [...s.sensors], entities: [...s.entities], decisions, maxRisk, related: [...related].sort((a, b) => a - b) });
  }
  return out.sort((a, b) => b.maxRisk - a.maxRisk || b.events.length - a.events.length);
}

function bucketize(rows, span, n) {
  const size = span / n;
  const buckets = Array.from({ length: n }, (_, i) => ({ from: i * size, to: (i + 1) * size, events: 0, findings: 0, actions: 0, gaps: 0, decisions: Object.fromEntries(DECISIONS.map((d) => [d, 0])) }));
  for (const r of rows) {
    const b = buckets[Math.min(n - 1, Math.floor(r.f.elapsed_ms / size))];
    if (r.kind === 'event') b.events += 1;
    else if (r.kind === 'finding') b.findings += 1;
    else if (r.kind === 'action_request') b.actions += 1;
    else if (r.kind === 'gap') b.gaps += 1;
    else if (r.kind === 'verdict') b.decisions[r.f.payload.decision] = (b.decisions[r.f.payload.decision] ?? 0) + 1;
  }
  return buckets;
}

/**
 * The causal chain around a frame: every frame that cites any of its
 * evidence, which links an event to the findings it raised, the risk it
 * moved, the verdict, the action and the action's receipt.
 */
export function causalChain(model, index) {
  const f = model.rows[index].f;
  const seen = new Set([index]);
  const queue = [...(f.evidence_ids ?? [])];
  const visited = new Set();
  while (queue.length) {
    const id = queue.shift();
    if (visited.has(id)) continue;
    visited.add(id);
    for (const i of model.byEvidence.get(id) ?? []) {
      if (seen.has(i)) continue;
      seen.add(i);
      // Follow actions and receipts one hop further: a receipt cites its request.
      const g = model.rows[i].f;
      if (g.kind === 'action_request' || g.kind === 'action_receipt') for (const e of g.evidence_ids ?? []) queue.push(e);
    }
    if (visited.size > 200) break;
  }
  // Verdicts lead to the actions they planned, and actions to their receipts.
  for (const i of [...seen]) {
    const g = model.rows[i].f;
    if (g.kind === 'verdict') for (const a of model.actionsByVerdict?.get(g.payload.verdict_id) ?? []) seen.add(a);
  }
  for (const i of [...seen]) {
    const g = model.rows[i].f;
    if (g.kind === 'action_request') for (const rc of model.receiptsByRequest?.get(g.payload.request.action_request_id) ?? []) seen.add(rc);
    if (g.kind === 'action_receipt') for (const a of model.rows) if (a.kind === 'action_request' && a.f.payload?.request?.action_request_id === g.payload.action_request_id) seen.add(a.i);
  }
  const order = { event: 0, finding: 1, risk: 2, verdict: 3, action_request: 4, action_receipt: 5 };
  return [...seen].sort((a, b) => (order[model.rows[a].kind] ?? 9) - (order[model.rows[b].kind] ?? 9) || a - b);
}

/** Rows matching a filter: free text, kinds, decision, sensor, entity, cursor. */
export function filterRows(model, q) {
  const text = (q.text ?? '').trim().toLowerCase();
  const terms = text ? text.split(/\s+/) : [];
  return model.rows.filter((r) => {
    if (q.kinds?.size && !q.kinds.has(r.kind)) return false;
    if (q.decision && !(r.kind === 'verdict' && r.outcome === q.decision)) return false;
    if (q.sensor && r.sensor !== q.sensor) return false;
    if (q.entity && !r.entities.includes(q.entity)) return false;
    if (q.securityOnly && (r.kind === 'event' || r.kind === 'risk' || (r.kind === 'verdict' && r.outcome === 'record'))) return false;
    if (q.upto !== undefined && r.i > q.upto) return false;
    return terms.every((t) => r.text.includes(t));
  });
}

/** CSV of rows, for spreadsheets and case files. */
export function toCsv(rows) {
  const head = ['frame', 'utc', 'elapsed_ms', 'kind', 'outcome', 'sensor', 'entities', 'summary', 'risk', 'evidence_ids'];
  const esc = (v) => {
    const s = String(v ?? '');
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  const lines = rows.map((r) => [r.f.index, new Date(r.f.time).toISOString(), r.f.elapsed_ms, r.kind, r.outcome, r.sensor, r.entities.join(' '), r.summary, r.risk ?? '', (r.f.evidence_ids ?? []).join(' ')].map(esc).join(','));
  return [head.join(','), ...lines].join('\n');
}
