// Frame detail: what a frame says, what was sent and received, what it
// caused, and the sealed evidence behind it.

import { causalChain, fieldReport } from '../model.js';
import { copy, entityChip, esc, formatElapsed, jsonHtml, kindBadge, kindLabel, outcomeBadge, riskBar, shortId, utc } from '../ui.js';

const FIELD_STATUS = {
  declared: ['good', 'declared in the schema'],
  privileged: ['bad', 'privileged: needs a role'],
  undeclared: ['warn', 'not in the schema'],
  undeclared_route: ['warn', 'route not declared'],
};

function kv(pairs) {
  return `<dl class="kv">${pairs.filter(([, v]) => v !== undefined && v !== null && v !== '').map(([k, v]) => `<dt>${esc(k)}</dt><dd>${v}</dd>`).join('')}</dl>`;
}

function e(v) {
  return esc(v ?? '');
}

export class Detail {
  constructor(ctx) {
    this.ctx = ctx;
    this.el = document.getElementById('drawer');
    this.title = document.getElementById('drawer-title');
    this.tabsEl = document.getElementById('drawer-tabs');
    this.body = document.getElementById('drawer-body');
    this.index = -1;
    this.tab = 'summary';
    document.getElementById('drawer-close').addEventListener('click', () => this.close());
    document.getElementById('drawer-prev').addEventListener('click', () => this.step(-1));
    document.getElementById('drawer-next').addEventListener('click', () => this.step(1));
  }

  get isOpen() {
    return !this.el.hidden;
  }

  close() {
    this.el.hidden = true;
    this.index = -1;
    this.ctx.onClose?.();
  }

  step(delta) {
    const n = this.ctx.neighbour(this.index, delta);
    if (n >= 0) this.show(n);
  }

  show(i, tab) {
    const m = this.ctx.model;
    const row = m.rows[i];
    if (!row) return;
    this.index = i;
    const f = row.f;
    const tabs = [['summary', 'Summary']];
    if (f.kind === 'event') tabs.push(['request', f.payload?.http_request ? 'Request and response' : 'Activity']);
    tabs.push(['chain', 'Decision chain'], ['evidence', 'Sealed evidence'], ['raw', 'Raw']);
    if (tab) this.tab = tab;
    if (!tabs.some(([k]) => k === this.tab)) this.tab = 'summary';
    this.title.innerHTML = `<div class="t1">${kindBadge(f.kind)} ${row.kind === 'verdict' ? outcomeBadge(row) : ''} ${e(row.summary)}</div><div class="t2">frame ${i + 1} of ${m.rows.length} · ${e(utc(f.time, true))} · +${e(formatElapsed(f.elapsed_ms))}</div>`;
    this.tabsEl.innerHTML = tabs.map(([k, label]) => `<button type="button" role="tab" class="tab${k === this.tab ? ' on' : ''}" data-tab="${k}" aria-selected="${k === this.tab}">${esc(label)}</button>`).join('');
    this.tabsEl.querySelectorAll('[data-tab]').forEach((b) => b.addEventListener('click', () => this.show(i, b.dataset.tab)));
    this.body.innerHTML = this[this.tab](row);
    this.body.scrollTop = 0;
    this.wire();
    this.el.hidden = false;
  }

  wire() {
    this.body.querySelectorAll('[data-entity]').forEach((b) => b.addEventListener('click', () => this.ctx.go(`entities?entity=${encodeURIComponent(b.dataset.entity)}`)));
    this.body.querySelectorAll('[data-frame]').forEach((b) => b.addEventListener('click', () => this.show(Number(b.dataset.frame))));
    this.body.querySelectorAll('[data-copy]').forEach((b) => b.addEventListener('click', () => copy(this.body.querySelector(b.dataset.copy).textContent, b)));
    this.body.querySelectorAll('[data-filter]').forEach((b) => b.addEventListener('click', () => this.ctx.go(b.dataset.filter)));
  }

  summary(row) {
    const f = row.f;
    const p = f.payload ?? {};
    const pairs = [
      ['Kind', e(kindLabel(f.kind))],
      ['Recorded', `${e(utc(f.time, true))}`],
      ['Sensor clock', `${e(utc(f.sensor_time, true))} (skew ${e(f.clock_skew_ms)} ms, corrected)`],
      ['Real elapsed', e(formatElapsed(f.elapsed_ms))],
      ['Sensor', `${e(f.sensor_id)} · sequence ${e(f.sensor_seq)}`],
      ['Counterfactual', f.counterfactual ? '<span class="chip warn">yes: never happened live</span>' : ''],
    ];
    if (f.kind === 'verdict') pairs.push(['Decision', outcomeBadge(row)], ['Mode', e(p.mode)], ['Ladder level', e(p.ladder_level)], ['Risk', riskBar(p.risk)], ['Reasons', (p.reasons ?? []).map((r) => `<div>${e(r)}</div>`).join('')], ['Sources', e((p.sources ?? []).join(', '))], ['Policy', e(p.policy_version)], ['Expires', p.expires_at ? e(utc(p.expires_at, true)) : 'no expiry: per request']);
    if (f.kind === 'finding') pairs.push(['Rule', e(p.rule)], ['Family', e(p.rule_family)], ['Method', e(p.method)], ['ATT&CK', e(p.technique)], ['Confidence', riskBar(p.confidence)], ['Severity', e(p.severity)], ['Observation', e(p.observation_point)]);
    if (f.kind === 'risk') pairs.push(['Score', riskBar(p.score)], ['Fast (30 min)', riskBar(p.fast_score)], ['Slow (7 day)', riskBar(p.slow_score)], ['Independent sources', e(p.independent_sources)], ['High confidence source', p.has_high_confidence_source ? 'yes' : 'no'], ['Deception hit', p.deception_hit ? 'yes' : 'no'], ['Target only', p.target_only ? 'yes: protection raised, never contained' : 'no'], ['Contributing findings', e((p.contributing_findings ?? []).join(', '))]);
    if (f.kind === 'action_request') {
      const r = p.request ?? {};
      pairs.push(['Action', e(r.action)], ['Target', r.target ? entityChip(`${r.target.type}:${r.target.id}`) : ''], ['Ladder level', e(r.ladder_level)], ['Confidence class', e(r.confidence_class)], ['Safeguard review', e(p.review)], ['Needs approval', p.needs_approval ? '<span class="chip warn">yes</span>' : 'no'], ['Approved by', e(r.approval?.approved_by)], ['Reversal', e(r.reversal_method)], ['Expiry', r.expiry ? e(utc(r.expiry, true)) : 'none'], ['Responder', e(r.responder || 'sensor enforced')]);
    }
    if (f.kind === 'action_receipt') pairs.push(['Result', e(p.result)], ['Verification', e(p.verification)], ['Reversal status', e(p.reversal_status)], ['Took', `${e(p.time_taken_ms)} ms`], ['Request', e(p.action_request_id)]);
    if (f.kind === 'gap') pairs.push(['Unobserved', e(p.unobserved)]);
    if (f.kind === 'policy') pairs.push(['Policy', e(p.policy_version)], ['Version', e(p.version)], ['Changed rules', e((p.changed_rules ?? []).join(', ') || 'none')]);
    const ents = row.entities.length ? `<div class="section-title">Entities</div><div class="chips">${row.entities.map((k) => entityChip(k)).join('')}</div>` : '';
    const filters = row.entities.length ? `<div class="chips">${row.entities.slice(0, 3).map((k) => `<button type="button" class="btn btn-sm btn-ghost" data-filter="events?entity=${encodeURIComponent(k)}">All frames for ${esc(shortId(k, 24))}</button>`).join('')}</div>` : '';
    return `${kv(pairs)}${ents}${filters}`;
  }

  request(row) {
    const f = row.f;
    const p = f.payload ?? {};
    const h = p.http_request;
    const x = p.ivar ?? {};
    const report = fieldReport(f, this.ctx.model.declared);
    const identity = [
      ['Client address', p.src_endpoint?.ip ? entityChip(`ip:${p.src_endpoint.ip}`) : ''],
      ['Identity', p.actor?.user?.uid ? `${entityChip(`${p.actor.user.type === 'service' ? 'service' : 'user'}:${p.actor.user.uid}`)} <span class="muted">keyed hash</span>` : '<span class="muted">anonymous</span>'],
      ['Session', p.actor?.session?.uid ? entityChip(`session:${p.actor.session.uid}`) : ''],
      ['Roles', e(p.actor?.authorizations)],
      ['Tenant', e(x.tenant)],
    ];
    let out = '';
    if (h) {
      const status = p.http_response?.code;
      out += `<div class="section-title">Sent by the client</div>${kv([
        ['Request', `<b>${e(h.http_method)}</b> ${e(h.url_path)}`],
        ['Declared route', report?.route ? `${e(report.route.method)} ${e(report.route.template)}${report.route.business_action ? ` · action <b>${e(report.route.business_action)}</b>` : ''}${report.route.roles?.length ? ` · roles ${e(report.route.roles.join(', '))}` : ''}` : '<span class="chip warn">not in the declared schema</span>'],
        ['User agent', e(h.user_agent)],
        ['Request id', e(x.request_id)],
        ['Intent token', x.intent_token ? '<span class="chip good">present</span>' : ''],
      ])}`;
      if (report?.fields.length) {
        out += `<div class="section-title">Body fields (${report.fields.length})</div><div class="fields">${report.fields.map((fl) => `<div class="field-row"><span>${e(fl.name)}</span><span class="chip ${FIELD_STATUS[fl.status][0]}">${esc(FIELD_STATUS[fl.status][1])}</span></div>`).join('')}</div>`;
      } else out += '<div class="note">No request body fields.</div>';
      out += `<div class="section-title">Returned to the client</div>${kv([
        ['Status', status ? `<b class="mono">${e(status)}</b>${status >= 400 ? ' <span class="chip warn">refused or failed</span>' : ''}` : '<span class="muted">not recorded (decided before the response)</span>'],
        ['Engine alerts', (x.engine_alerts ?? []).length ? (x.engine_alerts ?? []).map((a) => `<span class="chip warn">${e(a)}</span>`).join(' ') : ''],
      ])}`;
    } else {
      out += `<div class="section-title">Activity</div>${kv([
        ['Activity', e(p.activity_name)],
        ['Outcome', e(p.status)],
        ['Target', x.target_entity ? entityChip(x.target_entity) : ''],
        ['Process', p.process ? `${e(p.process.name)} (pid ${e(p.process.pid)}) from ${e(p.process.parent_name)}` : ''],
        ['Device', p.device ? `${e(p.device.hostname)} ${e(p.device.type ?? '')}` : ''],
        ['Destination', p.dst_endpoint ? `${e(p.dst_endpoint.hostname || p.dst_endpoint.ip)}:${e(p.dst_endpoint.port)}` : ''],
        ['Business action', e(x.business_action)],
        ['Value moved', x.value_moved ? e(x.value_moved) : ''],
        ['Records read', x.records_read ? e(x.records_read) : ''],
        ['Destructive', x.destructive ? '<span class="chip bad">yes</span>' : ''],
        ['Decoy touched', x.decoy_touched ? `<span class="chip bad">${e(x.decoy_id)}</span>` : ''],
      ])}`;
    }
    out += `<div class="section-title">Who</div>${kv(identity)}`;
    const attrs = Object.entries(x.attributes ?? {});
    if (attrs.length) out += `<div class="section-title">Sensor attributes</div>${kv(attrs.map(([k, v]) => [k, e(v)]))}`;
    if (Object.keys(f.hops_us ?? {}).length) out += `<div class="section-title">Pipeline latency</div>${kv(Object.entries(f.hops_us).map(([k, v]) => [k, `${(v / 1000).toFixed(3)} ms`]))}`;
    out += '<div class="note">Payload values never leave the sensor: they are redacted there and identifiers are keyed hashes (section 16). This view shows what the sensor sealed: field names, routes, statuses and decisions.</div>';
    return out;
  }

  chain(row) {
    const m = this.ctx.model;
    const chain = causalChain(m, row.i);
    const color = (r) => (r.kind === 'verdict' ? `var(--${r.outcome})` : `var(--${{ event: 'event', finding: 'finding', risk: 'risk', action_request: 'action', action_receipt: 'action', gap: 'gap' }[r.kind] ?? 'muted'})`);
    return `<div class="note">From the event that started it to the receipt of the response: every frame here cites the same sealed evidence or a verdict or action in this chain.</div>
      <div class="chain">${chain.map((i) => {
        const r = m.rows[i];
        return `<div class="chain-row${i === row.i ? ' self' : ''}" data-frame="${i}" role="button" tabindex="0"><span class="node" style="background:${color(r)}"></span><div><div class="what">${kindBadge(r.kind)} ${e(r.summary)}</div><div class="meta">frame ${i + 1} · +${e(formatElapsed(r.f.elapsed_ms))} · ${e(shortId(r.sensor, 20))}</div></div><div>${r.risk !== undefined ? `<span class="mono">${r.risk.toFixed(2)}</span>` : ''}</div></div>`;
      }).join('')}</div>`;
  }

  evidence(row) {
    const ids = [...new Set(row.f.evidence_ids ?? [])];
    if (!ids.length) return '<div class="note">An unobserved interval cites no evidence: no sensor saw this step, and the replay shows the gap instead of inferring a path.</div>';
    const map = this.ctx.evidence;
    return ids.map((id, n) => {
      const r = map.get(id);
      if (!r) return `<div class="section-title">${e(id)}</div><div class="note">Not included in this bundle.</div>`;
      return `<div class="section-title">${e(id)} · ${e(r.kind)}</div>${kv([
        ['Sequence', e(r.seq)],
        ['Sealed', e(utc(r.time, true))],
        ['Hash', `<span class="mono">${e(r.hash)}</span>`],
        ['Previous hash', `<span class="mono">${e(r.prev_hash)}</span>`],
        ['Signature', r.signature ? `${e(r.signature.alg)} by <b>${e(r.signature.key_id)}</b>` : 'unsigned'],
        ['Chain', '<span class="chip good">verified with every other record at load</span>'],
      ])}<div style="display:flex;justify-content:flex-end"><button type="button" class="btn btn-sm btn-ghost" data-copy="#ev-json-${n}">Copy record</button></div><pre class="json" id="ev-json-${n}">${jsonHtml(r)}</pre>`;
    }).join('');
  }

  raw(row) {
    return `<div style="display:flex;justify-content:flex-end"><button type="button" class="btn btn-sm btn-ghost" data-copy="#raw-json">Copy frame JSON</button></div><pre class="json" id="raw-json">${jsonHtml(row.f)}</pre>`;
  }
}
