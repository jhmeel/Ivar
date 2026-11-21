// Overview: the incident in one screen. Every tile and row links into the
// event stream, entity profiles or the frame detail.

import { activityChart, decisionBar, sparkline } from '../charts.js';
import { esc, entityChip, formatElapsed, riskBar, shortId, utc } from '../ui.js';

function kpi(label, value, sub, go, color) {
  return `<div class="kpi" ${go ? `data-go="${esc(go)}" tabindex="0" role="button"` : ''}>
    <div class="k-label">${color ? `<i class="dot" style="background:var(--${color})"></i>` : ''}${esc(label)}</div>
    <div class="k-value">${esc(value)}</div>
    ${sub ? `<div class="k-sub">${sub}</div>` : ''}
  </div>`;
}

function pct(a, b) {
  return b ? `${((a / b) * 100).toFixed(1)}%` : '0%';
}

export function renderOverview(el, ctx) {
  const m = ctx.model;
  const t = m.totals;
  const b = m.bundle;
  const blocked = (m.decisions.block ?? 0) + (m.decisions.contain ?? 0) + (m.decisions.refuse ?? 0);
  const firstTime = m.rows[0]?.f.time;
  const lastTime = m.rows[m.rows.length - 1]?.f.time;
  el.innerHTML = `
    <div class="ov-top">
      <section class="hero" aria-label="Outcome">
        <div class="hero-head">
          <div class="h-label">Outcome</div>
          <div class="h-meter" title="Share of verdicts issued in enforce mode"><span>Enforcing</span><b>${pct(t.enforced, t.verdicts)}</b><i><em style="width:${t.verdicts ? (t.enforced / t.verdicts) * 100 : 0}%"></em></i></div>
        </div>
        <div class="h-main" data-go="events?decision=contain" tabindex="0" role="button">
          <div class="h-value">${blocked}</div>
          <div>
            <div class="h-title">${blocked === 1 ? 'request or source' : 'requests or sources'} blocked or contained</div>
            <div class="h-sub">contain ${m.decisions.contain ?? 0} · block ${m.decisions.block ?? 0} · refuse ${m.decisions.refuse ?? 0} · from ${t.events} events across ${m.sensors.filter((s) => s.events).length} sensors in ${esc(formatElapsed(m.span))}</div>
          </div>
        </div>
        <ol class="flow" aria-label="Decision pipeline">
          ${[
            ['Events', t.events, 'events?kind=event', 'event', `${t.sources} source${t.sources === 1 ? '' : 's'}`],
            ['Findings', t.findings, 'events?kind=finding', 'finding', `${m.rules.length} rule${m.rules.length === 1 ? '' : 's'}`],
            ['Verdicts', t.verdicts, 'events?kind=verdict', 'record', 'scored'],
            ['Enforced', t.enforced, 'events?kind=verdict', 'block', pct(t.enforced, t.verdicts)],
            ['Actions', t.actions, 'events?kind=action_request', 'action', `${m.kinds.action_receipt ?? 0} receipts`],
          ].map(([l, v, go, c, sub]) => `<li class="step" data-go="${esc(go)}" tabindex="0" role="button"><div class="s-label"><i class="dot" style="background:var(--${c})"></i>${esc(l)}</div><div class="s-value">${esc(v)}</div><div class="s-sub">${esc(sub)}</div></li>`).join('')}
        </ol>
      </section>
      ${kpi('Throttled or challenged', (m.decisions.throttle ?? 0) + (m.decisions.challenge ?? 0), `throttle ${m.decisions.throttle ?? 0} · challenge ${m.decisions.challenge ?? 0}`, 'events?decision=throttle', 'throttle')}
      ${kpi('Sessions', t.sessions, 'transcripts with every request and response', 'sessions', 'ent-session')}
      ${kpi('Entities', m.entities.length, `${m.entities.filter((e) => e.lastDecision).length} with a decision against them`, 'entities', 'ent-user')}
      <div class="kpi ${t.gaps ? 'k-warn' : 'k-ok'}" data-go="events?kind=gap" tabindex="0" role="button">
        <div class="k-label">${t.gaps ? '<i class="dot" style="background:var(--warn)"></i>' : '<svg class="k-check" viewBox="0 0 16 16" aria-hidden="true"><circle cx="8" cy="8" r="7"/><path d="m5 8.2 2 2 4-4.4"/></svg>'}Unobserved intervals</div>
        <div class="k-value">${t.gaps}</div>
        <div class="k-sub">${t.gaps ? 'sequence gaps: events lost in transit' : 'every sensor sequence complete'}</div>
      </div>
    </div>

    <section class="pane chart" aria-label="Activity over time">
      <header><h2>Activity over time</h2><span class="pane-note">${esc(utc(firstTime, true))} to ${esc(utc(lastTime))} UTC · ${esc(formatElapsed(m.span))} real time · click a column to inspect it</span></header>
      <div id="ov-activity"></div>
      <div class="legend">${['record', 'throttle', 'challenge', 'block', 'contain', 'refuse'].map((d) => `<span><i class="dot" style="background:var(--${d})"></i>${d}</span>`).join('')}<span>bars: verdicts per interval · dots: events, findings, actions and unobserved intervals, sized by count</span></div>
    </section>

    <div class="grid-3">
      <section class="pane" aria-label="Highest risk entities">
        <header><h2>Highest risk entities</h2><a href="#/entities" class="pane-note">all ${m.entities.length}</a></header>
        <table class="tbl">
          <thead><tr><th>Entity</th><th>Risk over time</th><th>Peak</th><th>Last decision</th><th class="num">Events</th></tr></thead>
          <tbody>${m.entities.slice(0, 8).map((e) => `<tr class="click" data-entity-row="${esc(e.key)}"><td>${entityChip(e.key, { button: false })}</td><td class="spark" data-key="${esc(e.key)}"></td><td>${riskBar(e.maxRisk)}</td><td>${e.lastDecision ? `<span class="badge"><i style="background:var(--${esc(e.lastDecision)})"></i>${esc(e.lastDecision)}</span>` : '<span class="muted">none</span>'}</td><td class="num">${e.events}</td></tr>`).join('') || '<tr><td colspan="5" class="empty">No entities.</td></tr>'}</tbody>
        </table>
      </section>
      <section class="pane" aria-label="Decisions">
        <header><h2>Decisions</h2><span class="pane-note">${t.verdicts} verdicts</span></header>
        <div id="ov-decisions"></div>
        <div class="section-title" style="margin-top:16px">Rules that fired</div>
        <table class="tbl" style="margin-top:8px">
          <tbody>${m.rules.map((r) => `<tr class="click" data-rule="${esc(r.rule)}"><td><div class="mono">${esc(r.rule)}</div><div class="muted" style="font-size:12px">${esc(r.family)} · ${esc(r.technique ?? '')}</div></td><td class="num">${r.count}</td></tr>`).join('') || '<tr><td class="empty">No findings.</td></tr>'}</tbody>
        </table>
      </section>
    </div>

    <div class="grid-2">
      <section class="pane" aria-label="Sensor health">
        <header><h2>Sensor health</h2><span class="pane-note">per enforcement point</span></header>
        <table class="tbl">
          <thead><tr><th>Sensor</th><th>Layer</th><th class="num">Events</th><th class="num">Gaps</th><th class="num">Skew</th><th class="num">Median pipeline</th></tr></thead>
          <tbody>${m.sensors.filter((s) => s.events || s.gaps).map((s) => {
            const hops = [...s.hops].sort((a, b) => a - b);
            const med = hops.length ? `${(hops[Math.floor(hops.length / 2)] / 1000).toFixed(2)} ms` : '·';
            return `<tr class="click" data-sensor="${esc(s.id)}"><td class="mono">${esc(shortId(s.id, 26))}</td><td>${esc(s.layer.replace('_', ' '))}</td><td class="num">${s.events}</td><td class="num">${s.gaps ? `<span class="chip warn">${s.gaps}</span>` : '0'}</td><td class="num">${s.skew} ms</td><td class="num">${med}</td></tr>`;
          }).join('')}</tbody>
        </table>
        ${b.unobserved_layers?.length ? `<div class="note" style="margin-top:12px">No sensor on this tier for: <b>${esc(b.unobserved_layers.join(', '))}</b>. Steps there are unobserved, and the replay says so rather than inferring them.</div>` : ''}
      </section>
      <section class="pane" aria-label="Integrity">
        <header><h2>Integrity</h2><span class="pane-note">what makes this replay evidence</span></header>
        <dl class="kv">
          <dt>Source</dt><dd>${ctx.live ? 'live core, evidence hash chain re verified on every poll' : 'signed ReplayBundle, re executed in this browser'}</dd>
          <dt>Incident</dt><dd>${esc(b.incident_id ?? '')}</dd>
          <dt>Policy</dt><dd>${esc([b.policy_version, ...(b.policy_history ?? []).map((p) => p.policy_version)].filter(Boolean).join(' → '))}</dd>
          <dt>Engine</dt><dd>${esc(b.engine_version ?? '')}</dd>
          <dt>Verdicts reproduced</dt><dd>${ctx.live ? 'not applicable to a live stream' : `${esc(b._verified?.recorded_verdicts ?? '?')} of ${esc(b._verified?.recorded_verdicts ?? '?')}`}</dd>
          <dt>Signature</dt><dd>${b.signature ? esc(`${b.signature.alg} by ${b.signature.key_id}`) : 'unsigned'}</dd>
          <dt>Evidence chain head</dt><dd>${esc(b.evidence_chain_head ?? '')}</dd>
          <dt>Payload privacy</dt><dd>values redacted at the sensor; identifiers keyed hashed (section 16)</dd>
        </dl>
      </section>
    </div>`;

  el.querySelector('#ov-activity').appendChild(activityChart(m.buckets, m.span, ctx.cursorMs, (bk) => ctx.go(`events?from=${Math.floor(bk.from)}&to=${Math.ceil(bk.to)}`)));
  el.querySelector('#ov-decisions').appendChild(decisionBar(m.decisions));
  el.querySelectorAll('.spark').forEach((td) => td.appendChild(sparkline(m.byEntity.get(td.dataset.key).risk, m.span)));
  el.querySelectorAll('[data-go]').forEach((k) => {
    const go = (e) => (e?.stopPropagation(), ctx.go(k.dataset.go));
    k.addEventListener('click', go);
    k.addEventListener('keydown', (e) => (e.key === 'Enter' || e.key === ' ') && (e.preventDefault(), go(e)));
  });
  el.querySelectorAll('[data-entity-row]').forEach((tr) => tr.addEventListener('click', () => ctx.go(`entities?entity=${encodeURIComponent(tr.dataset.entityRow)}`)));
  el.querySelectorAll('[data-rule]').forEach((tr) => tr.addEventListener('click', () => ctx.go(`events?kind=finding&q=${encodeURIComponent(tr.dataset.rule)}`)));
  el.querySelectorAll('[data-sensor]').forEach((tr) => tr.addEventListener('click', () => ctx.go(`events?sensor=${encodeURIComponent(tr.dataset.sensor)}`)));
}
