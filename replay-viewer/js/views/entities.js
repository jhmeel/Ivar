// Entities: every IP, user, session, service and host the incident touched,
// ranked by risk, with a profile of each: risk over both timescales, its
// decisions, the entities seen with it and every frame about it.

import { riskChart, sparkline } from '../charts.js';
import { esc, entityChip, formatElapsed, kindBadge, riskBar, shortId } from '../ui.js';

const TYPES = ['ip', 'user', 'session', 'service', 'host'];

export class EntitiesView {
  constructor(el, ctx) {
    this.el = el;
    this.ctx = ctx;
    this.selected = '';
    this.type = '';
    this.text = '';
  }

  setQuery(params) {
    if (params.get('entity')) this.selected = params.get('entity');
  }

  render() {
    const m = this.ctx.model;
    const t = this.text.toLowerCase();
    const list = m.entities.filter((e) => (!this.type || e.type === this.type) && (!t || e.key.toLowerCase().includes(t)));
    if (!this.selected && list[0]) this.selected = list[0].key;
    const counts = Object.fromEntries(TYPES.map((k) => [k, m.entities.filter((e) => e.type === k).length]));
    this.el.innerHTML = `
      <div class="toolbar pane" style="padding:12px 14px">
        <input type="search" id="en-search" placeholder="Search entities…" value="${esc(this.text)}" aria-label="Search entities">
        <div class="chips">${TYPES.filter((k) => counts[k]).map((k) => `<button type="button" class="chip${this.type === k ? ' on' : ''}" data-type="${k}">${k} <span class="muted">${counts[k]}</span></button>`).join('')}</div>
        <span class="count">${list.length} entities</span>
      </div>
      <section class="pane" id="en-profile" aria-label="Entity profile"></section>
      <section class="pane" aria-label="All entities">
        <div style="max-height:420px;overflow:auto">
        <table class="tbl">
          <thead><tr><th>Entity</th><th>Risk</th><th>Peak</th><th>Decisions</th><th class="num">Events</th><th class="num">Findings</th><th>Seen</th></tr></thead>
          <tbody>${list.map((e) => `<tr class="click${e.key === this.selected ? ' sel' : ''}" data-key="${esc(e.key)}"><td>${entityChip(e.key, { button: false })}</td><td class="spark" data-key="${esc(e.key)}"></td><td>${riskBar(e.maxRisk)}</td><td><div class="chips">${Object.entries(e.decisions).map(([d, n]) => `<span class="badge"><i style="background:var(--${esc(d)})"></i>${esc(d)} ${n}</span>`).join('') || '<span class="muted">none</span>'}</div></td><td class="num">${e.events}</td><td class="num">${e.findings}</td><td class="mono muted">+${esc(formatElapsed(Math.max(0, e.first)))}</td></tr>`).join('') || '<tr><td colspan="7" class="empty">No entities.</td></tr>'}</tbody>
        </table></div>
      </section>`;
    this.el.querySelectorAll('.spark').forEach((td) => td.appendChild(sparkline(m.byEntity.get(td.dataset.key).risk, m.span)));
    this.el.querySelectorAll('tr[data-key]').forEach((tr) =>
      tr.addEventListener('click', () => {
        this.selected = tr.dataset.key;
        this.el.querySelectorAll('tr[data-key]').forEach((x) => x.classList.toggle('sel', x === tr));
        this.profile();
      }),
    );
    this.el.querySelectorAll('[data-type]').forEach((b) => b.addEventListener('click', () => ((this.type = this.type === b.dataset.type ? '' : b.dataset.type), this.render())));
    this.el.querySelector('#en-search').addEventListener('input', (e) => {
      this.text = e.target.value;
      const pos = e.target.selectionStart;
      this.render();
      const s = this.el.querySelector('#en-search');
      s.focus();
      s.setSelectionRange(pos, pos);
    });
    this.profile();
  }

  profile() {
    const box = this.el.querySelector('#en-profile');
    const m = this.ctx.model;
    const e = m.byEntity.get(this.selected);
    if (!e) {
      box.innerHTML = '<div class="empty">Select an entity.</div>';
      return;
    }
    const upto = this.ctx.follow ? this.ctx.cursor : Infinity;
    const frames = e.frames.filter((i) => i <= upto);
    const related = new Map();
    for (const i of frames) for (const k of m.rows[i].entities) if (k !== e.key) related.set(k, (related.get(k) ?? 0) + 1);
    const top = [...related.entries()].sort((a, b) => b[1] - a[1]).slice(0, 12);
    const notable = frames.filter((i) => m.rows[i].kind !== 'event' && m.rows[i].kind !== 'risk').slice(-14).reverse();
    box.innerHTML = `
      <header><h2>${esc(e.type)} profile</h2><span class="pane-note">${frames.length} frames · first +${esc(formatElapsed(Math.max(0, e.first)))} · last +${esc(formatElapsed(Math.max(0, e.last)))}</span></header>
      <div style="display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin-bottom:12px">${entityChip(e.key, { button: false })}
        <button type="button" class="btn btn-sm btn-ghost" data-go="events?entity=${encodeURIComponent(e.key)}">All ${frames.length} frames</button>
        <button type="button" class="btn btn-sm btn-ghost" data-go="events?entity=${encodeURIComponent(e.key)}&security=1">Security frames</button></div>
      <div class="section-title">Risk over time</div>
      <div id="en-risk" style="margin:8px 0 14px"></div>
      <div class="grid-2">
        <div>
          <div class="section-title">Latest findings, verdicts and actions</div>
          <div class="transcript" style="margin-top:8px">${notable.map((i) => { const r = m.rows[i]; return `<div class="tx" data-frame="${i}" role="button" tabindex="0"><span class="t">+${(r.f.elapsed_ms / 1000).toFixed(3)}s</span><span></span><div class="body">${kindBadge(r.kind)} ${r.kind === 'verdict' ? `<span class="badge"><i style="background:var(--${esc(r.outcome)})"></i>${esc(r.outcome)}</span>` : ''} ${esc(r.summary)}</div><span></span></div>`; }).join('') || '<div class="empty">Nothing beyond events.</div>'}</div>
        </div>
        <div>
          <div class="section-title">Seen with</div>
          <div class="chips" style="margin-top:8px">${top.map(([k, n]) => entityChip(k, { count: n })).join('') || '<span class="muted">no other entity</span>'}</div>
        </div>
      </div>`;
    box.querySelector('#en-risk').appendChild(riskChart(e.risk.filter((p) => p.i <= upto), m.span, (i) => this.ctx.open(i)));
    box.querySelectorAll('[data-frame]').forEach((r) => r.addEventListener('click', () => this.ctx.open(Number(r.dataset.frame))));
    box.querySelectorAll('[data-go]').forEach((b) => b.addEventListener('click', () => this.ctx.go(b.dataset.go)));
    box.querySelectorAll('[data-entity]').forEach((b) => b.addEventListener('click', () => ((this.selected = b.dataset.entity), this.render())));
  }
}

export { shortId };
