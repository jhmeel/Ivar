// Sessions: what each session sent and received, in order, with every IVAR
// finding, verdict and action about it interleaved where it happened.

import { esc, entityChip, formatElapsed, riskBar, shortId, utc } from '../ui.js';

const SORTS = {
  risk: (a, b) => b.maxRisk - a.maxRisk || b.events.length - a.events.length,
  requests: (a, b) => b.events.length - a.events.length,
  first: (a, b) => a.first - b.first,
};

export class SessionsView {
  constructor(el, ctx) {
    this.el = el;
    this.ctx = ctx;
    this.selected = '';
    this.sort = 'risk';
    this.text = '';
  }

  setQuery(params) {
    if (params.get('session')) this.selected = params.get('session');
  }

  list() {
    const t = this.text.toLowerCase();
    const upto = this.ctx.follow ? this.ctx.cursor : Infinity;
    return this.ctx.model.sessions
      .filter((s) => !t || `${s.key} ${s.ip} ${s.user} ${s.routes.join(' ')}`.toLowerCase().includes(t))
      .filter((s) => s.events[0] <= upto)
      .sort(SORTS[this.sort]);
  }

  render() {
    const sessions = this.list();
    if (!this.selected || !sessions.some((s) => s.key === this.selected)) this.selected = sessions[0]?.key ?? '';
    this.el.innerHTML = `
      <div class="toolbar pane" style="padding:12px 14px">
        <input type="search" id="se-search" placeholder="Search sessions: IP, user hash, route…" value="${esc(this.text)}" aria-label="Search sessions">
        <label class="field compact"><span>Sort</span><select id="se-sort"><option value="risk">Highest risk</option><option value="requests">Most requests</option><option value="first">First seen</option></select></label>
        <span class="count">${sessions.length} sessions</span>
      </div>
      <div class="split">
        <div class="list" id="se-list" role="listbox" aria-label="Sessions">${sessions.map((s) => this.card(s)).join('') || '<div class="empty">No sessions.</div>'}</div>
        <section class="pane" id="se-detail" aria-label="Session transcript"></section>
      </div>`;
    this.el.querySelector('#se-sort').value = this.sort;
    this.el.querySelector('#se-sort').addEventListener('change', (e) => {
      this.sort = e.target.value;
      this.render();
    });
    this.el.querySelector('#se-search').addEventListener('input', (e) => {
      this.text = e.target.value;
      const pos = e.target.selectionStart;
      this.render();
      const s = this.el.querySelector('#se-search');
      s.focus();
      s.setSelectionRange(pos, pos);
    });
    this.el.querySelectorAll('.card').forEach((c) =>
      c.addEventListener('click', () => {
        this.selected = c.dataset.key;
        this.el.querySelectorAll('.card').forEach((x) => x.classList.toggle('on', x === c));
        this.detail();
      }),
    );
    this.detail();
  }

  card(s) {
    const decisions = Object.entries(s.decisions).map(([d, n]) => `<span class="badge"><i style="background:var(--${esc(d)})"></i>${esc(d)} ${n}</span>`).join('');
    const label = s.session ? `session ${shortId(s.session, 14)}` : s.ip || 'unknown source';
    return `<div class="card${s.key === this.selected ? ' on' : ''}" data-key="${esc(s.key)}" role="option" aria-selected="${s.key === this.selected}">
      <div class="c1"><span>${esc(label)}</span><span>${s.maxRisk ? `<span class="mono" style="color:${s.maxRisk >= 0.85 ? 'var(--contain)' : 'var(--ink-2)'}">${s.maxRisk.toFixed(2)}</span>` : ''}</span></div>
      <div class="c2"><span>${s.events.length} requests</span><span>${s.routes.length} ${s.routes.some((r) => r.includes(' ')) ? 'routes' : 'activities'}</span><span>+${esc(formatElapsed(s.first))}</span>${s.user ? `<span>user ${esc(shortId(s.user, 12))}</span>` : ''}</div>
      ${decisions ? `<div class="chips">${decisions}</div>` : ''}
    </div>`;
  }

  detail() {
    const box = this.el.querySelector('#se-detail');
    const m = this.ctx.model;
    const s = m.sessions.find((x) => x.key === this.selected);
    if (!s) {
      box.innerHTML = '<div class="empty">Select a session.</div>';
      return;
    }
    const upto = this.ctx.follow ? this.ctx.cursor : Infinity;
    const items = [...s.events.map((i) => ['req', i]), ...s.related.map((i) => ['ivar', i])].filter(([, i]) => i <= upto).sort((a, b) => a[1] - b[1]);
    const statuses = Object.entries(s.statuses).map(([c, n]) => `<span class="chip${Number(c) >= 400 ? ' warn' : ''}">${esc(c)} × ${n}</span>`).join(' ');
    box.innerHTML = `
      <header><h2>Session transcript</h2><span class="pane-note">${items.length} entries · ${esc(utc(m.rows[s.events[0]].f.time, true))} to ${esc(utc(m.rows[s.events[s.events.length - 1]].f.time))}</span></header>
      <dl class="kv" style="margin-bottom:12px">
        <dt>Source</dt><dd>${s.ip ? entityChip(`ip:${s.ip}`) : '·'}</dd>
        <dt>Identity</dt><dd>${s.user ? `${entityChip(`user:${s.user}`)} <span class="muted">keyed hash</span>` : '<span class="muted">anonymous</span>'}</dd>
        ${s.session ? `<dt>Session</dt><dd>${entityChip(`session:${s.session}`)}</dd>` : ''}
        <dt>Seen by</dt><dd>${s.sensors.map((x) => `<span class="chip">${esc(shortId(x, 22))}</span>`).join(' ')}</dd>
        <dt>Responses</dt><dd>${statuses || '<span class="muted">not recorded</span>'}</dd>
        <dt>Peak risk</dt><dd>${riskBar(s.maxRisk)}</dd>
      </dl>
      <div class="legend" style="margin:0 0 8px"><span><b class="mono" style="color:var(--accent)">→</b> sent by the client</span><span><b class="mono" style="color:var(--verified)">←</b> returned to the client</span><span><b class="mono" style="color:var(--warn)">◆</b> IVAR finding, verdict or action</span></div>
      <div class="transcript">${items.map(([type, i]) => this.line(type, m.rows[i])).join('')}</div>`;
    box.querySelectorAll('[data-frame]').forEach((r) => r.addEventListener('click', () => this.ctx.open(Number(r.dataset.frame))));
    box.querySelectorAll('[data-entity]').forEach((b) => b.addEventListener('click', (e) => (e.stopPropagation(), this.ctx.go(`entities?entity=${encodeURIComponent(b.dataset.entity)}`))));
  }

  line(type, r) {
    const f = r.f;
    const p = f.payload ?? {};
    const t = `+${(f.elapsed_ms / 1000).toFixed(3)}s`;
    if (type === 'ivar') {
      const badge = r.kind === 'verdict' ? `<span class="badge"><i style="background:var(--${esc(r.outcome)})"></i>${esc(r.outcome)}</span>` : `<span class="badge"><i style="background:var(--${r.kind === 'finding' ? 'finding' : 'action'})"></i>${esc(r.kind === 'finding' ? 'finding' : 'action')}</span>`;
      return `<div class="tx ivar" data-frame="${r.i}" role="button" tabindex="0"><span class="t">${t}</span><span class="dir ivar">◆</span><div class="body">${badge} ${esc(r.summary)}</div><span class="mono muted">${r.risk !== undefined ? r.risk.toFixed(2) : ''}</span></div>`;
    }
    const h = p.http_request;
    const fields = h?.body_keys?.length ? `<div class="sub">fields: ${esc(h.body_keys.join(', '))}</div>` : '';
    const status = p.http_response?.code;
    const out = h ? `<b>${esc(h.http_method)}</b> ${esc(h.url_path)}${fields}` : `${esc(p.activity_name)} ${p.status ? `<span class="muted">${esc(p.status)}</span>` : ''}`;
    let html = `<div class="tx" data-frame="${r.i}" role="button" tabindex="0"><span class="t">${t}</span><span class="dir out">→</span><div class="body">${out}<div class="sub">${esc(shortId(f.sensor_id, 22))} · seq ${esc(f.sensor_seq)}</div></div><span></span></div>`;
    if (status) html += `<div class="tx" data-frame="${r.i}" role="button" tabindex="0"><span class="t"></span><span class="dir in">←</span><div class="body"><b class="mono">${esc(status)}</b> ${status >= 400 ? '<span class="chip warn">refused or failed</span>' : ''}</div><span></span></div>`;
    return html;
  }
}
