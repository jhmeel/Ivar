// Events: every frame of the incident in one virtualised table, filterable
// by text, kind, decision, sensor, entity and time window. Selecting a row
// opens the frame detail; the playhead row is marked and followed.

import { filterRows, DECISIONS } from '../model.js';
import { esc, entityChip, kindBadge, kindLabel, outcomeBadge, riskBar, shortId, utc } from '../ui.js';

const ROW = 38;
const KINDS = ['event', 'finding', 'risk', 'verdict', 'action_request', 'action_receipt', 'gap', 'policy'];

export class EventsView {
  constructor(el, ctx) {
    this.el = el;
    this.ctx = ctx;
    this.q = { text: '', kinds: new Set(), decision: '', sensor: '', entity: '', securityOnly: false };
    this.rows = [];
    this.selected = -1;
  }

  /** Apply filters from the route (#/events?kind=finding&entity=ip:1.2.3.4). */
  setQuery(params) {
    this.q = {
      text: params.get('q') ?? '',
      kinds: new Set((params.get('kind') ?? '').split(',').filter(Boolean)),
      decision: params.get('decision') ?? '',
      sensor: params.get('sensor') ?? '',
      entity: params.get('entity') ?? '',
      securityOnly: params.get('security') === '1',
      from: params.has('from') ? Number(params.get('from')) : undefined,
      to: params.has('to') ? Number(params.get('to')) : undefined,
    };
  }

  render() {
    const m = this.ctx.model;
    const sensors = [...new Set(m.rows.map((r) => r.sensor).filter(Boolean))].sort();
    this.el.innerHTML = `
      <div class="toolbar pane" style="padding:12px 14px">
        <input type="search" id="ev-search" placeholder="Search frames: path, IP, rule, entity, evidence id…" value="${esc(this.q.text)}" aria-label="Search frames">
        <select id="ev-decision" aria-label="Decision"><option value="">All decisions</option>${DECISIONS.map((d) => `<option ${this.q.decision === d ? 'selected' : ''}>${d}</option>`).join('')}</select>
        <select id="ev-sensor" aria-label="Sensor"><option value="">All sensors</option>${sensors.map((s) => `<option value="${esc(s)}" ${this.q.sensor === s ? 'selected' : ''}>${esc(shortId(s, 28))}</option>`).join('')}</select>
        <label class="toggle"><input type="checkbox" id="ev-security" ${this.q.securityOnly ? 'checked' : ''}><span>Security only</span></label>
        <span class="count" id="ev-count"></span>
        <div class="chips" style="flex-basis:100%">${KINDS.filter((k) => m.kinds[k]).map((k) => `<button type="button" class="chip${this.q.kinds.has(k) ? ' on' : ''}" data-kind="${k}">${esc(kindLabel(k))} <span class="muted">${m.kinds[k]}</span></button>`).join('')}
          ${this.q.entity ? `<span class="chip on" title="entity filter">${esc(shortId(this.q.entity, 34))} <button type="button" class="chip" data-clear="entity" aria-label="Clear entity filter" style="padding:0 6px">×</button></span>` : ''}
          ${this.q.from !== undefined ? `<span class="chip on">+${(this.q.from / 1000).toFixed(1)} s to +${(this.q.to / 1000).toFixed(1)} s <button type="button" class="chip" data-clear="window" aria-label="Clear time window" style="padding:0 6px">×</button></span>` : ''}
        </div>
      </div>
      <div class="etable" role="grid" aria-label="Frames">
        <div class="ehead" role="row"><span>#</span><span>Time UTC</span><span>Elapsed</span><span>Kind</span><span>Outcome</span><span>Sensor</span><span>Entity</span><span>Summary</span><span style="text-align:right">Risk</span></div>
        <div class="escroll" id="ev-scroll" tabindex="0"><div id="ev-spacer"></div></div>
      </div>`;
    this.scroll = this.el.querySelector('#ev-scroll');
    this.spacer = this.el.querySelector('#ev-spacer');
    this.el.querySelector('#ev-search').addEventListener('input', (e) => {
      this.q.text = e.target.value;
      this.refilter();
    });
    this.el.querySelector('#ev-decision').addEventListener('change', (e) => {
      this.q.decision = e.target.value;
      this.refilter();
    });
    this.el.querySelector('#ev-sensor').addEventListener('change', (e) => {
      this.q.sensor = e.target.value;
      this.refilter();
    });
    this.el.querySelector('#ev-security').addEventListener('change', (e) => {
      this.q.securityOnly = e.target.checked;
      this.refilter();
    });
    this.el.querySelectorAll('[data-kind]').forEach((b) =>
      b.addEventListener('click', () => {
        const k = b.dataset.kind;
        this.q.kinds.has(k) ? this.q.kinds.delete(k) : this.q.kinds.add(k);
        b.classList.toggle('on');
        this.refilter();
      }),
    );
    this.el.querySelectorAll('[data-clear]').forEach((b) =>
      b.addEventListener('click', () => {
        if (b.dataset.clear === 'entity') this.q.entity = '';
        else this.q.from = this.q.to = undefined;
        this.render();
      }),
    );
    this.scroll.addEventListener('scroll', () => this.paint());
    this.scroll.addEventListener('keydown', (e) => this.key(e));
    this.refilter();
  }

  refilter() {
    const m = this.ctx.model;
    let rows = filterRows(m, { ...this.q, upto: this.ctx.follow ? this.ctx.cursor : undefined });
    if (this.q.from !== undefined) rows = rows.filter((r) => r.f.elapsed_ms >= this.q.from && r.f.elapsed_ms <= this.q.to);
    this.rows = rows;
    this.ctx.filtered = rows;
    this.el.querySelector('#ev-count').textContent = `${rows.length} of ${m.rows.length} frames`;
    this.spacer.style.height = `${rows.length * ROW}px`;
    this.paint();
  }

  paint() {
    const top = this.scroll.scrollTop;
    const h = this.scroll.clientHeight || 600;
    const first = Math.max(0, Math.floor(top / ROW) - 10);
    const last = Math.min(this.rows.length, Math.ceil((top + h) / ROW) + 10);
    const cursor = this.ctx.cursor;
    let html = '';
    for (let k = first; k < last; k++) {
      const r = this.rows[k];
      const ents = r.entities.slice(0, 1).map((e) => entityChip(e, { button: false })).join('');
      const cls = `row${r.i === this.selected ? ' sel' : ''}${r.i === cursor ? ' cursor' : ''}`;
      html += `<div class="${cls}" role="row" data-i="${r.i}" style="top:${k * ROW}px">
        <span class="mono muted">${r.i + 1}</span>
        <span class="mono">${esc(utc(r.f.time))}</span>
        <span class="mono muted">+${(r.f.elapsed_ms / 1000).toFixed(3)}s</span>
        <span>${kindBadge(r.kind)}</span>
        <span>${outcomeBadge(r)}</span>
        <span class="mono muted" title="${esc(r.sensor)}">${esc(shortId(r.sensor, 18))}</span>
        <span>${ents}</span>
        <span title="${esc(r.summary)}">${esc(r.summary)}</span>
        <span>${r.risk !== undefined ? `<span class="mono">${r.risk.toFixed(2)}</span>` : ''}</span>
      </div>`;
    }
    this.spacer.innerHTML = html || (this.rows.length ? '' : '<div class="empty">No frames match these filters.</div>');
    this.spacer.querySelectorAll('.row').forEach((row) => row.addEventListener('click', () => this.open(Number(row.dataset.i))));
  }

  open(i) {
    this.selected = i;
    this.ctx.open(i);
    this.paint();
  }

  /** Bring the playhead row into view while playing. */
  follow(i) {
    const k = this.rows.findIndex((r) => r.i >= i);
    if (k < 0) return;
    const y = k * ROW;
    if (y < this.scroll.scrollTop || y > this.scroll.scrollTop + this.scroll.clientHeight - ROW) this.scroll.scrollTop = Math.max(0, y - this.scroll.clientHeight / 2);
    this.paint();
  }

  /** Next or previous row in the filtered order, for the detail drawer. */
  neighbour(i, delta) {
    const k = this.rows.findIndex((r) => r.i === i);
    const n = this.rows[k + delta];
    return n ? n.i : -1;
  }

  key(e) {
    if (!this.rows.length) return;
    const k = Math.max(0, this.rows.findIndex((r) => r.i === this.selected));
    let next = -1;
    if (e.key === 'ArrowDown' || e.key === 'j') next = Math.min(this.rows.length - 1, this.selected < 0 ? 0 : k + 1);
    if (e.key === 'ArrowUp' || e.key === 'k') next = Math.max(0, k - 1);
    if (e.key === 'Enter' && this.selected >= 0) return this.ctx.open(this.selected);
    if (next < 0) return;
    e.preventDefault();
    this.selected = this.rows[next].i;
    const y = next * ROW;
    if (y < this.scroll.scrollTop) this.scroll.scrollTop = y;
    if (y > this.scroll.scrollTop + this.scroll.clientHeight - ROW) this.scroll.scrollTop = y - this.scroll.clientHeight + ROW;
    this.ctx.open(this.selected);
    this.paint();
  }
}

export { riskBar };
