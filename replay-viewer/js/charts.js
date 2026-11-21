// SVG charts for the dashboard: stacked activity over time, a decision
// breakdown and sparklines. Thin marks, rounded data ends, a 2px surface gap
// between stacked segments, a hover tooltip on every mark, and legends with
// labels so identity is never colour alone.

import { svg, node, esc } from './svg.js';
import { formatElapsed } from './player.js';

export const DECISION_ORDER = ['record', 'throttle', 'challenge', 'block', 'contain', 'refuse'];
/** Stacking order validated for colour separation (see css/viewer.css). */
export const DECISION_STACK = ['refuse', 'throttle', 'record', 'block', 'challenge', 'contain'];

let tip;
function tooltip() {
  if (!tip) {
    tip = document.createElement('div');
    tip.className = 'tip';
    tip.hidden = true;
    document.body.appendChild(tip);
  }
  return tip;
}

export function showTip(e, html) {
  const t = tooltip();
  t.innerHTML = html;
  t.hidden = false;
  const pad = 14;
  const r = t.getBoundingClientRect();
  let x = e.clientX + pad;
  let y = e.clientY + pad;
  if (x + r.width > innerWidth - 8) x = e.clientX - r.width - pad;
  if (y + r.height > innerHeight - 8) y = e.clientY - r.height - pad;
  t.style.left = `${Math.max(8, x)}px`;
  t.style.top = `${Math.max(8, y)}px`;
}

export function hideTip() {
  if (tip) tip.hidden = true;
}

function bindTip(el, html) {
  el.addEventListener('mousemove', (e) => showTip(e, html()));
  el.addEventListener('mouseleave', hideTip);
}

/**
 * Activity over time: per bucket, decisions stacked as bars and findings,
 * actions and events as their own rows below, with the playhead marked.
 * `onPick(bucket)` filters the event stream to that window.
 */
export function activityChart(buckets, span, cursorMs, onPick) {
  const W = 1000, H = 230, left = 72, right = 10, top = 10, plot = 130, gapRow = 18;
  const s = svg(W, H);
  const maxVerdicts = Math.max(1, ...buckets.map((b) => DECISION_ORDER.reduce((a, d) => a + b.decisions[d], 0)));
  const bw = (W - left - right) / buckets.length;
  const y = (v) => top + plot - (v / maxVerdicts) * plot;
  for (const v of [0, Math.ceil(maxVerdicts / 2), maxVerdicts]) {
    node(s, 'line', { x1: left, x2: W - right, y1: y(v), y2: y(v), class: v ? 'grid' : 'axis' });
    node(s, 'text', { x: left - 6, y: y(v) + 4, 'text-anchor': 'end' }, String(v));
  }
  const rows = [['events', 'var(--event)'], ['findings', 'var(--finding)'], ['actions', 'var(--action)'], ['gaps', 'var(--gap)']];
  const maxRow = Object.fromEntries(rows.map(([k]) => [k, Math.max(1, ...buckets.map((b) => b[k]))]));
  rows.forEach(([k], i) => node(s, 'text', { x: left - 6, y: top + plot + 22 + i * gapRow + 4, 'text-anchor': 'end' }, k));
  buckets.forEach((b, i) => {
    const x = left + i * bw;
    let acc = 0;
    for (const d of DECISION_STACK) {
      const n = b.decisions[d];
      if (!n) continue;
      const y0 = y(acc), y1 = y(acc + n);
      node(s, 'rect', { x: x + 1, y: y1, width: Math.max(1, bw - 2), height: Math.max(1, y0 - y1 - 2), rx: 2, fill: `var(--${d})` });
      acc += n;
    }
    rows.forEach(([k, color], r) => {
      const v = b[k];
      if (!v) return;
      const cy = top + plot + 22 + r * gapRow;
      const size = 3 + 5 * Math.sqrt(v / maxRow[k]);
      node(s, 'circle', { cx: x + bw / 2, cy, r: size, fill: color, opacity: 0.9 });
    });
    const hit = node(s, 'rect', { x, y: top, width: bw, height: H - top - 16, class: 'hit' });
    bindTip(hit, () => {
      const parts = DECISION_ORDER.filter((d) => b.decisions[d]).map((d) => `<span class="badge"><i style="background:var(--${d})"></i>${d} <b>${b.decisions[d]}</b></span>`);
      return `<div><b>+${formatElapsed(Math.round(b.from))}</b> to <b>+${formatElapsed(Math.round(b.to))}</b></div><div class="chips" style="margin:6px 0">${parts.join('') || '<span class="muted">no verdicts</span>'}</div><div class="muted">${b.events} events · ${b.findings} findings · ${b.actions} actions · ${b.gaps} unobserved</div><div class="muted">click to see these frames</div>`;
    });
    hit.addEventListener('click', () => onPick?.(b));
  });
  if (cursorMs !== undefined) {
    const cx = left + (cursorMs / span) * (W - left - right);
    node(s, 'line', { x1: cx, x2: cx, y1: top, y2: H - 18, class: 'cursor' });
  }
  node(s, 'text', { x: left, y: H - 2 }, '+0');
  node(s, 'text', { x: W - right, y: H - 2, 'text-anchor': 'end' }, `+${formatElapsed(span)}`);
  return s;
}

/** Decisions as one horizontal bar with labelled segments. */
export function decisionBar(decisions) {
  const total = DECISION_ORDER.reduce((a, d) => a + (decisions[d] ?? 0), 0);
  const wrap = document.createElement('div');
  if (!total) {
    wrap.innerHTML = '<div class="empty">No verdicts.</div>';
    return wrap;
  }
  const W = 1000, H = 26;
  const s = svg(W, H);
  let x = 0;
  for (const d of DECISION_STACK) {
    const n = decisions[d] ?? 0;
    if (!n) continue;
    const w = (n / total) * W;
    const r = node(s, 'rect', { x: x + 1, y: 0, width: Math.max(2, w - 2), height: H, rx: 4, fill: `var(--${d})` });
    bindTip(r, () => `<span class="badge"><i style="background:var(--${d})"></i>${d}</span> <b>${n}</b> of ${total} (${((n / total) * 100).toFixed(1)}%)`);
    x += w;
  }
  wrap.appendChild(s);
  const legend = document.createElement('div');
  legend.className = 'legend';
  legend.innerHTML = DECISION_ORDER.filter((d) => decisions[d]).map((d) => `<span><i class="dot" style="background:var(--${d})"></i>${d} <b class="mono">${decisions[d]}</b></span>`).join('');
  wrap.appendChild(legend);
  return wrap;
}

/** A small risk sparkline (fast score) with the contain band. */
export function sparkline(points, span, w = 120, h = 26) {
  const s = svg(w, h);
  s.style.width = `${w}px`;
  s.style.height = `${h}px`;
  const y = (v) => 2 + (1 - v) * (h - 4);
  node(s, 'rect', { x: 0, y: y(1), width: w, height: y(0.85) - y(1), class: 'band' });
  if (points.length) {
    const x = (t) => (t / span) * w;
    node(s, 'polyline', { class: 'line-fast', points: points.map((p) => `${x(p.t).toFixed(1)},${y(p.fast ?? p.score).toFixed(1)}`).join(' ') });
    const last = points[points.length - 1];
    node(s, 'circle', { cx: x(last.t), cy: y(last.score), r: 2.5, fill: last.score >= 0.85 ? 'var(--contain)' : 'var(--risk)' });
  }
  return s;
}

/** Risk over time for one entity: fast and slow timescales, policy bands. */
export function riskChart(points, span, onPick) {
  const W = 1000, H = 220, left = 40, right = 10, top = 10, bottom = 24;
  const s = svg(W, H);
  const x = (t) => left + (t / span) * (W - left - right);
  const y = (v) => top + (1 - v) * (H - top - bottom);
  node(s, 'rect', { x: left, y: y(1), width: W - left - right, height: y(0.85) - y(1), class: 'band' });
  for (const b of [0.3, 0.6, 0.85]) {
    node(s, 'line', { x1: left, x2: W - right, y1: y(b), y2: y(b), class: 'grid' });
    node(s, 'text', { x: left - 6, y: y(b) + 4, 'text-anchor': 'end' }, b.toFixed(2));
  }
  node(s, 'text', { x: W - right - 4, y: y(1) + 13, 'text-anchor': 'end' }, 'contain band');
  if (points.length) {
    node(s, 'polyline', { class: 'line-slow', points: points.map((p) => `${x(p.t)},${y(p.slow)}`).join(' ') });
    node(s, 'polyline', { class: 'line-fast', points: points.map((p) => `${x(p.t)},${y(p.fast)}`).join(' ') });
    for (const p of points) {
      const c = node(s, 'circle', { cx: x(p.t), cy: y(p.score), r: 4, fill: p.score >= 0.85 ? 'var(--contain)' : 'var(--risk)', stroke: 'var(--panel)', 'stroke-width': 2, style: 'cursor:pointer' });
      bindTip(c, () => `<b>${p.score.toFixed(2)}</b> at +${formatElapsed(p.t)}<div class="muted">fast ${p.fast.toFixed(2)} · slow ${p.slow.toFixed(2)}</div>`);
      c.addEventListener('click', () => onPick?.(p.i));
    }
  }
  node(s, 'text', { x: left, y: H - 4 }, '+0');
  node(s, 'text', { x: W - right, y: H - 4, 'text-anchor': 'end' }, `+${formatElapsed(span)}`);
  const wrap = document.createElement('div');
  wrap.className = 'chart';
  wrap.appendChild(s);
  const legend = document.createElement('div');
  legend.className = 'legend';
  legend.innerHTML = '<span><i class="dot" style="background:var(--fast)"></i>fast, 30 min half life</span><span><i class="dot" style="background:var(--slow)"></i>slow, 7 day half life (dashed)</span><span><i class="dot" style="background:var(--contain)"></i>at or above 0.85: contain band</span>';
  wrap.appendChild(legend);
  return wrap;
}

export function tipText(s) {
  return esc(s);
}
