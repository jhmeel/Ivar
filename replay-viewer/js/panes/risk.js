// Risk view: the fast and slow timescales for one entity, with the policy
// bands (0.30, 0.60, 0.85) and the contain band shaded.

import { svg, node, title, entityKey, short } from '../svg.js';

const BANDS = [0.3, 0.6, 0.85];
let chosen = '';

export function renderRisk(el, bundle, index) {
  const risks = bundle.frames.map((f, i) => ({ f, i })).filter(({ f }) => f.kind === 'risk');
  if (!risks.length) {
    el.innerHTML = '<div class="empty">This bundle carries no risk frames.</div>';
    return;
  }
  const entities = [...new Set(risks.map(({ f }) => entityKey(f.payload.entity)))];
  if (!entities.includes(chosen)) {
    const peak = risks.reduce((a, b) => (b.f.payload.score > a.f.payload.score ? b : a));
    chosen = entityKey(peak.f.payload.entity);
  }
  const pick = document.createElement('select');
  pick.setAttribute('aria-label', 'Entity');
  for (const e of entities) pick.add(new Option(short(e, 40), e, false, e === chosen));
  pick.addEventListener('change', () => {
    chosen = pick.value;
    renderRisk(el, bundle, index);
  });

  const mine = risks.filter(({ f }) => entityKey(f.payload.entity) === chosen);
  const W = 480, H = 220, left = 34, right = 8, top = 8, bottom = 24;
  const span = Math.max(1, bundle.frames[bundle.frames.length - 1].elapsed_ms);
  const x = (ms) => left + (ms / span) * (W - left - right);
  const y = (v) => top + (1 - v) * (H - top - bottom);
  const s = svg(W, H);
  node(s, 'rect', { x: left, y: y(1), width: W - left - right, height: y(0.85) - y(1), class: 'band' });
  for (const b of BANDS) {
    node(s, 'line', { x1: left, x2: W - right, y1: y(b), y2: y(b), class: 'band-line' });
    node(s, 'text', { x: 0, y: y(b) + 4, class: 'muted mono' }, b.toFixed(2));
  }
  node(s, 'text', { x: W - right - 4, y: y(1) + 12, 'text-anchor': 'end', class: 'muted' }, 'contain');
  const upto = mine.filter(({ i }) => i <= index);
  for (const [cls, key] of [['line-fast', 'fast_score'], ['line-slow', 'slow_score']]) {
    if (upto.length) node(s, 'polyline', { class: cls, points: upto.map(({ f }) => `${x(f.elapsed_ms)},${y(f.payload[key])}`).join(' ') });
  }
  for (const { f } of upto) title(node(s, 'circle', { cx: x(f.elapsed_ms), cy: y(f.payload.score), r: 3, class: 'd-risk' }), `score ${f.payload.score.toFixed(2)} fast ${f.payload.fast_score.toFixed(2)} slow ${f.payload.slow_score.toFixed(2)}, ${f.payload.independent_sources} independent sources`);
  node(s, 'text', { x: left, y: H - 6, class: 'muted' }, '+0 ms');
  node(s, 'text', { x: W - right, y: H - 6, class: 'muted', 'text-anchor': 'end' }, `+${span} ms`);
  el.replaceChildren(pick, s);
  const last = upto[upto.length - 1]?.f.payload;
  const legend = document.createElement('div');
  legend.className = 'legend';
  legend.innerHTML = `<span><i style="background: var(--fast)"></i>fast, 30 min half life</span><span><i style="background: var(--slow)"></i>slow, 7 day half life</span>`;
  if (last) {
    const t = document.createElement('span');
    t.className = `chip${last.score >= 0.85 ? ' warn' : ''}`;
    t.textContent = `${last.score.toFixed(2)} · ${last.independent_sources} independent sources${last.target_only ? ' · target only' : ''}`;
    legend.prepend(t);
  }
  el.appendChild(legend);
}
