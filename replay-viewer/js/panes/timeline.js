// Timeline: one lane per frame kind, markers coloured by outcome, and
// unobserved intervals drawn as gaps rather than an inferred path.

import { svg, node, title, outcomeOf } from '../svg.js';

const LANES = ['event', 'finding', 'risk', 'verdict', 'action_request', 'action_receipt', 'edge_change', 'gap'];
const LABELS = { event: 'Events', finding: 'Findings', risk: 'Risk', verdict: 'Verdicts', action_request: 'Actions', action_receipt: 'Receipts', edge_change: 'Trust edges', gap: 'Unobserved' };
const DECISIONS = ['record', 'throttle', 'challenge', 'block', 'contain', 'refuse'];

export function renderTimeline(el, bundle, index, select) {
  const frames = bundle.frames;
  const lanes = LANES.filter((k) => frames.some((f) => f.kind === k));
  const W = 1000, left = 96, right = 14, laneH = 26, top = 6;
  const H = top + lanes.length * laneH + 22;
  const span = Math.max(1, frames[frames.length - 1].elapsed_ms);
  const x = (ms) => left + (ms / span) * (W - left - right);
  const s = svg(W, H);
  lanes.forEach((k, i) => {
    const y = top + i * laneH + 13;
    node(s, 'text', { x: 0, y: y + 4, class: 'muted' }, LABELS[k]);
    node(s, 'line', { x1: left, x2: W - right, y1: y, y2: y, class: 'lane-line' });
  });
  const cur = frames[index];
  node(s, 'line', { x1: x(cur.elapsed_ms), x2: x(cur.elapsed_ms), y1: top, y2: H - 18, class: 'cursor-line' });
  frames.forEach((f, i) => {
    const y = top + lanes.indexOf(f.kind) * laneH + 13;
    const cls = `marker d-${outcomeOf(f)}${i === index ? ' current' : ''}`;
    const m = f.kind === 'gap'
      ? node(s, 'rect', { x: x(f.elapsed_ms) - 7, y: y - 8, width: 14, height: 16, rx: 3, class: cls })
      : node(s, 'circle', { cx: x(f.elapsed_ms), cy: y, r: i === index ? 7.5 : 5.5, class: cls });
    title(m, `#${f.index} ${f.kind} ${outcomeOf(f)} at +${f.elapsed_ms} ms, ${f.sensor_id} seq ${f.sensor_seq}${f.payload?.unobserved ? `: ${f.payload.unobserved}` : ''}`);
    m.addEventListener('click', () => select(i));
  });
  node(s, 'text', { x: left, y: H - 4, class: 'muted mono' }, '+0 ms');
  node(s, 'text', { x: W - right, y: H - 4, class: 'muted mono', 'text-anchor': 'end' }, `+${span} ms`);
  el.replaceChildren(s);

  const legend = document.createElement('div');
  legend.className = 'legend';
  const present = new Set(frames.map(outcomeOf));
  for (const d of DECISIONS.filter((d) => present.has(d) || d === 'record')) {
    const item = document.createElement('span');
    item.innerHTML = `<i style="background: var(--${d})"></i>${d}`;
    legend.appendChild(item);
  }
  if (bundle.unobserved_layers?.length) {
    const item = document.createElement('span');
    item.innerHTML = `<i style="background: var(--gap); outline: 1px dashed var(--muted)"></i>no sensor on: ${bundle.unobserved_layers.join(', ')}`;
    legend.appendChild(item);
  }
  el.appendChild(legend);
}
