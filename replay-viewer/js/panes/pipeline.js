// Pipeline view: per hop latency (sensor, ingest, core, decide, enforce) for
// the event behind the current frame.

import { svg, node, title } from '../svg.js';

const HOPS = ['sensor', 'ingest', 'core', 'decide', 'enforce'];

export function renderPipeline(el, bundle, index) {
  let f = null;
  for (let i = index; i >= 0; i--) {
    if (Object.keys(bundle.frames[i].hops_us ?? {}).length) {
      f = bundle.frames[i];
      break;
    }
  }
  if (!f) {
    el.innerHTML = '<div class="empty">No per hop latency was recorded for this step.</div>';
    return;
  }
  const values = HOPS.map((h) => f.hops_us[h] ?? 0);
  const max = Math.max(...values, 1);
  const slowest = HOPS[values.indexOf(Math.max(...values))];
  const W = 480, rowH = 30, left = 70, label = 74;
  const track = W - left - label;
  const s = svg(W, HOPS.length * rowH);
  HOPS.forEach((h, i) => {
    const y = i * rowH;
    const us = f.hops_us[h];
    node(s, 'text', { x: 0, y: y + 18, class: 'muted' }, h);
    node(s, 'rect', { x: left, y: y + 7, width: track, height: 14, rx: 7, class: 'bar-track' });
    if (us === undefined) {
      node(s, 'text', { x: left + track + 8, y: y + 18, class: 'muted' }, 'not reported');
      return;
    }
    const w = Math.max(6, (us / max) * track);
    title(node(s, 'rect', { x: left, y: y + 7, width: w, height: 14, rx: 7, class: `bar-hop${h === slowest ? ' slowest' : ''}` }), `${h}: ${us} µs`);
    node(s, 'text', { x: left + track + 8, y: y + 18, class: 'mono' }, `${(us / 1000).toFixed(2)} ms`);
  });
  const total = values.reduce((a, b) => a + b, 0);
  el.replaceChildren(s);
  const legend = document.createElement('div');
  legend.className = 'legend';
  legend.innerHTML = `<span class="chip">${(total / 1000).toFixed(2)} ms end to end</span><span>frame #${f.index} from ${f.sensor_id}</span><span><i style="background: var(--throttle)"></i>slowest hop</span>`;
  el.appendChild(legend);
}
