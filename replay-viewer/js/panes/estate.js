// Estate map: every layer this platform tier should observe, each sensor seen
// in the evidence, and the layers no sensor covered drawn as unobserved.

import { svg, node, title } from '../svg.js';

export function renderEstate(el, bundle, index) {
  const sensors = new Map();
  for (const f of bundle.frames) {
    if (f.kind !== 'event') continue;
    const layer = f.payload?.ivar?.sensor_type || 'unknown';
    if (!sensors.has(layer)) sensors.set(layer, new Set());
    sensors.get(layer).add(f.sensor_id);
  }
  const unobserved = bundle.unobserved_layers ?? [];
  const layers = [...sensors.keys()].sort().concat([...unobserved].sort());
  const current = bundle.frames[index];
  const seenSoFar = new Set(bundle.frames.slice(0, index + 1).map((f) => f.sensor_id));
  const W = 480, rowH = 40;
  const s = svg(W, layers.length * rowH);
  layers.forEach((layer, i) => {
    const y = i * rowH + 4;
    node(s, 'text', { x: 0, y: y + 20, class: 'muted' }, layer.replace('_', ' '));
    if (unobserved.includes(layer)) {
      title(node(s, 'rect', { x: 100, y, width: W - 100, height: rowH - 10, rx: 7, class: 'node unobserved' }), `${layer}: no sensor on this tier, steps here are not observed`);
      node(s, 'text', { x: 114, y: y + 19, class: 'muted' }, 'unobserved on this tier');
      return;
    }
    [...sensors.get(layer)].forEach((id, j) => {
      const x = 100 + j * 128;
      const active = current.sensor_id === id;
      title(node(s, 'rect', { x, y, width: 120, height: rowH - 10, rx: 7, class: `node${seenSoFar.has(id) ? ' seen' : ''}${active ? ' active' : ''}` }), id);
      node(s, 'circle', { cx: x + 14, cy: y + 15, r: 3.5, fill: seenSoFar.has(id) ? 'var(--verified)' : 'var(--muted)' });
      node(s, 'text', { x: x + 24, y: y + 19, class: `mono node-text${active ? ' active' : ''}` }, id);
    });
  });
  el.replaceChildren(s);
}
