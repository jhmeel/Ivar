// Trust graph: the entities and edges the evidence shows up to the current
// frame. Edges a finding marked undeclared are dashed; edges an action
// narrowed are drawn heavier.

import { svg, node, title, entityKey, short } from '../svg.js';

function eventEdges(p) {
  const out = [];
  const ip = p?.src_endpoint?.ip;
  const user = p?.actor?.user?.uid;
  const target = p?.ivar?.target_entity;
  const dst = p?.dst_endpoint?.ip || p?.dst_endpoint?.svc_name;
  if (ip && user) out.push([`ip:${ip}`, `${p.actor.user.type === 'service' ? 'service' : 'user'}:${user}`]);
  const from = user ? `${p.actor.user.type === 'service' ? 'service' : 'user'}:${user}` : ip ? `ip:${ip}` : null;
  if (from && target) out.push([from, target]);
  if (from && dst) out.push([from, `endpoint:${dst}`]);
  return out;
}

export function buildGraph(frames, upto) {
  const nodes = new Set();
  const edges = new Map();
  const add = (a, b, flag) => {
    if (!a || !b || a === b) return;
    nodes.add(a);
    nodes.add(b);
    const k = `${a}>${b}`;
    const e = edges.get(k) ?? { a, b, undeclared: false, narrowed: false };
    if (flag) e[flag] = true;
    edges.set(k, e);
  };
  for (const f of frames.slice(0, upto + 1)) {
    if (f.kind === 'event') for (const [a, b] of eventEdges(f.payload)) add(a, b);
    if (f.kind === 'finding') {
      const ents = (f.payload?.entities ?? []).map(entityKey);
      for (let i = 1; i < ents.length; i++) add(ents[0], ents[i], f.payload.rule === 'undeclared_edge' ? 'undeclared' : undefined);
    }
    if (f.kind === 'edge_change') add(f.payload?.from, f.payload?.to, f.payload?.change === 'narrowed' ? 'narrowed' : undefined);
    if (f.kind === 'action_request' && /^trust_edge\./.test(f.payload?.request?.action ?? '')) {
      const t = entityKey(f.payload.request.target);
      for (const e of edges.values()) if (e.a === t || e.b === t) e.narrowed = true;
    }
  }
  return { nodes: [...nodes], edges: [...edges.values()] };
}

export function renderTrust(el, bundle, index) {
  const g = buildGraph(bundle.frames, index);
  if (!g.nodes.length) {
    el.innerHTML = '<div class="empty">No trust edges observed yet.</div>';
    return;
  }
  const W = 480, H = 320, cx = W / 2, cy = H / 2, r = Math.min(W, H) / 2 - 44;
  const pos = new Map(g.nodes.map((n, i) => {
    const a = (2 * Math.PI * i) / g.nodes.length - Math.PI / 2;
    return [n, [cx + r * Math.cos(a), cy + r * Math.sin(a)]];
  }));
  const s = svg(W, H);
  for (const e of g.edges) {
    const [x1, y1] = pos.get(e.a);
    const [x2, y2] = pos.get(e.b);
    title(node(s, 'line', { x1, y1, x2, y2, class: `edge${e.undeclared ? ' undeclared' : ''}${e.narrowed ? ' narrowed' : ''}` }), `${e.a} to ${e.b}${e.undeclared ? ' (undeclared)' : ''}${e.narrowed ? ' (narrowed)' : ''}`);
  }
  for (const n of g.nodes) {
    const [x, y] = pos.get(n);
    const type = n.split(':')[0];
    title(node(s, 'circle', { cx: x, cy: y, r: 8, class: `ent ent-${['ip', 'user', 'service'].includes(type) ? type : 'endpoint'}` }), n);
    node(s, 'text', { x, y: y + (y < cy ? -14 : 22), 'text-anchor': 'middle', class: 'mono' }, short(n.split(':').slice(1).join(':'), 16));
  }
  el.replaceChildren(s);
  const legend = document.createElement('div');
  legend.className = 'legend';
  legend.innerHTML = '<span><i class="ent-ip" style="background: var(--ent-ip)"></i>ip</span><span><i style="background: var(--ent-user)"></i>user</span><span><i style="background: var(--ent-service)"></i>service</span><span><i style="background: var(--ent-endpoint)"></i>endpoint</span><span class="sep"></span><span><i style="background: var(--contain)"></i>dashed: undeclared edge</span><span><i style="background: var(--throttle)"></i>heavy: narrowed by a response</span>';
  el.appendChild(legend);
}
