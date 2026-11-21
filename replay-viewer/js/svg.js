// Small helpers for building SVG and escaped HTML without a framework.

const NS = 'http://www.w3.org/2000/svg';

export function svg(width, height) {
  const el = document.createElementNS(NS, 'svg');
  el.setAttribute('viewBox', `0 0 ${width} ${height}`);
  el.setAttribute('role', 'img');
  return el;
}

export function node(parent, tag, attrs = {}, text) {
  const el = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) if (v !== undefined && v !== null) el.setAttribute(k, String(v));
  if (text !== undefined) el.textContent = text;
  parent.appendChild(el);
  return el;
}

export function title(el, text) {
  node(el, 'title', {}, text);
  return el;
}

export function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

export function short(id, n = 14) {
  const s = String(id ?? '');
  return s.length > n ? `${s.slice(0, n)}…` : s;
}

/** Outcome class for a frame marker. */
export function outcomeOf(frame) {
  if (frame.kind === 'verdict') return frame.payload?.decision ?? 'record';
  return frame.kind;
}

export function entityKey(e) {
  return e ? `${e.type}:${e.id}` : '';
}
