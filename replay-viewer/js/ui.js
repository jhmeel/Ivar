// Small shared pieces for the dashboard views. Every value that came from a
// bundle or a live core is untrusted data and goes through esc() before it
// reaches innerHTML.

import { esc } from './svg.js';
import { formatElapsed } from './player.js';

export { esc, formatElapsed };

const KIND_LABEL = { event: 'event', finding: 'finding', risk: 'risk', verdict: 'verdict', action_request: 'action', action_receipt: 'receipt', gap: 'unobserved', policy: 'policy', edge_change: 'trust edge' };
const KIND_COLOR = { event: 'event', finding: 'finding', risk: 'risk', verdict: 'accent', action_request: 'action', action_receipt: 'action', gap: 'gap', policy: 'accent', edge_change: 'throttle' };

export function kindLabel(kind) {
  return KIND_LABEL[kind] ?? kind;
}

export function kindBadge(kind) {
  return `<span class="badge"><i style="background:var(--${KIND_COLOR[kind] ?? 'muted'})"></i>${esc(kindLabel(kind))}</span>`;
}

export function outcomeBadge(row) {
  if (row.kind !== 'verdict') {
    if (row.kind === 'action_receipt') return `<span class="badge"><i style="background:var(--action)"></i>${esc(row.outcome)}</span>`;
    return '<span class="muted">·</span>';
  }
  return `<span class="badge"><i style="background:var(--${esc(row.outcome)})"></i>${esc(row.outcome)}</span>`;
}

export function utc(ms, withDate = false) {
  const d = new Date(ms);
  if (Number.isNaN(d.getTime())) return String(ms);
  const iso = d.toISOString();
  return withDate ? iso.replace('T', ' ').replace('Z', ' UTC') : iso.slice(11, 23);
}

export function shortId(s, n = 18) {
  const v = String(s ?? '');
  return v.length > n ? `${v.slice(0, n)}…` : v;
}

const ENT_COLOR = { ip: 'ent-ip', user: 'ent-user', service: 'ent-service', session: 'ent-session', host: 'ent-endpoint' };

export function entityChip(key, { button = true, on = false, count } = {}) {
  const type = key.split(':')[0];
  const dot = `<i class="dot" style="background:var(--${ENT_COLOR[type] ?? 'ent-endpoint'})"></i>`;
  const tag = button ? 'button' : 'span';
  const n = count !== undefined ? ` <span class="muted">×${esc(count)}</span>` : '';
  return `<${tag} class="chip${on ? ' on' : ''}" ${button ? `type="button" data-entity="${esc(key)}"` : ''} title="${esc(key)}">${dot}${esc(shortId(key, 34))}${n}</${tag}>`;
}

export function riskBar(v) {
  if (v === undefined || v === null || Number.isNaN(v)) return '<span class="muted">·</span>';
  return `<div class="bar-cell"><div class="track"><div class="fill${v >= 0.85 ? ' hot' : ''}" style="width:${Math.round(v * 100)}%"></div></div><span class="mono">${v.toFixed(2)}</span></div>`;
}

/** Pretty printed, syntax coloured, escaped JSON. */
export function jsonHtml(value) {
  const text = JSON.stringify(value, null, 2) ?? 'null';
  return esc(text).replace(/(&quot;(?:[^&]|&(?!quot;))*?&quot;)(\s*:)?|\b(-?\d+(?:\.\d+)?(?:e[+-]?\d+)?)\b|\b(true|false|null)\b/g, (m, str, colon, num, lit) => {
    if (str) return colon ? `<span class="k">${str}</span>${colon}` : `<span class="s">${str}</span>`;
    if (num) return `<span class="n">${num}</span>`;
    return `<span class="n">${lit}</span>`;
  });
}

export function download(name, type, data) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([data], { type }));
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 10_000);
}

export async function copy(text, button) {
  try {
    await navigator.clipboard.writeText(text);
    if (button) {
      const was = button.textContent;
      button.textContent = 'Copied';
      setTimeout(() => (button.textContent = was), 1200);
    }
  } catch {
    if (button) button.textContent = 'Copy blocked';
  }
}
