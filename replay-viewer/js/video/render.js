// Draws one video frame of a verified replay onto a 2D canvas.
//
// The video follows the replay fidelity rules (section 13.2): frames appear
// at their real elapsed time scaled by one playback speed, unobserved
// intervals are drawn as gaps, and the real elapsed clock is always on
// screen. Nothing is shown that the bundle does not contain.

import { outcomeOf, entityKey } from '../svg.js';
import { formatElapsed } from '../player.js';

export const WIDTH = 1280;
export const HEIGHT = 720;

const C = {
  bg: '#0a0d11', panel: '#12171d', panel2: '#171d24', line: '#222a33', lineStrong: '#2f3944',
  ink: '#e6edf3', ink2: '#b9c4cf', muted: '#7d8a98', accent: '#38bdf8', verified: '#2dd4bf',
  record: '#6b7785', throttle: '#f59e0b', challenge: '#a78bfa', block: '#fb923c', contain: '#f43f5e', refuse: '#e11d48',
  gap: '#3a4450', fast: '#38bdf8', slow: '#2dd4bf', band: 'rgba(244,63,94,0.12)',
};
const SANS = 'Inter, "Segoe UI", Roboto, system-ui, sans-serif';
const MONO = '"JetBrains Mono", "SF Mono", Menlo, Consolas, monospace';
const LANES = [['event', 'Events'], ['finding', 'Findings'], ['risk', 'Risk'], ['verdict', 'Verdicts'], ['action_request', 'Actions'], ['gap', 'Unobserved']];
const DECISIONS = ['record', 'throttle', 'challenge', 'block', 'contain', 'refuse'];

function colorFor(frame) {
  const o = outcomeOf(frame);
  if (C[o]) return C[o];
  if (frame.kind === 'finding') return C.challenge;
  if (frame.kind === 'risk') return C.fast;
  if (frame.kind === 'gap') return C.gap;
  if (frame.kind.startsWith('action')) return C.contain;
  return C.record;
}

function roundRect(g, x, y, w, h, r, fill, stroke) {
  g.beginPath();
  g.roundRect(x, y, w, h, r);
  if (fill) {
    g.fillStyle = fill;
    g.fill();
  }
  if (stroke) {
    g.strokeStyle = stroke;
    g.lineWidth = 1;
    g.stroke();
  }
}

function text(g, s, x, y, { size = 14, color = C.ink, font = SANS, weight = 400, align = 'left', max } = {}) {
  g.font = `${weight} ${size}px ${font}`;
  g.fillStyle = color;
  g.textAlign = align;
  g.textBaseline = 'alphabetic';
  let out = String(s ?? '');
  if (max && g.measureText(out).width > max) {
    while (out.length > 1 && g.measureText(out + '…').width > max) out = out.slice(0, -1);
    out += '…';
  }
  g.fillText(out, x, y);
}

function wrap(g, s, x, y, maxWidth, lineHeight, maxLines, opts) {
  g.font = `${opts.weight ?? 400} ${opts.size ?? 14}px ${opts.font ?? SANS}`;
  const words = String(s ?? '').split(/\s+/);
  let line = '';
  let lines = 0;
  for (const w of words) {
    const test = line ? `${line} ${w}` : w;
    if (g.measureText(test).width > maxWidth && line) {
      if (lines === maxLines - 1) {
        text(g, `${line}…`, x, y + lines * lineHeight, opts);
        return;
      }
      text(g, line, x, y + lines * lineHeight, opts);
      lines += 1;
      line = w;
    } else line = test;
  }
  if (line) text(g, line, x, y + lines * lineHeight, opts);
}

function panel(g, x, y, w, h, title, note) {
  roundRect(g, x, y, w, h, 10, C.panel, C.line);
  text(g, title.toUpperCase(), x + 16, y + 26, { size: 12, color: C.ink2, weight: 600 });
  if (note) text(g, note, x + w - 16, y + 26, { size: 12, color: C.muted, align: 'right' });
}

function shield(g, x, y, s) {
  g.save();
  g.translate(x, y);
  g.scale(s / 32, s / 32);
  g.strokeStyle = C.accent;
  g.lineWidth = 2.2;
  g.lineJoin = 'round';
  g.lineCap = 'round';
  g.beginPath();
  g.moveTo(16, 2); g.lineTo(4, 7); g.lineTo(4, 15);
  g.bezierCurveTo(4, 22.2, 9.1, 28.4, 16, 30);
  g.bezierCurveTo(22.9, 28.4, 28, 22.2, 28, 15);
  g.lineTo(28, 7); g.closePath();
  g.stroke();
  g.beginPath();
  g.moveTo(10, 16); g.lineTo(14, 16); g.lineTo(16, 11); g.lineTo(19, 21); g.lineTo(21, 16); g.lineTo(23, 16);
  g.stroke();
  g.restore();
}

/** Precomputed facts the renderer needs, so each video frame is cheap. */
export function prepare(bundle) {
  const frames = bundle.frames;
  const span = Math.max(1, frames[frames.length - 1].elapsed_ms);
  const lanes = LANES.filter(([k]) => frames.some((f) => f.kind === k || (k === 'action_request' && f.kind === 'action_receipt')));
  const layers = new Map();
  for (const f of frames) {
    if (f.kind !== 'event') continue;
    const layer = f.payload?.ivar?.sensor_type || 'unknown';
    if (!layers.has(layer)) layers.set(layer, new Set());
    layers.get(layer).add(f.sensor_id);
  }
  const unobserved = bundle.unobserved_layers ?? [];
  const policies = [bundle.policy_version, ...(bundle.policy_history ?? []).map((p) => p.policy_version)].filter(Boolean);
  return { frames, span, lanes, layers, unobserved, policies, verified: bundle._verified ?? bundle.re_execution };
}

/** The index of the last frame at or before `ms` of real elapsed time. */
export function frameAt(frames, ms) {
  let lo = 0;
  let hi = frames.length - 1;
  if (frames[0].elapsed_ms > ms) return -1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (frames[mid].elapsed_ms <= ms) lo = mid;
    else hi = mid - 1;
  }
  return lo;
}

function header(g, bundle, P) {
  g.fillStyle = C.bg;
  g.fillRect(0, 0, WIDTH, HEIGHT);
  shield(g, 24, 18, 30);
  text(g, 'IVAR', 64, 36, { size: 18, weight: 700 });
  text(g, 'Incident replay', 64, 52, { size: 12, color: C.muted });
  text(g, bundle.incident_id, 200, 36, { size: 16, weight: 600, font: MONO, max: 420 });
  text(g, `policy ${P.policies.join(' → ')}`, 200, 54, { size: 12, color: C.muted, font: MONO, max: 420 });
  const v = P.verified;
  roundRect(g, 760, 14, 496, 46, 10, 'rgba(45,212,191,0.08)', 'rgba(45,212,191,0.45)');
  g.beginPath();
  g.arc(784, 37, 11, 0, Math.PI * 2);
  g.strokeStyle = C.verified;
  g.lineWidth = 2;
  g.stroke();
  g.beginPath();
  g.moveTo(779, 37); g.lineTo(783, 41); g.lineTo(790, 33);
  g.stroke();
  text(g, 'Verified replay', 806, 33, { size: 14, weight: 600, color: C.verified });
  const signedBy = bundle.signature?.key_id ? `signed by ${bundle.signature.key_id}` : 'unsigned';
  text(g, `${v?.recorded_verdicts ?? '?'} of ${v?.recorded_verdicts ?? '?'} verdicts reproduced · ${signedBy} · chain ${String(bundle.evidence_chain_head).slice(0, 10)}…`, 806, 51, { size: 11, color: C.ink2, max: 440 });
}

function timeline(g, P, t, idx) {
  const x = 24, y = 76, w = 1232, h = 214;
  panel(g, x, y, w, h, 'Timeline', 'corrected clock, skew shown');
  const left = x + 110, right = x + w - 20, top = y + 44, laneH = Math.min(26, (h - 70) / P.lanes.length);
  const px = (ms) => left + (ms / P.span) * (right - left);
  P.lanes.forEach(([k, label], i) => {
    const ly = top + i * laneH + laneH / 2;
    text(g, label, x + 16, ly + 4, { size: 12, color: C.muted });
    g.strokeStyle = C.line;
    g.lineWidth = 1;
    g.beginPath();
    g.moveTo(left, ly); g.lineTo(right, ly);
    g.stroke();
  });
  for (let i = 0; i <= idx; i++) {
    const f = P.frames[i];
    const kind = f.kind === 'action_receipt' ? 'action_request' : f.kind;
    const lane = P.lanes.findIndex(([k]) => k === kind);
    if (lane < 0) continue;
    const ly = top + lane * laneH + laneH / 2;
    const cx = px(f.elapsed_ms);
    g.fillStyle = colorFor(f);
    if (f.kind === 'gap') g.fillRect(cx - 2, ly - 7, 4, 14);
    else {
      g.beginPath();
      g.arc(cx, ly, i === idx ? 7 : 4.5, 0, Math.PI * 2);
      g.fill();
      if (i === idx) {
        g.strokeStyle = C.ink;
        g.lineWidth = 2;
        g.stroke();
      }
    }
  }
  const head = px(Math.min(t, P.span));
  g.strokeStyle = C.accent;
  g.lineWidth = 1.5;
  g.beginPath();
  g.moveTo(head, top - 6); g.lineTo(head, top + P.lanes.length * laneH + 2);
  g.stroke();
  text(g, '+0 ms', left, y + h - 12, { size: 11, color: C.muted, font: MONO });
  text(g, `+${P.span} ms`, right, y + h - 12, { size: 11, color: C.muted, font: MONO, align: 'right' });
  let lx = left + 120;
  for (const d of DECISIONS) {
    g.fillStyle = C[d];
    g.beginPath();
    g.arc(lx, y + h - 16, 4.5, 0, Math.PI * 2);
    g.fill();
    text(g, d, lx + 9, y + h - 12, { size: 11, color: C.muted });
    lx += 82;
  }
  if (P.unobserved.length) text(g, `no sensor on: ${P.unobserved.join(', ')}`, lx + 8, y + h - 12, { size: 11, color: C.muted, max: right - lx - 140 });
}

function utc(ms) {
  const d = new Date(ms);
  return Number.isNaN(d.getTime()) ? String(ms) : d.toISOString().replace('T', ' ').replace('Z', '');
}

function describe(f) {
  const p = f.payload ?? {};
  switch (f.kind) {
    case 'event': {
      const h = p.http_request;
      const what = h ? `${h.http_method} ${h.url_path}` : p.activity_name;
      const who = p.src_endpoint?.ip || p.actor?.user?.uid || '';
      return { title: what, entity: who, detail: [p.activity_name, h?.body_keys?.length ? `fields: ${h.body_keys.join(', ')}` : '', p.status].filter(Boolean).join(' · ') };
    }
    case 'finding':
      return { title: `${p.rule}`, entity: (p.entities ?? []).map(entityKey).slice(0, 2).join(', '), detail: `${p.rule_family} · ${p.technique} · confidence ${p.confidence}` };
    case 'risk':
      return { title: `risk ${Number(p.score).toFixed(2)}`, entity: entityKey(p.entity), detail: `fast ${Number(p.fast_score).toFixed(2)} · slow ${Number(p.slow_score).toFixed(2)} · ${p.independent_sources} independent sources` };
    case 'verdict':
      return { title: `${p.decision}`, entity: entityKey(p.entity), detail: (p.reasons ?? []).join('; ') };
    case 'action_request': {
      const r = p.request ?? {};
      return { title: r.action || 'action', entity: entityKey(r.target), detail: `ladder level ${r.ladder_level} · ${r.confidence_class ?? ''} · review ${p.review ?? ''} · undo with ${r.reversal_method ?? ''}` };
    }
    case 'action_receipt':
      return { title: `receipt: ${p.result}`, entity: p.action_request_id, detail: `${p.verification ?? ''} · ${p.reversal_status ?? ''} · ${p.time_taken_ms ?? 0} ms` };
    case 'policy':
      return { title: `policy ${p.policy_version} applied`, entity: `version ${p.version}`, detail: p.changed_rules?.length ? `changed rules: ${p.changed_rules.join(', ')}` : 'no rule content changed' };
    case 'gap':
      return { title: 'unobserved interval', entity: f.sensor_id, detail: p.unobserved };
    default:
      return { title: f.kind, entity: '', detail: '' };
  }
}

function now(g, P, idx) {
  const x = 24, y = 302, w = 600, h = 250;
  panel(g, x, y, w, h, 'Now', idx >= 0 ? `frame ${idx + 1} of ${P.frames.length}` : 'waiting for the first frame');
  if (idx < 0) return;
  const f = P.frames[idx];
  const d = describe(f);
  const c = colorFor(f);
  const badge = outcomeOf(f).replace('_', ' ').toUpperCase();
  g.font = `700 12px ${SANS}`;
  const bw = g.measureText(badge).width + 20;
  roundRect(g, x + 16, y + 44, bw, 24, 12, c);
  text(g, badge, x + 26, y + 61, { size: 12, weight: 700, color: '#071017' });
  text(g, d.title, x + 26 + bw, y + 62, { size: 18, weight: 600, max: w - bw - 50 });
  const rows = [
    ['Entity', d.entity || '—'],
    ['Sensor', `${f.sensor_id} · seq ${f.sensor_seq}`],
    ['Clock', `${utc(f.time)} UTC · skew ${f.clock_skew_ms} ms`],
    ['Evidence', f.evidence_ids?.[0] ?? 'none: unobserved interval'],
  ];
  rows.forEach(([k, v], i) => {
    text(g, k, x + 16, y + 100 + i * 24, { size: 12, color: C.muted });
    text(g, v, x + 110, y + 100 + i * 24, { size: 13, font: MONO, color: C.ink2, max: w - 130 });
  });
  roundRect(g, x + 16, y + 192, w - 32, 44, 8, C.bg, C.line);
  wrap(g, d.detail || '—', x + 28, y + 210, w - 56, 17, 2, { size: 12, color: C.ink2 });
}

function riskChart(g, P, idx) {
  const x = 636, y = 302, w = 620, h = 250;
  let focus = '';
  for (let i = idx; i >= 0; i--) {
    if (P.frames[i].kind === 'risk') {
      focus = entityKey(P.frames[i].payload.entity);
      break;
    }
  }
  panel(g, x, y, w, h, 'Risk', focus ? focus : 'two timescales, policy bands');
  const left = x + 52, right = x + w - 18, top = y + 44, bottom = y + h - 34;
  const py = (v) => top + (1 - v) * (bottom - top);
  const px = (ms) => left + (ms / P.span) * (right - left);
  g.fillStyle = C.band;
  g.fillRect(left, py(1), right - left, py(0.85) - py(1));
  for (const b of [0.3, 0.6, 0.85]) {
    g.strokeStyle = C.lineStrong;
    g.setLineDash([3, 4]);
    g.beginPath();
    g.moveTo(left, py(b)); g.lineTo(right, py(b));
    g.stroke();
    g.setLineDash([]);
    text(g, b.toFixed(2), x + 14, py(b) + 4, { size: 11, color: C.muted, font: MONO });
  }
  text(g, 'contain', right - 4, py(1) + 14, { size: 11, color: C.muted, align: 'right' });
  if (!focus) return;
  const pts = [];
  for (let i = 0; i <= idx; i++) {
    const f = P.frames[i];
    if (f.kind === 'risk' && entityKey(f.payload.entity) === focus) pts.push(f);
  }
  for (const [key, color, dash] of [['slow_score', C.slow, [6, 4]], ['fast_score', C.fast, []]]) {
    g.strokeStyle = color;
    g.lineWidth = 2.2;
    g.setLineDash(dash);
    g.beginPath();
    pts.forEach((f, i) => (i ? g.lineTo(px(f.elapsed_ms), py(f.payload[key])) : g.moveTo(px(f.elapsed_ms), py(f.payload[key]))));
    g.stroke();
    g.setLineDash([]);
  }
  const last = pts[pts.length - 1]?.payload;
  if (last) {
    g.fillStyle = C.fast;
    g.beginPath();
    g.arc(px(pts[pts.length - 1].elapsed_ms), py(last.score), 4, 0, Math.PI * 2);
    g.fill();
    text(g, `${Number(last.score).toFixed(2)} · ${last.independent_sources} sources`, left, y + h - 12, { size: 12, color: last.score >= 0.85 ? C.throttle : C.ink2, font: MONO });
  }
  text(g, 'fast 30 min', right - 150, y + h - 12, { size: 11, color: C.fast });
  text(g, 'slow 7 d', right - 60, y + h - 12, { size: 11, color: C.slow });
}

function estate(g, P, idx) {
  const x = 24, y = 564, w = 600, h = 108;
  panel(g, x, y, w, h, 'Estate', 'sensors by layer');
  const current = idx >= 0 ? P.frames[idx].sensor_id : '';
  let cx = x + 16;
  const cy = y + 46;
  for (const [layer, sensors] of P.layers) {
    for (const id of sensors) {
      const label = `${layer.replace('_', ' ')} · ${id}`;
      g.font = `500 12px ${MONO}`;
      const bw = Math.min(260, g.measureText(label).width + 22);
      if (cx + bw > x + w - 12) break;
      roundRect(g, cx, cy, bw, 26, 7, id === current ? 'rgba(56,189,248,0.22)' : C.panel2, id === current ? C.accent : C.lineStrong);
      text(g, label, cx + 11, cy + 17, { size: 12, font: MONO, color: id === current ? C.ink : C.ink2, max: bw - 18 });
      cx += bw + 8;
    }
  }
  if (P.unobserved.length) text(g, `unobserved on this tier: ${P.unobserved.join(', ')}`, x + 16, y + h - 14, { size: 12, color: C.muted, max: w - 32 });
}

function counters(g, P, idx) {
  const x = 636, y = 564, w = 620, h = 108;
  panel(g, x, y, w, h, 'So far');
  const n = { event: 0, finding: 0, action_request: 0, gap: 0 };
  const decisions = {};
  for (let i = 0; i <= idx; i++) {
    const f = P.frames[i];
    if (f.kind in n) n[f.kind] += 1;
    if (f.kind === 'verdict') decisions[f.payload.decision] = (decisions[f.payload.decision] ?? 0) + 1;
  }
  const items = [['events', n.event, C.ink], ['findings', n.finding, C.challenge], ['actions', n.action_request, C.contain], ['unobserved', n.gap, C.muted]];
  items.forEach(([label, v, color], i) => {
    text(g, String(v), x + 20 + i * 100, y + 66, { size: 26, weight: 700, color, font: MONO });
    text(g, label, x + 20 + i * 100, y + 88, { size: 12, color: C.muted });
  });
  let dx = x + 420;
  let row = 0;
  for (const d of DECISIONS) {
    if (!decisions[d]) continue;
    g.fillStyle = C[d];
    g.beginPath();
    g.arc(dx, y + 52 + row * 22, 5, 0, Math.PI * 2);
    g.fill();
    text(g, `${d} ${decisions[d]}`, dx + 10, y + 56 + row * 22, { size: 12, color: C.ink2, font: MONO });
    row += 1;
    if (row === 3) {
      row = 0;
      dx += 96;
    }
  }
}

function footer(g, P, t, speed) {
  const y = HEIGHT - 36;
  g.fillStyle = C.bg;
  g.fillRect(0, y, WIDTH, 36);
  text(g, `real elapsed ${formatElapsed(Math.round(Math.min(t, P.span)))}`, 24, y + 24, { size: 14, font: MONO, color: C.ink });
  text(g, `playback ×${speed}`, 300, y + 24, { size: 13, font: MONO, color: C.muted });
  const bx = 440, bw = 816;
  roundRect(g, bx, y + 14, bw, 8, 4, C.panel2);
  roundRect(g, bx, y + 14, Math.max(8, (Math.min(t, P.span) / P.span) * bw), 8, 4, C.accent);
}

/** Opening card: what this replay is and how it was verified. */
export function drawTitle(g, bundle, P) {
  header(g, bundle, P);
  const v = P.verified;
  text(g, 'Incident replay', WIDTH / 2, 250, { size: 40, weight: 700, align: 'center' });
  text(g, bundle.incident_id, WIDTH / 2, 296, { size: 20, font: MONO, color: C.accent, align: 'center' });
  const lines = [
    `${P.frames.length} frames over ${formatElapsed(P.span)} of real time`,
    `re executed in the same engine: ${v?.recorded_verdicts} of ${v?.recorded_verdicts} live verdicts reproduced`,
    `evidence chain head ${bundle.evidence_chain_head}`,
    bundle.counterfactual ? `COUNTERFACTUAL under policy ${bundle.counterfactual_policy}: nothing here happened live` : `policy ${P.policies.join(' → ')}`,
  ];
  lines.forEach((l, i) => text(g, l, WIDTH / 2, 360 + i * 30, { size: 16, color: i === 3 && bundle.counterfactual ? C.throttle : C.ink2, align: 'center', font: i === 2 ? MONO : SANS }));
}

/** One frame of the replay at real elapsed time `t` (ms). */
export function drawFrame(g, bundle, P, t, speed) {
  const idx = frameAt(P.frames, t);
  header(g, bundle, P);
  timeline(g, P, t, idx);
  now(g, P, idx);
  riskChart(g, P, idx);
  estate(g, P, idx);
  counters(g, P, idx);
  footer(g, P, t, speed);
  if (bundle.counterfactual) {
    roundRect(g, 470, 82, 340, 26, 13, 'rgba(245,158,11,0.18)', C.throttle);
    text(g, `COUNTERFACTUAL · policy ${bundle.counterfactual_policy}`, 640, 100, { size: 12, weight: 700, color: C.throttle, align: 'center' });
  }
}

/** Closing card: the outcome in numbers. */
export function drawSummary(g, bundle, P) {
  drawFrame(g, bundle, P, P.span, 1);
  g.fillStyle = 'rgba(10,13,17,0.86)';
  g.fillRect(0, 70, WIDTH, HEIGHT - 70);
  const decisions = {};
  let findings = 0;
  for (const f of P.frames) {
    if (f.kind === 'verdict') decisions[f.payload.decision] = (decisions[f.payload.decision] ?? 0) + 1;
    if (f.kind === 'finding') findings += 1;
  }
  text(g, 'Outcome', WIDTH / 2, 230, { size: 34, weight: 700, align: 'center' });
  const parts = DECISIONS.filter((d) => decisions[d]).map((d) => `${d} ${decisions[d]}`);
  text(g, parts.join('   ·   '), WIDTH / 2, 290, { size: 18, font: MONO, color: C.ink2, align: 'center' });
  text(g, `${findings} findings · ${P.frames.filter((f) => f.kind === 'action_request').length} actions · ${P.frames.filter((f) => f.kind === 'gap').length} unobserved intervals`, WIDTH / 2, 330, { size: 16, color: C.muted, align: 'center' });
  text(g, 'Every frame cites sealed evidence. Re verify the signed bundle in the replay viewer.', WIDTH / 2, 400, { size: 15, color: C.verified, align: 'center' });
}
