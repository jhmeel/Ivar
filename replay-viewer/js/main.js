// IVAR console entry point: load and verify a replay (or follow a live
// core), build the model once, and route between the views. Playback moves
// one cursor that every view, the event stream and the detail drawer share.

import { verifyBundle, evidenceIndex, VerificationError } from './bundle.js';
import { Player, formatElapsed } from './player.js';
import { buildModel, toCsv } from './model.js';
import { esc, shortId, download } from './ui.js';
import { renderOverview } from './views/overview.js';
import { EventsView } from './views/events.js';
import { Detail } from './views/detail.js';
import { SessionsView } from './views/sessions.js';
import { EntitiesView } from './views/entities.js';
import { renderGraph } from './views/graph.js';
import { LiveSource } from './live.js';
import { exportMp4, defaultSpeed } from './video/encode.js';
import { Theater } from './theater.js';

const $ = (id) => document.getElementById(id);
const VIEWS = ['overview', 'events', 'sessions', 'entities', 'graph'];

const state = {
  live: null,
  counterfactual: null,
  stream: null,
  mode: 'live',
  source: 'replay',
  model: null,
  evidence: new Map(),
  keyring: '',
  texts: [],
  view: 'overview',
  follow: false,
  liveSource: null,
};

// The context every view receives.
const ctx = {
  get model() {
    // The overview answers "as of the playhead" from the frames up to it;
    // the other views filter by the cursor themselves.
    if (state.follow && state.view === 'overview' && state.model && player.frames.length) return modelUpTo(player.index);
    return state.model;
  },
  get evidence() {
    return state.evidence;
  },
  get cursor() {
    return player.frames.length ? player.index : -1;
  },
  get cursorMs() {
    return player.frames.length ? player.frames[player.index]?.elapsed_ms : undefined;
  },
  get follow() {
    return state.follow;
  },
  get live() {
    return state.source === 'live';
  },
  filtered: [],
  open: (i) => detail.show(i),
  go: (route) => (location.hash = `#/${route}`),
  seek: (i, openDetail) => {
    player.step(i - player.index);
    if (openDetail) detail.show(i);
  },
  neighbour: (i, delta) => {
    if (state.view === 'events') return events.neighbour(i, delta);
    const n = i + delta;
    return n >= 0 && n < (state.model?.rows.length ?? 0) ? n : -1;
  },
};

let prefix = { index: -1, model: null };
function modelUpTo(index) {
  if (prefix.index !== index || prefix.source !== state.model) {
    const b = state.model.bundle;
    prefix = { index, source: state.model, model: buildModel({ ...b, frames: b.frames.slice(0, index + 1) }) };
  }
  return prefix.model;
}

const views = {};
const events = new EventsView(document.querySelector('.view[data-view=events]'), ctx);
const sessions = new SessionsView(document.querySelector('.view[data-view=sessions]'), ctx);
const entities = new EntitiesView(document.querySelector('.view[data-view=entities]'), ctx);
const detail = new Detail(ctx);
views.overview = (el) => renderOverview(el, ctx);
views.events = () => events.render();
views.sessions = () => sessions.render();
views.entities = () => entities.render();
views.graph = (el) => renderGraph(el, ctx);

// Verification seal: idle, busy, ok, live or error.
function seal(kind, title, checks = '', meta = {}) {
  $('seal').className = `seal ${kind}`;
  $('status').textContent = title;
  $('seal-checks').innerHTML = checks;
  $('seal-meta').innerHTML = Object.entries(meta).map(([k, v]) => `<dt>${esc(k)}</dt><dd title="${esc(v)}">${esc(shortId(v, 20))}</dd>`).join('');
}

function current() {
  if (state.source === 'live') return state.stream;
  return state.mode === 'counterfactual' && state.counterfactual ? state.counterfactual : state.live ?? state.counterfactual;
}

// Routing: #/view?filters
function parseRoute() {
  const [path, query] = location.hash.replace(/^#\/?/, '').split('?');
  const view = VIEWS.includes(path) ? path : 'overview';
  return { view, params: new URLSearchParams(query ?? '') };
}

function route() {
  if (!state.model) return;
  const { view, params } = parseRoute();
  state.view = view;
  if (view === 'events') events.setQuery(params);
  if (view === 'sessions') sessions.setQuery(params);
  if (view === 'entities') entities.setQuery(params);
  document.querySelectorAll('.sidebar a').forEach((a) => a.classList.toggle('on', a.dataset.view === view));
  document.querySelectorAll('.view').forEach((s) => (s.hidden = s.dataset.view !== view));
  renderView();
  if (params.get('frame')) detail.show(Number(params.get('frame')) - 1);
}

const TITLES = {
  overview: ['Overview', 'The incident at a glance: what happened, to whom, and what the system did about it.'],
  events: ['Events', 'Every frame, searchable. Select one to see what was sent, what it caused and the sealed evidence.'],
  sessions: ['Sessions', 'What each session sent and received, with the IVAR decisions in line.'],
  entities: ['Entities', 'Every address, identity, session and service the incident touched, ranked by risk.'],
  graph: ['Graph', 'Trust edges, the estate, pipeline latency and the timeline at the playhead.'],
};

function renderView() {
  const el = document.querySelector(`.view[data-view=${state.view}]`);
  views[state.view](el);
  const [title, sub] = TITLES[state.view];
  document.querySelector('#view-title h1').textContent = title;
  document.querySelector('#view-title p').textContent = sub;
}

// Playback: the cursor moves; views follow when "As of playhead" is on.
function onFrame(index) {
  const b = current();
  if (!b || !b.frames.length) return;
  $('clock-frame').textContent = `${index + 1} / ${b.frames.length}`;
  $('clock-elapsed').textContent = formatElapsed(b.frames[index].elapsed_ms);
  $('scrub').max = String(b.frames.length - 1);
  $('scrub').value = String(index);
  $('play').classList.toggle('playing', player.playing);
  $('play').setAttribute('aria-label', player.playing ? 'Pause' : 'Play');
  if (state.view === 'events') {
    if (state.follow) events.refilter();
    events.follow(index);
  } else if (state.view === 'graph' || state.follow) renderView();
  if (detail.isOpen && player.playing) detail.show(index);
}

const player = new Player(onFrame);

function setModel(bundle) {
  state.model = buildModel(bundle);
  state.evidence = evidenceIndex(bundle);
  $('nav-events-count').textContent = state.model.totals.frames;
  $('nav-sessions-count').textContent = state.model.totals.sessions;
  $('nav-entities-count').textContent = state.model.entities.length;
  ['export-csv', 'export-json'].forEach((id) => ($(id).disabled = false));
  $('export-mp4').disabled = state.source === 'live';
}

async function verifyAll() {
  state.live = state.counterfactual = null;
  if (!state.texts.length) return;
  $('app').hidden = true;
  seal('busy', 'Verifying…', 'Checking the bundle signature and evidence chain, then re executing every event in this browser.');
  try {
    for (const text of state.texts) {
      const { bundle, reExecution, engine } = await verifyBundle(text, state.keyring, $('redaction-key').value);
      bundle._verified = { ...reExecution, engine };
      if (bundle.counterfactual) state.counterfactual = bundle;
      else state.live = bundle;
    }
  } catch (e) {
    seal('error', 'Not rendered: this replay could not be verified', esc(e instanceof VerificationError ? e.message : String(e)));
    return;
  }
  const b = state.live ?? state.counterfactual;
  const cfInput = document.querySelector('input[name=mode][value=counterfactual]');
  const liveInput = document.querySelector('input[name=mode][value=live]');
  cfInput.disabled = !state.counterfactual;
  liveInput.disabled = !state.live;
  state.mode = state.live ? 'live' : 'counterfactual';
  (state.live ? liveInput : cfInput).checked = true;
  const v = b._verified;
  seal('ok', 'Verified replay', [state.keyring ? '<span class="chk">Signature</span>' : '<span class="skip">Signature not checked (no keyring)</span>', '<span class="chk">Evidence hash chain</span>', `<span class="chk">${v.recorded_verdicts} of ${v.recorded_verdicts} verdicts reproduced</span>`].join(''), { Incident: b.incident_id, Policy: b.policy_version, Engine: v.engine, 'Chain head': b.evidence_chain_head });
  switchMode();
}

function switchMode() {
  const b = current();
  $('cf-banner').hidden = !b.counterfactual;
  if (b.counterfactual) $('cf-banner').innerHTML = `<strong>Counterfactual</strong> under policy <span class="chip warn">${esc(b.counterfactual_policy)}</span>: what that policy would have done with the same sealed evidence. Nothing here happened live.`;
  setModel(b);
  $('app').hidden = false;
  player.load(b.frames, Math.min(player.index, b.frames.length - 1));
  route();
}

// Live mode.
function startLive(e) {
  e?.preventDefault();
  state.liveSource?.stop();
  state.source = 'live';
  seal('busy', 'Connecting…', 'Reading sealed evidence from the core and verifying its hash chain.');
  const base = $('live-url').value.trim();
  const src = new LiveSource({
    base,
    operator: $('live-operator').value.trim(),
    roles: $('live-roles').value.trim(),
    onUpdate: (u) => {
      if (!u) {
        $('seal-checks').innerHTML = $('seal-checks').innerHTML.replace(/last poll [^<]*/, `last poll ${new Date().toLocaleTimeString()}`);
        return;
      }
      const atEnd = !player.frames.length || player.index >= player.frames.length - 1;
      state.stream = { incident_id: `live ${base || location.host}`, frames: u.frames, evidence: u.records, evidence_chain_head: u.head, policy_version: '', policy_history: [], engine_version: '', unobserved_layers: [], counterfactual: false, policy: null };
      seal('live', `Live: ${u.records.length} sealed records`, `<span class="chk">Evidence hash chain verified</span><span class="chk">${u.incidents.length} incidents open</span><span>${u.fresh} new · last poll ${new Date().toLocaleTimeString()}</span>`, { Core: base || location.host, 'Chain head': u.head });
      setModel(state.stream);
      $('app').hidden = false;
      $('cf-banner').hidden = true;
      player.load(u.frames, atEnd ? u.frames.length - 1 : player.index);
      route();
    },
    onError: (err) => {
      const msg = err.message ?? String(err);
      // An unreachable core is an outage, retried on every poll; a chain that
      // does not verify is tampering, and the view stays halted on it.
      if (/does not verify/.test(msg)) seal('error', 'Live view halted: evidence failed verification', esc(msg));
      else seal('busy', 'Core unreachable: retrying', `${esc(msg)} · the last verified state stays on screen`);
    },
  });
  state.liveSource = src;
  src.start();
}

function setSource(source) {
  document.querySelectorAll('[data-source]').forEach((b) => {
    b.classList.toggle('on', b.dataset.source === source);
    b.setAttribute('aria-selected', String(b.dataset.source === source));
  });
  $('replay-loaders').hidden = source !== 'replay';
  $('live-loaders').hidden = source !== 'live';
  if (source === 'replay') {
    state.liveSource?.stop();
    state.source = 'replay';
  }
}

function markLoaded(input, files) {
  const label = input.closest('label');
  const span = label.querySelector('span');
  label.classList.toggle('loaded', files.length > 0);
  span.textContent = files.length ? files.map((f) => f.name).join(', ') : span.dataset.name;
}

async function readFiles(input) {
  const files = [...input.files];
  markLoaded(input, files);
  return Promise.all(files.map((f) => f.text()));
}

// Exports.
async function exportCurrent() {
  const b = current();
  if (!b) return;
  const btn = $('export-mp4');
  const label = $('export-label');
  btn.disabled = true;
  try {
    const speed = Math.max(Number($('speed').value), defaultSpeed(b));
    const { blob, codec } = await exportMp4(b, { speed, onProgress: (p) => (label.textContent = `${Math.round(p * 100)}%`) });
    download(`replay-${b.incident_id}${b.counterfactual ? '-counterfactual' : ''}.mp4`, 'video/mp4', blob);
    label.textContent = codec;
  } catch (e) {
    label.textContent = 'failed';
    seal('error', 'Video export failed', esc(e.message ?? String(e)));
  } finally {
    btn.disabled = false;
    setTimeout(() => (label.textContent = 'MP4'), 4000);
  }
}

function exportRows(kind) {
  const b = current();
  if (!b) return;
  const rows = state.view === 'events' && ctx.filtered.length ? ctx.filtered : state.model.rows;
  if (kind === 'csv') download(`frames-${b.incident_id}.csv`, 'text/csv', toCsv(rows));
  else download(`frames-${b.incident_id}.json`, 'application/json', JSON.stringify(rows.map((r) => r.f), null, 2));
}

// Full screen replay, drawn by the same renderer as the MP4 export.
const theater = new Theater({
  onExit: (index) => player.step(index - player.index),
  onExport: () => exportCurrent(),
});
function openTheater() {
  const b = current();
  if (!b || !b.frames.length) return;
  player.pause();
  theater.open(b, b.frames[player.index]?.elapsed_ms ?? 0, Number($('speed').value));
}

// Wiring.
$('fullscreen').addEventListener('click', openTheater);
document.querySelectorAll('[data-source]').forEach((b) => b.addEventListener('click', () => setSource(b.dataset.source)));
$('live-loaders').addEventListener('submit', startLive);
$('bundle-file').addEventListener('change', async (e) => {
  state.texts = await readFiles(e.target);
  verifyAll();
});
$('keyring-file').addEventListener('change', async (e) => {
  state.keyring = (await readFiles(e.target))[0] ?? '';
  verifyAll();
});
$('redaction-key').addEventListener('change', verifyAll);
$('load-sample').addEventListener('click', async () => {
  const get = (p) => fetch(p).then((r) => (r.ok ? r.text() : Promise.reject(new Error(`${p}: ${r.status}`))));
  try {
    const [live, cf, ring, key] = await Promise.all(['samples/bundle.json', 'samples/counterfactual.json', 'samples/keyring.json', 'samples/redaction_key.hex'].map(get));
    state.texts = [live, cf];
    state.keyring = ring;
    $('redaction-key').value = key.trim();
    markLoaded($('bundle-file'), [{ name: 'sample bundles' }]);
    markLoaded($('keyring-file'), [{ name: 'keyring.json' }]);
    verifyAll();
  } catch (e) {
    seal('error', 'Could not load the sample', esc(e.message));
  }
});
$('export-mp4').addEventListener('click', exportCurrent);
$('export-csv').addEventListener('click', () => exportRows('csv'));
$('export-json').addEventListener('click', () => exportRows('json'));
$('theme').addEventListener('click', () => {
  const root = document.documentElement;
  const dark = root.dataset.theme ? root.dataset.theme === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches;
  root.dataset.theme = dark ? 'light' : 'dark';
  try {
    localStorage.setItem('ivar-theme', root.dataset.theme);
  } catch {
    /* storage unavailable: the choice lasts for this page */
  }
  if (state.model) renderView();
});
try {
  const t = localStorage.getItem('ivar-theme');
  if (t) document.documentElement.dataset.theme = t;
} catch {
  /* storage unavailable */
}
$('play').addEventListener('click', () => {
  if (player.playing) player.pause();
  else player.play();
  onFrame(player.index);
});
$('step').addEventListener('click', () => player.step(1));
$('step-back').addEventListener('click', () => player.step(-1));
$('scrub').addEventListener('input', (e) => player.step(Number(e.target.value) - player.index));
$('speed').addEventListener('change', (e) => (player.speed = Number(e.target.value)));
$('follow').addEventListener('change', (e) => {
  state.follow = e.target.checked;
  if (state.view === 'events') events.refilter();
  else renderView();
});
document.querySelectorAll('input[name=mode]').forEach((r) => r.addEventListener('change', (e) => ((state.mode = e.target.value), switchMode())));
window.addEventListener('hashchange', route);

document.addEventListener('dragover', (e) => {
  e.preventDefault();
  document.body.classList.add('dragging');
});
document.addEventListener('dragleave', (e) => !e.relatedTarget && document.body.classList.remove('dragging'));
document.addEventListener('drop', async (e) => {
  e.preventDefault();
  document.body.classList.remove('dragging');
  setSource('replay');
  const texts = await Promise.all([...e.dataTransfer.files].map((f) => f.text()));
  const bundles = [];
  for (const t of texts) {
    try {
      const j = JSON.parse(t);
      if (j.frames) bundles.push(t);
      else if (j.keys) state.keyring = t;
    } catch {
      /* not JSON: ignored */
    }
  }
  if (bundles.length) state.texts = bundles;
  verifyAll();
});

document.addEventListener('keydown', (e) => {
  if (e.target instanceof HTMLInputElement && e.target.type !== 'range' && e.target.type !== 'checkbox') return;
  if (e.target instanceof HTMLSelectElement || $('app').hidden) return;
  if (theater.isOpen) return;
  if ((e.key === 'f' || e.key === 'F') && !e.ctrlKey && !e.metaKey) return openTheater();
  if (e.key === 'Escape' && detail.isOpen) return detail.close();
  if (detail.isOpen && (e.key === 'j' || e.key === 'k')) return detail.step(e.key === 'j' ? 1 : -1);
  if (e.key === 'ArrowRight') player.step(1);
  if (e.key === 'ArrowLeft') player.step(-1);
  if (e.key === ' ' && !(e.target instanceof HTMLButtonElement)) {
    e.preventDefault();
    $('play').click();
  }
  const n = Number(e.key);
  if (!e.ctrlKey && !e.metaKey && n >= 1 && n <= VIEWS.length && !(e.target instanceof HTMLInputElement)) ctx.go(VIEWS[n - 1]);
});

// Used by scripts/export-replay.cjs: verify a bundle exactly as the console
// does, then export it, returning the MP4 as base64.
window.ivarExportMp4 = async (bundleText, keyringText, redactionKeyHex, options = {}) => {
  const { bundle, reExecution, engine } = await verifyBundle(bundleText, keyringText, redactionKeyHex);
  bundle._verified = { ...reExecution, engine };
  const { blob, codec, seconds, speed } = await exportMp4(bundle, { speed: options.speed ?? defaultSpeed(bundle), fps: options.fps });
  const bytes = new Uint8Array(await blob.arrayBuffer());
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return { base64: btoa(bin), codec, seconds, speed, frames: bundle.frames.length, verdicts: reExecution.recorded_verdicts };
};

// A console served by a core at /console/ opens on live mode.
if (location.pathname.includes('/console')) {
  setSource('live');
  $('live-url').placeholder = location.origin;
}
