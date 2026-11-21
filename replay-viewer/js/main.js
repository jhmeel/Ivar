// Replay viewer entry point: load, verify, then wire the panes to the clock.

import { verifyBundle, evidenceIndex, VerificationError } from './bundle.js';
import { Player, formatElapsed } from './player.js';
import { esc, short } from './svg.js';
import { renderTimeline } from './panes/timeline.js';
import { renderEstate } from './panes/estate.js';
import { renderPipeline } from './panes/pipeline.js';
import { renderTrust } from './panes/trust.js';
import { renderRisk } from './panes/risk.js';
import { renderInspector } from './panes/inspector.js';
import { exportMp4, defaultSpeed } from './video/encode.js';

const $ = (id) => document.getElementById(id);
const state = { live: null, counterfactual: null, mode: 'live', evidence: new Map(), keyring: '', texts: [] };

/** The verification seal: idle, busy, ok or error. */
function seal(kind, title, checks = '', meta = {}) {
  $('seal').className = `seal ${kind}`;
  $('status').textContent = title;
  $('seal-checks').innerHTML = checks;
  $('seal-meta').innerHTML = Object.entries(meta).map(([k, v]) => `<dt>${esc(k)}</dt><dd title="${esc(v)}">${esc(short(v, 18))}</dd>`).join('');
}

function current() {
  return state.mode === 'counterfactual' && state.counterfactual ? state.counterfactual : state.live ?? state.counterfactual;
}

function render(index) {
  const b = current();
  if (!b) return;
  const select = (i) => player.step(i - player.index);
  renderTimeline($('timeline'), b, index, select);
  renderEstate($('estate'), b, index);
  renderPipeline($('pipeline'), b, index);
  renderTrust($('trust'), b, index);
  renderRisk($('risk'), b, index);
  renderInspector($('inspector'), b, index, state.evidence);
  $('clock-frame').textContent = `${index + 1} / ${b.frames.length}`;
  $('clock-elapsed').textContent = formatElapsed(b.frames[index].elapsed_ms);
  $('scrub').max = String(b.frames.length - 1);
  $('scrub').value = String(index);
  $('play').classList.toggle('playing', player.playing);
  $('play').setAttribute('aria-label', player.playing ? 'Pause' : 'Play');
}

const player = new Player(render);

async function verifyAll() {
  state.live = state.counterfactual = null;
  $('viewer').hidden = true;
  if (!state.texts.length) return;
  seal('busy', 'Verifying…', 'Checking the bundle signature and evidence chain, then re executing every event in this browser.');
  try {
    for (const text of state.texts) {
      const { bundle, reExecution, engine } = await verifyBundle(text, state.keyring, $('redaction-key').value);
      bundle._verified = { ...reExecution, engine };
      if (bundle.counterfactual) state.counterfactual = bundle;
      else state.live = bundle;
    }
  } catch (e) {
    const msg = e instanceof VerificationError ? e.message : String(e);
    seal('error', 'Not rendered: this replay could not be verified', esc(msg));
    return;
  }
  const b = state.live ?? state.counterfactual;
  state.evidence = evidenceIndex(b);
  const cfInput = document.querySelector('input[name=mode][value=counterfactual]');
  const liveInput = document.querySelector('input[name=mode][value=live]');
  cfInput.disabled = !state.counterfactual;
  liveInput.disabled = !state.live;
  state.mode = state.live ? 'live' : 'counterfactual';
  (state.live ? liveInput : cfInput).checked = true;
  const v = b._verified;
  const checks = [
    state.keyring ? '<span class="chk">Signature</span>' : '<span class="skip">Signature not checked (no keyring)</span>',
    '<span class="chk">Evidence hash chain</span>',
    `<span class="chk">${v.recorded_verdicts} of ${v.recorded_verdicts} verdicts reproduced</span>`,
  ].join('');
  seal('ok', 'Verified replay', checks, { Incident: b.incident_id, Policy: b.policy_version, Engine: v.engine, 'Chain head': b.evidence_chain_head });
  $('viewer').hidden = false;
  switchMode();
}

function switchMode() {
  const b = current();
  $('cf-banner').hidden = !b.counterfactual;
  if (b.counterfactual) $('cf-banner').innerHTML = `<strong>Counterfactual</strong> under policy <span class="chip warn">${esc(b.counterfactual_policy)}</span>: what that policy would have done with the same sealed evidence. Nothing live changes.`;
  player.load(b.frames, player.index);
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

// Drag and drop: bundles and a keyring can be dropped anywhere on the page.
document.addEventListener('dragover', (e) => {
  e.preventDefault();
  document.body.classList.add('dragging');
});
document.addEventListener('dragleave', (e) => {
  if (!e.relatedTarget) document.body.classList.remove('dragging');
});
document.addEventListener('drop', async (e) => {
  e.preventDefault();
  document.body.classList.remove('dragging');
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

$('play').addEventListener('click', () => {
  if (player.playing) player.pause();
  else player.play();
  render(player.index);
});
$('step').addEventListener('click', () => player.step(1));
$('step-back').addEventListener('click', () => player.step(-1));
$('scrub').addEventListener('input', (e) => player.step(Number(e.target.value) - player.index));
$('speed').addEventListener('change', (e) => (player.speed = Number(e.target.value)));
document.querySelectorAll('input[name=mode]').forEach((r) =>
  r.addEventListener('change', (e) => {
    state.mode = e.target.value;
    switchMode();
  }),
);
document.addEventListener('keydown', (e) => {
  if (e.target instanceof HTMLInputElement && e.target.type !== 'range') return;
  if (e.target instanceof HTMLSelectElement || $('viewer').hidden) return;
  if (e.key === 'ArrowRight') player.step(1);
  if (e.key === 'ArrowLeft') player.step(-1);
  if (e.key === ' ') {
    e.preventDefault();
    $('play').click();
  }
});

// Video export: the verified replay currently shown, at the selected speed
// (raised for long incidents so the video stays short).
async function exportCurrent() {
  const b = current();
  if (!b) return;
  const btn = $('export-mp4');
  const label = $('export-label');
  btn.disabled = true;
  try {
    const speed = Math.max(Number($('speed').value), defaultSpeed(b));
    const { blob, codec } = await exportMp4(b, { speed, onProgress: (p) => (label.textContent = `Exporting ${Math.round(p * 100)}%`) });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `replay-${b.incident_id}${b.counterfactual ? '-counterfactual' : ''}.mp4`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 10_000);
    label.textContent = `Exported (${codec})`;
  } catch (e) {
    label.textContent = 'Export failed';
    seal('error', 'Video export failed', esc(e.message ?? String(e)));
  } finally {
    btn.disabled = false;
    setTimeout(() => (label.textContent = 'Export MP4'), 4000);
  }
}
$('export-mp4').addEventListener('click', exportCurrent);

// Used by scripts/export-replay.cjs: verify a bundle exactly as the viewer
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
