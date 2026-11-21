// Inspector: the current frame, its timing, and every evidence record it
// cites, with the record's hash link and signature.

import { esc, outcomeOf } from '../svg.js';
import { formatElapsed } from '../player.js';

export function renderInspector(el, bundle, index, evidence) {
  const f = bundle.frames[index];
  const ids = [...new Set(f.evidence_ids)];
  const outcome = outcomeOf(f);
  el.innerHTML = `
    <div class="inspect">
      <dl class="kv">
        <dt>Frame</dt><dd>#${f.index} <span class="kind-badge d-bg" style="background: var(--${['record', 'throttle', 'challenge', 'block', 'contain', 'refuse'].includes(outcome) ? outcome : 'accent'})">${esc(outcome.replace('_', ' '))}</span>${f.counterfactual ? ' <span class="chip warn">counterfactual</span>' : ''}</dd>
        <dt>Corrected time</dt><dd>${f.time} ms</dd>
        <dt>Sensor time</dt><dd>${f.sensor_time} ms, skew ${f.clock_skew_ms} ms</dd>
        <dt>Sensor</dt><dd>${esc(f.sensor_id)} · seq ${f.sensor_seq}</dd>
        <dt>Real elapsed</dt><dd>${formatElapsed(f.elapsed_ms)}</dd>
        <dt>Evidence</dt><dd class="ids">${ids.length ? ids.map((id) => `<button type="button" data-id="${esc(id)}">${esc(id)}</button>`).join('') : 'none: unobserved interval'}</dd>
      </dl>
      <div>
        <div class="pre-label" id="inspector-label">Frame payload</div>
        <pre id="inspector-body"></pre>
      </div>
    </div>`;
  const body = el.querySelector('#inspector-body');
  const label = el.querySelector('#inspector-label');
  body.textContent = JSON.stringify(f.payload, null, 2);
  el.querySelectorAll('button[data-id]').forEach((b) =>
    b.addEventListener('click', () => {
      const on = b.classList.contains('on');
      el.querySelectorAll('button[data-id]').forEach((x) => x.classList.remove('on'));
      if (on) {
        label.textContent = 'Frame payload';
        body.textContent = JSON.stringify(f.payload, null, 2);
        return;
      }
      b.classList.add('on');
      const r = evidence.get(b.dataset.id);
      label.textContent = `Sealed evidence ${b.dataset.id}`;
      body.textContent = r ? JSON.stringify(r, null, 2) : `${b.dataset.id} is not in this bundle`;
    }),
  );
}
