// Live mode: follow a running core's sealed evidence as it is written and
// turn each record into a frame the way the replay engine does. The whole
// hash chain is re verified before every update is shown, so a tampered
// store halts the view instead of being displayed.
//
// The console is served by the core at /console/ so these calls are same
// origin; the staff SSO proxy in front of the core sets the operator
// headers. For a local core without a proxy the operator and roles typed in
// the console are sent instead.

import init, { verifyEvidenceChain } from '../pkg/ivar_wasm.js';

let ready;

/** Turn sealed evidence records into replay frames (see crates/ivar-replay frames.rs). */
export function recordsToFrames(records) {
  const frames = [];
  const lastSeq = new Map();
  let current = { sensor: '', seq: 0 };
  for (const r of records) {
    const p = r.payload ?? {};
    if (r.kind === 'event') {
      const x = p.ivar ?? {};
      const sensor = x.sensor_id ?? '';
      const seq = x.sensor_seq ?? 0;
      const prev = lastSeq.get(sensor);
      if (prev !== undefined && seq > prev + 1) {
        frames.push({ index: 0, time: p.time ?? r.time, sensor_time: p.time ?? r.time, clock_skew_ms: 0, sensor_id: sensor, sensor_seq: prev + 1, kind: 'gap', evidence_ids: [], payload: { unobserved: `sequence ${prev + 1} to ${seq - 1} missing from ${sensor}` }, counterfactual: false, hops_us: {}, elapsed_ms: 0 });
      }
      if (seq) lastSeq.set(sensor, Math.max(prev ?? 0, seq));
      current = { sensor, seq };
      const hops = {};
      for (const h of ['sensor', 'ingest', 'core', 'decide', 'enforce']) {
        const v = Number(x.attributes?.[`hop_${h}_us`]);
        if (v) hops[h] = v;
      }
      frames.push({ index: 0, time: r.time, sensor_time: p.time ?? r.time, clock_skew_ms: r.time - (p.time ?? r.time), sensor_id: sensor, sensor_seq: seq, kind: 'event', evidence_ids: [r.evidence_id], payload: p, counterfactual: false, hops_us: hops, elapsed_ms: 0 });
      continue;
    }
    const ids = [r.evidence_id, ...(Array.isArray(p.evidence_ids) ? p.evidence_ids : []), ...(Array.isArray(p.request?.evidence_ids) ? p.request.evidence_ids : [])];
    frames.push({ index: 0, time: r.time, sensor_time: r.time, clock_skew_ms: 0, sensor_id: current.sensor, sensor_seq: current.seq, kind: r.kind, evidence_ids: [...new Set(ids)], payload: p, counterfactual: false, hops_us: {}, elapsed_ms: 0 });
  }
  frames.sort((a, b) => a.time - b.time);
  const start = frames[0]?.time ?? 0;
  frames.forEach((f, i) => {
    f.index = i;
    f.elapsed_ms = f.time - start;
  });
  return frames;
}

export class LiveSource {
  constructor({ base, operator, roles, onUpdate, onError, intervalMs = 2000 }) {
    this.base = (base || '').replace(/\/$/, '');
    this.headers = {};
    if (operator) {
      this.headers['x-ivar-operator'] = operator;
      this.headers['x-ivar-roles'] = roles || 'analyst';
      this.headers['x-ivar-hardware-2fa'] = 'true';
    }
    this.onUpdate = onUpdate;
    this.onError = onError;
    this.intervalMs = intervalMs;
    this.records = [];
    // The exact JSON text of every record batch: the hash chain covers those
    // bytes, and re serialising parsed JSON in JavaScript rewrites numbers
    // (0.0 becomes 0), so verification always runs on the text as received.
    this.rawParts = [];
    this.timer = null;
    this.polls = 0;
  }

  async start() {
    ready ??= init();
    await ready;
    await this.poll();
    this.timer = setInterval(() => void this.poll(), this.intervalMs);
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = null;
  }

  async get(path, keepRaw = false) {
    const res = await fetch(`${this.base}${path}`, { headers: this.headers, credentials: 'same-origin' });
    const text = await res.text();
    if (keepRaw) this.lastRaw = text;
    let body;
    try {
      body = JSON.parse(text);
    } catch {
      throw new Error(`${path}: ${res.status} ${text.slice(0, 120)}`);
    }
    if (!res.ok) throw new Error(`${path}: ${res.status} ${body.error ?? text.slice(0, 120)}`);
    return body;
  }

  async poll() {
    if (this.busy) return;
    this.busy = true;
    try {
      const from = this.records.length ? this.records[this.records.length - 1].seq + 1 : 0;
      const fresh = await this.get(`/v1/evidence?from_seq=${from}`, true);
      this.polls += 1;
      if (fresh.length || this.polls === 1) {
        const all = this.records.concat(fresh);
        const inner = this.lastRaw.trim().replace(/^\[/, '').replace(/\]$/, '').trim();
        const parts = inner ? [...this.rawParts, inner] : this.rawParts;
        // Re verify the whole chain: a record that does not link halts the view.
        const out = JSON.parse(verifyEvidenceChain(`[${parts.join(',')}]`));
        if (out.error) throw new Error(`evidence chain does not verify: ${out.error}`);
        this.records = all;
        this.rawParts = parts;
        this.head = out.head;
        const incidents = await this.get('/v1/incidents').catch(() => []);
        this.onUpdate({ records: all, frames: recordsToFrames(all), head: out.head, incidents, fresh: fresh.length });
      } else this.onUpdate(null);
    } catch (e) {
      this.onError(e);
    } finally {
      this.busy = false;
    }
  }

  /** A signed replay of one incident from the core, for the replay views. */
  replay(incidentId) {
    return fetch(`${this.base}/v1/incidents/${encodeURIComponent(incidentId)}/replay`, { headers: this.headers }).then((r) => r.text());
  }
}
