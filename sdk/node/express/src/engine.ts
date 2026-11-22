// The verified decision core, loaded as WebAssembly.

import * as core from '@ivar/core-wasm';
import type { Verdict } from './types';

export interface LocalResult {
  local: 'block' | 'cached' | 'forward';
  verdict?: Verdict;
}

export class Engine {
  policyJson: string;
  /** Version of the policy in force; a refresh only applies a newer one. */
  policyVersion: number;
  private sensor: core.LocalSensor;
  private embedded?: core.Core;
  private verdicts = new Map<string, Verdict>();

  constructor(policy: unknown, redactionKey: string, embedded: boolean) {
    this.policyJson = policy ? (typeof policy === 'string' ? policy : JSON.stringify(policy)) : core.defaultPolicy(Date.now());
    this.policyVersion = Number(JSON.parse(this.policyJson).version ?? 0);
    this.sensor = new core.LocalSensor(this.policyJson);
    if (embedded) this.embedded = new core.Core(this.policyJson, redactionKey || '00');
    this.warm();
  }

  /**
   * Warm the WebAssembly code paths so the first real request stays in
   * budget: a plain read and a write with body fields on a declared route.
   */
  private warm(): void {
    const samples = [
      { activity_name: 'http.request', http_request: { http_method: 'GET', url_path: '/' }, src_endpoint: { ip: '192.0.2.1' }, ivar: {} },
      { activity_name: 'http.request', http_request: { http_method: 'POST', url_path: '/login', body_keys: ['email', 'password'] }, actor: { user: { uid: 'kh_warm' } }, src_endpoint: { ip: '192.0.2.1' }, ivar: {} },
    ].map((e) => JSON.stringify(e));
    for (let i = 0; i < 200; i++) this.sensor.decide(samples[i % samples.length], Date.now());
  }

  /**
   * Swap in a newer verified policy. The fast path is rebuilt from it and
   * keeps the core's unexpired verdicts; the embedded core keeps its trust
   * graph, risk and evidence. Throws when the core refuses the policy, and
   * the current one stays in force.
   */
  updatePolicy(policyJson: string, now = Date.now()): void {
    const sensor = new core.LocalSensor(policyJson);
    if (this.embedded) {
      const r = JSON.parse(this.embedded.updatePolicy(policyJson, now));
      if (r.error) throw new Error(r.error);
    }
    this.sensor = sensor;
    this.policyJson = policyJson;
    this.policyVersion = Number(JSON.parse(policyJson).version ?? 0);
    for (const v of this.verdicts.values()) if (!v.expires_at || v.expires_at > now) this.sensor.pushVerdict(JSON.stringify(v));
    this.warm();
  }

  /** The sensor fast path: known attacks and cached verdicts, no round trip. */
  decide(event: Record<string, unknown>, now: number): LocalResult {
    return JSON.parse(this.sensor.decide(JSON.stringify(event), now)) as LocalResult;
  }

  /** Full scoring in the embedded core; called off the request path. */
  process(event: Record<string, unknown>, now: number): { decision: string; verdicts: Verdict[]; incidents: string[] } | undefined {
    if (!this.embedded) return undefined;
    const out = JSON.parse(this.embedded.process(JSON.stringify(event), now));
    if (out.error) throw new Error(out.error);
    for (const v of out.verdicts as Verdict[]) this.pushVerdict(v);
    return out;
  }

  pushVerdict(v: Verdict): void {
    if (v.entity) this.verdicts.set(`${v.entity.type}:${v.entity.id}`, v);
    this.sensor.pushVerdict(JSON.stringify(v));
  }

  evidence(): unknown[] {
    return this.embedded ? JSON.parse(this.embedded.evidence()) : [];
  }

  incidents(): unknown[] {
    return this.embedded ? JSON.parse(this.embedded.incidents()) : [];
  }
}
