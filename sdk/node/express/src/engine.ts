// The verified decision core, loaded as WebAssembly.

import * as core from '@ivar/core-wasm';
import type { Verdict } from './types';

export interface LocalResult {
  local: 'block' | 'cached' | 'forward';
  verdict?: Verdict;
}

export class Engine {
  readonly policyJson: string;
  private sensor: core.LocalSensor;
  private embedded?: core.Core;

  constructor(policy: unknown, redactionKey: string, embedded: boolean) {
    this.policyJson = policy ? JSON.stringify(policy) : core.defaultPolicy(Date.now());
    this.sensor = new core.LocalSensor(this.policyJson);
    if (embedded) this.embedded = new core.Core(this.policyJson, redactionKey || '00');
    // Warm the WebAssembly code paths so the first request stays in budget.
    for (let i = 0; i < 3; i++) this.sensor.decide(JSON.stringify({ activity_name: 'http.request', http_request: { http_method: 'GET', url_path: '/' }, ivar: {} }), Date.now());
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
    this.sensor.pushVerdict(JSON.stringify(v));
  }

  evidence(): unknown[] {
    return this.embedded ? JSON.parse(this.embedded.evidence()) : [];
  }

  incidents(): unknown[] {
    return this.embedded ? JSON.parse(this.embedded.incidents()) : [];
  }
}
