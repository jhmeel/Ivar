// The action sink: one guard call at the point of a high consequence action.
// It checks the intent token, consequence invariants and time locks, and has
// an observe mode that shows what it would refuse before it refuses anything.

import * as core from '@ivar/core-wasm';
import type { IntentKeys } from './types';

export type SinkOutcome =
  | { outcome: 'executes'; claims?: unknown }
  | { outcome: 'refused'; reason: string }
  | { outcome: 'blocked_alert'; invariant_id: string; used: number; limit: number; action_on_breach: string }
  | { outcome: 'held'; lock: { lock_id: string; release_at: number; owners: string[] } };

export interface SinkDecision {
  outcome: SinkOutcome;
  intent_mode: 'off' | 'observe' | 'enforce';
  would_refuse?: string | null;
  open_incident: boolean;
}

export interface SinkRequest {
  action: string;
  subject: string;
  identity: string;
  business: string;
  value_moved: number;
  records_read: number;
  destructive: boolean;
  intent_token?: string | null;
  payload?: unknown;
}

export class ActionSink {
  private sink: core.Sink;

  constructor(keys: IntentKeys, invariants: unknown[], mode: 'off' | 'observe' | 'enforce', perAction: Record<string, string> = {}) {
    this.sink = new core.Sink(keys.rootPublicKey, JSON.stringify(keys.stepKeys), JSON.stringify(invariants), mode, JSON.stringify(perAction));
  }

  guard(req: SinkRequest, now = Date.now()): SinkDecision {
    const out = JSON.parse(this.sink.guard(JSON.stringify(req), now));
    if (out.error) throw new Error(out.error);
    return out as SinkDecision;
  }

  cancel(lockId: string, owner: string, req: SinkRequest): unknown {
    return JSON.parse(this.sink.cancel(lockId, owner, JSON.stringify(req)));
  }

  /** Change INTENT_BINDING for one action in place; held time locks are kept. */
  setMode(action: string, mode: 'off' | 'observe' | 'enforce'): void {
    this.sink.setMode(action, mode);
  }

  releaseDue(now = Date.now()): unknown[] {
    return JSON.parse(this.sink.releaseDue(now));
  }
}
