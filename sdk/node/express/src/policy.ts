// Signed policy for the SDK: verified at start, refreshed from the control
// plane, and kept on local disk so a restart while the control plane is down
// keeps the last verified policy (sections 11.2 and 15, defect F1).

import * as core from '@ivar/core-wasm';
import { readFileSync, renameSync, writeFileSync } from 'node:fs';
import type { Engine } from './engine';
import type { Alert, PolicyStatus } from './types';

export interface PolicySourceOptions {
  bundle?: string;
  keyring?: unknown;
  controlUrl?: string;
  refreshMs?: number;
  stateFile?: string;
  sensorId: string;
}

/** Verify a signed bundle against the keyring; returns the PolicyContent JSON. */
export function verifyBundle(archiveB64: string, keyring: unknown, currentVersion: number, now = Date.now()): string {
  const out = core.verifyPolicyBundle(archiveB64.trim(), typeof keyring === 'string' ? keyring : JSON.stringify(keyring), currentVersion, now);
  const parsed = JSON.parse(out);
  if (parsed.error) throw new Error(parsed.error);
  return out;
}

function readState(file?: string): string | undefined {
  if (!file) return undefined;
  try {
    return readFileSync(file, 'utf8').trim() || undefined;
  } catch {
    return undefined;
  }
}

function writeState(file: string | undefined, archiveB64: string): void {
  if (!file) return;
  const tmp = `${file}.tmp`;
  writeFileSync(tmp, archiveB64.trim());
  renameSync(tmp, file);
}

/**
 * The policy to start from: the newer of the configured bundle and the one
 * kept on disk, both verified. Undefined when neither is given.
 */
export function initialPolicy(o: PolicySourceOptions, alert: (a: Alert) => void): { json: string; source: PolicyStatus['source']; archive: string } | undefined {
  if (!o.bundle && !o.stateFile) return undefined;
  if (!o.keyring) throw new Error('policyKeyring is required to verify a signed policy');
  let best: { json: string; source: PolicyStatus['source']; archive: string; version: number } | undefined;
  for (const [archive, source] of [[o.bundle, 'bundle'], [readState(o.stateFile), 'state_file']] as const) {
    if (!archive) continue;
    try {
      const json = verifyBundle(archive, o.keyring, 0);
      const version = Number(JSON.parse(json).version ?? 0);
      if (!best || version > best.version) best = { json, source, archive, version };
    } catch (e) {
      alert({ kind: 'policy_rejected', message: `${source} policy refused: ${(e as Error).message}` });
    }
  }
  if (!best && o.bundle) throw new Error('no signed policy verified; refusing to start on an unverified policy');
  return best;
}

/** Polls the control plane and applies newer signed policy to the engine. */
export class PolicyRefresher {
  private timer?: NodeJS.Timeout;
  private inFlight?: Promise<boolean>;

  constructor(private engine: Engine, private o: PolicySourceOptions, private alert: (a: Alert) => void, private onApplied: (s: PolicyStatus) => void) {}

  start(): void {
    if (!this.o.controlUrl) return;
    if (!this.o.keyring) throw new Error('policyKeyring is required with controlUrl');
    this.timer = setInterval(() => void this.refresh(), this.o.refreshMs ?? 30_000);
    this.timer.unref();
    void this.refresh();
  }

  stop(): void {
    if (this.timer) clearInterval(this.timer);
  }

  /**
   * One poll. Exposed for tests and for an operator triggered refresh.
   * Concurrent callers share the poll already in flight.
   */
  refresh(): Promise<boolean> {
    if (!this.o.controlUrl) return Promise.resolve(false);
    this.inFlight ??= this.poll().finally(() => (this.inFlight = undefined));
    return this.inFlight;
  }

  private async poll(): Promise<boolean> {
    const base = this.o.controlUrl;
    if (!base) return false;
    try {
      const url = `${base.replace(/\/$/, '')}/v1/policy/bundle?have=${this.engine.policyVersion}&sensor=${encodeURIComponent(this.o.sensorId)}`;
      const res = await fetch(url, { signal: AbortSignal.timeout(5_000) });
      if (res.status === 204) return false;
      if (res.status !== 200) {
        // The control plane is down or answered an error: keep the last
        // verified policy in force.
        return false;
      }
      const archive = await res.text();
      let json: string;
      try {
        json = verifyBundle(archive, this.o.keyring, this.engine.policyVersion);
      } catch (e) {
        this.alert({ kind: 'policy_rejected', message: `signed policy refused, current policy kept: ${(e as Error).message}` });
        return false;
      }
      const version = Number(JSON.parse(json).version ?? 0);
      if (version <= this.engine.policyVersion) return false;
      try {
        this.engine.updatePolicy(json);
      } catch (e) {
        this.alert({ kind: 'policy_rejected', message: `the core refused policy ${version}, current policy kept: ${(e as Error).message}` });
        return false;
      }
      writeState(this.o.stateFile, archive);
      const label = String(JSON.parse(json).policy_version ?? '');
      this.alert({ kind: 'policy_applied', message: `policy ${version} (${label}) applied` });
      this.onApplied({ version, policyVersion: label, source: 'control_plane' });
      return true;
    } catch {
      return false;
    }
  }
}

export { writeState as persistPolicy };
