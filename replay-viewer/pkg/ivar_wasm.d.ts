/* tslint:disable */
/* eslint-disable */

export class Core {
    free(): void;
    [Symbol.dispose](): void;
    drift(): string;
    evidence(): string;
    incidents(): string;
    constructor(policy_json: string, redaction_key_hex: string);
    process(event_json: string, now_ms: number): string;
    tick(now_ms: number): string;
}

export class LocalSensor {
    free(): void;
    [Symbol.dispose](): void;
    decide(event_json: string, now_ms: number): string;
    constructor(policy_json: string);
    pushVerdict(verdict_json: string): boolean;
}

export class Sink {
    free(): void;
    [Symbol.dispose](): void;
    cancel(lock_id: string, owner: string, request_json: string): string;
    guard(request_json: string, now_ms: number): string;
    constructor(root_public_hex: string, step_keys_json: string, invariants_json: string, default_mode: string, modes_json: string);
    releaseDue(now_ms: number): string;
    revoke(revocation_id_hex: string): void;
    setMode(action: string, mode: string): boolean;
}

export function attestStep(step_seed_hex: string, step: string, token: string, root_public_hex: string, narrowing_json: string): string;

export function compileDeclarations(kind: string, file: string, text: string, holder: string): string;

export function defaultPolicy(now_ms: number): string;

export function engineVersion(): string;

export function mintIntent(root_seed_hex: string, intent_id: string, action: string, subject: string, limits_json: string, expiry_ms: number): string;

export function narrowIntent(token: string, root_public_hex: string, narrowing_json: string): string;

export function reverifyBundle(bundle_json: string, keyring_json: string, redaction_key_hex: string): string;

export function stepPublicKey(step_seed_hex: string): string;

export function verifyEvidenceChain(records_json: string): string;

export function verifyPolicyBundle(archive_base64: string, keyring_json: string, current_version: number, now_ms: number): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_core_free: (a: number, b: number) => void;
    readonly __wbg_localsensor_free: (a: number, b: number) => void;
    readonly __wbg_sink_free: (a: number, b: number) => void;
    readonly attestStep: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => [number, number];
    readonly compileDeclarations: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number];
    readonly core_drift: (a: number) => [number, number];
    readonly core_evidence: (a: number) => [number, number];
    readonly core_incidents: (a: number) => [number, number];
    readonly core_new: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly core_process: (a: number, b: number, c: number, d: number) => [number, number];
    readonly core_tick: (a: number, b: number) => [number, number];
    readonly defaultPolicy: (a: number) => [number, number];
    readonly engineVersion: () => [number, number];
    readonly localsensor_decide: (a: number, b: number, c: number, d: number) => [number, number];
    readonly localsensor_new: (a: number, b: number) => [number, number, number];
    readonly localsensor_pushVerdict: (a: number, b: number, c: number) => number;
    readonly mintIntent: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number) => [number, number];
    readonly narrowIntent: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number];
    readonly reverifyBundle: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number];
    readonly sink_cancel: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number];
    readonly sink_guard: (a: number, b: number, c: number, d: number) => [number, number];
    readonly sink_new: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => [number, number, number];
    readonly sink_releaseDue: (a: number, b: number) => [number, number];
    readonly sink_revoke: (a: number, b: number, c: number) => void;
    readonly sink_setMode: (a: number, b: number, c: number, d: number, e: number) => number;
    readonly stepPublicKey: (a: number, b: number) => [number, number];
    readonly verifyEvidenceChain: (a: number, b: number) => [number, number];
    readonly verifyPolicyBundle: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number];
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
