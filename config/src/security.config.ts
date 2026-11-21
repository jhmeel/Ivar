// security.config.ts
//
// The application hardening configuration, extended with the IVAR settings
// rather than replaced (section 15). What carries over unchanged: the three
// security profiles, startup validation, additive lists, monitor then enforce
// rollout, protection for shared networks, the incident checklist and the
// evidence rules. Every setting keeps the same resolve order: profile
// default, environment override, hard limits and cross checks, then signed
// runtime flags.
//
// The fixes for the nine verified defects (Appendix A, section 21.1) are
// marked F1 to F9 where they apply.

import { createPublicKey, verify as edVerify, KeyObject } from 'node:crypto';
import { readFileSync, writeFileSync, renameSync, existsSync } from 'node:fs';

export type Profile = 'standard' | 'payments' | 'lockdown';
export type Env = 'development' | 'staging' | 'production';
export type DetectionMode = 'observe' | 'enforce';
export type AiAutonomy = 'off' | 'advise' | 'propose' | 'bounded';
export type IntentBinding = 'off' | 'observe' | 'enforce';
export type RuntimePosture = 'standard' | 'payments' | 'lockdown';
export type RegistrationMode = 'open' | 'invite' | 'closed';

export interface SecurityConfig {
  // Existing hardening settings named in Appendix A.
  SECURITY_PROFILE: Profile;
  STAFF_2FA_REQUIRED: boolean;
  REFRESH_TOKEN_ROTATION: boolean;
  VERIFIED_EMAIL_REQUIRED: boolean;
  ABUSE_EXEMPT_CIDRS: string[];
  SHARED_NETWORK_CIDRS: string[];
  BLOCKED_EMAIL_PATTERNS: RegExp[];
  PUBLIC_SIGNUP_ROLES: string[];
  PIN_LOCK_DURATION: string;
  PURGE_GRACE_PERIOD: string;
  AUDIT_RETENTION: string;
  BAN_DURATION: string;
  REPEAT_BAN_DURATION: string;
  HANDLES_MONEY: boolean;
  HANDLES_STAFF_ACCESS: boolean;
  // IVAR settings (section 15).
  DETECTION_MODE: DetectionMode;
  AUTO_CONTAIN_MAX_USERS_PCT: number;
  AI_AUTONOMY: AiAutonomy;
  EVIDENCE_RETENTION: string;
  RUNTIME_POSTURE: RuntimePosture;
  INTENT_BINDING: { default: IntentBinding; perAction: Record<string, IntentBinding> };
  TIME_LOCKS: string;
  FAIL_OPEN_BUDGET_PCT: number;
  RISK_HALF_LIVES: { fast: string; slow: string };
}

export class ConfigError extends Error {
  constructor(public setting: string, message: string) {
    super(`${setting}: ${message}`);
  }
}

const PROFILE_DEFAULTS: Record<Profile, Partial<SecurityConfig>> = {
  standard: { STAFF_2FA_REQUIRED: false, REFRESH_TOKEN_ROTATION: false, VERIFIED_EMAIL_REQUIRED: false, RUNTIME_POSTURE: 'standard', DETECTION_MODE: 'observe' },
  payments: { STAFF_2FA_REQUIRED: true, REFRESH_TOKEN_ROTATION: true, VERIFIED_EMAIL_REQUIRED: true, RUNTIME_POSTURE: 'payments', DETECTION_MODE: 'observe' },
  lockdown: { STAFF_2FA_REQUIRED: true, REFRESH_TOKEN_ROTATION: true, VERIFIED_EMAIL_REQUIRED: true, RUNTIME_POSTURE: 'lockdown', DETECTION_MODE: 'enforce' },
};

const BASE: SecurityConfig = {
  SECURITY_PROFILE: 'standard',
  STAFF_2FA_REQUIRED: false,
  REFRESH_TOKEN_ROTATION: false,
  VERIFIED_EMAIL_REQUIRED: false,
  ABUSE_EXEMPT_CIDRS: [],
  SHARED_NETWORK_CIDRS: ['100.64.0.0/10'],
  BLOCKED_EMAIL_PATTERNS: [],
  PUBLIC_SIGNUP_ROLES: ['customer'],
  PIN_LOCK_DURATION: '15m',
  PURGE_GRACE_PERIOD: '30d',
  AUDIT_RETENTION: '400d',
  BAN_DURATION: '1h',
  REPEAT_BAN_DURATION: '24h',
  HANDLES_MONEY: false,
  HANDLES_STAFF_ACCESS: false,
  DETECTION_MODE: 'observe',
  AUTO_CONTAIN_MAX_USERS_PCT: 0.5,
  AI_AUTONOMY: 'advise',
  EVIDENCE_RETENTION: '400d',
  RUNTIME_POSTURE: 'standard',
  INTENT_BINDING: { default: 'observe', perAction: {} },
  TIME_LOCKS: 'time-locks.yaml',
  FAIL_OPEN_BUDGET_PCT: 0.1,
  RISK_HALF_LIVES: { fast: '30m', slow: '7d' },
};

/** F9: `forever` is allowed only on the two ban settings. */
export const FOREVER_ALLOWED = new Set(['BAN_DURATION', 'REPEAT_BAN_DURATION']);
const DURATION = /^(\d+)(s|m|h|d)$/;

export function durationSeconds(setting: string, v: string): number {
  if (v === 'forever') {
    if (!FOREVER_ALLOWED.has(setting)) throw new ConfigError(setting, '`forever` is only allowed on BAN_DURATION and REPEAT_BAN_DURATION');
    return Number.POSITIVE_INFINITY;
  }
  const m = DURATION.exec(v.trim());
  if (!m) throw new ConfigError(setting, `expected a duration such as 30m or 400d, got ${v}`);
  return Number(m[1]) * { s: 1, m: 60, h: 3600, d: 86400 }[m[2] as 's' | 'm' | 'h' | 'd'];
}

/** F2: an exemption may not be broader than the agreed prefix. */
export const MAX_EXEMPT_PREFIX = { v4: 16, v6: 48 };

export function checkExemption(cidr: string, env: Env): void {
  const [addr, len] = cidr.trim().split('/');
  const bits = Number(len);
  const v6 = addr.includes(':');
  if (!addr || !Number.isInteger(bits) || bits < 0 || bits > (v6 ? 128 : 32)) throw new ConfigError('ABUSE_EXEMPT_CIDRS', `${cidr} is not a CIDR`);
  const min = v6 ? MAX_EXEMPT_PREFIX.v6 : MAX_EXEMPT_PREFIX.v4;
  if (bits < min && env === 'production') {
    throw new ConfigError('ABUSE_EXEMPT_CIDRS', `${cidr} is broader than the agreed /${min}; an exemption this wide means no IP in it can ever be banned`);
  }
}

/**
 * F6: user supplied patterns run on a linear time engine or are rejected.
 * JavaScript's engine backtracks, so unsafe constructs are refused before
 * compilation: backreferences, lookaround, and any quantified group that
 * itself contains a quantifier or an alternation (star height above one,
 * the shape behind ^(a+)+$).
 */
export function safePattern(source: string): RegExp {
  if (source.length > 256) throw new ConfigError('BLOCKED_EMAIL_PATTERNS', 'pattern longer than 256 characters');
  if (/\\[1-9]|\\k</.test(source)) throw new ConfigError('BLOCKED_EMAIL_PATTERNS', `${source}: backreferences are not allowed`);
  if (/\(\?[=!<]/.test(source)) throw new ConfigError('BLOCKED_EMAIL_PATTERNS', `${source}: lookaround is not allowed`);
  // Walk groups: a group followed by a quantifier may not contain a quantifier or "|".
  const stack: { start: number; quantified: boolean; alt: boolean }[] = [];
  for (let i = 0; i < source.length; i++) {
    const c = source[i];
    if (c === '\\') {
      i++;
      continue;
    }
    if (c === '[') {
      const end = source.indexOf(']', i + 1);
      i = end < 0 ? source.length : end;
      continue;
    }
    if (c === '(') stack.push({ start: i, quantified: false, alt: false });
    else if (c === '|' && stack.length) stack[stack.length - 1].alt = true;
    else if ((c === '*' || c === '+' || c === '?' || c === '{') && stack.length) stack[stack.length - 1].quantified = true;
    else if (c === ')') {
      const g = stack.pop();
      const next = source[i + 1];
      const groupQuantified = next === '*' || next === '+' || next === '{' || (next === '?' && source[i + 2] !== undefined);
      if (g && groupQuantified && (g.quantified || g.alt)) {
        throw new ConfigError('BLOCKED_EMAIL_PATTERNS', `${source}: nested quantifiers can take exponential time`);
      }
      if (g && g.quantified && stack.length) stack[stack.length - 1].quantified = true;
    }
  }
  try {
    return new RegExp(source, 'i');
  } catch (e) {
    throw new ConfigError('BLOCKED_EMAIL_PATTERNS', `${source}: ${(e as Error).message}`);
  }
}

/** F8: patterns come from a structured file (a JSON array), never a comma split string. */
export function loadPatterns(path: string): RegExp[] {
  const parsed: unknown = JSON.parse(readFileSync(path, 'utf8'));
  if (!Array.isArray(parsed) || !parsed.every((p) => typeof p === 'string')) {
    throw new ConfigError('BLOCKED_EMAIL_PATTERNS_FILE', 'must be a JSON array of strings');
  }
  return parsed.map(safePattern);
}

/** F7: public signup roles are an explicit allowlist, not a denylist of role names. */
export const PUBLIC_ROLE_ALLOWLIST = new Set(['customer', 'guest']);

export function resolve(profile: Profile, env: Env, overrides: Record<string, string | undefined>, flags: SignedFlags = {}): SecurityConfig {
  // 1. Profile default.
  const c: SecurityConfig = { ...BASE, ...PROFILE_DEFAULTS[profile], SECURITY_PROFILE: profile } as SecurityConfig;
  // 2. Environment override.
  const o = overrides;
  const bool = (k: string, v?: string) => {
    if (v === undefined) return undefined;
    if (v !== 'true' && v !== 'false') throw new ConfigError(k, 'expected true or false');
    return v === 'true';
  };
  for (const k of ['STAFF_2FA_REQUIRED', 'REFRESH_TOKEN_ROTATION', 'VERIFIED_EMAIL_REQUIRED', 'HANDLES_MONEY', 'HANDLES_STAFF_ACCESS'] as const) {
    const b = bool(k, o[k]);
    if (b !== undefined) c[k] = b;
  }
  // Additive lists: an override adds to the defaults, it never replaces them.
  if (o.ABUSE_EXEMPT_CIDRS) c.ABUSE_EXEMPT_CIDRS = [...c.ABUSE_EXEMPT_CIDRS, ...o.ABUSE_EXEMPT_CIDRS.split(',').map((s) => s.trim()).filter(Boolean)];
  if (o.SHARED_NETWORK_CIDRS) c.SHARED_NETWORK_CIDRS = [...c.SHARED_NETWORK_CIDRS, ...o.SHARED_NETWORK_CIDRS.split(',').map((s) => s.trim()).filter(Boolean)];
  if (o.BLOCKED_EMAIL_PATTERNS !== undefined) {
    throw new ConfigError('BLOCKED_EMAIL_PATTERNS', 'set BLOCKED_EMAIL_PATTERNS_FILE to a JSON array instead (F8)');
  }
  if (o.BLOCKED_EMAIL_PATTERNS_FILE) c.BLOCKED_EMAIL_PATTERNS = loadPatterns(o.BLOCKED_EMAIL_PATTERNS_FILE);
  if (o.PUBLIC_SIGNUP_ROLES) c.PUBLIC_SIGNUP_ROLES = o.PUBLIC_SIGNUP_ROLES.split(',').map((s) => s.trim()).filter(Boolean);
  for (const k of ['PIN_LOCK_DURATION', 'PURGE_GRACE_PERIOD', 'AUDIT_RETENTION', 'BAN_DURATION', 'REPEAT_BAN_DURATION', 'EVIDENCE_RETENTION', 'TIME_LOCKS'] as const) {
    if (o[k]) c[k] = o[k]!.trim();
  }
  if (o.DETECTION_MODE) c.DETECTION_MODE = oneOf('DETECTION_MODE', o.DETECTION_MODE, ['observe', 'enforce']);
  if (o.AI_AUTONOMY) c.AI_AUTONOMY = oneOf('AI_AUTONOMY', o.AI_AUTONOMY, ['off', 'advise', 'propose', 'bounded']);
  if (o.RUNTIME_POSTURE) c.RUNTIME_POSTURE = oneOf('RUNTIME_POSTURE', o.RUNTIME_POSTURE, ['standard', 'payments', 'lockdown']);
  if (o.AUTO_CONTAIN_MAX_USERS_PCT) c.AUTO_CONTAIN_MAX_USERS_PCT = num('AUTO_CONTAIN_MAX_USERS_PCT', o.AUTO_CONTAIN_MAX_USERS_PCT);
  if (o.FAIL_OPEN_BUDGET_PCT) c.FAIL_OPEN_BUDGET_PCT = num('FAIL_OPEN_BUDGET_PCT', o.FAIL_OPEN_BUDGET_PCT);
  if (o.RISK_HALF_LIVES) {
    const [fast, slow] = o.RISK_HALF_LIVES.split(',').map((s) => s.trim());
    c.RISK_HALF_LIVES = { fast, slow };
  }
  if (o.INTENT_BINDING) {
    for (const part of o.INTENT_BINDING.split(',')) {
      const [a, m] = part.split('=');
      if (m === undefined) c.INTENT_BINDING.default = oneOf('INTENT_BINDING', a, ['off', 'observe', 'enforce']);
      else c.INTENT_BINDING.perAction[a.trim()] = oneOf('INTENT_BINDING', m, ['off', 'observe', 'enforce']);
    }
  }
  // 3. Hard limits and cross checks (startup validation).
  validate(c, env);
  // 4. Signed runtime flags (F3, F4): only runtime settings, only when signed.
  for (const [name, f] of Object.entries(flags)) {
    if (name === 'DETECTION_MODE') c.DETECTION_MODE = oneOf(name, f.value, ['observe', 'enforce']);
    if (name === 'RUNTIME_POSTURE') c.RUNTIME_POSTURE = oneOf(name, f.value, ['standard', 'payments', 'lockdown']);
    if (name.startsWith('INTENT_BINDING.')) c.INTENT_BINDING.perAction[name.slice(15)] = oneOf(name, f.value, ['off', 'observe', 'enforce']);
  }
  return c;
}

function oneOf<T extends string>(k: string, v: string, allowed: T[]): T {
  const x = v.trim().toLowerCase() as T;
  if (!allowed.includes(x)) throw new ConfigError(k, `expected one of ${allowed.join(', ')}`);
  return x;
}

function num(k: string, v: string): number {
  const n = Number(v);
  if (!Number.isFinite(n)) throw new ConfigError(k, 'expected a number');
  return n;
}

export function validate(c: SecurityConfig, env: Env): void {
  for (const cidr of c.ABUSE_EXEMPT_CIDRS) checkExemption(cidr, env); // F2
  for (const k of ['PIN_LOCK_DURATION', 'PURGE_GRACE_PERIOD', 'AUDIT_RETENTION', 'BAN_DURATION', 'REPEAT_BAN_DURATION', 'EVIDENCE_RETENTION'] as const) durationSeconds(k, c[k]); // F9
  for (const r of c.PUBLIC_SIGNUP_ROLES) {
    if (!PUBLIC_ROLE_ALLOWLIST.has(r)) throw new ConfigError('PUBLIC_SIGNUP_ROLES', `${r} is not on the public role allowlist`); // F7
  }
  // F5: the standard profile is blocked in production for services that
  // handle money or staff access when staff 2FA, refresh rotation or
  // verified email checks are off.
  if (env === 'production' && (c.HANDLES_MONEY || c.HANDLES_STAFF_ACCESS)) {
    const off = (['STAFF_2FA_REQUIRED', 'REFRESH_TOKEN_ROTATION', 'VERIFIED_EMAIL_REQUIRED'] as const).filter((k) => !c[k]);
    if (c.SECURITY_PROFILE === 'standard' && off.length) {
      throw new ConfigError('SECURITY_PROFILE', `standard profile with ${off.join(', ')} off is not allowed in production for a service that handles money or staff access`);
    }
  }
  if (!(c.AUTO_CONTAIN_MAX_USERS_PCT > 0 && c.AUTO_CONTAIN_MAX_USERS_PCT <= 5)) throw new ConfigError('AUTO_CONTAIN_MAX_USERS_PCT', 'must be above 0 and at most 5');
  if (!(c.FAIL_OPEN_BUDGET_PCT >= 0 && c.FAIL_OPEN_BUDGET_PCT <= 1)) throw new ConfigError('FAIL_OPEN_BUDGET_PCT', 'must be between 0 and 1');
  if (durationSeconds('EVIDENCE_RETENTION', c.EVIDENCE_RETENTION) < 90 * 86400) throw new ConfigError('EVIDENCE_RETENTION', 'evidence must stay searchable well beyond 90 days');
  if (durationSeconds('RISK_HALF_LIVES', c.RISK_HALF_LIVES.fast) >= durationSeconds('RISK_HALF_LIVES', c.RISK_HALF_LIVES.slow)) throw new ConfigError('RISK_HALF_LIVES', 'fast must be shorter than slow');
}

// Runtime flags and kill switches (F1, F3, F4).

export interface SignedFlag {
  name: string;
  value: string;
  version: number;
  issued_at: number;
  signature: { alg: string; key_id: string; sig: string } | null;
}
export type SignedFlags = Record<string, SignedFlag>;

export const SAFEST: Record<string, string> = { PAYOUTS_ENABLED: 'false', REGISTRATION_MODE: 'closed', SIGNING_ENABLED: 'false', EXPORTS_ENABLED: 'false', RUNTIME_POSTURE: 'lockdown', DETECTION_MODE: 'enforce' };

/** The flag store the existing guide keeps in Redis, behind an interface. */
export interface FlagBackend {
  get(name: string): Promise<SignedFlag | null>;
}

function flagBytes(f: SignedFlag): Buffer {
  return Buffer.from(`ivar.flag.v1\n${f.name}\n${f.value}\n${f.version}\n${f.issued_at}`);
}

/** F3: every flag change is signed and versioned. */
export function verifyFlag(f: SignedFlag, keys: Record<string, KeyObject>): boolean {
  if (!f.signature || f.signature.alg !== 'ed25519') return false;
  const k = keys[f.signature.key_id];
  return !!k && edVerify(null, flagBytes(f), k, Buffer.from(f.signature.sig, 'base64'));
}

export function ed25519PublicKey(hex: string): KeyObject {
  // SPKI prefix for an Ed25519 public key.
  return createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(hex, 'hex')]), format: 'der', type: 'spki' });
}

/**
 * F1: the last known signed state is persisted locally, and the safest value
 * is held when it is missing, so a restart while Redis is down cannot reopen
 * payouts or registration.
 */
export class FlagClient {
  constructor(private backend: FlagBackend, private keys: Record<string, KeyObject>, private stateFile: string, private onAlert: (m: string) => void = () => {}) {}

  private disk(): SignedFlags {
    try {
      return existsSync(this.stateFile) ? (JSON.parse(readFileSync(this.stateFile, 'utf8')) as SignedFlags) : {};
    } catch {
      return {};
    }
  }

  private save(all: SignedFlags): void {
    const tmp = `${this.stateFile}.tmp`;
    writeFileSync(tmp, JSON.stringify(all));
    renameSync(tmp, this.stateFile);
  }

  async get(name: string): Promise<{ value: string; source: 'store' | 'local_disk' | 'safest_default' }> {
    const disk = this.disk();
    const local = disk[name] && verifyFlag(disk[name], this.keys) ? disk[name] : undefined;
    let remote: SignedFlag | null = null;
    try {
      remote = await this.backend.get(name);
    } catch {
      remote = null;
    }
    if (remote && !verifyFlag(remote, this.keys)) {
      this.onAlert(`unsigned or invalid write to flag ${name} refused`);
      remote = null;
    }
    if (remote && local && local.version > remote.version) {
      this.onAlert(`older version of flag ${name} refused`);
      remote = null;
    }
    if (remote) {
      this.save({ ...disk, [name]: remote });
      return { value: remote.value, source: 'store' };
    }
    if (local) return { value: local.value, source: 'local_disk' };
    this.onAlert(`flag ${name} missing: holding the safest value`);
    return { value: SAFEST[name] ?? '', source: 'safest_default' };
  }

  /** Signed runtime flags for resolve(): RUNTIME_POSTURE moves the fleet to lockdown with no deploy (F4). */
  async runtime(names: string[] = ['DETECTION_MODE', 'RUNTIME_POSTURE']): Promise<SignedFlags> {
    const out: SignedFlags = {};
    for (const n of names) {
      const r = await this.get(n);
      out[n] = { name: n, value: r.value, version: 0, issued_at: 0, signature: null };
    }
    return out;
  }
}
