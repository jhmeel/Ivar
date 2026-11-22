// Public types of the Express SDK.

import type { Request } from 'express';

export type Mode = 'observe' | 'enforce';

export interface IvarOptions {
  /** Observe mode records decisions without affecting a request (section 8.2). */
  mode: Mode;
  /** Who is acting. Hashed with the deployment key before it leaves the process. */
  identity: (req: Request) => string | undefined | null;
  /** Session id, when the app has one. */
  session?: (req: Request) => string | undefined | null;
  /** Roles of the caller, for positive security on privileged fields. */
  roles?: (req: Request) => string[] | undefined;
  /** Tenant or business unit for per business invariants. */
  tenant?: (req: Request) => string | undefined;
  /** Core ingest endpoint. When unset, the core runs embedded in this process. */
  coreUrl?: string;
  /** The sensor token the core issued for this sensor id (`ivar-core token sensor`). */
  coreToken?: string;
  /** Verified PolicyContent. Defaults to the spec default policy. Prefer policyBundle. */
  policy?: unknown;
  /** Signed policy bundle (base64 archive from ivar-control build), verified before use. */
  policyBundle?: string;
  /** Trusted policy keys (the keyring JSON) that policyBundle and refreshes must verify against. */
  policyKeyring?: unknown;
  /** Control plane URL. The SDK polls it for newer signed policy, so a signed change such as
   *  DETECTION_MODE or the runtime posture reaches the app with no deploy. */
  controlUrl?: string;
  /** Poll period for controlUrl, milliseconds. Defaults to 30 seconds. */
  policyRefreshMs?: number;
  /** Where the last verified bundle is kept, so a restart while the control plane is down keeps it. */
  policyStateFile?: string;
  /** Deployment key for keyed identifier hashes, hex. */
  redactionKey?: string;
  sensorId?: string;
  /** Routes under these prefixes fail closed when the check fails. */
  adminPrefixes?: string[];
  /** Added latency budget on the request path, milliseconds (section 18: under 1 ms at p99). */
  budgetMs?: number;
  /** Called on alerts: SDK faults, fail open, refused actions. */
  onAlert?: (alert: Alert) => void;
  /** Respond to a challenge (step up verification). Defaults to 401 with a step up header. */
  onChallenge?: (req: Request, res: import('express').Response, verdict: Verdict) => void;
}

export interface Alert {
  kind: 'sdk_fault' | 'fail_open' | 'action_refused' | 'invariant_breach' | 'time_lock' | 'budget_exceeded' | 'policy_applied' | 'policy_rejected' | 'client_ip_unverified';
  message: string;
  details?: unknown;
}

export interface Verdict {
  verdict_id: string;
  decision: 'allow' | 'record' | 'throttle' | 'challenge' | 'block' | 'contain' | 'refuse';
  entity?: { type: string; id: string };
  risk: number;
  reasons: string[];
  sources: string[];
  policy_version: string;
  expires_at: number;
  mode: Mode;
  ladder_level: number;
}

export interface GuardOptions {
  /** INTENT_BINDING for this sink. Defaults to the policy's mode for the action. */
  intentBinding?: 'off' | 'observe' | 'enforce';
  /** Business value moved by this action, in minor units. */
  value?: (req: Request) => number;
  records?: (req: Request) => number;
  destructive?: boolean;
  /** The subject the intent was minted for. Defaults to the session, then the identity. */
  subject?: (req: Request) => string | undefined;
  payload?: (req: Request) => unknown;
}

export interface PolicyStatus {
  version: number;
  policyVersion: string;
  source: 'default' | 'options' | 'bundle' | 'state_file' | 'control_plane';
}

export interface IntentKeys {
  /** Root public key of the intent issuer, hex. */
  rootPublicKey: string;
  /** Step name to the public key that must attest it. */
  stepKeys: Record<string, string>;
}
