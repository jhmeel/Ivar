// @ivar/express: the IVAR application SDK for Express.
//
//   import { ivar } from '@ivar/express';
//   app.use(ivar({ mode: 'observe', identity: (req) => req.user?.id }));
//
// Observe mode records decisions without affecting a request. In enforce mode
// known attacks are blocked inside the SDK from cached, signed policy, and
// verdicts from the core apply to later requests. Scoring runs off the
// request path. A fault in the SDK fails open on public routes and raises an
// alert; admin routes fail closed (section 11.2).

import type { NextFunction, Request, RequestHandler, Response } from 'express';
import { randomUUID } from 'node:crypto';
import { Engine } from './engine';
import { buildEvent, EventContext, OCSF_API_ACTIVITY, OCSF_AUTHENTICATION, OCSF_HTTP_ACTIVITY } from './event';
import { INTENT_HEADER } from './intent';
import { ActionSink, SinkDecision, SinkRequest } from './sink';
import { HttpTransport, Transport } from './transport';
import { initialPolicy, persistPolicy, PolicyRefresher } from './policy';
import type { Alert, GuardOptions, IvarOptions, IntentKeys, PolicyStatus, Verdict } from './types';

export * from './types';
export { mintIntent, attestStep, narrowIntent, stepPublicKey, INTENT_HEADER } from './intent';
export { ActionSink } from './sink';
export { keyedHash } from './redact';
export { verifyBundle } from './policy';

export interface RequestIvar {
  /** Report a login attempt so spraying and takeover can be correlated. */
  login(result: { success: boolean; account: string }): void;
  /** Report a signup. */
  signup(result: { success: boolean; account?: string }): void;
  /** Report a business action such as a payout, role change or export. */
  action(name: string, details?: { value?: number; records?: number; destructive?: boolean; attributes?: Record<string, string> }): void;
  /** The verdict the SDK applied to this request, if any. */
  verdict?: Verdict;
}

declare module 'express-serve-static-core' {
  interface Request {
    ivar?: RequestIvar;
    ivarRequestId?: string;
  }
}

export interface IvarMiddleware extends RequestHandler {
  /** Action sink middleware: intent binding, consequence invariants and time locks. */
  guard(action: string, keys: IntentKeys, options?: GuardOptions): RequestHandler;
  engine: Engine;
  /** The policy in force and where it came from. */
  policy(): PolicyStatus;
  /** Poll the control plane now; resolves true when a newer signed policy was applied. */
  refreshPolicy(): Promise<boolean>;
  /** Stop timers and flush. */
  close(): void;
}

const DEFAULT_ADMIN_PREFIXES = ['/admin'];
/** Distinct identities behind one client address that suggest the address is a proxy. */
const CROWDED_IDENTITIES = 10;

/**
 * Phase 1 exit test: the real client IP is verified. Raises one alert when
 * forwarded headers arrive but Express does not trust a proxy, or when many
 * identities share one client address, both signs that every request is
 * attributed to the proxy rather than to the person behind it.
 */
function clientIpCheck(alert: (a: Alert) => void) {
  let warned = false;
  const byIp = new Map<string, Set<string>>();
  return (req: Request, identity: string | undefined | null) => {
    if (warned) return;
    if (req.headers['x-forwarded-for'] && !req.app.get('trust proxy')) {
      warned = true;
      alert({ kind: 'client_ip_unverified', message: "X-Forwarded-For arrives but Express does not trust a proxy: set app.set('trust proxy', <your gateway address>) so the real client IP is used" });
      return;
    }
    if (!identity || !req.ip) return;
    if (byIp.size > 10_000) byIp.clear();
    const seen = byIp.get(req.ip) ?? new Set<string>();
    seen.add(identity);
    byIp.set(req.ip, seen);
    if (seen.size >= CROWDED_IDENTITIES) {
      warned = true;
      alert({ kind: 'client_ip_unverified', message: `${seen.size} identities share client address ${req.ip}: it is probably a proxy; check 'trust proxy' covers every gateway hop`, details: { ip: req.ip } });
    }
  };
}

function alertSink(opts: IvarOptions): (a: Alert) => void {
  return opts.onAlert ?? ((a) => console.error(`[ivar] ${a.kind}: ${a.message}`));
}

export function ivar(opts: IvarOptions): IvarMiddleware {
  const alert = alertSink(opts);
  const budget = opts.budgetMs ?? 1;
  const adminPrefixes = opts.adminPrefixes ?? DEFAULT_ADMIN_PREFIXES;
  const source = { bundle: opts.policyBundle, keyring: opts.policyKeyring, controlUrl: opts.controlUrl, refreshMs: opts.policyRefreshMs, stateFile: opts.policyStateFile, sensorId: opts.sensorId ?? 'express-sdk' };
  const signed = initialPolicy(source, alert);
  const engine = new Engine(signed?.json ?? opts.policy, opts.redactionKey ?? '', !opts.coreUrl);
  if (signed) persistPolicy(source.stateFile, signed.archive);
  const parsedPolicy = JSON.parse(engine.policyJson);
  let status: PolicyStatus = { version: engine.policyVersion, policyVersion: String(parsedPolicy.policy_version ?? ''), source: signed?.source ?? (opts.policy ? 'options' : 'default') };
  const refresher = new PolicyRefresher(engine, source, alert, (s) => (status = s));
  refresher.start();
  const transport: Transport | undefined = opts.coreUrl
    ? new HttpTransport(opts.coreUrl, opts.sensorId ?? 'express-sdk', (vs) => vs.forEach((v) => engine.pushVerdict(v)))
    : undefined;

  const submit = (event: Record<string, unknown>) => {
    // Scoring runs off the request path.
    const activity = String(event.activity_name ?? '');
    const urgent = activity.startsWith('auth.') || activity === 'business.action';
    setImmediate(() => {
      try {
        if (transport) transport.send(event, urgent);
        else engine.process(event, Date.now());
      } catch (e) {
        alert({ kind: 'sdk_fault', message: String(e) });
      }
    });
  };

  const report = (req: Request, ctx: EventContext) => submit(buildEvent(req, opts, ctx, Date.now()));
  const checkClientIp = clientIpCheck(alert);

  const apply = (req: Request, res: Response, next: NextFunction, v: Verdict): void => {
    req.ivar!.verdict = v;
    switch (v.decision) {
      case 'block':
      case 'contain':
      case 'refuse':
        res.status(403).json({ error: 'request blocked', verdict_id: v.verdict_id });
        return;
      case 'challenge':
        if (opts.onChallenge) return opts.onChallenge(req, res, v);
        res.status(401).set('www-authenticate', 'step-up').json({ error: 'step up verification required', verdict_id: v.verdict_id });
        return;
      case 'throttle':
        res.status(429).set('retry-after', '1').json({ error: 'slow down', verdict_id: v.verdict_id });
        return;
      default:
        next();
    }
  };

  const middleware = ((req: Request, res: Response, next: NextFunction) => {
    const started = performance.now();
    const admin = adminPrefixes.some((p) => req.path.startsWith(p));
    req.ivarRequestId = (req.headers['x-request-id'] as string | undefined) ?? randomUUID();
    checkClientIp(req, opts.identity(req));
    req.ivar = {
      login: (r) => report(req, { activity: 'auth.login', classUid: OCSF_AUTHENTICATION, success: r.success, target: `user:${r.account}` }),
      signup: (r) => report(req, { activity: 'auth.signup', classUid: OCSF_AUTHENTICATION, success: r.success, target: r.account ? `user:${r.account}` : undefined }),
      action: (name, d = {}) =>
        report(req, { activity: 'business.action', classUid: OCSF_API_ACTIVITY, businessAction: name, value: d.value, records: d.records, destructive: d.destructive, attributes: d.attributes }),
    };
    let local;
    try {
      local = engine.decide(buildEvent(req, opts, { activity: 'http.request', classUid: OCSF_HTTP_ACTIVITY }, Date.now()), Date.now());
    } catch (e) {
      if (admin) {
        res.status(503).json({ error: 'security check unavailable' });
        alert({ kind: 'sdk_fault', message: `admin route failed closed: ${e}` });
        return;
      }
      alert({ kind: 'fail_open', message: String(e) });
      return next();
    }
    const elapsed = performance.now() - started;
    if (elapsed > budget) alert({ kind: 'budget_exceeded', message: `local decision took ${elapsed.toFixed(3)} ms`, details: { path: req.path } });

    res.on('finish', () => report(req, { activity: 'http.request', classUid: OCSF_HTTP_ACTIVITY, status: res.statusCode }));

    // DETECTION_MODE is signed runtime policy: block only when the local mode
    // and the verdict's signed mode both say enforce.
    if (local.verdict && opts.mode === 'enforce' && local.verdict.mode === 'enforce') return apply(req, res, next, local.verdict);
    if (local.verdict) req.ivar.verdict = { ...local.verdict, mode: 'observe' };
    next();
  }) as IvarMiddleware;

  middleware.engine = engine;
  middleware.policy = () => status;
  middleware.refreshPolicy = () => refresher.refresh();
  middleware.close = () => {
    refresher.stop();
    transport?.close();
  };

  middleware.guard = (action: string, keys: IntentKeys, g: GuardOptions = {}) => {
    const policy = JSON.parse(engine.policyJson);
    const perAction: Record<string, string> = { ...(policy.intent_binding ?? {}) };
    if (g.intentBinding) perAction[action] = g.intentBinding;
    const sink = new ActionSink(keys, policy.invariants ?? [], perAction[action] === undefined ? 'observe' : (perAction[action] as 'off' | 'observe' | 'enforce'), perAction);
    let seenVersion = engine.policyVersion;
    return (req: Request, res: Response, next: NextFunction) => {
      if (engine.policyVersion !== seenVersion && !g.intentBinding) {
        // A newer signed policy arrived: follow its INTENT_BINDING for this action.
        const mode = (JSON.parse(engine.policyJson).intent_binding ?? {})[action] as 'off' | 'observe' | 'enforce' | undefined;
        sink.setMode(action, mode ?? 'observe');
        seenVersion = engine.policyVersion;
      }
      const subject = g.subject?.(req) ?? opts.session?.(req) ?? opts.identity(req) ?? '';
      const sreq: SinkRequest = {
        action,
        subject,
        identity: opts.identity(req) ?? '',
        business: opts.tenant?.(req) ?? '',
        value_moved: g.value?.(req) ?? 0,
        records_read: g.records?.(req) ?? 0,
        destructive: g.destructive ?? false,
        intent_token: (req.headers[INTENT_HEADER] as string | undefined) ?? null,
        payload: g.payload?.(req) ?? null,
      };
      let d: SinkDecision;
      try {
        d = sink.guard(sreq);
      } catch (e) {
        // Action sinks guard irreversible actions: they fail closed.
        alert({ kind: 'sdk_fault', message: `action sink failed closed: ${e}` });
        res.status(503).json({ error: 'action check unavailable' });
        return;
      }
      report(req, {
        activity: 'business.action',
        classUid: OCSF_API_ACTIVITY,
        businessAction: action,
        value: sreq.value_moved,
        records: sreq.records_read,
        destructive: sreq.destructive,
        attributes: { sink_outcome: d.outcome.outcome, ...(d.would_refuse ? { would_refuse: d.would_refuse } : {}) },
      });
      switch (d.outcome.outcome) {
        case 'executes':
          if (d.would_refuse) alert({ kind: 'action_refused', message: `observe: would refuse ${action}: ${d.would_refuse}` });
          return next();
        case 'refused':
          alert({ kind: 'action_refused', message: `${action} refused: ${d.outcome.reason}` });
          res.status(403).json({ error: 'no valid intent chain for this action' });
          return;
        case 'blocked_alert':
          alert({ kind: 'invariant_breach', message: `${action} would breach ${d.outcome.invariant_id}`, details: d.outcome });
          res.status(409).json({ error: 'consequence limit reached', invariant: d.outcome.invariant_id });
          return;
        case 'held':
          alert({ kind: 'time_lock', message: `${action} held until ${new Date(d.outcome.lock.release_at).toISOString()}`, details: d.outcome.lock });
          res.status(202).json({ status: 'held', lock_id: d.outcome.lock.lock_id, release_at: d.outcome.lock.release_at });
          return;
      }
    };
  };

  return middleware;
}

export default ivar;
