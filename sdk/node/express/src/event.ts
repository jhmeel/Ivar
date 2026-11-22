// Express request to OCSF SecurityEvent with the IVAR extension.

import type { Request } from 'express';
import { bodyKeys, keyedHash, safeAttributes } from './redact';
import type { IvarOptions } from './types';

export const OCSF_HTTP_ACTIVITY = 4002;
export const OCSF_AUTHENTICATION = 3002;
export const OCSF_API_ACTIVITY = 6003;

let seq = 0;

export interface EventContext {
  activity: string;
  classUid: number;
  status?: number;
  success?: boolean;
  target?: string;
  businessAction?: string;
  value?: number;
  records?: number;
  destructive?: boolean;
  intentToken?: string;
  attributes?: Record<string, string>;
}

function clientIp(req: Request): string {
  // Express resolves X-Forwarded-For only when `trust proxy` is set, which is
  // how the real client IP is verified (phase 1 exit test).
  return req.ip ?? req.socket.remoteAddress ?? '';
}

/**
 * Build the OCSF event for a request. Only events sent to the core consume a
 * sequence number (`sent`), so a gap in the sequence always means a lost
 * event, never a local check (section 13.2).
 */
export function buildEvent(req: Request, opts: IvarOptions, ctx: EventContext, now: number, sent = true): Record<string, unknown> {
  const key = opts.redactionKey ?? '';
  const id = opts.identity(req) ?? '';
  const session = opts.session?.(req) ?? '';
  const roles = opts.roles?.(req) ?? [];
  const requestId = (req.headers['x-request-id'] as string | undefined) ?? (req as unknown as { ivarRequestId?: string }).ivarRequestId ?? '';
  if (sent) seq += 1;
  return {
    class_uid: ctx.classUid,
    category_uid: Math.floor(ctx.classUid / 1000),
    activity_id: 1,
    type_uid: ctx.classUid * 100 + 1,
    time: now,
    severity_id: 1,
    status_id: ctx.success === false ? 2 : 1,
    activity_name: ctx.activity,
    metadata: {
      version: '1.3.0',
      product: { name: 'ivar', vendor_name: 'ivar', version: '0.1.2' },
      extensions: [{ name: 'ivar', uid: '999', version: '1.0.0' }],
    },
    actor: {
      user: id ? { uid: key ? keyedHash(key, id) : id, type: 'human' } : undefined,
      session: session ? { uid: session } : undefined,
      authorizations: roles.join(','),
    },
    src_endpoint: { ip: clientIp(req) },
    http_request: { http_method: req.method, url_path: req.originalUrl.split('?')[0], user_agent: String(req.headers['user-agent'] ?? '').slice(0, 256), body_keys: bodyKeys(req.body) },
    http_response: ctx.status ? { code: ctx.status } : undefined,
    ivar: {
      sensor_id: opts.sensorId ?? 'express-sdk',
      sensor_type: 'app_sdk',
      observation_point: 'app_sdk',
      sensor_seq: seq,
      request_id: requestId,
      business_action: ctx.businessAction ?? '',
      intent_token: ctx.intentToken ?? '',
      target_entity: ctx.target ? (ctx.target.startsWith('user:') && key ? `user:${keyedHash(key, ctx.target.slice(5))}` : ctx.target) : '',
      value_moved: ctx.value ?? 0,
      records_read: ctx.records ?? 0,
      destructive: ctx.destructive ?? false,
      tenant: opts.tenant?.(req) ?? '',
      attributes: safeAttributes(ctx.attributes ?? {}),
    },
  };
}
