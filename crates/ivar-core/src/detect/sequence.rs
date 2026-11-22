//! Sequence correlation: match ordered steps across entities and sensors.
//! Best at multi stage attacks; needs tuned time windows (rule params).

use super::{actor_entities, finding, target_entities, vocabulary as v, DetectContext, Detector};
use crate::time::SECOND_MS;
use ivar_contracts::{DetectionMethodName, Finding, SecurityEvent};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Timestamped values per key, trimmed to a window.
#[derive(Default)]
struct Window {
    items: BTreeMap<String, VecDeque<(i64, String)>>,
    fired: BTreeSet<String>,
}

impl Window {
    fn push(&mut self, key: &str, now: i64, value: &str, window_ms: i64) -> &VecDeque<(i64, String)> {
        let q = self.items.entry(key.to_string()).or_default();
        q.push_back((now, value.to_string()));
        while q.front().map(|(t, _)| now - t > window_ms).unwrap_or(false) {
            q.pop_front();
        }
        if q.len() == 1 {
            self.fired.remove(key);
        }
        q
    }

    fn recent(&self, key: &str, now: i64, window_ms: i64) -> usize {
        self.items.get(key).map(|q| q.iter().filter(|(t, _)| now - t <= window_ms).count()).unwrap_or(0)
    }

    /// Drop keys whose newest value is older than `before`: past every window.
    fn evict(&mut self, before: i64) {
        let fired = &mut self.fired;
        self.items.retain(|k, q| {
            let keep = q.back().map(|(t, _)| *t >= before).unwrap_or(false);
            if !keep {
                fired.remove(k);
            }
            keep
        });
    }

    /// Fire once per key until the window empties.
    fn fire_once(&mut self, key: &str) -> bool {
        self.fired.insert(key.to_string())
    }
}

/// Failed logins across every source, with running counts per source and per
/// account, so a surge spread thin over many addresses is visible without
/// rescanning the window on every event.
#[derive(Default)]
struct Surge {
    items: VecDeque<(i64, String, String)>,
    by_source: BTreeMap<String, u32>,
    by_account: BTreeMap<String, u32>,
}

impl Surge {
    fn push(&mut self, now: i64, source: &str, account: &str, window_ms: i64) {
        self.items.push_back((now, source.to_string(), account.to_string()));
        *self.by_source.entry(source.to_string()).or_default() += 1;
        *self.by_account.entry(account.to_string()).or_default() += 1;
        while let Some((t, s, a)) = self.items.front().cloned() {
            if now - t <= window_ms {
                break;
            }
            self.items.pop_front();
            for (map, key) in [(&mut self.by_source, s), (&mut self.by_account, a)] {
                if let Some(n) = map.get_mut(&key) {
                    *n -= 1;
                    if *n == 0 {
                        map.remove(&key);
                    }
                }
            }
        }
    }
}

fn distinct(q: &VecDeque<(i64, String)>) -> usize {
    q.iter().map(|(_, v)| v.as_str()).collect::<BTreeSet<_>>().len()
}

#[derive(Default)]
pub struct SequenceDetector {
    missing_routes: Window,
    failed_logins: Window,
    failed_by_account: Window,
    signups: Window,
    internal_hosts: Window,
    agent_hosts: Window,
    renames: Window,
    spraying_sources: BTreeMap<String, i64>,
    failed_everywhere: Surge,
    stuffing_sources: Window,
    refused_objects: Window,
}

impl SequenceDetector {
    fn evict(&mut self, before: i64) {
        for w in [&mut self.missing_routes, &mut self.failed_logins, &mut self.failed_by_account, &mut self.signups, &mut self.internal_hosts, &mut self.agent_hosts, &mut self.renames] {
            w.evict(before);
        }
        self.stuffing_sources.evict(before);
        self.refused_objects.evict(before);
        self.spraying_sources.retain(|_, t| *t >= before);
    }

    fn window_ms(ctx: &DetectContext, rule: &str, default_secs: u64) -> i64 {
        ctx.rules.param_u64(rule, "window_secs", default_secs) as i64 * SECOND_MS
    }
}

fn is_internal(ip: &str) -> bool {
    ip.parse::<std::net::IpAddr>()
        .map(|a| match a {
            std::net::IpAddr::V4(v4) => v4.is_private() || v4.is_loopback(),
            std::net::IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00,
        })
        .unwrap_or(false)
}

impl Detector for SequenceDetector {
    fn evict_idle(&mut self, before: i64) {
        self.evict(before);
    }
    fn name(&self) -> &'static str {
        "sequence_correlation"
    }
    fn method(&self) -> DetectionMethodName {
        DetectionMethodName::SequenceCorrelation
    }
    fn detect(&mut self, ctx: &DetectContext, ev: &SecurityEvent) -> Vec<Finding> {
        let mut out = Vec::new();
        let now = ctx.now;
        let actors = actor_entities(ev);
        let src = ev.src_endpoint.as_ref().map(|s| s.ip.clone()).unwrap_or_default();
        let ext = ev.ext();

        match ev.activity_name.as_str() {
            v::HTTP_REQUEST => {
                let undeclared = ctx
                    .http_route_missing(ev);
                if undeclared && !src.is_empty() {
                    let w = Self::window_ms(ctx, "route_scan_burst", 300);
                    let path = ev.http_request.as_ref().map(|r| r.url_path.clone()).unwrap_or_default();
                    let n = distinct(self.missing_routes.push(&src, now, &path, w));
                    if n as u64 >= ctx.rules.param_u64("route_scan_burst", "distinct_routes", 20) && self.missing_routes.fire_once(&src) {
                        out.extend(finding(ctx, ev, "route_scan_burst", actors.clone(), format!("{src} probed {n} missing routes")));
                    }
                }
                // Object enumeration (broken object level authorisation): one
                // caller refused many different objects on the same route.
                let refused = ev.http_response.as_ref().map(|r| matches!(r.code, 401 | 403 | 404)).unwrap_or(false);
                if refused && !undeclared {
                    if let Some(req) = &ev.http_request {
                        let caller = ev
                            .actor
                            .as_ref()
                            .and_then(|a| a.session.as_ref().map(|s| s.uid.clone()).filter(|s| !s.is_empty()).or_else(|| a.user.as_ref().map(|u| u.uid.clone()).filter(|u| !u.is_empty())))
                            .unwrap_or_else(|| src.clone());
                        let route = if ext.declared_route.is_empty() { req.url_path.rsplit_once('/').map(|(p, _)| p.to_string()).unwrap_or_default() } else { ext.declared_route.clone() };
                        if !caller.is_empty() {
                            let key = format!("{caller} {} {route}", req.http_method);
                            let w = Self::window_ms(ctx, "object_enumeration", 120);
                            let n = distinct(self.refused_objects.push(&key, now, &req.url_path, w));
                            if n as u64 >= ctx.rules.param_u64("object_enumeration", "distinct_objects", 10) && self.refused_objects.fire_once(&key) {
                                out.extend(finding(ctx, ev, "object_enumeration", actors.clone(), format!("{caller} was refused {n} different objects on {} {route}", req.http_method)));
                            }
                        }
                    }
                }
            }
            v::AUTH_LOGIN => {
                let targets = target_entities(ev);
                let account = targets.first().map(|t| t.id.clone()).or_else(|| ev.actor.as_ref().and_then(|a| a.user.as_ref()).map(|u| u.uid.clone())).unwrap_or_default();
                let w = Self::window_ms(ctx, "auth_spray", 600);
                let w2 = Self::window_ms(ctx, "login_after_failures", 600);
                if ev.status_id == 2 {
                    if !src.is_empty() {
                        let q = self.failed_logins.push(&src, now, &account, w);
                        let (count, accounts) = (q.len(), distinct(q));
                        if count as u64 >= ctx.rules.param_u64("auth_spray", "failures", 10)
                            && accounts as u64 >= ctx.rules.param_u64("auth_spray", "distinct_accounts", 5)
                        {
                            self.spraying_sources.insert(src.clone(), now);
                            if self.failed_logins.fire_once(&src) {
                                let mut ents = actors.clone();
                                ents.extend(targets.clone());
                                out.extend(finding(ctx, ev, "auth_spray", ents, format!("{src} sprayed {count} failed logins across {accounts} accounts")));
                            }
                        }
                    }
                    if !account.is_empty() {
                        self.failed_by_account.push(&account, now, &src, w2);
                    }
                    // Distributed stuffing: few failures per address and per
                    // account, many across them. While the surge lasts, every
                    // address that fails a login is part of it.
                    if !src.is_empty() {
                        let ws = Self::window_ms(ctx, "auth_stuffing_distributed", 300);
                        self.failed_everywhere.push(now, &src, &account, ws);
                        let f = &self.failed_everywhere;
                        let surge = f.items.len() as u64 >= ctx.rules.param_u64("auth_stuffing_distributed", "failures", 50)
                            && f.by_source.len() as u64 >= ctx.rules.param_u64("auth_stuffing_distributed", "distinct_sources", 20)
                            && f.by_account.len() as u64 >= ctx.rules.param_u64("auth_stuffing_distributed", "distinct_accounts", 20);
                        if surge {
                            self.spraying_sources.insert(src.clone(), now);
                            self.stuffing_sources.push(&src, now, &account, ws);
                            if self.stuffing_sources.fire_once(&src) {
                                let (n, sources, accounts) = (f.items.len(), f.by_source.len(), f.by_account.len());
                                out.extend(finding(ctx, ev, "auth_stuffing_distributed", actors.clone(), format!("{src} is one of {sources} addresses behind {n} failed logins across {accounts} accounts")));
                            }
                        }
                    }
                } else if ev.status_id == 1 {
                    let need = ctx.rules.param_u64("login_after_failures", "failures", 5) as usize;
                    let account_failures = self.failed_by_account.recent(&account, now, w2);
                    let from_sprayer = self.spraying_sources.get(&src).map(|t| now - t <= w2).unwrap_or(false);
                    if account_failures >= need || from_sprayer {
                        out.extend(finding(ctx, ev, "login_after_failures", actors.clone(), format!("login succeeded after {account_failures} failures{}", if from_sprayer { " from a spraying source" } else { "" })));
                    }
                }
            }
            v::AUTH_SIGNUP if !src.is_empty() => {
                let w = Self::window_ms(ctx, "signup_flood", 600);
                let n = self.signups.push(&src, now, &ctx.evidence_id.to_string(), w).len();
                if n as u64 >= ctx.rules.param_u64("signup_flood", "signups", 20) && self.signups.fire_once(&src) {
                    out.extend(finding(ctx, ev, "signup_flood", actors.clone(), format!("{n} signups from {src}")));
                }
            }
            v::NET_CONNECT => {
                let dst = ev.dst_endpoint.as_ref().map(|d| d.ip.clone()).unwrap_or_default();
                if is_internal(&dst) {
                    let holder = ev.device.as_ref().map(|d| d.hostname.clone()).filter(|h| !h.is_empty()).unwrap_or(src.clone());
                    let w = Self::window_ms(ctx, "internal_scan", 300);
                    let n = distinct(self.internal_hosts.push(&holder, now, &dst, w));
                    if n as u64 >= ctx.rules.param_u64("internal_scan", "distinct_hosts", 20) && self.internal_hosts.fire_once(&holder) {
                        out.extend(finding(ctx, ev, "internal_scan", actors.clone(), format!("{holder} connected to {n} internal hosts")));
                    }
                    let is_agent = ev.actor.as_ref().and_then(|a| a.user.as_ref()).map(|u| u.r#type == "agent" || u.r#type == "service").unwrap_or(false);
                    if is_agent {
                        let id = ev.actor.as_ref().and_then(|a| a.user.as_ref()).map(|u| u.uid.clone()).unwrap_or_default();
                        let w = Self::window_ms(ctx, "machine_speed_lateral", 60);
                        let n = distinct(self.agent_hosts.push(&id, now, &dst, w));
                        if n as u64 >= ctx.rules.param_u64("machine_speed_lateral", "distinct_hosts", 5) && self.agent_hosts.fire_once(&id) {
                            out.extend(finding(ctx, ev, "machine_speed_lateral", actors.clone(), format!("{id} reached {n} hosts within a minute")));
                        }
                    }
                }
            }
            v::FILE_RENAME | v::FILE_WRITE if ext.attributes.get("entropy_high").map(|e| e == "true").unwrap_or(ev.activity_name == v::FILE_RENAME) => {
                let host = ev.device.as_ref().map(|d| d.hostname.clone()).unwrap_or_default();
                let w = Self::window_ms(ctx, "mass_encryption", 60);
                let n = self.renames.push(&host, now, "", w).len();
                if n as u64 >= ctx.rules.param_u64("mass_encryption", "renames", 100) && self.renames.fire_once(&host) {
                    out.extend(finding(ctx, ev, "mass_encryption", actors.clone(), format!("{n} files rewritten on {host} within a minute")));
                }
            }
            _ => {}
        }
        out
    }
}

impl DetectContext<'_> {
    /// True when the request is for a route that is not declared.
    pub fn http_route_missing(&self, ev: &SecurityEvent) -> bool {
        let Some(req) = &ev.http_request else { return false };
        if self.declared.routes.is_empty() {
            return ev.http_response.as_ref().map(|r| r.code == 404).unwrap_or(false);
        }
        self.declared.match_route(&req.http_method, &req.url_path).is_none()
    }
}
