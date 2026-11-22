//! Edge filter logic, independent of the proxy host.

use crate::config::EdgeConfig;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ivar_contracts::sign::verify_policy;
use ivar_contracts::{PolicyBundle, PolicyContent, SecurityEvent, Verdict};
use ivar_core::detect::vocabulary as v;
use ivar_core::failure::{EventBuffer, FailOpenBudget, FailOpenDecision};
use ivar_core::redact::Redactor;
use ivar_core::sensor::{ocsf_class, EventBuilder, LocalDecision, SensorPolicy};

/// What the host should do with the request.
#[derive(Debug, Clone, PartialEq)]
pub enum EdgeAction {
    Continue,
    Respond { status: u32, body: String, headers: Vec<(String, String)> },
}

/// The parts of a request the filter reads.
#[derive(Debug, Clone, Default)]
pub struct RequestView {
    pub method: String,
    pub path: String,
    pub client_ip: String,
    pub user_agent: String,
    pub request_id: String,
    pub content_type: String,
    pub session: String,
    pub engine_alerts: Vec<String>,
}

const HEARTBEAT_MS: i64 = 20_000;

pub struct EdgeLogic {
    pub cfg: EdgeConfig,
    sensor: Option<SensorPolicy>,
    policy_version: u64,
    policy_label: String,
    budget: FailOpenBudget,
    outbox: EventBuffer<SecurityEvent>,
    /// The batch sent and not yet acknowledged; requeued if the call fails.
    unacked: Vec<SecurityEvent>,
    /// Position in the core's verdict feed (see ivar-server feed).
    verdict_cursor: u64,
    last_heartbeat: i64,
    redactor: Redactor,
    seq: u64,
    /// When the filter started; see STARTUP_GRACE_MS.
    started_at: i64,
}

/// A filter that has just started has no verified policy until its first
/// fetch from the control plane. For this long, public routes pass instead
/// of counting against the fail open budget, so a rolling restart does not
/// throttle customers; admin routes still fail closed.
pub const STARTUP_GRACE_MS: i64 = 10_000;



#[derive(Debug, PartialEq)]
pub enum PolicyUpdate {
    Applied { version: u64 },
    /// Signature invalid, rollback or expired: the current policy stays.
    Rejected { reason: String },
}

fn respond(status: u32, error: &str, verdict: Option<&Verdict>) -> EdgeAction {
    let body = serde_json::json!({ "error": error, "verdict_id": verdict.map(|v| v.verdict_id.clone()) }).to_string();
    let mut headers = vec![("content-type".to_string(), "application/json".to_string())];
    if status == 401 {
        headers.push(("www-authenticate".into(), "step-up".into()));
    }
    if status == 429 {
        headers.push(("retry-after".into(), "1".into()));
    }
    EdgeAction::Respond { status, body, headers }
}

impl EdgeLogic {
    pub fn new(cfg: EdgeConfig, now: i64) -> Self {
        let redactor = Redactor::new(&hex::decode(&cfg.redaction_key_hex).unwrap_or_default());
        let mut logic = EdgeLogic {
            budget: FailOpenBudget::new(cfg.fail_open_budget_pct),
            outbox: EventBuffer::new(cfg.max_outbox),
            unacked: Vec::new(),
            verdict_cursor: 0,
            last_heartbeat: i64::MIN / 2,
            sensor: None,
            policy_version: 0,
            policy_label: String::new(),
            redactor,
            seq: 0,
            started_at: now,
            cfg,
        };
        if !logic.cfg.policy_bundle_base64.is_empty() {
            let b = logic.cfg.policy_bundle_base64.clone();
            let _ = logic.apply_bundle(&b, now);
        }
        logic
    }

    pub fn policy_version(&self) -> (u64, &str) {
        (self.policy_version, &self.policy_label)
    }

    /// DETECTION_MODE is a signed runtime setting: the filter blocks only
    /// when the verified policy says enforce. The local mode is a ceiling,
    /// so a filter deployed in observe for rollout phase 1 never blocks.
    fn enforce(&self) -> bool {
        self.cfg.mode == "enforce" && self.sensor.as_ref().map(|s| s.enforce).unwrap_or(false)
    }

    /// Verify and apply a signed policy bundle. An invalid signature, an older
    /// version or an expired bundle is rejected and the current policy kept.
    pub fn apply_bundle(&mut self, archive_base64: &str, now: i64) -> PolicyUpdate {
        let reject = |reason: String| PolicyUpdate::Rejected { reason };
        let Ok(bytes) = B64.decode(archive_base64.trim()) else { return reject("not base64".into()) };
        let bundle = match PolicyBundle::from_archive(&bytes) {
            Ok(b) => b,
            Err(e) => return reject(e.to_string()),
        };
        if let Err(e) = verify_policy(&self.cfg.keyring, &bundle) {
            return reject(e.to_string());
        }
        if bundle.content.version < self.policy_version {
            return reject(format!("rollback from {} to {} refused", self.policy_version, bundle.content.version));
        }
        if bundle.content.expires_at < now {
            return reject("expired bundle refused".into());
        }
        match self.apply_policy(&bundle.content) {
            Ok(()) => PolicyUpdate::Applied { version: bundle.content.version },
            Err(reason) => reject(reason),
        }
    }

    fn apply_policy(&mut self, p: &PolicyContent) -> Result<(), String> {
        self.sensor = Some(SensorPolicy::try_from_policy(p)?);
        self.policy_version = p.version;
        self.policy_label = p.policy_version.clone();
        Ok(())
    }

    fn admin(&self, path: &str) -> bool {
        self.cfg.admin_prefixes.iter().any(|p| path.starts_with(p.as_str()))
    }

    /// Build an event for this request. Only events sent to the core consume
    /// a sequence number (`sent`), so a gap in the sequence always means an
    /// event was lost, never a local check (section 13.2).
    fn event(&mut self, r: &RequestView, body_keys: &[&str], status: u32, now: i64, sent: bool) -> SecurityEvent {
        if sent {
            self.seq += 1;
        }
        let mut b = EventBuilder::new(ocsf_class::HTTP_ACTIVITY, v::HTTP_REQUEST, now, &self.cfg.sensor_id, "edge", self.seq)
            .src_ip(&r.client_ip)
            .http(&r.method, &r.path, body_keys, status)
            .request_id(&r.request_id)
            .observation_point("edge");
        if !r.session.is_empty() {
            b = b.session(&r.session);
        }
        for a in &r.engine_alerts {
            b = b.engine_alert(a, 0.9);
        }
        let mut ev = b.build();
        if let Some(h) = ev.http_request.as_mut() {
            h.user_agent = r.user_agent.chars().take(256).collect();
        }
        self.redactor.apply(&mut ev, None, now);
        ev
    }

    fn decide(&mut self, ev: &SecurityEvent, now: i64, admin: bool, route: &str, request_id: &str) -> EdgeAction {
        let Some(sensor) = self.sensor.as_ref() else {
            // No verified policy yet: admin routes fail closed; the rest pass
            // while the first fetch is due, then within the fail open budget.
            if !admin && now - self.started_at < STARTUP_GRACE_MS {
                return EdgeAction::Continue;
            }
            return self.failure(route, request_id, admin);
        };
        let (verdict, _local) = match sensor.decide(ev, now) {
            LocalDecision::Block(v) => (v, true),
            LocalDecision::Cached(v) => (v, false),
            LocalDecision::Forward => return EdgeAction::Continue,
        };
        if !self.enforce() || verdict.mode != "enforce" {
            return EdgeAction::Continue;
        }
        match verdict.decision.as_str() {
            "block" | "contain" | "refuse" => respond(403, "request blocked", Some(&verdict)),
            "challenge" => respond(401, "step up verification required", Some(&verdict)),
            "throttle" => respond(429, "slow down", Some(&verdict)),
            _ => EdgeAction::Continue,
        }
    }

    /// The filter crashed or timed out on this request (section 11.2).
    pub fn failure(&mut self, route: &str, request_id: &str, admin: bool) -> EdgeAction {
        match self.budget.failed(route, request_id, admin) {
            FailOpenDecision::PassAndReinspect => EdgeAction::Continue,
            FailOpenDecision::FailClosed => respond(503, "security check unavailable", None),
            FailOpenDecision::ThrottleAndPage => respond(429, "route throttled to a safe rate", None),
        }
    }

    /// Request ids that passed uninspected and must be inspected again.
    pub fn reinspection(&mut self) -> Vec<String> {
        self.budget.drain_reinspection()
    }

    pub fn on_request_headers(&mut self, r: &RequestView, now: i64) -> EdgeAction {
        let admin = self.admin(&r.path);
        self.budget.inspected(&r.path);
        let ev = self.event(r, &[], 0, now, false);
        self.decide(&ev, now, admin, &r.path, &r.request_id)
    }

    /// Body stage: positive security on field names (mass assignment, role writes).
    pub fn on_request_body(&mut self, r: &RequestView, body: &[u8], now: i64) -> (EdgeAction, Vec<String>) {
        if !r.content_type.contains("json") || body.len() > self.cfg.max_body_bytes {
            return (EdgeAction::Continue, vec![]);
        }
        let keys: Vec<String> = serde_json::from_slice::<serde_json::Value>(body)
            .ok()
            .and_then(|v| v.as_object().map(|o| o.keys().take(64).cloned().collect()))
            .unwrap_or_default();
        let refs: Vec<&str> = keys.iter().map(String::as_str).collect();
        let ev = self.event(r, &refs, 0, now, false);
        let admin = self.admin(&r.path);
        (self.decide(&ev, now, admin, &r.path, &r.request_id), keys)
    }

    /// After the response: queue the event for the core.
    pub fn on_log(&mut self, r: &RequestView, body_keys: &[String], status: u32, now: i64) {
        let refs: Vec<&str> = body_keys.iter().map(String::as_str).collect();
        let ev = self.event(r, &refs, status, now, true);
        self.outbox.push(ev);
    }

    /// The batch to send to the core ingest gateway, as JSON.
    pub fn drain_outbox(&mut self) -> Option<Vec<u8>> {
        if self.outbox.is_empty() {
            return None;
        }
        let events = self.outbox.drain();
        let dropped = std::mem::take(&mut self.outbox.dropped);
        let body = serde_json::to_vec(&serde_json::json!({ "sensor_id": self.cfg.sensor_id, "dropped": dropped, "events": events, "verdict_cursor": self.verdict_cursor })).ok();
        self.unacked = events;
        body
    }

    /// Queue a heartbeat every 20 seconds, so a gateway worker with no
    /// traffic is not mistaken for a silenced one (tamper monitoring). A
    /// heartbeat carries the current sequence and does not consume one.
    pub fn heartbeat(&mut self, now: i64) {
        if now - self.last_heartbeat < HEARTBEAT_MS {
            return;
        }
        self.last_heartbeat = now;
        let ev = EventBuilder::new(ocsf_class::HTTP_ACTIVITY, v::SENSOR_HEARTBEAT, now, &self.cfg.sensor_id, "edge", self.seq).observation_point("edge").build();
        self.outbox.push(ev);
    }

    /// The last batch was not acknowledged (the core is down or answered an
    /// error): put it back so it is sent again, oldest first.
    pub fn requeue_unacked(&mut self) {
        let mut pending = std::mem::take(&mut self.unacked);
        pending.extend(self.outbox.drain());
        for ev in pending {
            self.outbox.push(ev);
        }
    }

    /// The verdict feed request for a tick with no events to send.
    pub fn feed_path(&self) -> String {
        format!("/v1/verdicts?since={}", self.verdict_cursor)
    }

    /// The policy refresh request.
    pub fn policy_path(&self) -> String {
        format!("/v1/policy/bundle?have={}", self.policy_version)
    }

    /// Verdicts from the core's ingest acknowledgement or the verdict feed.
    pub fn apply_ack(&mut self, ack: &[u8]) -> usize {
        self.unacked.clear();
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(ack) else { return 0 };
        if let Some(c) = v.get("verdict_cursor").and_then(|c| c.as_u64()) {
            self.verdict_cursor = self.verdict_cursor.max(c);
        }
        let verdicts: Vec<Verdict> = v.get("verdicts").and_then(|x| serde_json::from_value(x.clone()).ok()).unwrap_or_default();
        let n = verdicts.len();
        if let Some(s) = self.sensor.as_mut() {
            for v in verdicts {
                s.push_verdict(v);
            }
        }
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ivar_contracts::sign::{sign_policy, KeyPair, Keyring};
    use ivar_core::declare::compile_openapi;
    use ivar_core::policy::spec_default_policy;

    fn keys() -> (KeyPair, KeyPair, Keyring) {
        let a = KeyPair::ed25519_from_seed("policy-a", [1; 32]);
        let b = KeyPair::ed25519_from_seed("policy-b", [2; 32]);
        let mut ring = Keyring::default();
        ring.add(a.public(), &["policy"]);
        ring.add(b.public(), &["policy"]);
        (a, b, ring)
    }

    fn bundle(version: u64, signers: &[&KeyPair], weakens: bool) -> String {
        bundle_with_mode(version, signers, weakens, "enforce")
    }

    fn bundle_with_mode(version: u64, signers: &[&KeyPair], weakens: bool, detection_mode: &str) -> String {
        let mut p = spec_default_policy(0);
        p.settings.insert("detection_mode".into(), serde_json::json!(detection_mode));
        p.version = version;
        p.policy_version = format!("edge-{version}");
        p.weakens_protection = weakens;
        p.declared = compile_openapi("api.yaml", "openapi: 3.0.3\npaths:\n  /users/{id}:\n    patch:\n      requestBody:\n        content:\n          application/json:\n            schema: { type: object, properties: { name: { type: string }, role: { type: string, readOnly: true } } }\n").unwrap().to_value();
        B64.encode(sign_policy(&p, signers).unwrap().to_archive().unwrap())
    }

    fn logic(mode: &str) -> EdgeLogic {
        let (a, _, ring) = keys();
        EdgeLogic::new(EdgeConfig { mode: mode.into(), keyring: ring, policy_bundle_base64: bundle(5, &[&a], false), ..Default::default() }, 0)
    }

    fn req(path: &str) -> RequestView {
        RequestView { method: "GET".into(), path: path.into(), client_ip: "203.0.113.7".into(), request_id: "r1".into(), ..Default::default() }
    }

    #[test]
    fn blocks_decoy_route_and_privileged_field_in_enforce_mode() {
        let mut l = logic("enforce");
        assert!(matches!(l.on_request_headers(&req("/.env.backup"), 1), EdgeAction::Respond { status: 403, .. }));
        assert_eq!(l.on_request_headers(&req("/hello"), 1), EdgeAction::Continue);
        let mut r = req("/users/9");
        r.method = "PATCH".into();
        r.content_type = "application/json".into();
        let (a, keys) = l.on_request_body(&r, br#"{"name":"x","role":"admin"}"#, 1);
        assert!(matches!(a, EdgeAction::Respond { status: 403, .. }));
        assert_eq!(keys, vec!["name", "role"]);
    }

    #[test]
    fn observe_mode_never_blocks_and_reports() {
        let mut l = logic("observe");
        assert_eq!(l.on_request_headers(&req("/.env.backup"), 1), EdgeAction::Continue);
        l.on_log(&req("/.env.backup"), &[], 404, 2);
        let batch: serde_json::Value = serde_json::from_slice(&l.drain_outbox().unwrap()).unwrap();
        assert_eq!(batch["events"].as_array().unwrap().len(), 1);
        assert!(l.drain_outbox().is_none());
    }

    #[test]
    fn core_verdicts_apply_to_later_requests() {
        let mut l = logic("enforce");
        let observe = serde_json::json!({"verdicts": [{"verdict_id": "vrd_0", "decision": "contain", "mode": "observe", "entity": {"type": "ip", "id": "203.0.113.7"}, "expires_at": 0}]});
        assert_eq!(l.apply_ack(observe.to_string().as_bytes()), 1);
        assert_eq!(l.on_request_headers(&req("/hello"), 4), EdgeAction::Continue, "a verdict made in observe is recorded, never enforced");
        let ack = serde_json::json!({"verdicts": [{"verdict_id": "vrd_1", "decision": "contain", "mode": "enforce", "entity": {"type": "ip", "id": "203.0.113.7"}, "expires_at": 0}]});
        assert_eq!(l.apply_ack(ack.to_string().as_bytes()), 1);
        assert!(matches!(l.on_request_headers(&req("/hello"), 5), EdgeAction::Respond { status: 403, .. }));
    }

    #[test]
    fn policy_updates_are_verified() {
        let (a, b, _) = keys();
        let mut l = logic("enforce");
        let forged = KeyPair::ed25519_from_seed("policy-a", [9; 32]);
        assert!(matches!(l.apply_bundle(&bundle(6, &[&forged], false), 1), PolicyUpdate::Rejected { .. }));
        assert!(matches!(l.apply_bundle(&bundle(4, &[&a], false), 1), PolicyUpdate::Rejected { .. }), "rollback");
        assert!(matches!(l.apply_bundle(&bundle(6, &[&a], true), 1), PolicyUpdate::Rejected { .. }), "weakening needs two keys");
        assert_eq!(l.apply_bundle(&bundle(6, &[&a, &b], true), 1), PolicyUpdate::Applied { version: 6 });
        assert_eq!(l.policy_version().0, 6);
    }

    #[test]
    fn no_policy_fails_open_within_budget_and_admin_fails_closed() {
        let mut l = EdgeLogic::new(EdgeConfig { mode: "enforce".into(), ..Default::default() }, 0);
        assert!(matches!(l.on_request_headers(&req("/admin/users"), 1), EdgeAction::Respond { status: 503, .. }), "admin fails closed, even at startup");
        for _ in 0..50 {
            assert_eq!(l.on_request_headers(&req("/pay"), 1), EdgeAction::Continue, "public routes pass while the first policy fetch is due");
        }
        let after = STARTUP_GRACE_MS + 1;
        assert_eq!(l.on_request_headers(&req("/pay"), after), EdgeAction::Continue);
        assert!(matches!(l.on_request_headers(&req("/pay"), after), EdgeAction::Respond { status: 429, .. }), "then within the fail open budget");
        assert_eq!(l.reinspection(), vec!["r1"]);
    }

    #[test]
    fn signed_observe_mode_never_blocks_even_with_local_enforce() {
        let (a, _, ring) = keys();
        let mut l = EdgeLogic::new(EdgeConfig { mode: "enforce".into(), keyring: ring, policy_bundle_base64: bundle_with_mode(5, &[&a], false, "observe"), ..Default::default() }, 0);
        let r = RequestView { method: "PATCH".into(), path: "/users/7".into(), client_ip: "198.51.100.9".into(), content_type: "application/json".into(), ..Default::default() };
        let (action, _) = l.on_request_body(&r, br#"{"role":"admin"}"#, 1_000);
        assert!(matches!(action, EdgeAction::Continue), "observe records, it never blocks");
    }

    #[test]
    fn unacknowledged_batches_are_requeued_and_the_feed_cursor_advances() {
        let mut l = logic("enforce");
        l.on_log(&req("/hello"), &[], 200, 1);
        let first: serde_json::Value = serde_json::from_slice(&l.drain_outbox().unwrap()).unwrap();
        assert_eq!(first["verdict_cursor"], 0);
        l.requeue_unacked();
        let again: serde_json::Value = serde_json::from_slice(&l.drain_outbox().unwrap()).unwrap();
        assert_eq!(again["events"].as_array().unwrap().len(), 1, "the lost batch is sent again");
        let ack = serde_json::json!({"verdicts": [{"verdict_id": "vrd_9", "decision": "contain", "mode": "enforce", "entity": {"type": "ip", "id": "198.51.100.9"}, "expires_at": 0}], "verdict_cursor": 42});
        assert_eq!(l.apply_ack(ack.to_string().as_bytes()), 1);
        assert!(l.drain_outbox().is_none(), "acknowledged: nothing left to resend");
        assert_eq!(l.feed_path(), "/v1/verdicts?since=42");
        assert_eq!(l.policy_path(), "/v1/policy/bundle?have=5");
        let mut r = req("/hello");
        r.client_ip = "198.51.100.9".into();
        assert!(matches!(l.on_request_headers(&r, 5), EdgeAction::Respond { status: 403, .. }), "a containment learned from the feed is enforced");
    }

    #[test]
    fn only_sent_events_consume_sequence_numbers() {
        let mut l = logic("enforce");
        l.on_request_headers(&req("/hello"), 1);
        l.on_log(&req("/hello"), &[], 200, 2);
        l.on_request_headers(&req("/hello"), 3);
        l.on_log(&req("/hello"), &[], 200, 4);
        l.heartbeat(5);
        let batch: serde_json::Value = serde_json::from_slice(&l.drain_outbox().unwrap()).unwrap();
        let seqs: Vec<u64> = batch["events"].as_array().unwrap().iter().map(|e| e["ivar"]["sensor_seq"].as_u64().unwrap()).collect();
        assert_eq!(seqs, vec![1, 2, 2], "two requests, then a heartbeat at the current sequence");
        l.heartbeat(6);
        assert!(l.drain_outbox().is_none(), "one heartbeat per period");
    }
}

