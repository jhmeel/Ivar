//! Shared service state: the decision core, the policy, pending approvals,
//! and the queues that keep responders and sinks off the decision path.

use crate::responders::Responders;
use crate::sinks::{Outbound, Sink};
use crate::store::FileEvidenceStore;
use ivar_contracts::sign::{verify_policy, Keyring};
use ivar_contracts::{ActionReceipt, ActionRequest, EntityRef, PolicyBundle, PolicyContent, SecurityEvent, Verdict};
use ivar_core::engine::{CoreOptions, ReviewedAction};
use ivar_core::evidence::EvidenceKind;
use ivar_core::policy::{CedarPolicy, OperatorRequest};
use ivar_core::safeguards::ReviewOutcome;
use ivar_core::DecisionCore;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

pub fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

#[derive(Debug, Clone, Serialize)]
pub struct PendingApproval {
    pub request: ActionRequest,
    pub reason: String,
    pub approvers: BTreeSet<String>,
}

#[derive(Debug, Default, Clone, Serialize)]
pub struct Metrics {
    pub events_total: u64,
    pub verdicts_by_decision: BTreeMap<String, u64>,
    pub actions_total: u64,
    pub ingest_micros_total: u64,
    pub policy_rejected_total: u64,
}

pub struct Inner {
    pub core: DecisionCore<FileEvidenceStore>,
    pub policy_archive_b64: String,
    pub policy_history: BTreeMap<u64, PolicyContent>,
    pub pending: BTreeMap<String, PendingApproval>,
    pub metrics: Metrics,
    pub cedar: CedarPolicy,
    /// Standing verdicts for every enforcement point (crate::feed).
    pub feed: crate::feed::VerdictFeed,
}

pub struct AppState {
    pub inner: Mutex<Inner>,
    pub keyring: Keyring,
    pub redaction_key: Vec<u8>,
    pub public_url: String,
    pub expected_layers: Vec<String>,
    pub shard: u32,
    pub shards: u32,
    /// Signs ReplayBundles (section 13): the shard's evidence key, so the
    /// deployment keyring lists it with the evidence and replay roles.
    pub replay_key: ivar_contracts::sign::KeyPair,
    policy_dir: Option<std::path::PathBuf>,
    outbound: mpsc::Sender<Outbound>,
    actions: mpsc::Sender<ActionRequest>,
}

#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("{0}")]
    Invalid(String),
}

/// Verify a signed archive: signatures (two keys for weakening changes),
/// rollback and expiry.
pub fn verify_bundle(ring: &Keyring, archive_b64: &str, current_version: u64, now: i64) -> Result<PolicyContent, PolicyError> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};
    let bytes = B64.decode(archive_b64.trim()).map_err(|e| PolicyError::Invalid(e.to_string()))?;
    let b = PolicyBundle::from_archive(&bytes).map_err(|e| PolicyError::Invalid(e.to_string()))?;
    verify_policy(ring, &b).map_err(|e| PolicyError::Invalid(e.to_string()))?;
    if b.content.version < current_version {
        return Err(PolicyError::Invalid(format!("rollback from {current_version} to {} refused", b.content.version)));
    }
    if b.content.expires_at < now {
        return Err(PolicyError::Invalid("expired policy bundle refused".into()));
    }
    Ok(b.content)
}

pub struct StartOptions {
    pub evidence: FileEvidenceStore,
    pub policy_archive_b64: String,
    pub keyring: Keyring,
    pub evidence_key: ivar_contracts::sign::KeyPair,
    pub redaction_key: Vec<u8>,
    pub public_url: String,
    pub expected_layers: Vec<String>,
    pub sinks: Vec<Box<dyn Sink>>,
    pub responders: Responders,
    pub shard: u32,
    pub shards: u32,
    /// Where every applied policy bundle is kept by version. On restart the
    /// core resumes at the newest verified one, so a policy an operator
    /// pushed is never silently replaced by the older bundle in the config.
    pub policy_dir: Option<std::path::PathBuf>,
}

/// Verified bundles kept in `dir`, as (version, archive, content).
fn stored_policies(ring: &Keyring, dir: &std::path::Path) -> Vec<(u64, String, PolicyContent)> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else { return out };
    for e in entries.flatten() {
        let path = e.path();
        if path.extension().map(|x| x == "bundle").unwrap_or(false) {
            if let Ok(text) = std::fs::read_to_string(&path) {
                match verify_bundle(ring, &text, 0, now_ms()) {
                    Ok(p) => out.push((p.version, text.trim().to_string(), p)),
                    Err(e) => tracing::warn!(file = %path.display(), error = %e, "stored policy refused"),
                }
            }
        }
    }
    out.sort_by_key(|(v, _, _)| *v);
    out
}

fn store_policy(dir: &std::path::Path, version: u64, archive_b64: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!("{version}.bundle.tmp"));
    std::fs::write(&tmp, archive_b64.trim())?;
    std::fs::rename(tmp, dir.join(format!("{version}.bundle")))
}

impl AppState {
    pub fn start(o: StartOptions) -> anyhow::Result<Arc<Self>> {
        let configured = verify_bundle(&o.keyring, &o.policy_archive_b64, 0, now_ms()).map_err(|e| anyhow::anyhow!("startup policy rejected: {e}"))?;
        let stored = o.policy_dir.as_deref().map(|d| stored_policies(&o.keyring, d)).unwrap_or_default();
        let mut history: BTreeMap<u64, PolicyContent> = stored.iter().map(|(v, _, p)| (*v, p.clone())).collect();
        history.entry(configured.version).or_insert_with(|| configured.clone());
        let (policy, archive) = match stored.last() {
            Some((v, a, p)) if *v > configured.version => {
                tracing::info!(stored = v, configured = configured.version, "resuming at the newest verified policy");
                (p.clone(), a.clone())
            }
            _ => (configured.clone(), o.policy_archive_b64.trim().to_string()),
        };
        if let Some(d) = &o.policy_dir {
            store_policy(d, policy.version, &archive)?;
        }
        let cedar = CedarPolicy::parse(&policy.cedar_policies).map_err(|e| anyhow::anyhow!(e.to_string()))?;
        let replay_key = o.evidence_key.clone();
        let core = DecisionCore::with_store(policy.clone(), CoreOptions { evidence_signer: Some(o.evidence_key), redaction_key: o.redaction_key.clone() }, o.evidence)?;
        let (out_tx, out_rx) = mpsc::channel::<Outbound>();
        let (act_tx, act_rx) = mpsc::channel::<ActionRequest>();
        let state = Arc::new(AppState {
            inner: Mutex::new(Inner {
                core,
                policy_archive_b64: archive,
                policy_history: history,
                pending: BTreeMap::new(),
                metrics: Metrics::default(),
                cedar,
                feed: Default::default(),
            }),
            keyring: o.keyring,
            redaction_key: o.redaction_key,
            public_url: o.public_url,
            expected_layers: o.expected_layers,
            shard: o.shard,
            shards: o.shards,
            replay_key,
            policy_dir: o.policy_dir,
            outbound: out_tx,
            actions: act_tx,
        });
        let mut sinks = o.sinks;
        std::thread::Builder::new().name("ivar-sinks".into()).spawn(move || {
            for item in out_rx {
                for s in sinks.iter_mut() {
                    if let Err(e) = s.send(&item) {
                        tracing::warn!(sink = s.name(), error = %e, "sink failed");
                    }
                }
            }
        })?;
        let weak = Arc::downgrade(&state);
        let mut responders = o.responders;
        std::thread::Builder::new().name("ivar-responders".into()).spawn(move || {
            for req in act_rx {
                let receipt = responders.execute(&req, now_ms());
                match weak.upgrade() {
                    Some(s) => s.record_receipt(&req, receipt),
                    None => break,
                }
            }
        })?;
        Ok(state)
    }

    pub fn emit(&self, item: Outbound) {
        let _ = self.outbound.send(item);
    }

    fn record_receipt(&self, req: &ActionRequest, receipt: ActionReceipt) {
        let mut g = self.inner.lock().expect("state");
        g.core.record_evidence(EvidenceKind::ActionReceipt, receipt.time, serde_json::to_value(&receipt).unwrap_or_default());
        drop(g);
        let revokes = ["session.revoke", "user.lock", "user.suspend", "oauth_grant.revoke", "api_key.suspend", "agent.suspend"];
        if receipt.result == "done" && revokes.contains(&req.action.as_str()) {
            let subject = req.target.as_ref().map(|t| t.id.clone()).unwrap_or_default();
            let event_type = if req.action == "session.revoke" { crate::sinks::caep::SESSION_REVOKED } else { crate::sinks::caep::CREDENTIAL_CHANGE };
            self.emit(Outbound::Revocation { subject, reason: format!("{} by IVAR verdict {}", req.action, req.verdict_id), event_type: event_type.into() });
        }
    }

    fn dispatch(&self, actions: &[ReviewedAction], g: &mut Inner) {
        for a in actions {
            let req = a.planned.request.clone();
            match &a.review {
                ReviewOutcome::Allowed | ReviewOutcome::Downgraded { .. } if !a.planned.needs_approval => {
                    g.metrics.actions_total += 1;
                    let _ = self.actions.send(req);
                }
                ReviewOutcome::NeedsApproval { reason } => {
                    let url = format!("{}/v1/approvals/{}", self.public_url, req.action_request_id);
                    self.emit(Outbound::ApprovalNeeded { action_request: serde_json::to_value(&req).unwrap_or_default(), approve_url: url });
                    g.pending.insert(req.action_request_id.clone(), PendingApproval { request: req, reason: reason.clone(), approvers: BTreeSet::new() });
                }
                _ => {}
            }
        }
    }

    /// Judge a batch of events. Returns the verdicts for sensors to cache.
    /// Ingest a batch and answer with its verdicts plus, when the sensor
    /// sent a cursor, every standing verdict since it; returns the new cursor.
    pub fn ingest_with_feed(&self, events: Vec<SecurityEvent>, cursor: Option<u64>) -> (u64, Vec<Verdict>, u64) {
        let (accepted, mut verdicts) = self.ingest(events);
        let g = self.inner.lock().expect("state");
        if let Some(c) = cursor {
            for v in g.feed.since(c, now_ms()) {
                if !verdicts.iter().any(|x| x.verdict_id == v.verdict_id) {
                    verdicts.push(v);
                }
            }
        }
        (accepted, verdicts, g.feed.cursor())
    }

    /// Standing verdicts since `cursor`, for a sensor polling while idle.
    pub fn verdicts_since(&self, cursor: u64) -> (Vec<Verdict>, u64) {
        let g = self.inner.lock().expect("state");
        (g.feed.since(cursor, now_ms()), g.feed.cursor())
    }

    pub fn ingest(&self, events: Vec<SecurityEvent>) -> (u64, Vec<Verdict>) {
        let started = std::time::Instant::now();
        let mut verdicts = Vec::new();
        let mut accepted = 0;
        let mut g = self.inner.lock().expect("state");
        for ev in events {
            if crate::shard_of(&ev, self.shards) != self.shard {
                continue;
            }
            accepted += 1;
            let ocsf = serde_json::to_value(&ev).unwrap_or_default();
            let now = now_ms();
            let out = g.core.process(ev, now);
            g.metrics.events_total += 1;
            for v in &out.verdicts {
                *g.metrics.verdicts_by_decision.entry(v.decision.clone()).or_insert(0) += 1;
                g.feed.push(v);
                if v.decision != "record" {
                    self.emit(Outbound::Verdict { verdict: serde_json::to_value(v).unwrap_or_default() });
                }
            }
            for id in &out.incidents {
                if let Some(i) = g.core.incidents().get(id) {
                    self.emit(Outbound::Incident { incident: serde_json::to_value(i).unwrap_or_default() });
                }
            }
            self.emit(Outbound::Event { ocsf });
            self.dispatch(&out.actions, &mut g);
            verdicts.extend(out.verdicts.into_iter().filter(|v| v.decision != "record"));
        }
        g.metrics.ingest_micros_total += started.elapsed().as_micros() as u64;
        (accepted, verdicts)
    }

    /// An operator approves a pending action. Cedar decides per action; a
    /// destructive or fleet wide action needs two distinct approvers.
    pub fn approve(&self, id: &str, operator: &str, roles: Vec<String>, hardware_2fa: bool) -> Result<String, String> {
        let mut g = self.inner.lock().expect("state");
        let pending = g.pending.get(id).cloned().ok_or("unknown approval")?;
        let destructive = pending.request.ladder_level >= 5;
        let mut approvers = pending.approvers.clone();
        approvers.insert(operator.to_string());
        let cedar_action = match pending.request.ladder_level {
            6 => "killswitch",
            5 => "isolate",
            _ => "approve",
        };
        let req = OperatorRequest {
            operator: operator.into(),
            roles,
            action: cedar_action.into(),
            target: pending.request.target.as_ref().map(|t| t.key()).unwrap_or_default(),
            approvers: approvers.len() as u32,
            destructive_or_fleet_wide: destructive,
            hardware_2fa,
        };
        let need = if destructive { 2 } else { 1 };
        if approvers.len() < need {
            if !g.cedar.allow_operator(&OperatorRequest { approvers: 2, ..req.clone() }).unwrap_or(false) {
                return Err("operator is not authorised for this action".into());
            }
            g.pending.get_mut(id).expect("pending").approvers = approvers;
            return Ok("recorded; a second approver is required".into());
        }
        if !g.cedar.allow_operator(&req).unwrap_or(false) {
            return Err("operator is not authorised for this action".into());
        }
        let mut action = g.pending.remove(id).expect("pending").request;
        action.approval = Some(ivar_contracts::Approval { approved_by: operator.into(), approvers: approvers.into_iter().collect(), approved_at: now_ms() });
        action.evidence_captured_first = true;
        g.core.record_evidence(EvidenceKind::ActionRequest, now_ms(), serde_json::json!({ "approved": action }));
        g.metrics.actions_total += 1;
        let _ = self.actions.send(action);
        Ok("approved".into())
    }

    /// Apply a newly signed policy. An invalid signature, rollback or expiry
    /// is rejected and the current policy kept.
    pub fn update_policy(&self, archive_b64: &str) -> Result<u64, String> {
        let mut g = self.inner.lock().expect("state");
        let current = g.core.policy().version;
        let p = match verify_bundle(&self.keyring, archive_b64, current, now_ms()) {
            Ok(p) => p,
            Err(e) => {
                g.metrics.policy_rejected_total += 1;
                return Err(e.to_string());
            }
        };
        let cedar = CedarPolicy::parse(&p.cedar_policies).map_err(|e| e.to_string())?;
        g.core.update_policy(p.clone(), now_ms()).map_err(|e| e.to_string())?;
        g.cedar = cedar;
        g.policy_archive_b64 = archive_b64.trim().to_string();
        let v = p.version;
        if let Some(d) = &self.policy_dir {
            if let Err(e) = store_policy(d, v, archive_b64) {
                tracing::error!(error = %e, "applied policy could not be stored; a restart would resume at an older version");
            }
        }
        g.policy_history.insert(v, p);
        Ok(v)
    }

    /// Sink decisions reported by SDKs (intent refusals, invariant breaches, time locks).
    pub fn record_sink(&self, subject: EntityRef, decision: serde_json::Value) -> Option<String> {
        let open = decision.get("open_incident").and_then(|v| v.as_bool()).unwrap_or(false);
        if let Some(lock) = decision.pointer("/outcome/lock") {
            let url = format!("{}/v1/timelocks/{}", self.public_url, lock.get("lock_id").and_then(|v| v.as_str()).unwrap_or(""));
            self.emit(Outbound::TimeLock { lock: lock.clone(), cancel_url: url });
        }
        let mut g = self.inner.lock().expect("state");
        g.core.record_sink(&subject, &decision, open, now_ms())
    }
}
