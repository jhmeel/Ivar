//! The deterministic decision core.

use super::observe::observation;
use super::output::{EngineOutput, ReviewedAction};
use crate::config::{DetectionMode, Settings};
use crate::declare::Declarations;
use crate::detect::{
    actor_entities, target_entities, vocabulary as v, BaselineDetector, DeceptionDetector, DetectContext, Detector, DriftDetector, InvariantDetector,
    MlDetector, PositiveSecurityDetector, RuleCatalog, SequenceDetector, SignatureDetector,
};
use crate::evidence::{EvidenceKind, EvidenceStore, MemoryEvidenceStore};
use crate::failure::TamperMonitor;
use crate::ids;
use crate::incident::IncidentTracker;
use crate::policy::{decide, AutoActionContext, CedarPolicy, Decision, DecisionInput};
use crate::redact::Redactor;
use crate::response::{plan_actions, LADDER};
use crate::risk::{RiskAssessment, RiskEngine};
use crate::safeguards::{review, BlastRadiusBudget, BreakerEvent, CircuitBreaker, ReviewContext, ReviewOutcome, SharedNetworks};
use crate::trust::TrustGraph;
use ivar_contracts::sign::KeyPair;
use ivar_contracts::{DetectionMethod, EntityRef, Finding, PolicyContent, SecurityEvent, TimelineEntry, Verdict};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

/// Accounts this old or older count as established for the blast radius budget.
const ESTABLISHED_AFTER_DAYS: u64 = 30;
/// Legitimate looking blocks within the breaker window that trip a changed rule.
const BREAKER_THRESHOLD: usize = 20;

pub struct CoreOptions {
    pub evidence_signer: Option<KeyPair>,
    pub redaction_key: Vec<u8>,
}

impl Default for CoreOptions {
    fn default() -> Self {
        CoreOptions { evidence_signer: None, redaction_key: b"ivar-default-redaction-key".to_vec() }
    }
}

pub struct DecisionCore<S: EvidenceStore = MemoryEvidenceStore> {
    policy: PolicyContent,
    settings: Settings,
    catalog: RuleCatalog,
    declared: Declarations,
    graph: TrustGraph,
    risk: RiskEngine,
    detectors: Vec<Box<dyn Detector>>,
    cedar: CedarPolicy,
    budget: BlastRadiusBudget,
    shared: SharedNetworks,
    breaker: CircuitBreaker,
    tamper: TamperMonitor,
    incidents: IncidentTracker,
    evidence: S,
    signer: Option<KeyPair>,
    redactor: Redactor,
    containments: BTreeMap<String, u32>,
    /// Distinct accounts seen behind each source address, up to the crowded
    /// threshold. An address carrying many accounts is a proxy, gateway or
    /// shared network, and is never contained (section 11.1).
    accounts_by_ip: BTreeMap<String, BTreeSet<String>>,
    /// Event time of the next idle sweep.
    next_sweep: i64,
}

#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("policy: {0}")]
    Policy(String),
}

fn default_detectors() -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(SignatureDetector),
        Box::new(PositiveSecurityDetector),
        Box::new(BaselineDetector::default()),
        Box::new(SequenceDetector::default()),
        Box::new(MlDetector::default()),
        Box::new(DeceptionDetector),
        Box::new(DriftDetector),
        Box::new(InvariantDetector::default()),
    ]
}

fn challengeable(ev: &SecurityEvent) -> bool {
    matches!(ev.activity_name.as_str(), v::AUTH_LOGIN | v::AUTH_SIGNUP | v::AUTH_PASSWORD_RESET)
        || matches!(ev.ext().business_action.as_str(), "login" | "payout" | "password_reset")
}

/// Distinct accounts behind one address that mark it as shared.
pub const CROWDED_ADDRESS_ACCOUNTS: usize = 10;
const MAX_TRACKED_ADDRESSES: usize = 200_000;
/// Per entity state untouched for this long (event time) is forgotten, so
/// memory follows active customers, not every customer ever seen.
pub const ENTITY_IDLE_MS: i64 = 90 * 24 * 3_600_000;
/// How often, in event time, idle state is swept.
const SWEEP_EVERY_MS: i64 = 3_600_000;

fn established(ev: &SecurityEvent) -> bool {
    let ext = ev.ext();
    ext.attributes.get("established").map(|e| e == "true").unwrap_or(false)
        || ext.attributes.get("account_age_days").and_then(|d| d.parse::<u64>().ok()).map(|d| d >= ESTABLISHED_AFTER_DAYS).unwrap_or(false)
}

fn confidence_class(a: &RiskAssessment) -> &'static str {
    if a.risk.deception_hit {
        "deception"
    } else if a.risk.independent_sources >= 3 && a.risk.has_high_confidence_source {
        "multi_source_high"
    } else if a.risk.has_high_confidence_source {
        "two_source_high"
    } else {
        "two_source"
    }
}

impl DecisionCore<MemoryEvidenceStore> {
    pub fn new(policy: PolicyContent, opts: CoreOptions) -> Result<Self, CoreError> {
        Self::with_store(policy, opts, MemoryEvidenceStore::default())
    }
}

impl<S: EvidenceStore> DecisionCore<S> {
    pub fn with_store(policy: PolicyContent, opts: CoreOptions, evidence: S) -> Result<Self, CoreError> {
        let settings = Settings::from_map(&policy.settings);
        let cedar = CedarPolicy::parse(&policy.cedar_policies).map_err(|e| CoreError::Policy(e.to_string()))?;
        let declared = Declarations::parse(&policy.declared).map_err(|e| CoreError::Policy(format!("declared intent does not parse: {e}")))?;
        let mut graph = TrustGraph::new();
        for e in &declared.edges {
            graph.declare(e.clone());
        }
        let mut thresholds = policy.thresholds.clone();
        thresholds.half_life_fast_secs = settings.risk_half_life_fast_secs;
        thresholds.half_life_slow_secs = settings.risk_half_life_slow_secs;
        Ok(DecisionCore {
            catalog: RuleCatalog::from_policy(&policy),
            risk: RiskEngine::new(&thresholds, &policy.method_weights),
            budget: BlastRadiusBudget::new(settings.auto_contain_max_users_pct),
            shared: SharedNetworks::new(&policy.shared_networks),
            breaker: CircuitBreaker::new(BREAKER_THRESHOLD),
            tamper: TamperMonitor::default(),
            incidents: IncidentTracker::default(),
            detectors: default_detectors(),
            redactor: Redactor::new(&opts.redaction_key),
            signer: opts.evidence_signer,
            containments: BTreeMap::new(),
            accounts_by_ip: BTreeMap::new(),
            next_sweep: 0,
            declared,
            graph,
            cedar,
            settings,
            policy,
            evidence,
        })
    }

    /// Apply a newly verified policy without losing the trust graph, risk,
    /// incidents or evidence. Rules whose content changed are handed to the
    /// circuit breaker so only they can return to observe mode.
    pub fn update_policy(&mut self, policy: PolicyContent, now: i64) -> Result<Vec<String>, CoreError> {
        // Validate everything before changing anything, so a refused policy
        // leaves the current one fully in force.
        let cedar = CedarPolicy::parse(&policy.cedar_policies).map_err(|e| CoreError::Policy(e.to_string()))?;
        let declared = Declarations::parse(&policy.declared).map_err(|e| CoreError::Policy(format!("declared intent does not parse: {e}")))?;
        let catalog = RuleCatalog::from_policy(&policy);
        let mut changed = Vec::new();
        for r in catalog.all() {
            if self.catalog.get(&r.rule_id) != Some(r) {
                changed.push(r.rule_id.clone());
            }
        }
        for id in &changed {
            self.breaker.rule_changed(id, now);
        }
        for e in &declared.edges {
            self.graph.declare(e.clone());
        }
        self.settings = Settings::from_map(&policy.settings);
        self.budget = BlastRadiusBudget::new(self.settings.auto_contain_max_users_pct);
        self.shared = SharedNetworks::new(&policy.shared_networks);
        self.cedar = cedar;
        self.catalog = catalog;
        self.declared = declared;
        self.seal(EvidenceKind::Policy, now, "", json!({"policy_version": policy.policy_version, "version": policy.version, "changed_rules": changed}));
        self.policy = policy;
        Ok(changed)
    }

    /// Seal evidence produced outside `process` (receipts, approvals) with
    /// this instance's evidence key, on the same hash chain.
    pub fn record_evidence(&mut self, kind: EvidenceKind, now: i64, payload: serde_json::Value) -> String {
        self.seal(kind, now, "", payload)
    }

    /// Add a detector plugin. Plugins run after the built in methods.
    pub fn add_detector(&mut self, d: Box<dyn Detector>) {
        self.detectors.push(d);
    }

    pub fn policy(&self) -> &PolicyContent {
        &self.policy
    }
    pub fn settings(&self) -> &Settings {
        &self.settings
    }
    pub fn graph(&self) -> &TrustGraph {
        &self.graph
    }
    pub fn graph_mut(&mut self) -> &mut TrustGraph {
        &mut self.graph
    }
    pub fn risk(&self) -> &RiskEngine {
        &self.risk
    }
    pub fn incidents(&self) -> &IncidentTracker {
        &self.incidents
    }
    pub fn evidence(&self) -> &S {
        &self.evidence
    }
    pub fn evidence_mut(&mut self) -> &mut S {
        &mut self.evidence
    }
    pub fn breaker_mut(&mut self) -> &mut CircuitBreaker {
        &mut self.breaker
    }

    fn seal(&mut self, kind: EvidenceKind, now: i64, hint: &str, payload: serde_json::Value) -> String {
        self.evidence.append(self.signer.as_ref(), kind, now, hint, payload)
    }

    fn mode(&self) -> &'static str {
        match self.settings.detection_mode {
            DetectionMode::Observe => "observe",
            DetectionMode::Enforce => "enforce",
        }
    }

    /// Judge one event. The event is redacted, sealed as evidence, used to
    /// update the trust fabric, run through every detection method, scored,
    /// decided by policy and reviewed by the safeguards.
    pub fn process(&mut self, ev: SecurityEvent, now: i64) -> EngineOutput {
        self.process_inner(ev, now, None)
    }

    /// Re judge an event already sealed in the evidence store, under its
    /// recorded evidence id. Used by the replay engine: ids derive from the
    /// recorded evidence, so records interleaved live (receipts, approvals,
    /// sink reports) cannot shift them.
    pub fn process_recorded(&mut self, ev: SecurityEvent, now: i64, evidence_id: &str) -> EngineOutput {
        self.process_inner(ev, now, Some(evidence_id.to_string()))
    }

    fn process_inner(&mut self, mut ev: SecurityEvent, now: i64, recorded: Option<String>) -> EngineOutput {
        if now >= self.next_sweep {
            // On a fixed event time schedule, never the wall clock, so a
            // replay of the same evidence forgets exactly what the live core did.
            if self.next_sweep > 0 {
                let before = now - ENTITY_IDLE_MS;
                for d in self.detectors.iter_mut() {
                    d.evict_idle(before);
                }
                self.budget.active_users(now);
            }
            self.next_sweep = (now / SWEEP_EVERY_MS + 1) * SWEEP_EVERY_MS;
        }
        self.redactor.apply(&mut ev, None, now);
        let ext = ev.ext();
        self.tamper.seen(&ext.sensor_id, now);
        if let Some(u) = ev.actor.as_ref().and_then(|a| a.user.as_ref()) {
            if !u.uid.is_empty() {
                self.budget.seen_user(&u.uid, now);
                if let Some(ip) = ev.src_endpoint.as_ref().map(|s| s.ip.clone()).filter(|ip| !ip.is_empty()) {
                    if self.accounts_by_ip.len() >= MAX_TRACKED_ADDRESSES && !self.accounts_by_ip.contains_key(&ip) {
                        self.accounts_by_ip.clear();
                    }
                    let seen = self.accounts_by_ip.entry(ip).or_default();
                    if seen.len() < CROWDED_ADDRESS_ACCOUNTS {
                        seen.insert(u.uid.clone());
                    }
                }
            }
        }
        if ev.activity_name == v::SENSOR_HEARTBEAT {
            return EngineOutput::default();
        }

        let evidence_id = match recorded {
            Some(id) => id,
            None => self.seal(EvidenceKind::Event, now, "", crate::evidence::compact(serde_json::to_value(&ev).unwrap_or_default())),
        };
        if let Some(e) = ev.ivar.as_mut() {
            e.evidence_id = evidence_id.clone();
            if e.declared_route.is_empty() {
                if let Some(r) = ev.http_request.as_ref().and_then(|r| self.declared.match_route(&r.http_method, &r.url_path)) {
                    e.declared_route = r.template.clone();
                }
            }
        }

        let est = established(&ev);
        for a in actor_entities(&ev) {
            if est && a.r#type == "user" {
                self.graph.ensure_node(&a).established = true;
            }
        }

        // Trust fabric.
        let trust = observation(&ev, now).map(|o| self.graph.observe(&o));

        // Detection.
        let ctx = DetectContext {
            policy: &self.policy,
            rules: &self.catalog,
            declared: &self.declared,
            trust: trust.as_ref(),
            evidence_id: &evidence_id,
            now,
            baselines_may_learn: self.settings.compromise_assessment_done,
            redactor: &self.redactor,
        };
        let mut findings: Vec<Finding> = Vec::new();
        for d in self.detectors.iter_mut() {
            findings.extend(d.detect(&ctx, &ev));
        }

        let mut out = EngineOutput { evidence_id: evidence_id.clone(), ..Default::default() };
        let mut enforced = Vec::new();
        for f in findings {
            let observe_rule = !self.catalog.enforced(&f.rule) || self.breaker.is_tripped(&f.rule);
            let fid = self.seal(EvidenceKind::Finding, now, "", serde_json::to_value(&f).unwrap_or_default());
            let mut f = f;
            f.evidence_ids.push(fid);
            if observe_rule {
                out.observe_only.push(f);
            } else {
                self.risk.add(&f);
                enforced.push(f);
            }
        }
        if let Some(t) = &trust {
            let edge_risk = enforced.iter().map(|f| f.confidence).fold(0.0, f64::max);
            if edge_risk > 0.0 {
                self.graph.set_edge_risk(&t.edge_id, edge_risk);
            }
        }

        // Entities to judge: everyone who acted, plus targets of findings.
        let mut entities: Vec<EntityRef> = actor_entities(&ev);
        for f in &enforced {
            for e in &f.entities {
                if !entities.iter().any(|x| x.key() == e.key()) {
                    entities.push(e.clone());
                }
            }
        }
        for t in target_entities(&ev) {
            if !entities.iter().any(|x| x.key() == t.key()) {
                entities.push(t);
            }
        }

        let can_challenge = challengeable(&ev);
        let mode = self.mode();
        let mut evidence_ids = vec![evidence_id.clone()];
        evidence_ids.extend(enforced.iter().flat_map(|f| f.evidence_ids.iter().skip(1).cloned()));
        let related = actor_entities(&ev);

        for entity in entities {
            let a = self.risk.assess(&entity.key(), now);
            if a.risk.score <= 0.0 && !a.risk.deception_hit {
                continue;
            }
            let (mut decision, _band, mut reasons) = decide(&DecisionInput { assessment: &a, thresholds: &self.policy.thresholds, challengeable: can_challenge });
            reasons.extend(self.reasons_for(&a));

            // Cedar: may the core take this action automatically?
            let protected = self.policy.protected_entities.iter().any(|p| p.entity.key() == entity.key());
            let cctx = AutoActionContext {
                ladder_level: decision.ladder_level(),
                risk: a.risk.score,
                independent_sources: a.risk.independent_sources,
                deception_hit: a.risk.deception_hit,
                target_only: a.risk.target_only,
                protected,
                ai_autonomy: self.settings.ai_autonomy.as_str().into(),
                runtime_posture: self.settings.runtime_posture.as_str().into(),
            };
            if !self.cedar.allow_auto("core", decision.as_str(), &entity.key(), &cctx).unwrap_or(false) && decision == Decision::Contain {
                reasons.push("policy does not allow automatic containment: request blocked, person asked".into());
                decision = Decision::Block;
            }

            let verdict_id = ids::derive("vrd", &[&evidence_id, &entity.key()]);
            let repeats = *self.containments.get(&entity.key()).unwrap_or(&0);
            let mut planned = plan_actions(decision, &entity, &related, &verdict_id, &evidence_ids, confidence_class(&a), now, repeats, mode);
            planned.retain(|p| {
                !out.actions.iter().any(|x| x.planned.request.target.as_ref().map(|t| t.key()) == p.request.target.as_ref().map(|t| t.key()) && x.planned.request.action == p.request.action)
            });
            for p in planned.iter_mut() {
                let est = p.request.target.as_ref().map(|t| self.graph.node(&t.key()).map(|n| n.established).unwrap_or(false) || est).unwrap_or(est);
                let crowded = p.request.target.as_ref().filter(|t| t.r#type == "ip").and_then(|t| self.accounts_by_ip.get(&t.id)).map(|s| s.len() >= CROWDED_ADDRESS_ACCOUNTS).unwrap_or(false);
                let outcome = review(p, &mut ReviewContext { assessment: &a, protected: &self.policy.protected_entities, shared: &self.shared, crowded, budget: &mut self.budget, established: est, now });
                match &outcome {
                    ReviewOutcome::Refused { reason } => {
                        reasons.push(format!("safeguard: {reason}"));
                        if decision == Decision::Contain {
                            decision = if can_challenge { Decision::Challenge } else { Decision::Block };
                        }
                    }
                    // The verdict follows the safeguard: sensors enforce the
                    // verdict, so a containment the safeguards downgraded or
                    // held for a person must not reach them as a containment.
                    ReviewOutcome::Downgraded { reason, to, .. } => {
                        reasons.push(format!("safeguard: {reason}"));
                        if decision == Decision::Contain {
                            decision = if to == "throttle" { Decision::Throttle } else if can_challenge { Decision::Challenge } else { Decision::Block };
                        }
                    }
                    ReviewOutcome::NeedsApproval { reason } => {
                        reasons.push(format!("safeguard: {reason}"));
                        if decision == Decision::Contain && p.request.ladder_level == 4 {
                            decision = if can_challenge { Decision::Challenge } else { Decision::Block };
                        }
                    }
                    ReviewOutcome::Allowed => {}
                }
                let aid = self.seal(EvidenceKind::ActionRequest, now, "", json!({"request": p.request, "review": format!("{:?}", outcome), "needs_approval": p.needs_approval}));
                p.request.evidence_ids.push(aid);
                if decision == Decision::Contain && p.request.ladder_level == 4 && matches!(outcome, ReviewOutcome::Allowed) {
                    *self.containments.entry(p.request.target.as_ref().map(|t| t.key()).unwrap_or_default()).or_insert(0) += 1;
                }
                out.actions.push(ReviewedAction { planned: p.clone(), review: outcome });
            }

            let rung = &LADDER[decision.ladder_level() as usize];
            let mut sources: Vec<String> = enforced
                .iter()
                .filter(|f| f.entities.iter().any(|e| e.key() == entity.key()))
                .map(|f| f.observation_point.clone())
                .collect();
            sources.sort();
            sources.dedup();
            let verdict = Verdict {
                verdict_id: verdict_id.clone(),
                decision: decision.as_str().into(),
                entity: Some(EntityRef { role: 0, ..entity.clone() }),
                risk: (a.risk.score * 100.0).round() / 100.0,
                reasons,
                sources,
                policy_version: self.policy.policy_version.clone(),
                expires_at: rung.expires_at(now, repeats),
                mode: mode.into(),
                evidence_ids: evidence_ids.clone(),
                time: now,
                ladder_level: decision.ladder_level(),
            };
            self.seal(EvidenceKind::Verdict, now, "", serde_json::to_value(&verdict).unwrap_or_default());
            if decision >= Decision::Block {
                self.feed_breaker(&enforced, &a, est, now);
            }

            // Incidents.
            let opens = decision == Decision::Contain || a.risk.deception_hit || enforced.iter().any(|f| f.critical_positive_security && f.entities.iter().any(|e| e.key() == entity.key()));
            let entry = TimelineEntry { time: now, kind: "verdict".into(), summary: format!("{} {} at risk {:.2}", decision.as_str(), entity.key(), a.risk.score), evidence_ids: evidence_ids.clone() };
            let stage = enforced.iter().map(|f| f.attack_stage.clone()).max().unwrap_or_default();
            let incident = if opens {
                Some(self.incidents.open_or_extend(&format!("{} on {}", stage.replace('_', " "), entity.key()), &stage, &related_with(&related, &entity), entry, &self.policy.policy_version, now))
            } else if decision >= Decision::Throttle {
                self.incidents.link(&related_with(&related, &entity), entry)
            } else {
                None
            };
            if let Some(id) = incident {
                self.incidents.add_verdict(&id, &verdict_id);
                for a in out.actions.iter().filter(|x| x.planned.request.verdict_id == verdict_id) {
                    self.incidents.add_action(&id, &a.planned.request.action_request_id);
                }
                if !out.incidents.contains(&id) {
                    out.incidents.push(id);
                }
            }
            out.risks.push(a.risk.clone());
            out.verdicts.push(verdict);
        }

        // Decoys fired out of context open an incident without containing anyone.
        for f in enforced.iter().filter(|f| f.rule == "decoy_out_of_context") {
            let entry = TimelineEntry { time: now, kind: "decoy_out_of_context".into(), summary: f.explanation.clone(), evidence_ids: f.evidence_ids.clone() };
            let id = self.incidents.open_or_extend("decoy used outside its issued context", "credential_theft", &f.entities, entry, &self.policy.policy_version, now);
            if !out.incidents.contains(&id) {
                out.incidents.push(id);
            }
        }

        self.risk.prune(now);
        out.findings = enforced;
        out
    }

    fn reasons_for(&self, a: &RiskAssessment) -> Vec<String> {
        let ledger = a.risk.entity.as_ref().and_then(|e| self.risk.ledger(&e.key()));
        let mut rules: Vec<String> = Vec::new();
        if let Some(l) = ledger {
            for c in l.acted.iter().chain(l.targeted.iter()) {
                if !rules.contains(&c.family) {
                    rules.push(c.family.clone());
                }
            }
        }
        rules
    }

    fn feed_breaker(&mut self, enforced: &[Finding], a: &RiskAssessment, established: bool, now: i64) {
        let legit = established && a.risk.independent_sources <= 1 && !a.risk.deception_hit;
        let ev = if legit { BreakerEvent::LegitimateLookingBlock } else { BreakerEvent::AttackBlock };
        for f in enforced {
            if self.breaker.record(&f.rule, ev, now) {
                self.seal(EvidenceKind::Policy, now, "", json!({"circuit_breaker": f.rule, "state": "observe"}));
            }
        }
    }

    /// An application error after a block counts toward the circuit breaker
    /// of the rules that produced the block.
    pub fn application_error(&mut self, rules: &[String], now: i64) {
        for r in rules {
            self.breaker.record(r, BreakerEvent::ApplicationError, now);
        }
    }

    /// A rule's content changed: the breaker watches it for the next window.
    pub fn rule_changed(&mut self, rule: &str, now: i64) {
        self.breaker.rule_changed(rule, now);
    }

    /// Record a sink decision (intent refusal, invariant breach, time lock)
    /// and open an incident when it needs one.
    pub fn record_sink(&mut self, subject: &EntityRef, decision: &serde_json::Value, open_incident: bool, now: i64) -> Option<String> {
        let eid = self.seal(EvidenceKind::SinkDecision, now, "", decision.clone());
        if !open_incident {
            return None;
        }
        let entry = TimelineEntry { time: now, kind: "sink".into(), summary: decision.get("outcome").map(|o| o.to_string()).unwrap_or_default(), evidence_ids: vec![eid] };
        Some(self.incidents.open_or_extend(&format!("action refused for {}", subject.key()), "impact", std::slice::from_ref(subject), entry, &self.policy.policy_version.clone(), now))
    }

    /// Periodic work: tamper alerts for sensors silent for 60 seconds.
    pub fn tick(&mut self, now: i64) -> Vec<String> {
        let silent = self.tamper.check(now);
        let mut opened = Vec::new();
        for s in &silent {
            let eid = self.seal(EvidenceKind::Tamper, now, "", json!({"sensor_id": s, "silent_for_ms": crate::failure::TAMPER_AFTER_MS}));
            let entry = TimelineEntry { time: now, kind: "tamper".into(), summary: format!("sensor {s} stopped reporting"), evidence_ids: vec![eid] };
            opened.push(self.incidents.open_or_extend(&format!("sensor {s} silent"), "defense_evasion", &[EntityRef::actor("sensor", s)], entry, &self.policy.policy_version.clone(), now));
        }
        opened
    }

    /// Findings that drift produced before any traffic: unused grants,
    /// undeclared edges, standing privilege and unowned machine identities.
    pub fn drift_report(&self) -> Vec<crate::trust::DriftItem> {
        self.graph.drift()
    }

    pub fn method_of(f: &Finding) -> DetectionMethod {
        DetectionMethod::try_from(f.method).unwrap_or(DetectionMethod::Unspecified)
    }
}

fn related_with(related: &[EntityRef], entity: &EntityRef) -> Vec<EntityRef> {
    let mut v: Vec<EntityRef> = related.iter().map(|e| EntityRef { role: 0, ..e.clone() }).collect();
    if !v.iter().any(|e| e.key() == entity.key()) {
        v.push(EntityRef { role: 0, ..entity.clone() });
    }
    v
}
