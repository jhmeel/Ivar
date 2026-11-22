//! Detection engine (section 10).
//!
//! Eight detection methods feed one risk score per entity, so a block rests
//! on combined evidence. Each method is a separate `Detector`; new methods
//! arrive as detector plugins through the same trait.

mod baselines;
mod catalog;
mod deception;
mod drift;
mod entities;
mod invariants;
mod ml;
mod positive_security;
mod sequence;
mod signatures;
pub mod vocabulary;

pub use baselines::BaselineDetector;
pub use catalog::{default_rules, RuleCatalog};
pub use deception::{DeceptionDetector, DecoyContextMismatch};
pub use drift::DriftDetector;
pub use entities::{actor_entities, target_entities};
pub use invariants::InvariantDetector;
pub use ml::MlDetector;
pub use positive_security::PositiveSecurityDetector;
pub use sequence::SequenceDetector;
pub use signatures::SignatureDetector;

use crate::declare::Declarations;
use crate::ids;
use crate::trust::ObservationOutcome;
use ivar_contracts::{DetectionMethodName, EntityRef, Finding, PolicyContent, SecurityEvent};

/// Everything a detector may read while judging one event.
pub struct DetectContext<'a> {
    pub policy: &'a PolicyContent,
    pub rules: &'a RuleCatalog,
    pub declared: &'a Declarations,
    pub trust: Option<&'a ObservationOutcome>,
    pub evidence_id: &'a str,
    pub now: i64,
    /// Baselines only learn after the compromise assessment (section 16.1).
    pub baselines_may_learn: bool,
    /// Keyed hashing of identifiers, so detectors can compare policy values
    /// (honey account names) with redacted event values.
    pub redactor: &'a crate::redact::Redactor,
}

/// One detection method.
pub trait Detector: Send {
    fn name(&self) -> &'static str;
    fn method(&self) -> DetectionMethodName;
    fn detect(&mut self, ctx: &DetectContext, ev: &SecurityEvent) -> Vec<Finding>;
    /// Forget per entity state last touched before `before` (event time).
    /// Called on a fixed event time schedule, so a replay forgets the same.
    fn evict_idle(&mut self, _before: i64) {}
}

/// Build a finding for a catalog rule. Returns None when the rule is unknown
/// or disabled in the policy.
pub(crate) fn finding(
    ctx: &DetectContext,
    ev: &SecurityEvent,
    rule_id: &str,
    entities: Vec<EntityRef>,
    explanation: String,
) -> Option<Finding> {
    finding_with_confidence(ctx, ev, rule_id, entities, explanation, None)
}

pub(crate) fn finding_with_confidence(
    ctx: &DetectContext,
    ev: &SecurityEvent,
    rule_id: &str,
    entities: Vec<EntityRef>,
    explanation: String,
    confidence: Option<f64>,
) -> Option<Finding> {
    let rule = ctx.rules.get(rule_id)?;
    let ext = ev.ext();
    let source_event = if ext.request_id.is_empty() { ctx.evidence_id.to_string() } else { format!("req:{}", ext.request_id) };
    let critical = rule.params.get("critical_positive_security").and_then(|v| v.as_bool()).unwrap_or(false);
    let deception = rule.method == DetectionMethodName::Deception
        && rule.params.get("contain").and_then(|v| v.as_bool()).unwrap_or(true);
    Some(Finding {
        finding_id: ids::derive("fnd", &[ctx.evidence_id, rule_id]),
        rule: rule_id.to_string(),
        rule_family: rule.family.clone(),
        technique: rule.technique.clone(),
        method: rule.method.to_proto() as i32,
        confidence: confidence.unwrap_or(rule.confidence).clamp(0.0, 1.0),
        severity: rule.severity,
        evidence_ids: vec![ctx.evidence_id.to_string()],
        entities,
        observation_point: if ext.observation_point.is_empty() { ext.sensor_id.clone() } else { ext.observation_point.clone() },
        time: ctx.now,
        critical_positive_security: critical,
        deception_hit: deception,
        attack_stage: rule.attack_stage.clone(),
        explanation,
        source_event,
    })
}
