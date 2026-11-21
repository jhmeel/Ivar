//! Consequence invariants as a detection method: limits on outcomes such as
//! value moved, records read and destructive operations per window. They catch
//! any technique that ends in loss, including ones not yet known; the main
//! weakness is that limits must be set per business and they fire late in the
//! chain. The action sink enforces the same invariants inline; here the core
//! measures every observed outcome so a breach anywhere becomes a finding.

use super::{actor_entities, finding, DetectContext, Detector};
use crate::invariants::{InvariantCheck, InvariantEngine, Measured};
use ivar_contracts::{DetectionMethodName, Finding, SecurityEvent};

#[derive(Default)]
pub struct InvariantDetector {
    engine: Option<InvariantEngine>,
}

impl Detector for InvariantDetector {
    fn name(&self) -> &'static str {
        "consequence_invariants"
    }
    fn method(&self) -> DetectionMethodName {
        DetectionMethodName::ConsequenceInvariants
    }
    fn detect(&mut self, ctx: &DetectContext, ev: &SecurityEvent) -> Vec<Finding> {
        let ext = ev.ext();
        let engine = self.engine.get_or_insert_with(|| InvariantEngine::new(ctx.policy.invariants.clone()));
        let identity = ev
            .actor
            .as_ref()
            .and_then(|a| a.user.as_ref().map(|u| u.uid.clone()).filter(|u| !u.is_empty()).or_else(|| Some(a.app_name.clone())))
            .unwrap_or_default();
        let action = if ext.business_action.is_empty() { ev.activity_name.clone() } else { ext.business_action.clone() };
        let m = Measured {
            action: &action,
            identity: &identity,
            business: &ext.tenant,
            value_moved: ext.value_moved,
            records_read: ext.records_read as f64,
            destructive: ext.destructive,
        };
        let breach = match engine.check(&m, ctx.now) {
            InvariantCheck::Breach { invariant_id, used, limit, .. } => Some(format!("{invariant_id}: {used} of {limit}")),
            _ => {
                engine.record(&m, ctx.now, false);
                ext.attributes.get("invariant_breach").cloned()
            }
        };
        let Some(what) = breach else { return vec![] };
        let id = what.split(':').next().unwrap_or("").to_string();
        finding(ctx, ev, "invariant_breach", actor_entities(ev), format!("consequence invariant breached ({what})"))
            .map(|mut f| {
                f.rule_family = format!("consequence.{id}");
                f
            })
            .into_iter()
            .collect()
    }
}
