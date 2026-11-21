//! Declared intent drift: compare observed trust edges with those compiled
//! from schemas, infrastructure code, IAM and CI files. Best at new or unused
//! grants, undeclared egress and shadow routes; only as good as the
//! declarations teams keep current.

use super::{actor_entities, finding, vocabulary as v, DetectContext, Detector};
use ivar_contracts::{DetectionMethodName, Finding, SecurityEvent};

#[derive(Default)]
pub struct DriftDetector;

impl Detector for DriftDetector {
    fn name(&self) -> &'static str {
        "declared_intent_drift"
    }
    fn method(&self) -> DetectionMethodName {
        DetectionMethodName::DeclaredIntentDrift
    }
    fn detect(&mut self, ctx: &DetectContext, ev: &SecurityEvent) -> Vec<Finding> {
        let mut out = Vec::new();
        let ext = ev.ext();
        let actors = actor_entities(ev);
        if let Some(t) = ctx.trust {
            if t.undeclared && t.first_use {
                let rule = if ev.activity_name == v::NET_CONNECT && ext.attributes.get("service_to_service").map(|s| s == "true").unwrap_or(false) {
                    "new_service_path"
                } else {
                    "undeclared_edge"
                };
                out.extend(finding(ctx, ev, rule, actors.clone(), format!("trust edge {} is used but never declared", t.edge_id)));
            }
        }
        if !ext.egress_destination.is_empty() && ext.sensor_type != "build_runner" && !ctx.declared.egress.is_empty() {
            let holder = ext.attributes.get("holder").cloned().unwrap_or_default();
            if !ctx.declared.egress_declared(&holder, &ext.egress_destination) {
                out.extend(finding(ctx, ev, "undeclared_egress", actors, format!("outbound connection from {holder} to {} is not declared", ext.egress_destination)));
            }
        }
        out
    }
}
