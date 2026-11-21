//! Deception (sections 5.6, 10.3): decoy routes, canary tokens, honey
//! accounts, honey OAuth grants, canary environment variables and decoy AI
//! tools. Only an attacker reaches for them, so a hit is the cleanest high
//! confidence signal. Registered backup, indexing and scanning jobs that touch
//! decoys do not raise alarms. A decoy is bound to the context it was issued
//! for: a hit from elsewhere opens an incident instead of containing, so a
//! stolen honey token cannot be planted to get a victim contained.

use super::{actor_entities, finding, vocabulary as v, DetectContext, Detector};
use ivar_contracts::{DecoySpec, DetectionMethodName, Finding, SecurityEvent};

#[derive(Default)]
pub struct DeceptionDetector;

/// Marker returned alongside a finding when a decoy fired out of its context.
pub struct DecoyContextMismatch;

fn touched<'a>(decoys: &'a [DecoySpec], ev: &SecurityEvent, hash: &dyn Fn(&str) -> String) -> Option<&'a DecoySpec> {
    let ext = ev.ext();
    if ext.decoy_touched && !ext.decoy_id.is_empty() {
        if let Some(d) = decoys.iter().find(|d| d.decoy_id == ext.decoy_id) {
            return Some(d);
        }
    }
    let path = ev.http_request.as_ref().map(|r| r.url_path.as_str()).unwrap_or("");
    let target = ext.target_entity.as_str();
    let attr = |k: &str| ext.attributes.get(k).cloned().unwrap_or_default();
    decoys.iter().find(|d| match d.kind.as_str() {
        "route" => !path.is_empty() && path.split('?').next() == Some(d.marker.as_str()),
        "canary_token" | "fake_deploy_token" => attr("token_fp") == d.marker,
        "honey_account" => {
            let h = hash(&d.marker);
            target.ends_with(&format!(":{}", d.marker)) || target.ends_with(&format!(":{h}")) || attr("account") == d.marker || attr("account") == h
        }
        "honey_oauth_grant" => attr("oauth_grant") == d.marker,
        "decoy_tool" => ev.activity_name == v::AI_TOOL_CALL && attr("tool") == d.marker,
        "canary_env" => attr("env_var") == d.marker,
        "canary_secret" => attr("secret") == d.marker,
        _ => false,
    })
}

impl Detector for DeceptionDetector {
    fn name(&self) -> &'static str {
        "deception"
    }
    fn method(&self) -> DetectionMethodName {
        DetectionMethodName::Deception
    }
    fn detect(&mut self, ctx: &DetectContext, ev: &SecurityEvent) -> Vec<Finding> {
        let hash = |v: &str| ctx.redactor.id(v);
        let Some(decoy) = touched(&ctx.policy.decoys, ev, &hash) else { return vec![] };
        let actors = actor_entities(ev);
        let registered = ctx
            .policy
            .decoy_touchers
            .iter()
            .any(|t| actors.iter().any(|a| a.key() == t.entity.key()));
        if registered {
            return vec![];
        }
        let ext = ev.ext();
        let context = ext.attributes.get("context").cloned().unwrap_or_else(|| ext.tenant.clone());
        let in_context = decoy.issued_context.is_empty() || decoy.issued_context == "*" || decoy.issued_context == context;
        let rule = if in_context { "decoy_touch" } else { "decoy_out_of_context" };
        finding(
            ctx,
            ev,
            rule,
            actors,
            format!("{} decoy {} touched ({}){}", decoy.kind, decoy.decoy_id, decoy.protects, if in_context { "" } else { " outside its issued context" }),
        )
        .into_iter()
        .collect()
    }
}
