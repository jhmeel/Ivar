//! The decision core and the sensor local fast path.

use crate::err;
use ivar_contracts::{PolicyContent, SecurityEvent};
use ivar_core::engine::CoreOptions;
use ivar_core::sensor::{LocalDecision, SensorPolicy};
use ivar_core::DecisionCore;
use serde_json::json;
pub struct Core {
    inner: DecisionCore,
}
impl Core {
    /// `policy_json` is a PolicyContent; `redaction_key_hex` the deployment's
    /// keyed hash key.
    pub fn new(policy_json: &str, redaction_key_hex: &str) -> Result<Core, String> {
        let policy: PolicyContent = serde_json::from_str(policy_json).map_err(err)?;
        let key = hex::decode(redaction_key_hex).map_err(err)?;
        let inner = DecisionCore::new(policy, CoreOptions { evidence_signer: None, redaction_key: key }).map_err(err)?;
        Ok(Core { inner })
    }

    /// Apply a newer verified PolicyContent without losing the trust graph,
    /// risk, incidents or evidence. A policy the core refuses leaves the
    /// current one in force. Returns the rules whose content changed.
    pub fn update_policy(&mut self, policy_json: &str, now_ms: f64) -> String {
        let policy: PolicyContent = match serde_json::from_str(policy_json) {
            Ok(p) => p,
            Err(e) => return err(e),
        };
        match self.inner.update_policy(policy, now_ms as i64) {
            Ok(changed) => json!({ "applied": true, "changed_rules": changed }).to_string(),
            Err(e) => err(e),
        }
    }

    /// Judge one SecurityEvent. Returns decision, verdicts, findings, actions and incidents.
    pub fn process(&mut self, event_json: &str, now_ms: f64) -> String {
        let ev: SecurityEvent = match serde_json::from_str(event_json) {
            Ok(e) => e,
            Err(e) => return err(e),
        };
        let out = self.inner.process(ev, now_ms as i64);
        json!({
            "evidence_id": out.evidence_id,
            "decision": out.decision(),
            "verdicts": out.verdicts,
            "findings": out.findings,
            "observe_only": out.observe_only,
            "risks": out.risks,
            "actions": out.actions.iter().map(|a| json!({"request": a.planned.request, "needs_approval": a.planned.needs_approval, "review": format!("{:?}", a.review)})).collect::<Vec<_>>(),
            "incidents": out.incidents,
        })
        .to_string()
    }

    /// Evidence records sealed so far (for replay and export).
    pub fn evidence(&self) -> String {
        use ivar_core::evidence::EvidenceStore;
        serde_json::to_string(&self.inner.evidence().records()).unwrap_or_else(err)
    }

    pub fn incidents(&self) -> String {
        serde_json::to_string(&self.inner.incidents().all().collect::<Vec<_>>()).unwrap_or_else(err)
    }

    pub fn drift(&self) -> String {
        serde_json::to_string(&self.inner.drift_report()).unwrap_or_else(err)
    }

    pub fn tick(&mut self, now_ms: f64) -> String {
        serde_json::to_string(&self.inner.tick(now_ms as i64)).unwrap_or_else(err)
    }
}

/// The sensor local fast path: blocks known attacks in about a millisecond.
pub struct LocalSensor {
    inner: SensorPolicy,
}
impl LocalSensor {
    pub fn new(policy_json: &str) -> Result<LocalSensor, String> {
        let policy: PolicyContent = serde_json::from_str(policy_json).map_err(err)?;
        Ok(LocalSensor { inner: SensorPolicy::try_from_policy(&policy)? })
    }

    pub fn decide(&self, event_json: &str, now_ms: f64) -> String {
        let ev: SecurityEvent = match serde_json::from_str(event_json) {
            Ok(e) => e,
            Err(e) => return err(e),
        };
        match self.inner.decide(&ev, now_ms as i64) {
            LocalDecision::Block(v) => json!({"local": "block", "verdict": v}),
            LocalDecision::Cached(v) => json!({"local": "cached", "verdict": v}),
            LocalDecision::Forward => json!({"local": "forward"}),
        }
        .to_string()
    }
    pub fn push_verdict(&mut self, verdict_json: &str) -> bool {
        match serde_json::from_str(verdict_json) {
            Ok(v) => {
                self.inner.push_verdict(v);
                true
            }
            Err(_) => false,
        }
    }
}

/// Compile declarations: `kind` is openapi, iam, kubernetes, github_workflow,
/// npm_lockfile or terraform_plan.
pub fn compile_declarations(kind: &str, file: &str, text: &str, holder: &str) -> String {
    use ivar_core::declare as d;
    let r = match kind {
        "openapi" => d::compile_openapi(file, text),
        "iam" => d::compile_iam_policy(file, holder, "", text),
        "kubernetes" => d::compile_kubernetes(file, text),
        "github_workflow" => d::compile_github_workflow(file, text),
        "npm_lockfile" => d::compile_npm_lockfile(file, text),
        "terraform_plan" => d::compile_terraform_plan(file, text),
        other => return err(format!("unknown declaration kind {other}")),
    };
    match r {
        Ok(decl) => decl.to_value().to_string(),
        Err(e) => err(e),
    }
}
