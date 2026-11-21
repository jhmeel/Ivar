//! Maps a decision on an entity to concrete, reversible actions.

use super::ladder::LADDER;
use crate::ids;
use crate::policy::Decision;
use ivar_contracts::{ActionReceipt, ActionRequest, Approval, EntityRef};

#[derive(Debug, Clone, PartialEq)]
pub struct PlannedAction {
    pub request: ActionRequest,
    /// True when a person or playbook must approve before it runs.
    pub needs_approval: bool,
}

/// The action and its reversal for a ladder level and entity type.
fn action_for(level: u32, entity_type: &str) -> (&'static str, &'static str) {
    match (level, entity_type) {
        (1, _) => ("throttle", "throttle.lift"),
        (2, "session") | (2, "user") => ("session.step_up", "session.step_up.clear"),
        (2, _) => ("challenge", "challenge.clear"),
        (3, _) => ("request.block", "none.per_request"),
        (4, "ip") => ("ip.ban", "ip.unban"),
        (4, "session") => ("session.revoke", "session.restore"),
        (4, "user") => ("user.lock", "user.unlock"),
        (4, "api_key") => ("api_key.suspend", "api_key.resume"),
        (4, "oauth_grant") => ("oauth_grant.revoke", "oauth_grant.restore"),
        (4, "agent") => ("agent.suspend", "agent.resume"),
        (4, "service") => ("trust_edge.narrow", "trust_edge.restore"),
        (4, "device") => ("device.block", "device.unblock"),
        (4, _) => ("identity.contain", "identity.release"),
        (5, "process") => ("process.kill", "none.process_restart_by_owner"),
        (5, _) => ("workload.quarantine", "workload.release"),
        (6, _) => ("killswitch", "killswitch.reverse"),
        _ => ("record", "none"),
    }
}

/// Plan the actions for one decision. Containment of a session also locks the
/// account behind it, as in the worked example (section 10.2).
#[allow(clippy::too_many_arguments)]
pub fn plan_actions(
    decision: Decision,
    entity: &EntityRef,
    related: &[EntityRef],
    verdict_id: &str,
    evidence_ids: &[String],
    confidence_class: &str,
    now: i64,
    repeats: u32,
    mode: &str,
) -> Vec<PlannedAction> {
    let level = decision.ladder_level();
    if level == 0 {
        return vec![];
    }
    let rung = &LADDER[level as usize];
    let mut targets = vec![entity.clone()];
    if decision == Decision::Contain && entity.r#type == "session" {
        targets.extend(related.iter().filter(|e| e.r#type == "user").cloned());
    }
    targets
        .into_iter()
        .map(|t| {
            let (action, reversal) = action_for(level, &t.r#type);
            let id = ids::derive("act", &[verdict_id, &t.key(), action]);
            PlannedAction {
                needs_approval: level >= 5,
                request: ActionRequest {
                    action_request_id: id,
                    target: Some(t),
                    action: action.into(),
                    ladder_level: level,
                    expiry: rung.expires_at(now, repeats),
                    approval: Some(Approval { approved_by: if level >= 5 { String::new() } else { "policy:auto".into() }, approvers: vec![], approved_at: now }),
                    reversal_method: reversal.into(),
                    evidence_ids: evidence_ids.to_vec(),
                    verdict_id: verdict_id.into(),
                    confidence_class: confidence_class.into(),
                    evidence_captured_first: false,
                    time: now,
                    responder: String::new(),
                    mode: mode.into(),
                },
            }
        })
        .collect()
}

pub fn receipt_for(req: &ActionRequest, result: &str, time_taken_ms: u64, verification: &str, now: i64) -> ActionReceipt {
    ActionReceipt {
        action_receipt_id: ids::derive("rcp", &[&req.action_request_id, result]),
        action_request_id: req.action_request_id.clone(),
        result: result.into(),
        time_taken_ms,
        verification: verification.into(),
        reversal_status: if req.reversal_method.starts_with("none") { "not_reversible".into() } else { "reversible".into() },
        time: now,
        responder: req.responder.clone(),
    }
}
