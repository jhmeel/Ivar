//! The safeguard review every planned action passes before it runs.

use super::{BlastRadiusBudget, SharedNetworks};
use crate::response::PlannedAction;
use crate::risk::RiskAssessment;
use ivar_contracts::ProtectedEntity;

#[derive(Debug, Clone, PartialEq)]
pub enum ReviewOutcome {
    Allowed,
    /// The action was replaced with a milder one.
    Downgraded { from: String, to: String, reason: String },
    /// Automation stops here; a person must approve.
    NeedsApproval { reason: String },
    Refused { reason: String },
}

pub struct ReviewContext<'a> {
    pub assessment: &'a RiskAssessment,
    pub protected: &'a [ProtectedEntity],
    pub shared: &'a SharedNetworks,
    /// The target address carries many distinct accounts (a proxy, gateway or
    /// shared network seen in traffic, not only the configured ranges).
    pub crowded: bool,
    pub budget: &'a mut BlastRadiusBudget,
    pub established: bool,
    pub now: i64,
}

pub fn review(action: &mut PlannedAction, ctx: &mut ReviewContext) -> ReviewOutcome {
    let req = &mut action.request;
    let target = req.target.clone().unwrap_or_default();
    let r = &ctx.assessment.risk;

    // Reversal: every action records exactly how to undo it.
    if req.reversal_method.is_empty() {
        return ReviewOutcome::Refused { reason: "no reversal method recorded".into() };
    }
    // Actor, not target: no account is contained on evidence that it was attacked.
    if req.ladder_level >= 4 && r.target_only {
        return ReviewOutcome::Refused { reason: "target side evidence only".into() };
    }
    // Two source rule: levels 4 and above need two independent sources, except deception hits.
    if req.ladder_level >= 4 && r.independent_sources < 2 && !r.deception_hit {
        return ReviewOutcome::Refused { reason: "levels 4 and above need two independent sources".into() };
    }
    // Shared networks: Carrier NAT ranges, and any address carrying many
    // accounts, are throttled and never banned or contained.
    if target.r#type == "ip" && req.ladder_level >= 4 && (ctx.shared.contains(&target.id) || ctx.crowded) {
        let from = req.action.clone();
        req.action = "throttle".into();
        req.reversal_method = "throttle.lift".into();
        req.ladder_level = 1;
        req.expiry = crate::response::LADDER[1].expires_at(ctx.now, 0);
        let why = if ctx.crowded && !ctx.shared.contains(&target.id) { "address carries many accounts" } else { "shared network" };
        return ReviewOutcome::Downgraded { from, to: "throttle".into(), reason: format!("{why}: throttled, never banned") };
    }
    // Protected entities: partners, health checks and break glass admins need a person.
    if req.ladder_level >= 4 && ctx.protected.iter().any(|p| p.entity.key() == target.key()) {
        action.needs_approval = true;
        return ReviewOutcome::NeedsApproval { reason: "protected entity".into() };
    }
    // Evidence first: volatile evidence is captured before a kill or isolation.
    if req.ladder_level >= 5 && !req.evidence_captured_first {
        action.needs_approval = true;
        return ReviewOutcome::NeedsApproval { reason: "capture volatile evidence first".into() };
    }
    // Blast radius budget.
    if req.ladder_level == 4 && !ctx.budget.try_spend(&req.confidence_class, ctx.established, ctx.now) {
        action.needs_approval = true;
        return ReviewOutcome::NeedsApproval { reason: "blast radius budget for this confidence class is spent".into() };
    }
    if action.needs_approval {
        return ReviewOutcome::NeedsApproval { reason: "level 5 and 6 actions need a playbook or a person".into() };
    }
    ReviewOutcome::Allowed
}
