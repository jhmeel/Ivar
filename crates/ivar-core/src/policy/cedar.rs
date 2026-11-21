//! Cedar policies (section 20): the declarative layer that authorises
//! automatic actions by the core and manual actions by operators. Hard
//! safeguards in `crate::safeguards` apply whatever these policies say.

use cedar_policy::{Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::str::FromStr;

#[derive(Debug, thiserror::Error)]
pub enum CedarError {
    #[error("cedar policy: {0}")]
    Policy(String),
    #[error("cedar request: {0}")]
    Request(String),
}

/// Facts about a proposed automatic action.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AutoActionContext {
    pub ladder_level: u32,
    pub risk: f64,
    pub independent_sources: u32,
    pub deception_hit: bool,
    pub target_only: bool,
    pub protected: bool,
    pub ai_autonomy: String,
    pub runtime_posture: String,
}

/// A manual action by an operator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorRequest {
    pub operator: String,
    pub roles: Vec<String>,
    pub action: String,
    pub target: String,
    /// Number of distinct approvers already attached.
    pub approvers: u32,
    /// Destructive or fleet wide actions need two approvers (section 16).
    pub destructive_or_fleet_wide: bool,
    /// Hardware backed staff 2FA was used for this session.
    pub hardware_2fa: bool,
}

pub struct CedarPolicy {
    set: PolicySet,
    authorizer: Authorizer,
}

fn uid(s: &str) -> Result<EntityUid, CedarError> {
    EntityUid::from_str(s).map_err(|e| CedarError::Request(e.to_string()))
}

fn quote(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".into())
}

impl CedarPolicy {
    pub fn parse(text: &str) -> Result<Self, CedarError> {
        let set = PolicySet::from_str(text).map_err(|e| CedarError::Policy(e.to_string()))?;
        Ok(CedarPolicy { set, authorizer: Authorizer::new() })
    }

    fn allowed(&self, principal: &str, action: &str, resource: &str, ctx: serde_json::Value, entities: Entities) -> Result<bool, CedarError> {
        let context = Context::from_json_value(ctx, None).map_err(|e| CedarError::Request(e.to_string()))?;
        let req = Request::new(uid(principal)?, uid(action)?, uid(resource)?, context, None).map_err(|e| CedarError::Request(e.to_string()))?;
        Ok(self.authorizer.is_authorized(&req, &self.set, &entities).decision() == Decision::Allow)
    }

    /// May the given engine principal ("core" or "ai") take this action automatically?
    pub fn allow_auto(&self, principal: &str, action: &str, target: &str, c: &AutoActionContext) -> Result<bool, CedarError> {
        let ctx = json!({
            "ladder_level": c.ladder_level as i64,
            "risk_bp": (c.risk * 10_000.0).round() as i64,
            "independent_sources": c.independent_sources as i64,
            "deception_hit": c.deception_hit,
            "target_only": c.target_only,
            "protected": c.protected,
            "ai_autonomy": c.ai_autonomy,
            "runtime_posture": c.runtime_posture,
        });
        self.allowed(
            &format!("Ivar::Engine::{}", quote(principal)),
            &format!("Ivar::Action::{}", quote(action)),
            &format!("Ivar::Entity::{}", quote(target)),
            ctx,
            Entities::empty(),
        )
    }

    /// Per action authorisation for operators, with roles as Cedar parents.
    pub fn allow_operator(&self, r: &OperatorRequest) -> Result<bool, CedarError> {
        let parents: Vec<serde_json::Value> = r.roles.iter().map(|role| json!({"type": "Ivar::Role", "id": role})).collect();
        let mut ents = vec![json!({"uid": {"type": "Ivar::Operator", "id": r.operator}, "attrs": {}, "parents": parents})];
        for role in &r.roles {
            ents.push(json!({"uid": {"type": "Ivar::Role", "id": role}, "attrs": {}, "parents": []}));
        }
        let entities = Entities::from_json_value(serde_json::Value::Array(ents), None).map_err(|e| CedarError::Request(e.to_string()))?;
        let ctx = json!({"approvers": r.approvers as i64, "destructive_or_fleet_wide": r.destructive_or_fleet_wide, "hardware_2fa": r.hardware_2fa});
        self.allowed(
            &format!("Ivar::Operator::{}", quote(&r.operator)),
            &format!("Ivar::Action::{}", quote(&r.action)),
            &format!("Ivar::Entity::{}", quote(&r.target)),
            ctx,
            entities,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::default_cedar_policies;

    fn p() -> CedarPolicy {
        CedarPolicy::parse(&default_cedar_policies()).unwrap()
    }

    #[test]
    fn core_auto_actions() {
        let p = p();
        let mut c = AutoActionContext { ladder_level: 4, independent_sources: 2, ai_autonomy: "advise".into(), runtime_posture: "standard".into(), ..Default::default() };
        assert!(p.allow_auto("core", "contain", "session:s1", &c).unwrap());
        c.independent_sources = 1;
        assert!(!p.allow_auto("core", "contain", "session:s1", &c).unwrap());
        c.deception_hit = true;
        assert!(p.allow_auto("core", "contain", "session:s1", &c).unwrap());
        c.protected = true;
        assert!(!p.allow_auto("core", "contain", "session:s1", &c).unwrap());
        let low = AutoActionContext { ladder_level: 1, ai_autonomy: "advise".into(), ..Default::default() };
        assert!(p.allow_auto("core", "throttle", "ip:1.2.3.4", &low).unwrap());
    }

    #[test]
    fn ai_bounded_only_up_to_level_three() {
        let p = p();
        let mut c = AutoActionContext { ladder_level: 3, ai_autonomy: "bounded".into(), ..Default::default() };
        assert!(p.allow_auto("ai", "block", "ip:1.2.3.4", &c).unwrap());
        c.ladder_level = 4;
        assert!(!p.allow_auto("ai", "contain", "ip:1.2.3.4", &c).unwrap());
        c.ladder_level = 2;
        c.ai_autonomy = "propose".into();
        assert!(!p.allow_auto("ai", "challenge", "ip:1.2.3.4", &c).unwrap());
    }

    #[test]
    fn operators_need_roles_two_approvers_and_2fa() {
        let p = p();
        let mut r = OperatorRequest { operator: "alice".into(), roles: vec!["incident_lead".into()], action: "killswitch".into(), target: "payouts".into(), approvers: 1, destructive_or_fleet_wide: true, hardware_2fa: true };
        assert!(!p.allow_operator(&r).unwrap());
        r.approvers = 2;
        assert!(p.allow_operator(&r).unwrap());
        r.hardware_2fa = false;
        assert!(!p.allow_operator(&r).unwrap());
        let viewer = OperatorRequest { operator: "bob".into(), roles: vec!["analyst".into()], action: "killswitch".into(), target: "payouts".into(), approvers: 2, destructive_or_fleet_wide: true, hardware_2fa: true };
        assert!(!p.allow_operator(&viewer).unwrap());
    }
}
