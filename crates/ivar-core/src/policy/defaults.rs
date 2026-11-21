//! The spec default policy. Every value here is a starting point that teams
//! tune per environment during observe mode; operator decisions from section
//! 21 are recorded in operator-decisions.yaml and override these.

use crate::config::Settings;
use ivar_contracts::{
    DecoySpec, Invariant, InvariantScope, MeasuredOutcome, PolicyContent, Thresholds, TimeLock, CONTRACT_VERSION,
};
use std::collections::BTreeMap;

/// Cedar policies for automatic and operator actions.
pub fn default_cedar_policies() -> String {
    r#"
// The core may record, throttle, challenge and block automatically.
permit (
  principal == Ivar::Engine::"core",
  action in [Ivar::Action::"record", Ivar::Action::"throttle", Ivar::Action::"challenge", Ivar::Action::"block"],
  resource
);

// Containment (ladder level 4) is automatic only at high confidence: two
// independent sources, or a deception hit.
permit (
  principal == Ivar::Engine::"core",
  action == Ivar::Action::"contain",
  resource
) when { context.independent_sources >= 2 || context.deception_hit };

// Never contain on target side evidence, and never contain a protected entity
// without a person.
forbid (principal, action == Ivar::Action::"contain", resource) when { context.target_only };
forbid (principal, action == Ivar::Action::"contain", resource) when { context.protected };

// Levels 5 and 6 are never automatic for the core.
forbid (principal == Ivar::Engine::"core", action, resource) when { context.ladder_level >= 5 };

// AI at autonomy A3 (bounded) may trigger pre approved actions up to level 3.
permit (
  principal == Ivar::Engine::"ai",
  action in [Ivar::Action::"record", Ivar::Action::"throttle", Ivar::Action::"challenge", Ivar::Action::"block"],
  resource
) when { context.ai_autonomy == "bounded" && context.ladder_level <= 3 };
forbid (principal == Ivar::Engine::"ai", action, resource) when { context.ladder_level >= 4 };

// Operators: every action needs hardware backed staff 2FA.
forbid (principal is Ivar::Operator, action, resource) unless { context.hardware_2fa };

// Destructive or fleet wide actions need two approvers.
forbid (principal is Ivar::Operator, action, resource) when { context.destructive_or_fleet_wide && context.approvers < 2 };

// Analysts may read, replay and annotate.
permit (
  principal in Ivar::Role::"analyst",
  action in [Ivar::Action::"read", Ivar::Action::"replay", Ivar::Action::"annotate"],
  resource
);

// On call may isolate workloads (level 5) and reverse actions.
permit (
  principal in Ivar::Role::"on_call",
  action in [Ivar::Action::"read", Ivar::Action::"replay", Ivar::Action::"isolate", Ivar::Action::"reverse", Ivar::Action::"approve", Ivar::Action::"cancel_time_lock"],
  resource
);

// The incident lead may use business kill switches (level 6) and posture.
permit (
  principal in Ivar::Role::"incident_lead",
  action in [Ivar::Action::"read", Ivar::Action::"replay", Ivar::Action::"isolate", Ivar::Action::"reverse", Ivar::Action::"approve", Ivar::Action::"killswitch", Ivar::Action::"set_posture", Ivar::Action::"cancel_time_lock"],
  resource
);

// Owners of irreversible actions may cancel a time lock.
permit (
  principal in Ivar::Role::"owner",
  action == Ivar::Action::"cancel_time_lock",
  resource
);

// Policy authors may sign policy; weakening changes need a second key (TUF threshold).
permit (
  principal in Ivar::Role::"policy_author",
  action == Ivar::Action::"sign_policy",
  resource
);
"#
    .to_string()
}

pub fn default_invariants() -> Vec<Invariant> {
    vec![
        Invariant {
            invariant_id: "hot_wallet_outflow".into(),
            action: "payout".into(),
            measured_outcome: MeasuredOutcome::ValueMoved,
            scope: InvariantScope::Business,
            window_secs: 3600,
            limit: 1_000_000.0,
            time_lock: Some(TimeLock { threshold: 50_000.0, delay_secs: 30 * 60, cancelling_owners: vec!["user:treasury-owner-1".into(), "user:treasury-owner-2".into()] }),
            approvers: vec!["role:treasury".into()],
            action_on_breach: "block_and_alert".into(),
        },
        Invariant {
            invariant_id: "per_identity_records".into(),
            action: "*".into(),
            measured_outcome: MeasuredOutcome::RecordsRead,
            scope: InvariantScope::Identity,
            window_secs: 24 * 3600,
            limit: 10_000.0,
            time_lock: None,
            approvers: vec!["role:data_owner".into()],
            action_on_breach: "suspend_identity".into(),
        },
        Invariant {
            invariant_id: "destructive_management_ops".into(),
            action: "*".into(),
            measured_outcome: MeasuredOutcome::DestructiveOperations,
            scope: InvariantScope::Global,
            window_secs: 3600,
            limit: 5.0,
            time_lock: Some(TimeLock { threshold: 0.0, delay_secs: 30 * 60, cancelling_owners: vec!["user:infra-owner".into()] }),
            approvers: vec!["role:infra".into(), "role:infra".into()],
            action_on_breach: "block_and_alert".into(),
        },
    ]
}

/// Decoys generated from the trust graph start from these templates.
pub fn default_decoys() -> Vec<DecoySpec> {
    vec![
        DecoySpec { decoy_id: "dcy_route_env".into(), kind: "route".into(), marker: "/.env.backup".into(), issued_context: "*".into(), protects: "edge".into() },
        DecoySpec { decoy_id: "dcy_tool_export".into(), kind: "decoy_tool".into(), marker: "export_all_customers".into(), issued_context: "*".into(), protects: "ai agents".into() },
    ]
}

pub fn spec_default_policy(now: i64) -> PolicyContent {
    let settings = Settings::spec_defaults();
    let mut intent_binding = BTreeMap::new();
    for action in ["payout", "signing", "deploy", "role_grant", "bulk_export", "agent_action"] {
        intent_binding.insert(action.to_string(), settings.intent_binding.as_str().to_string());
    }
    PolicyContent {
        contract: CONTRACT_VERSION.into(),
        version: 1,
        policy_version: "default-1".into(),
        issued_at: now,
        expires_at: now + 30 * 24 * 3600 * 1000,
        thresholds: Thresholds::spec_defaults(),
        method_weights: crate::risk::RiskEngine::default_method_weights(),
        rules: vec![],
        protected_entities: vec![],
        invariants: default_invariants(),
        decoys: default_decoys(),
        decoy_touchers: vec![],
        cedar_policies: default_cedar_policies(),
        settings: settings.to_map(),
        shared_networks: vec!["100.64.0.0/10".into()],
        intent_binding,
        declared: serde_json::Value::Null,
        plugin_versions: BTreeMap::new(),
        weakens_protection: false,
    }
}
