//! The built in rule catalog. A PolicyBundle may override any rule (confidence,
//! enforce flag, parameters) or add new ones; the catalog merges both.

use ivar_contracts::{DetectionMethodName as M, DetectionRule, PolicyContent};
use serde_json::{json, Value};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default)]
pub struct RuleCatalog {
    rules: BTreeMap<String, DetectionRule>,
}

impl RuleCatalog {
    pub fn from_policy(policy: &PolicyContent) -> Self {
        let mut rules: BTreeMap<String, DetectionRule> = default_rules().into_iter().map(|r| (r.rule_id.clone(), r)).collect();
        for r in &policy.rules {
            rules.insert(r.rule_id.clone(), r.clone());
        }
        RuleCatalog { rules }
    }

    pub fn get(&self, id: &str) -> Option<&DetectionRule> {
        self.rules.get(id)
    }

    pub fn param_u64(&self, id: &str, key: &str, default: u64) -> u64 {
        self.get(id).and_then(|r| r.params.get(key)).and_then(Value::as_u64).unwrap_or(default)
    }

    pub fn param_f64(&self, id: &str, key: &str, default: f64) -> f64 {
        self.get(id).and_then(|r| r.params.get(key)).and_then(Value::as_f64).unwrap_or(default)
    }

    pub fn param_strings(&self, id: &str, key: &str) -> Vec<String> {
        self.get(id)
            .and_then(|r| r.params.get(key))
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).map(String::from).collect())
            .unwrap_or_default()
    }

    /// Rules outside the catalog come from plugins, whose lifecycle stage
    /// (shadow, canary, active) already decides whether they enforce.
    pub fn enforced(&self, id: &str) -> bool {
        self.get(id).map(|r| r.enforce).unwrap_or(true)
    }

    pub fn all(&self) -> impl Iterator<Item = &DetectionRule> {
        self.rules.values()
    }
}

#[allow(clippy::too_many_arguments)]
fn rule(id: &str, family: &str, method: M, technique: &str, stage: &str, confidence: f64, severity: u32, params: Value) -> DetectionRule {
    DetectionRule {
        rule_id: id.into(),
        family: family.into(),
        method,
        technique: technique.into(),
        attack_stage: stage.into(),
        confidence,
        severity,
        params,
        enforce: true,
    }
}

/// The default rules, one row per signal named in sections 3.1, 4, 8 and 10.
pub fn default_rules() -> Vec<DetectionRule> {
    use M::*;
    vec![
        // Reconnaissance
        rule("route_404", "recon.route_scan", PositiveSecurity, "T1595.003", "reconnaissance", 0.05, 1, json!({})),
        rule("route_scan_burst", "recon.route_scan_burst", SequenceCorrelation, "T1595.003", "reconnaissance", 0.35, 2, json!({"distinct_routes": 20, "window_secs": 300})),
        // Initial access
        rule("engine_alert", "signature", Signatures, "T1190", "initial_access", 0.80, 3, json!({})),
        rule("auth_spray", "credential.spray", SequenceCorrelation, "T1110.003", "initial_access", 0.57, 3, json!({"failures": 10, "distinct_accounts": 5, "window_secs": 600})),
        rule("login_after_failures", "credential.spray_success", SequenceCorrelation, "T1110", "initial_access", 0.35, 3, json!({"failures": 5, "window_secs": 600})),
        rule("signup_flood", "abuse.signup_flood", SequenceCorrelation, "T1136", "initial_access", 0.60, 2, json!({"signups": 20, "window_secs": 600})),
        rule("sim_swap_sensitive_action", "identity.sim_swap", BehaviourBaselines, "T1451", "initial_access", 0.60, 3, json!({"window_secs": 172800, "actions": ["password_reset", "payout", "login"]})),
        rule("remote_tool_not_allowlisted", "access.remote_tool", PositiveSecurity, "T1219", "initial_access", 0.80, 4, json!({"allowlist": []})),
        rule("new_remote_session", "access.remote_session", BehaviourBaselines, "T1219", "initial_access", 0.45, 2, json!({})),
        rule("extension_not_allowlisted", "access.remote_extension", PositiveSecurity, "T1176", "initial_access", 0.75, 3, json!({"allowlist": []})),
        // Execution
        rule("web_process_shell", "execution.web_shell", PositiveSecurity, "T1059", "execution", 0.95, 5, json!({"critical_positive_security": true})),
        rule("unexpected_binary", "execution.unexpected_binary", PositiveSecurity, "T1204", "execution", 0.70, 4, json!({})),
        rule("code_exec_during_load", "execution.data_pipeline", PositiveSecurity, "T1059.006", "execution", 0.90, 5, json!({"critical_positive_security": true})),
        // Credential theft
        rule("secret_file_read", "credential.secret_access", Signatures, "T1552.001", "credential_theft", 0.70, 4, json!({})),
        rule("metadata_access", "credential.cloud_metadata", Signatures, "T1552.005", "credential_theft", 0.80, 4, json!({})),
        rule("token_new_context", "credential.token_reuse", BehaviourBaselines, "T1550", "credential_theft", 0.50, 3, json!({})),
        rule("revoked_credential_use", "credential.revoked_use", PositiveSecurity, "T1550", "credential_theft", 0.90, 4, json!({})),
        rule("runner_memory_read", "credential.runner_memory", Signatures, "T1003", "credential_theft", 0.90, 5, json!({})),
        rule("new_device", "baseline.new_device", BehaviourBaselines, "T1078", "credential_theft", 0.30, 2, json!({})),
        // Privilege escalation
        rule("privileged_field_write", "privesc.role_write", PositiveSecurity, "T1098", "privilege_escalation", 0.95, 5, json!({"critical_positive_security": true})),
        rule("mass_assignment", "privesc.mass_assignment", PositiveSecurity, "T1098", "privilege_escalation", 0.60, 3, json!({})),
        rule("new_admin_account", "privesc.new_admin", BehaviourBaselines, "T1136.001", "privilege_escalation", 0.70, 4, json!({})),
        rule("app_self_granted_role", "privesc.self_grant", PositiveSecurity, "T1098.003", "privilege_escalation", 0.95, 5, json!({"critical_positive_security": true})),
        rule("new_app_secret", "privesc.new_app_secret", BehaviourBaselines, "T1098.001", "privilege_escalation", 0.60, 3, json!({})),
        rule("cross_tenant_access", "privesc.other_user_records", PositiveSecurity, "T1078", "privilege_escalation", 0.85, 4, json!({})),
        // Lateral movement
        rule("new_service_path", "lateral.new_service_path", DeclaredIntentDrift, "T1021", "lateral_movement", 0.40, 3, json!({})),
        rule("internal_scan", "lateral.internal_scan", SequenceCorrelation, "T1046", "lateral_movement", 0.65, 3, json!({"distinct_hosts": 20, "window_secs": 300})),
        rule("machine_speed_lateral", "lateral.machine_speed", SequenceCorrelation, "T1570", "lateral_movement", 0.75, 4, json!({"distinct_hosts": 5, "window_secs": 60})),
        rule("outside_delegated_purpose", "agent.goal_hijack", PositiveSecurity, "ASI01", "lateral_movement", 0.85, 4, json!({})),
        // Data theft
        rule("bulk_read_anomaly", "exfil.bulk_read", BehaviourBaselines, "T1530", "data_theft", 0.70, 4, json!({})),
        rule("dns_tunnelling", "exfil.dns_tunnel", Signatures, "T1048.003", "data_theft", 0.70, 4, json!({"label_len": 40, "entropy": 3.8})),
        rule("undeclared_egress", "drift.egress", DeclaredIntentDrift, "T1041", "data_theft", 0.50, 3, json!({})),
        rule("build_undeclared_egress", "supply.build_egress", PositiveSecurity, "T1041", "data_theft", 0.85, 5, json!({})),
        rule("ai_sensitive_data_to_model", "ai.data_to_model", Signatures, "LLM02", "data_theft", 0.55, 3, json!({})),
        // Impact
        rule("mass_encryption", "impact.mass_encryption", SequenceCorrelation, "T1486", "impact", 0.90, 5, json!({"renames": 100, "window_secs": 60})),
        rule("backup_deletion", "impact.backup_deletion", Signatures, "T1490", "impact", 0.85, 5, json!({})),
        rule("mass_vm_action", "impact.mass_vm", Signatures, "T1529", "impact", 0.80, 5, json!({})),
        rule("invariant_breach", "consequence", ConsequenceInvariants, "T1657", "impact", 1.0, 5, json!({"critical_positive_security": true})),
        // Supply chain
        rule("package_integrity_mismatch", "supply.package_integrity", PositiveSecurity, "T1195.002", "initial_access", 0.90, 5, json!({"critical_positive_security": true})),
        rule("package_unpinned", "supply.package_unpinned", DeclaredIntentDrift, "T1195.002", "initial_access", 0.50, 3, json!({})),
        rule("workflow_change", "supply.workflow_change", BehaviourBaselines, "T1677", "persistence", 0.45, 3, json!({})),
        // Edge devices
        rule("version_downgrade", "edge.version_downgrade", Signatures, "T1601", "persistence", 0.80, 4, json!({})),
        // AI
        rule("prompt_injection_marker", "ai.prompt_injection", Signatures, "LLM01", "initial_access", 0.60, 3, json!({})),
        rule("agent_tool_outside_scope", "agent.tool_misuse", PositiveSecurity, "ASI02", "privilege_escalation", 0.85, 4, json!({})),
        // Deception
        rule("decoy_touch", "deception", Deception, "T1078", "credential_theft", 1.0, 5, json!({"contain": true})),
        rule("decoy_out_of_context", "deception.out_of_context", Deception, "T1078", "credential_theft", 0.30, 3, json!({"contain": false})),
        // Drift
        rule("undeclared_edge", "drift.edge", DeclaredIntentDrift, "T1078", "privilege_escalation", 0.30, 2, json!({})),
        rule("shadow_route", "drift.shadow_route", DeclaredIntentDrift, "API9", "reconnaissance", 0.20, 2, json!({})),
        // Shared indicator network (section 17): hashes and scores filled in by the control plane.
        rule("shared_indicator", "intel.shared_indicator", Signatures, "T1583", "reconnaissance", 0.6, 3, json!({"network_key_hex": "", "hashes": {}})),
        // Machine learning (advisory)
        rule("ml_anomaly", "ml.anomaly", MachineLearning, "", "", 0.50, 2, json!({"threshold": 0.8})),
    ]
}
