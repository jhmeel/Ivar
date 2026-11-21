//! Permission checks: a manifest may only ask for what the registry policy
//! allows for its plugin type, within the registry's resource ceilings.

use ivar_contracts::{PluginManifest, PluginType};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const SUPPORTED_API: &[&str] = &["ivar.plugin/v1"];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryPolicy {
    /// Actions each plugin type may be granted.
    pub allowed_actions: BTreeMap<String, Vec<String>>,
    /// Network patterns operators approved, e.g. "*.okta.com:443".
    pub allowed_network: Vec<String>,
    pub allowed_secrets: Vec<String>,
    pub max_memory_mb: u64,
    pub max_cpu_ms_per_call: u64,
    pub max_timeout_ms: u64,
}

impl Default for RegistryPolicy {
    fn default() -> Self {
        let mut allowed_actions = BTreeMap::new();
        allowed_actions.insert(
            "responder".to_string(),
            ["session.revoke", "user.suspend", "user.lock", "api_key.suspend", "ip.ban", "ip.unban", "oauth_grant.revoke", "workload.quarantine", "process.kill", "trust_edge.narrow", "host.isolate"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        );
        RegistryPolicy {
            allowed_actions,
            allowed_network: vec![],
            allowed_secrets: vec![],
            max_memory_mb: 512,
            max_cpu_ms_per_call: 1000,
            max_timeout_ms: 30_000,
        }
    }
}

fn type_key(t: PluginType) -> String {
    serde_json::to_value(t).ok().and_then(|v| v.as_str().map(String::from)).unwrap_or_default()
}

/// "*.okta.com:443" matches "acme.okta.com:443".
pub fn network_matches(pattern: &str, host_port: &str) -> bool {
    match pattern.strip_prefix("*.") {
        Some(rest) => host_port.ends_with(&format!(".{rest}")),
        None => pattern == host_port,
    }
}

pub fn check(m: &PluginManifest, policy: &RegistryPolicy) -> Result<(), Vec<String>> {
    let mut v = Vec::new();
    if !SUPPORTED_API.contains(&m.api.as_str()) {
        v.push(format!("api {} is not supported", m.api));
    }
    let allowed = policy.allowed_actions.get(&type_key(m.plugin_type)).cloned().unwrap_or_default();
    for a in &m.permissions.actions {
        if !allowed.contains(a) {
            v.push(format!("action {a} is not allowed for {} plugins", type_key(m.plugin_type)));
        }
    }
    for n in &m.permissions.network {
        let ok = policy.allowed_network.iter().any(|p| p == n || network_matches(p, n.trim_start_matches("*.")));
        if !ok {
            v.push(format!("network {n} is not approved"));
        }
    }
    for s in &m.permissions.secrets {
        if !policy.allowed_secrets.contains(s) {
            v.push(format!("secret {s} is not approved"));
        }
    }
    if m.limits.memory_mb > policy.max_memory_mb {
        v.push(format!("memory {} MB above ceiling {}", m.limits.memory_mb, policy.max_memory_mb));
    }
    if m.limits.cpu_ms_per_call > policy.max_cpu_ms_per_call {
        v.push(format!("cpu {} ms above ceiling {}", m.limits.cpu_ms_per_call, policy.max_cpu_ms_per_call));
    }
    if m.limits.timeout_ms > policy.max_timeout_ms {
        v.push(format!("timeout {} ms above ceiling {}", m.limits.timeout_ms, policy.max_timeout_ms));
    }
    if v.is_empty() {
        Ok(())
    } else {
        Err(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The okta-responder manifest from section 14, verbatim.
    pub const OKTA: &str = "name: okta-responder\nversion: 1.4.0\ntype: responder\napi: ivar.plugin/v1\npermissions:\n  actions: [session.revoke, user.suspend]\n  network: [\"*.okta.com:443\"]\n  secrets: [okta_api_token]\nlimits: { memory_mb: 128, cpu_ms_per_call: 50, timeout_ms: 2000 }\nsignature: sigstore\n";

    #[test]
    fn spec_manifest_passes_with_approved_access() {
        let m = PluginManifest::from_yaml(OKTA).unwrap();
        let mut p = RegistryPolicy::default();
        assert!(check(&m, &p).is_err(), "network and secret not yet approved");
        p.allowed_network.push("*.okta.com:443".into());
        p.allowed_secrets.push("okta_api_token".into());
        assert!(check(&m, &p).is_ok());
        let mut greedy = m.clone();
        greedy.permissions.actions.push("killswitch".into());
        assert!(check(&greedy, &p).is_err());
    }
}
