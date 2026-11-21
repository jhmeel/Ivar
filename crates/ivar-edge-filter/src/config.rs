//! Filter configuration, given as JSON in the gateway's plugin config.

use ivar_contracts::sign::Keyring;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct EdgeConfig {
    pub sensor_id: String,
    /// observe or enforce.
    pub mode: String,
    pub redaction_key_hex: String,
    /// FAIL_OPEN_BUDGET_PCT.
    pub fail_open_budget_pct: f64,
    pub admin_prefixes: Vec<String>,
    /// Largest request body inspected for field names.
    pub max_body_bytes: usize,
    /// Gateway cluster of the core ingest gateway.
    pub core_cluster: String,
    pub core_authority: String,
    /// Gateway cluster of the control plane that serves signed policy.
    pub control_cluster: String,
    pub control_authority: String,
    /// Trusted policy keys.
    pub keyring: Keyring,
    /// A signed policy bundle to start from (base64 archive).
    pub policy_bundle_base64: String,
    /// Flush and policy refresh period.
    pub tick_ms: u64,
    pub max_outbox: usize,
}

impl Default for EdgeConfig {
    fn default() -> Self {
        EdgeConfig {
            sensor_id: "edge-1".into(),
            mode: "observe".into(),
            redaction_key_hex: String::new(),
            fail_open_budget_pct: 0.1,
            admin_prefixes: vec!["/admin".into()],
            max_body_bytes: 64 * 1024,
            core_cluster: "ivar_core".into(),
            core_authority: "ivar-core".into(),
            control_cluster: "ivar_control".into(),
            control_authority: "ivar-control".into(),
            keyring: Keyring::default(),
            policy_bundle_base64: String::new(),
            tick_ms: 1000,
            max_outbox: 10_000,
        }
    }
}
