//! PolicyBundle (signed archive): rules, thresholds, protected entities, version.
//! Produced by the control plane, consumed by sensors and engines.

use crate::error::ContractError;
use crate::invariant::Invariant;
use crate::proto::{DetectionMethod, EntityRef};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Thresholds {
    /// Risk bands (§10.1). Defaults 0.30 / 0.60 / 0.85.
    pub throttle: f64,
    pub challenge: f64,
    pub contain: f64,
    /// Half lives in seconds (RISK_HALF_LIVES, default 30m, 7d).
    pub half_life_fast_secs: u64,
    pub half_life_slow_secs: u64,
    /// Per timescale thresholds: the slow timescale is scored against its own thresholds.
    pub slow_throttle: f64,
    pub slow_challenge: f64,
    pub slow_contain: f64,
    /// Confidence at or above which a source counts as "high confidence".
    pub high_confidence: f64,
}

impl Thresholds {
    pub fn spec_defaults() -> Self {
        Thresholds {
            throttle: 0.30,
            challenge: 0.60,
            contain: 0.85,
            half_life_fast_secs: 30 * 60,
            half_life_slow_secs: 7 * 24 * 3600,
            slow_throttle: 0.30,
            slow_challenge: 0.60,
            slow_contain: 0.85,
            high_confidence: 0.55,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProtectedEntity {
    pub entity: EntityRef,
    /// partner, health_check, break_glass_admin, backup_system, identity_service, hypervisor ...
    pub class: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DecoySpec {
    pub decoy_id: String,
    /// route, canary_token, honey_account, honey_oauth_grant, decoy_tool, canary_env, fake_deploy_token
    pub kind: String,
    /// The value or path that identifies the decoy (a route, token fingerprint, tool name ...).
    pub marker: String,
    /// The context the decoy was issued for (§16.1 Decoy planting): a hit from
    /// elsewhere opens an incident instead of containing.
    pub issued_context: String,
    /// The trust graph path this decoy protects.
    pub protects: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RegisteredDecoyToucher {
    /// Backup, indexing and scanning jobs that legitimately touch decoys.
    pub entity: EntityRef,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DetectionRule {
    pub rule_id: String,
    pub family: String,
    pub method: DetectionMethodName,
    pub technique: String,
    pub attack_stage: String,
    pub confidence: f64,
    pub severity: u32,
    /// Rule specific parameters (match conditions, windows ...).
    pub params: serde_json::Value,
    /// Rules returned to observe by the circuit breaker are enforced=false.
    pub enforce: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum DetectionMethodName {
    Signatures,
    PositiveSecurity,
    BehaviourBaselines,
    SequenceCorrelation,
    MachineLearning,
    Deception,
    DeclaredIntentDrift,
    ConsequenceInvariants,
}

impl DetectionMethodName {
    pub fn to_proto(self) -> DetectionMethod {
        match self {
            Self::Signatures => DetectionMethod::Signatures,
            Self::PositiveSecurity => DetectionMethod::PositiveSecurity,
            Self::BehaviourBaselines => DetectionMethod::BehaviourBaselines,
            Self::SequenceCorrelation => DetectionMethod::SequenceCorrelation,
            Self::MachineLearning => DetectionMethod::MachineLearning,
            Self::Deception => DetectionMethod::Deception,
            Self::DeclaredIntentDrift => DetectionMethod::DeclaredIntentDrift,
            Self::ConsequenceInvariants => DetectionMethod::ConsequenceInvariants,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PolicyContent {
    pub contract: String,
    /// Monotonic bundle version (TUF rollback protection compares this).
    pub version: u64,
    /// Human version string, e.g. "payments 2026.11.3".
    pub policy_version: String,
    pub issued_at: i64,
    pub expires_at: i64,
    pub thresholds: Thresholds,
    /// w per detection method.
    pub method_weights: BTreeMap<DetectionMethodName, f64>,
    pub rules: Vec<DetectionRule>,
    pub protected_entities: Vec<ProtectedEntity>,
    pub invariants: Vec<Invariant>,
    pub decoys: Vec<DecoySpec>,
    pub decoy_touchers: Vec<RegisteredDecoyToucher>,
    /// Cedar policies (policy language used by the decision core, §20).
    pub cedar_policies: String,
    /// Settings resolved by the control plane (§15).
    pub settings: BTreeMap<String, serde_json::Value>,
    /// Shared networks: throttled, never banned (Carrier NAT ranges).
    pub shared_networks: Vec<String>,
    /// Actions that require an intent token, with per action INTENT_BINDING mode.
    pub intent_binding: BTreeMap<String, String>,
    /// Allowed OpenAPI routes and schemas, compiled by the declaration compiler.
    pub declared: serde_json::Value,
    /// Rule packs / plugins pinned by this bundle (name to version).
    pub plugin_versions: BTreeMap<String, String>,
    /// True when the change lowers a threshold or adds an exemption; needs >= 2 policy keys.
    pub weakens_protection: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BundleSignature {
    pub alg: String,
    pub key_id: String,
    /// base64 signature over the exact bytes of policy.json
    pub sig: String,
}

/// A signed archive: a tar with `policy.json` and `signatures.json`.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyBundle {
    pub content_bytes: Vec<u8>,
    pub content: PolicyContent,
    pub signatures: Vec<BundleSignature>,
}


impl PolicyBundle {
    pub fn to_archive(&self) -> Result<Vec<u8>, ContractError> {
        let mut builder = tar::Builder::new(Vec::new());
        let sigs = serde_json::to_vec_pretty(&self.signatures)?;
        for (name, data) in [("policy.json", &self.content_bytes), ("signatures.json", &sigs)] {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_mtime(0);
            header.set_cksum();
            builder
                .append_data(&mut header, name, data.as_slice())
                .map_err(|e| ContractError::Archive(e.to_string()))?;
        }
        builder.into_inner().map_err(|e| ContractError::Archive(e.to_string()))
    }

    pub fn from_archive(bytes: &[u8]) -> Result<Self, ContractError> {
        use std::io::Read;
        let mut ar = tar::Archive::new(bytes);
        let mut content_bytes = None;
        let mut sig_bytes = None;
        for entry in ar.entries().map_err(|e| ContractError::Archive(e.to_string()))? {
            let mut entry = entry.map_err(|e| ContractError::Archive(e.to_string()))?;
            let path = entry
                .path()
                .map_err(|e| ContractError::Archive(e.to_string()))?
                .to_string_lossy()
                .to_string();
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf).map_err(|e| ContractError::Archive(e.to_string()))?;
            match path.as_str() {
                "policy.json" => content_bytes = Some(buf),
                "signatures.json" => sig_bytes = Some(buf),
                other => return Err(ContractError::Archive(format!("unexpected entry {other}"))),
            }
        }
        let content_bytes = content_bytes.ok_or_else(|| ContractError::Archive("missing policy.json".into()))?;
        let sig_bytes = sig_bytes.ok_or_else(|| ContractError::Archive("missing signatures.json".into()))?;
        Ok(PolicyBundle {
            content: serde_json::from_slice(&content_bytes)?,
            signatures: serde_json::from_slice(&sig_bytes)?,
            content_bytes,
        })
    }
}

