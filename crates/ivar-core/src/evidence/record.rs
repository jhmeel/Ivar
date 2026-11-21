//! One sealed evidence record.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// A SecurityEvent as received: the input the replay re executes.
    Event,
    Finding,
    Risk,
    Verdict,
    ActionRequest,
    ActionReceipt,
    EdgeChange,
    Incident,
    Policy,
    Custody,
    SinkDecision,
    Tamper,
    /// A gap: an interval where no sensor observed this layer.
    Gap,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CustodyEntry {
    pub actor: String,
    pub action: String,
    pub time: i64,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvidenceRecord {
    pub seq: u64,
    pub evidence_id: String,
    pub time: i64,
    pub kind: EvidenceKind,
    pub incident_hint: String,
    pub payload: serde_json::Value,
    pub prev_hash: String,
    pub hash: String,
    pub signature: Option<ivar_contracts::BundleSignature>,
}

impl EvidenceRecord {
    /// The bytes the hash covers.
    pub fn digest_input(seq: u64, time: i64, kind: EvidenceKind, prev_hash: &str, payload: &serde_json::Value) -> Vec<u8> {
        let kind = serde_json::to_string(&kind).unwrap_or_default();
        let payload = serde_json::to_string(payload).unwrap_or_default();
        format!("ivar.evidence.v1\n{seq}\n{time}\n{kind}\n{prev_hash}\n{payload}").into_bytes()
    }
}
