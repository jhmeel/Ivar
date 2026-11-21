//! ReplayBundle (signed, versioned JSON): frames in order, evidence IDs per
//! frame, engine, policy and plugin versions, re execution result and the
//! counterfactual flag. Produced by the replay engine, consumed by the replay
//! viewer and the evidence store.

use crate::policy::BundleSignature;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReplayFrame {
    pub index: u64,
    /// Corrected time (sensor clock + measured skew).
    pub time: i64,
    /// Sensor's own timestamp, never hidden.
    pub sensor_time: i64,
    pub clock_skew_ms: i64,
    pub sensor_id: String,
    pub sensor_seq: u64,
    /// event, finding, risk, verdict, action_request, action_receipt, edge_change, gap
    pub kind: String,
    pub evidence_ids: Vec<String>,
    pub payload: serde_json::Value,
    pub counterfactual: bool,
    /// Per hop latency (sensor, ingest, core, decide, enforce) in microseconds when known.
    pub hops_us: BTreeMap<String, u64>,
    /// True elapsed time since the first frame.
    pub elapsed_ms: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReExecution {
    pub matched: bool,
    pub recorded_verdicts: usize,
    pub replayed_verdicts: usize,
    pub mismatches: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ReplayBundle {
    pub contract: String,
    pub bundle_version: u32,
    pub incident_id: String,
    pub engine_version: String,
    pub policy_version: String,
    pub plugin_versions: BTreeMap<String, String>,
    pub counterfactual: bool,
    pub counterfactual_policy: Option<String>,
    pub evidence_chain_head: String,
    pub frames: Vec<ReplayFrame>,
    pub re_execution: ReExecution,
    /// Unobserved layers on this platform tier (e.g. host on application tier).
    pub unobserved_layers: Vec<String>,
    /// The sealed evidence the frames rest on, so the viewer can re execute it.
    pub evidence: Vec<serde_json::Value>,
    /// The policy content used, so the viewer can re execute with the same policy.
    pub policy: serde_json::Value,
    /// Later policy versions applied during the evidence window, in order.
    #[serde(default)]
    pub policy_history: Vec<serde_json::Value>,
    pub signature: Option<BundleSignature>,
}

