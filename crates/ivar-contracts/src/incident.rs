//! Incident (JSON): timeline, affected entities, attack stage, status.
//! Produced by the correlation engine, consumed by analysts and the SIEM.

use crate::proto::EntityRef;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Incident {
    pub contract: String,
    pub incident_id: String,
    pub title: String,
    pub opened_at: i64,
    pub status: IncidentStatus,
    pub attack_stage: String,
    pub timeline: Vec<TimelineEntry>,
    pub affected_entities: Vec<EntityRef>,
    pub verdict_ids: Vec<String>,
    pub action_request_ids: Vec<String>,
    pub policy_version: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IncidentStatus {
    Open,
    Contained,
    Resolved,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TimelineEntry {
    pub time: i64,
    pub kind: String,
    pub summary: String,
    pub evidence_ids: Vec<String>,
}

