//! Trust edges are the unit of detection (section 6.1).

use crate::ids;
use ivar_contracts::{EntityRef, TrustEdge};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EdgeState {
    Active,
    Narrowed,
    Revoked,
}

impl EdgeState {
    pub fn as_str(self) -> &'static str {
        match self {
            EdgeState::Active => "active",
            EdgeState::Narrowed => "narrowed",
            EdgeState::Revoked => "revoked",
        }
    }
}

pub fn edge_id(holder: &EntityRef, resource: &str, permission: &str) -> String {
    ids::derive("edg", &[&holder.key(), resource, permission])
}

/// One observed use of a trust relationship.
#[derive(Debug, Clone, Default)]
pub struct Observation {
    pub holder: EntityRef,
    pub resource: String,
    pub permission: String,
    /// Device or network context the credential was presented from.
    pub context: String,
    pub records: f64,
    pub action: String,
    pub time: i64,
}

/// What the graph learned from one observation.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ObservationOutcome {
    pub edge_id: String,
    /// The edge was never declared or granted.
    pub undeclared: bool,
    /// First use of a declared edge ever.
    pub first_use: bool,
    /// Token presented from a context never seen before for this edge.
    pub new_context: bool,
    /// Agent or machine acting outside its delegated purpose.
    pub outside_purpose: bool,
    /// Bulk read far above this edge's usage profile.
    pub bulk_anomaly: bool,
    /// The grant has expired or was revoked.
    pub expired_or_revoked: bool,
}

pub(crate) fn new_edge(holder: &EntityRef, resource: &str, permission: &str) -> TrustEdge {
    TrustEdge {
        edge_id: edge_id(holder, resource, permission),
        holder: Some(holder.clone()),
        resource: resource.to_string(),
        permission: permission.to_string(),
        state: EdgeState::Active.as_str().to_string(),
        usage: Some(Default::default()),
        ..Default::default()
    }
}
