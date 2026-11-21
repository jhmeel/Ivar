//! Nodes of the trust graph: human, service, agent, token, device and package.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Human,
    Service,
    Agent,
    Token,
    Device,
    Package,
    Resource,
}

/// An explicit, time limited delegation recording whose authority a machine
/// identity uses and for what (principle 3).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Delegation {
    pub from: String,
    pub purpose: String,
    /// Resources the delegated task may reach. Anything else is outside its purpose.
    pub scope: Vec<String>,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Node {
    /// "type:id" key.
    pub key: String,
    pub kind: NodeKind,
    /// Every machine and agent has a named human owner.
    pub owner: Option<String>,
    pub delegation: Option<Delegation>,
    /// Established accounts count against the blast radius budget.
    pub established: bool,
}

impl Node {
    pub fn new(key: &str, kind: NodeKind) -> Self {
        Node { key: key.to_string(), kind, owner: None, delegation: None, established: false }
    }

    /// True when the resource is inside this node's delegated purpose.
    pub fn within_delegation(&self, resource: &str, now: i64) -> bool {
        match &self.delegation {
            None => true,
            Some(d) => now <= d.expires_at && d.scope.iter().any(|s| scope_matches(s, resource)),
        }
    }
}

/// Scope patterns: exact, or a trailing `*` prefix match.
pub fn scope_matches(pattern: &str, value: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => value.starts_with(prefix),
        None => pattern == value,
    }
}
