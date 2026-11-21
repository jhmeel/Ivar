//! The live trust graph. Every sensor contributes to it; detection runs
//! against it; responses narrow or revoke one edge rather than a whole identity.

use super::edge::{edge_id, new_edge, EdgeState, Observation, ObservationOutcome};
use super::node::{scope_matches, Node, NodeKind};
use ivar_contracts::{EntityRef, EntityRole, TrustEdge};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Contexts remembered per edge before the oldest is dropped.
const MAX_CONTEXTS: usize = 32;
/// A read counts as bulk when it is this many times the edge's previous maximum.
const BULK_FACTOR: f64 = 10.0;
/// Reads smaller than this are never bulk, whatever the history.
const BULK_FLOOR: f64 = 1_000.0;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DriftKind {
    /// Declared or granted, but never used.
    UnusedGrant,
    /// Used, but never declared.
    UndeclaredEdge,
    /// Standing privilege: a grant without an expiry.
    StandingPrivilege,
    /// A machine identity without a named human owner.
    Unowned,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DriftItem {
    pub kind: DriftKind,
    pub edge_id: String,
    pub holder: String,
    pub resource: String,
    pub permission: String,
    /// The declaration that explains the finding, when there is one.
    pub declared_in: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrustGraph {
    nodes: BTreeMap<String, Node>,
    edges: BTreeMap<String, TrustEdge>,
}

impl TrustGraph {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn node(&self, key: &str) -> Option<&Node> {
        self.nodes.get(key)
    }

    pub fn upsert_node(&mut self, node: Node) {
        self.nodes.insert(node.key.clone(), node);
    }

    pub fn ensure_node(&mut self, entity: &EntityRef) -> &mut Node {
        let key = entity.key();
        self.nodes.entry(key.clone()).or_insert_with(|| Node::new(&key, kind_of(&entity.r#type)))
    }

    pub fn edge(&self, id: &str) -> Option<&TrustEdge> {
        self.edges.get(id)
    }

    pub fn edges(&self) -> impl Iterator<Item = &TrustEdge> {
        self.edges.values()
    }

    pub fn nodes(&self) -> impl Iterator<Item = &Node> {
        self.nodes.values()
    }

    /// Add an edge from a declaration (OpenAPI, Terraform, IAM, CI ...) or an
    /// identity connector grant. Declared intent comes before learned behaviour.
    pub fn declare(&mut self, mut edge: TrustEdge) -> String {
        let holder = edge.holder.clone().unwrap_or_default();
        self.ensure_node(&holder);
        edge.edge_id = edge_id(&holder, &edge.resource, &edge.permission);
        edge.declared = true;
        if edge.state.is_empty() {
            edge.state = EdgeState::Active.as_str().into();
        }
        if edge.usage.is_none() {
            edge.usage = Some(Default::default());
        }
        let id = edge.edge_id.clone();
        match self.edges.get_mut(&id) {
            Some(existing) => {
                existing.declared = true;
                existing.declared_in = edge.declared_in;
                existing.purpose = edge.purpose;
                existing.scope = edge.scope;
                existing.expiry = edge.expiry;
                existing.granted_by = edge.granted_by;
                existing.owner = edge.owner;
            }
            None => {
                self.edges.insert(id.clone(), edge);
            }
        }
        id
    }

    /// Record one use of trust and report how it compares with the grant.
    pub fn observe(&mut self, obs: &Observation) -> ObservationOutcome {
        let holder = EntityRef { role: EntityRole::Unspecified as i32, ..obs.holder.clone() };
        let within_delegation = self.ensure_node(&holder).within_delegation(&obs.resource, obs.time);
        let id = self.matching_edge(&holder, &obs.resource, &obs.permission)
            .unwrap_or_else(|| edge_id(&holder, &obs.resource, &obs.permission));

        let mut outcome = ObservationOutcome { edge_id: id.clone(), outside_purpose: !within_delegation, ..Default::default() };
        let edge = self.edges.entry(id).or_insert_with(|| {
            outcome.undeclared = true;
            new_edge(&holder, &obs.resource, &obs.permission)
        });
        if !edge.declared {
            outcome.undeclared = true;
        }
        edge.observed = true;
        if edge.state == EdgeState::Revoked.as_str() || (edge.expiry > 0 && obs.time > edge.expiry) {
            outcome.expired_or_revoked = true;
        }
        let usage = edge.usage.get_or_insert_with(Default::default);
        outcome.first_use = usage.uses == 0;
        if !obs.context.is_empty() && !usage.contexts.iter().any(|c| c == &obs.context) {
            outcome.new_context = usage.uses > 0;
            usage.contexts.push(obs.context.clone());
            if usage.contexts.len() > MAX_CONTEXTS {
                usage.contexts.remove(0);
            }
        }
        if usage.uses > 0 && obs.records >= BULK_FLOOR && obs.records > usage.max_records_per_use.max(1.0) * BULK_FACTOR {
            outcome.bulk_anomaly = true;
        }
        usage.mean_records_per_use =
            (usage.mean_records_per_use * usage.uses as f64 + obs.records) / (usage.uses as f64 + 1.0);
        usage.max_records_per_use = usage.max_records_per_use.max(obs.records);
        usage.uses += 1;
        if usage.first_used == 0 {
            usage.first_used = obs.time;
        }
        usage.last_used = obs.time;
        if !obs.action.is_empty() {
            *usage.actions.entry(obs.action.clone()).or_insert(0) += 1;
        }
        outcome
    }

    /// An edge whose resource pattern covers the observed resource.
    fn matching_edge(&self, holder: &EntityRef, resource: &str, permission: &str) -> Option<String> {
        let exact = edge_id(holder, resource, permission);
        if self.edges.contains_key(&exact) {
            return Some(exact);
        }
        let key = holder.key();
        self.edges
            .values()
            .find(|e| {
                e.holder.as_ref().map(|h| h.key()) == Some(key.clone())
                    && (e.permission == permission || e.permission == "*")
                    && scope_matches(&e.resource, resource)
            })
            .map(|e| e.edge_id.clone())
    }

    /// Narrow an edge to a smaller scope. Narrowing never widens.
    pub fn narrow(&mut self, id: &str, scope: &str, expiry: i64) -> bool {
        match self.edges.get_mut(id) {
            Some(e) if e.state != EdgeState::Revoked.as_str() => {
                e.scope = scope.to_string();
                if e.expiry == 0 || (expiry > 0 && expiry < e.expiry) {
                    e.expiry = expiry;
                }
                e.state = EdgeState::Narrowed.as_str().into();
                true
            }
            _ => false,
        }
    }

    pub fn revoke(&mut self, id: &str) -> bool {
        match self.edges.get_mut(id) {
            Some(e) => {
                e.state = EdgeState::Revoked.as_str().into();
                true
            }
            None => false,
        }
    }

    /// Reverse a revocation or narrowing (every action can be undone).
    pub fn restore(&mut self, id: &str) -> bool {
        match self.edges.get_mut(id) {
            Some(e) => {
                e.state = EdgeState::Active.as_str().into();
                true
            }
            None => false,
        }
    }

    pub fn set_edge_risk(&mut self, id: &str, risk: f64) {
        if let Some(e) = self.edges.get_mut(id) {
            e.risk = risk;
        }
    }

    /// Drift between what was declared and what is observed (section 6.3).
    /// This produces findings on the first day of observe mode.
    pub fn drift(&self) -> Vec<DriftItem> {
        let mut out = Vec::new();
        for e in self.edges.values() {
            let holder = e.holder.as_ref().map(|h| h.key()).unwrap_or_default();
            let item = |kind| DriftItem {
                kind,
                edge_id: e.edge_id.clone(),
                holder: holder.clone(),
                resource: e.resource.clone(),
                permission: e.permission.clone(),
                declared_in: e.declared_in.clone(),
            };
            if e.declared && !e.observed {
                out.push(item(DriftKind::UnusedGrant));
            }
            if e.observed && !e.declared {
                out.push(item(DriftKind::UndeclaredEdge));
            }
            if e.declared && e.expiry == 0 && is_machine(&holder) {
                out.push(item(DriftKind::StandingPrivilege));
            }
        }
        for n in self.nodes.values() {
            if matches!(n.kind, NodeKind::Service | NodeKind::Agent | NodeKind::Token) && n.owner.is_none() {
                out.push(DriftItem {
                    kind: DriftKind::Unowned,
                    edge_id: String::new(),
                    holder: n.key.clone(),
                    resource: String::new(),
                    permission: String::new(),
                    declared_in: String::new(),
                });
            }
        }
        out
    }
}

fn is_machine(key: &str) -> bool {
    ["service:", "agent:", "api_key:", "token:", "oauth_grant:"].iter().any(|p| key.starts_with(p))
}

pub(crate) fn kind_of(entity_type: &str) -> NodeKind {
    match entity_type {
        "user" | "human" => NodeKind::Human,
        "service" | "workload" | "process" | "host" => NodeKind::Service,
        "agent" => NodeKind::Agent,
        "token" | "api_key" | "session" | "oauth_grant" => NodeKind::Token,
        "device" | "ip" => NodeKind::Device,
        "package" | "image" | "model" | "dataset" => NodeKind::Package,
        _ => NodeKind::Resource,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trust::Delegation;

    fn obs(holder: &EntityRef, resource: &str, records: f64, ctx: &str, t: i64) -> Observation {
        Observation { holder: holder.clone(), resource: resource.into(), permission: "read".into(), context: ctx.into(), records, action: "read".into(), time: t }
    }

    #[test]
    fn declared_edge_then_drift_and_misuse() {
        let mut g = TrustGraph::new();
        let svc = EntityRef::actor("service", "billing");
        g.declare(TrustEdge { holder: Some(svc.clone()), resource: "db:invoices".into(), permission: "read".into(), declared_in: "iam/billing.json".into(), expiry: 0, ..Default::default() });
        g.declare(TrustEdge { holder: Some(svc.clone()), resource: "s3:exports".into(), permission: "read".into(), declared_in: "iam/billing.json".into(), ..Default::default() });
        let o = g.observe(&obs(&svc, "db:invoices", 10.0, "pod-a", 1));
        assert!(!o.undeclared && o.first_use);
        let o = g.observe(&obs(&svc, "db:invoices", 50_000.0, "pod-b", 2));
        assert!(o.bulk_anomaly && o.new_context);
        let o = g.observe(&obs(&svc, "payments:api", 1.0, "pod-a", 3));
        assert!(o.undeclared);
        let drift = g.drift();
        assert!(drift.iter().any(|d| d.kind == DriftKind::UnusedGrant && d.resource == "s3:exports"));
        assert!(drift.iter().any(|d| d.kind == DriftKind::UndeclaredEdge && d.resource == "payments:api"));
        assert!(drift.iter().any(|d| d.kind == DriftKind::StandingPrivilege));
        assert!(drift.iter().any(|d| d.kind == DriftKind::Unowned));
    }

    #[test]
    fn agent_outside_delegated_purpose() {
        let mut g = TrustGraph::new();
        let agent = EntityRef::actor("agent", "support-bot");
        let mut n = Node::new(&agent.key(), NodeKind::Agent);
        n.owner = Some("user:alice".into());
        n.delegation = Some(Delegation { from: "user:alice".into(), purpose: "answer tickets".into(), scope: vec!["db:tickets*".into()], expires_at: 100 });
        g.upsert_node(n);
        assert!(!g.observe(&obs(&agent, "db:tickets/42", 1.0, "", 5)).outside_purpose);
        assert!(g.observe(&obs(&agent, "payments:api", 1.0, "", 6)).outside_purpose);
        assert!(g.observe(&obs(&agent, "db:tickets/43", 1.0, "", 200)).outside_purpose);
    }

    #[test]
    fn revoke_and_restore_one_edge() {
        let mut g = TrustGraph::new();
        let k = EntityRef::actor("api_key", "k1");
        let id = g.declare(TrustEdge { holder: Some(k.clone()), resource: "orders".into(), permission: "read".into(), ..Default::default() });
        assert!(g.revoke(&id));
        assert!(g.observe(&obs(&k, "orders", 1.0, "", 1)).expired_or_revoked);
        assert!(g.restore(&id));
        assert!(!g.observe(&obs(&k, "orders", 1.0, "", 2)).expired_or_revoked);
    }
}
