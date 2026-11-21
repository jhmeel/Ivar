//! The trust fabric (section 6): a continuously verified model of every actor
//! and every trust relationship in the estate. It sits under the detection
//! core as the primary source of truth.

mod edge;
mod graph;
mod node;

pub use edge::{edge_id, EdgeState, Observation, ObservationOutcome};
pub use graph::{DriftItem, DriftKind, TrustGraph};
pub use node::{Delegation, Node, NodeKind};
