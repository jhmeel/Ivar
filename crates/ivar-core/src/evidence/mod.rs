//! Evidence store (sections 13.1, 16).
//!
//! Evidence is written to append only storage with a verifiable hash chain
//! and a recorded chain of custody. Every record is signed. The replay engine
//! verifies the chain before it re executes anything.

mod record;
mod store;

pub use record::{CustodyEntry, EvidenceKind, EvidenceRecord};
pub use store::{verify_chain, ChainError, EvidenceStore, MemoryEvidenceStore, GENESIS_HASH};
