//! IVAR decision core.
//!
//! Deterministic and local (principle 7): nothing in this crate reads a clock,
//! a random source or the network. Time is always an argument and every id is
//! derived from the evidence, so the replay engine can re run sealed evidence
//! and reproduce each verdict exactly (section 13.1). The crate compiles to
//! WebAssembly, so application SDKs, the edge filter and the replay viewer all
//! run the same verified code (section 20).
//!
//! Each domain lives in its own module and talks to its neighbours through the
//! contracts in `ivar_contracts`, so any part can be replaced on its own.

pub mod config;
pub mod declare;
pub mod detect;
pub mod engine;
pub mod evidence;
pub mod failure;
pub mod ids;
pub mod incident;
pub mod intent;
pub mod invariants;
pub mod policy;
pub mod redact;
pub mod response;
pub mod risk;
pub mod safeguards;
pub mod sensor;
pub mod sink;
pub mod time;
pub mod trust;

pub use engine::{DecisionCore, EngineOutput};

/// Version of the decision engine, pinned in every ReplayBundle (section 13.2).
pub const ENGINE_VERSION: &str = concat!("ivar-core/", env!("CARGO_PKG_VERSION"));
