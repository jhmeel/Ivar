//! Incident replay (section 13).
//!
//! The replay engine reads an incident's evidence from the append only store
//! and verifies its hash chain. It then re runs the recorded events through
//! the same detection core, policy version and plugin versions that judged
//! them live. The verdicts it produces must match the recorded verdicts
//! exactly; any mismatch halts the replay and flags the evidence or the
//! engine, so a replay can never show a decision the live system did not make.

mod build;
mod frames;
pub mod library;

pub use build::{build_replay, reverify_bundle, ReplayError, ReplayRequest};
pub use frames::{frames_for, SensorClock};

/// Version of the ReplayBundle format.
pub const BUNDLE_VERSION: u32 = 1;
