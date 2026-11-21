//! Prevention and safe response (section 11).
//!
//! Response climbs a seven level ladder, using the mildest action that stops
//! the threat. Every automatic action expires unless a person extends it, and
//! every action records exactly how to undo it.

mod ladder;
mod orchestrator;

pub use ladder::{Rung, LADDER};
pub use orchestrator::{plan_actions, receipt_for, PlannedAction};
