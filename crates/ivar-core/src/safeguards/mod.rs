//! Safeguards on every automatic action (section 11.1).
//!
//! These are hard limits: they apply whatever the policy bundle or the AI
//! layer asks for, so the automated responder cannot be steered into taking
//! the business offline (section 16.1).

mod blast_radius;
mod circuit_breaker;
mod review;
mod shared_networks;

pub use blast_radius::BlastRadiusBudget;
pub use circuit_breaker::{BreakerEvent, CircuitBreaker};
pub use review::{review, ReviewContext, ReviewOutcome};
pub use shared_networks::SharedNetworks;
