//! What happens when something fails (section 11.2).
//!
//! Failure behaviour is set per control and declared in policy: traffic
//! filters fail open within a budget, kill switches hold their safest state,
//! and silence from a sensor is treated as a possible attack.

mod buffer;
mod fail_open;
mod table;
mod tamper;

pub use buffer::EventBuffer;
pub use fail_open::{FailOpenBudget, FailOpenDecision};
pub use table::{behaviour_for, Failure, FailureBehaviour, FAILURE_TABLE};
pub use tamper::{TamperMonitor, TAMPER_AFTER_MS};
