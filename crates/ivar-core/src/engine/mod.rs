//! The decision core: correlates evidence across layers and stops attacks
//! that look harmless in any single log (sections 7 and 10).
//!
//! `DecisionCore::process` is a pure function of the policy, the previous
//! state and the event, which is what lets the replay engine re execute
//! sealed evidence and match the live verdicts exactly.

mod core;
mod observe;
mod output;

pub use self::core::{CoreOptions, DecisionCore};
pub use output::{EngineOutput, ReviewedAction};
