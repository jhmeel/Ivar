//! The sensor side of the decision flow (section 7.1, figure 4).
//!
//! A known attack is blocked inside the sensor in about a millisecond, with
//! no round trip. Anything else is normalised to OCSF and sent to the core.
//! Sensors keep enforcing their last signed policy and the core's cached
//! verdicts when the core is unreachable.

mod fast_path;
mod ocsf;

pub use fast_path::{LocalDecision, SensorPolicy};
pub use ocsf::{ocsf_class, EventBuilder};
