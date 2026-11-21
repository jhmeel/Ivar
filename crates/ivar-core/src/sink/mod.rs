//! The action sink (sections 6.2, 11.1, 20.1): one guard call at the point of
//! a high consequence action. It checks the intent token, the consequence
//! invariants and any time lock, in that order (figure 5). It has an observe
//! mode that shows what it would refuse before it refuses anything.

mod guard;

pub use guard::{ActionSink, SinkDecision, SinkOutcome, SinkRequest};
