//! Policy decision (sections 7.1, 10.1, 16).
//!
//! The risk score is mapped to a response band; Cedar policies then decide
//! whether the core may take the action automatically, and whether an
//! operator may take an action by hand.

mod bands;
mod cedar;
mod defaults;

pub use bands::{decide, Band, Decision, DecisionInput};
pub use cedar::{AutoActionContext, CedarPolicy, OperatorRequest};
pub use defaults::{default_cedar_policies, spec_default_policy};
