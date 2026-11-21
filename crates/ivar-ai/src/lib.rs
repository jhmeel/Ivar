//! AI layer (section 12).
//!
//! Any AI model can plug in through one provider interface, but AI only
//! recommends and the policy engine decides. The model never holds
//! credentials, and it is never placed in the inline path of a live request:
//! detection continues without AI, and every AI failure leaves the
//! deterministic decision unchanged.

pub mod advisor;
pub mod config;
pub mod guardrails;
pub mod provider;
pub mod roles;
pub mod schema;

pub use advisor::{ActionProposal, AiLayer};
pub use config::{AiConfig, Autonomy};
pub use provider::{AiProvider, AiRequest, AiResponse, ProviderError};
pub use roles::Role;
