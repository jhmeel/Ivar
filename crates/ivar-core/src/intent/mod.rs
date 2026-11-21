//! Intent binding (section 6.2).
//!
//! Every high consequence action must carry a verifiable chain back to the
//! business intent that caused it. Intent travels as a short lived,
//! attenuable capability token (a Biscuit): minted where the intent starts,
//! attested by each later step with that step's own key, narrowed but never
//! widened, and verified by the SDK where the action happens. A valid stolen
//! credential with no chain behind it cannot act.

mod chains;
mod token;

pub use chains::{chain_for, IntentChain, CHAINS};
pub use token::{narrow, IntentError, IntentIssuer, IntentVerifier, Narrowing, StepAttestor, VerifyRequest};
