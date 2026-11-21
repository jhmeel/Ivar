//! The IVAR edge filter.
//!
//! The filter logic is plain Rust in `logic`, tested natively; `host` is the
//! thin Proxy-Wasm glue compiled for the gateway. Coraza with the OWASP Core
//! Rule Set runs as its own proxy-wasm filter in front of this one (virtual
//! patching); its alerts reach the core through the shared log pipeline, and
//! this filter blocks known attacks from signed policy, decoy routes,
//! positive security against the OpenAPI schema and core verdicts.

pub mod config;
pub mod logic;

#[cfg(target_arch = "wasm32")]
mod host;

pub use config::EdgeConfig;
pub use logic::{EdgeAction, EdgeLogic, RequestView};
