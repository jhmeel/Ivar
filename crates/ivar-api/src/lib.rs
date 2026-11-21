//! The JSON level API of the decision core.
//!
//! Every function takes and returns JSON strings, so any host can call the
//! same verified core. `ivar-wasm` exposes it to JavaScript through
//! wasm-bindgen and `ivar-abi` exposes it through a C ABI for every other
//! WebAssembly runtime. Errors are returned as `{"error": "..."}`.

pub mod core_api;
pub mod intent_api;
pub mod policy_api;
pub mod replay_api;
pub mod sink_api;

pub use core_api::{compile_declarations, Core, LocalSensor};
pub use policy_api::{default_policy, verify_policy_bundle};
pub use intent_api::{attest_step, mint_intent, narrow_intent, step_public_key};
pub use replay_api::{reverify_bundle, verify_evidence_chain};
pub use sink_api::Sink;

pub fn err(e: impl std::fmt::Display) -> String {
    serde_json::json!({ "error": e.to_string() }).to_string()
}

pub fn seed(hex_seed: &str) -> Result<[u8; 32], String> {
    let b = hex::decode(hex_seed).map_err(|e| e.to_string())?;
    b.try_into().map_err(|_| "seed must be 32 bytes".to_string())
}

/// Engine version, pinned in replay bundles.
pub fn engine_version() -> String {
    ivar_core::ENGINE_VERSION.to_string()
}
