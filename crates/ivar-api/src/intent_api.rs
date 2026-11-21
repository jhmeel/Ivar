//! Intent tokens: minted at the origin, attested by each step, narrowed by anyone.

use crate::{err, seed};
use ivar_core::intent::{narrow, IntentIssuer, Narrowing, StepAttestor};
use serde::Deserialize;
use std::collections::BTreeMap;

#[derive(Deserialize, Default)]
struct NarrowingSpec {
    #[serde(default)]
    max: BTreeMap<String, i64>,
    #[serde(default)]
    expiry_ms: Option<i64>,
}

fn narrowing(json: &str) -> Result<Narrowing, String> {
    let s: NarrowingSpec = if json.trim().is_empty() { NarrowingSpec::default() } else { serde_json::from_str(json).map_err(err)? };
    Ok(Narrowing { max: s.max, expiry_ms: s.expiry_ms })
}

/// Returns `{"token": "...", "root_public_key": "..."}`.
pub fn mint_intent(root_seed_hex: &str, intent_id: &str, action: &str, subject: &str, limits_json: &str, expiry_ms: f64) -> String {
    let run = || -> Result<String, String> {
        let issuer = IntentIssuer::from_seed(&seed(root_seed_hex)?).map_err(err)?;
        let limits: BTreeMap<String, i64> = serde_json::from_str(limits_json).map_err(err)?;
        let token = issuer.mint(intent_id, action, subject, &limits, expiry_ms as i64).map_err(err)?;
        Ok(serde_json::json!({"token": token, "root_public_key": issuer.public_key_hex()}).to_string())
    };
    run().unwrap_or_else(|e| e)
}
pub fn attest_step(step_seed_hex: &str, step: &str, token: &str, root_public_hex: &str, narrowing_json: &str) -> String {
    let run = || -> Result<String, String> {
        let a = StepAttestor::from_seed(step, &seed(step_seed_hex)?).map_err(err)?;
        let t = a.attest(token, root_public_hex, &narrowing(narrowing_json)?).map_err(err)?;
        Ok(serde_json::json!({"token": t, "step_public_key": a.public_key_hex()}).to_string())
    };
    run().unwrap_or_else(|e| e)
}
pub fn narrow_intent(token: &str, root_public_hex: &str, narrowing_json: &str) -> String {
    let run = || -> Result<String, String> {
        let t = narrow(token, root_public_hex, &narrowing(narrowing_json)?).map_err(err)?;
        Ok(serde_json::json!({ "token": t }).to_string())
    };
    run().unwrap_or_else(|e| e)
}

/// Public key for a seed, so a step can register its key with the verifier.
pub fn step_public_key(step_seed_hex: &str) -> String {
    match seed(step_seed_hex).and_then(|s| StepAttestor::from_seed("k", &s).map_err(err)) {
        Ok(a) => a.public_key_hex(),
        Err(e) => e,
    }
}
