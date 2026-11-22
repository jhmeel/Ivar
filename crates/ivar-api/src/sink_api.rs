//! The action sink: one guard call where a high consequence action happens.

use crate::err;
use ivar_contracts::Invariant;
use ivar_core::config::IntentBindingMode;
use ivar_core::intent::IntentVerifier;
use ivar_core::invariants::InvariantEngine;
use ivar_core::sink::{ActionSink, SinkRequest};
use std::collections::BTreeMap;
pub struct Sink {
    inner: ActionSink,
}

fn mode(s: &str) -> Result<IntentBindingMode, String> {
    IntentBindingMode::parse(s).ok_or_else(|| err(format!("unknown intent binding mode {s}")))
}
impl Sink {
    /// `step_keys_json`: step name to public key hex. `modes_json`: action to mode.
    pub fn new(root_public_hex: &str, step_keys_json: &str, invariants_json: &str, default_mode: &str, modes_json: &str) -> Result<Sink, String> {
        let keys: BTreeMap<String, String> = serde_json::from_str(step_keys_json).map_err(err)?;
        let invariants: Vec<Invariant> = serde_json::from_str(invariants_json).map_err(err)?;
        let raw: BTreeMap<String, String> = if modes_json.trim().is_empty() { BTreeMap::new() } else { serde_json::from_str(modes_json).map_err(err)? };
        let mut modes = BTreeMap::new();
        for (k, v) in raw {
            modes.insert(k, mode(&v)?);
        }
        let inner = ActionSink::new(IntentVerifier::new(root_public_hex, keys), InvariantEngine::new(invariants), mode(default_mode)?, modes);
        Ok(Sink { inner })
    }

    pub fn guard(&mut self, request_json: &str, now_ms: f64) -> String {
        let r: SinkRequest = match serde_json::from_str(request_json) {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        serde_json::to_string(&self.inner.guard(&r, now_ms as i64)).unwrap_or_else(err)
    }

    pub fn cancel(&mut self, lock_id: &str, owner: &str, request_json: &str) -> String {
        let r: SinkRequest = match serde_json::from_str(request_json) {
            Ok(r) => r,
            Err(e) => return err(e),
        };
        match self.inner.cancel(lock_id, owner, &r) {
            Ok(h) => serde_json::to_string(&h).unwrap_or_else(err),
            Err(e) => err(e),
        }
    }
    /// What the sink remembers (consumed intents, consequence totals, held
    /// actions), as JSON, for a host that keeps it between processes.
    pub fn state(&self) -> String {
        serde_json::to_string(&self.inner.state()).unwrap_or_else(err)
    }

    /// Take up state from an earlier `state`.
    pub fn restore(&mut self, state_json: &str) -> String {
        if state_json.trim().is_empty() {
            return serde_json::json!({ "ok": true }).to_string();
        }
        match serde_json::from_str(state_json) {
            Ok(st) => {
                self.inner.restore(st);
                serde_json::json!({ "ok": true }).to_string()
            }
            Err(e) => err(e),
        }
    }

    pub fn release_due(&mut self, now_ms: f64) -> String {
        serde_json::to_string(&self.inner.release_due(now_ms as i64)).unwrap_or_else(err)
    }
    pub fn set_mode(&mut self, action: &str, m: &str) -> bool {
        match mode(m) {
            Ok(m) => {
                self.inner.set_mode(action, m);
                true
            }
            Err(_) => false,
        }
    }

    pub fn revoke(&mut self, revocation_id_hex: &str) {
        self.inner.verifier_mut().revoke(revocation_id_hex);
    }
}
