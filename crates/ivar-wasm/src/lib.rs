//! wasm-bindgen wrapper over `ivar-api` for JavaScript hosts.

use ivar_api as api;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(js_name = engineVersion)]
pub fn engine_version() -> String {
    api::engine_version()
}

#[wasm_bindgen(js_name = defaultPolicy)]
pub fn default_policy(now_ms: f64) -> String {
    api::default_policy(now_ms)
}

#[wasm_bindgen(js_name = verifyPolicyBundle)]
pub fn verify_policy_bundle(archive_base64: &str, keyring_json: &str, current_version: f64, now_ms: f64) -> String {
    api::verify_policy_bundle(archive_base64, keyring_json, current_version, now_ms)
}

#[wasm_bindgen(js_name = compileDeclarations)]
pub fn compile_declarations(kind: &str, file: &str, text: &str, holder: &str) -> String {
    api::compile_declarations(kind, file, text, holder)
}

#[wasm_bindgen(js_name = mintIntent)]
pub fn mint_intent(root_seed_hex: &str, intent_id: &str, action: &str, subject: &str, limits_json: &str, expiry_ms: f64) -> String {
    api::mint_intent(root_seed_hex, intent_id, action, subject, limits_json, expiry_ms)
}

#[wasm_bindgen(js_name = attestStep)]
pub fn attest_step(step_seed_hex: &str, step: &str, token: &str, root_public_hex: &str, narrowing_json: &str) -> String {
    api::attest_step(step_seed_hex, step, token, root_public_hex, narrowing_json)
}

#[wasm_bindgen(js_name = narrowIntent)]
pub fn narrow_intent(token: &str, root_public_hex: &str, narrowing_json: &str) -> String {
    api::narrow_intent(token, root_public_hex, narrowing_json)
}

#[wasm_bindgen(js_name = stepPublicKey)]
pub fn step_public_key(step_seed_hex: &str) -> String {
    api::step_public_key(step_seed_hex)
}

#[wasm_bindgen(js_name = reverifyBundle)]
pub fn reverify_bundle(bundle_json: &str, keyring_json: &str, redaction_key_hex: &str) -> String {
    api::reverify_bundle(bundle_json, keyring_json, redaction_key_hex)
}

#[wasm_bindgen(js_name = verifyEvidenceChain)]
pub fn verify_evidence_chain(records_json: &str) -> String {
    api::verify_evidence_chain(records_json)
}

#[wasm_bindgen]
pub struct Core(api::Core);

#[wasm_bindgen]
impl Core {
    #[wasm_bindgen(constructor)]
    pub fn new(policy_json: &str, redaction_key_hex: &str) -> Result<Core, String> {
        api::Core::new(policy_json, redaction_key_hex).map(Core)
    }
    pub fn process(&mut self, event_json: &str, now_ms: f64) -> String {
        self.0.process(event_json, now_ms)
    }
    pub fn evidence(&self) -> String {
        self.0.evidence()
    }
    pub fn incidents(&self) -> String {
        self.0.incidents()
    }
    pub fn drift(&self) -> String {
        self.0.drift()
    }
    pub fn tick(&mut self, now_ms: f64) -> String {
        self.0.tick(now_ms)
    }
}

#[wasm_bindgen]
pub struct LocalSensor(api::LocalSensor);

#[wasm_bindgen]
impl LocalSensor {
    #[wasm_bindgen(constructor)]
    pub fn new(policy_json: &str) -> Result<LocalSensor, String> {
        api::LocalSensor::new(policy_json).map(LocalSensor)
    }
    pub fn decide(&self, event_json: &str, now_ms: f64) -> String {
        self.0.decide(event_json, now_ms)
    }
    #[wasm_bindgen(js_name = pushVerdict)]
    pub fn push_verdict(&mut self, verdict_json: &str) -> bool {
        self.0.push_verdict(verdict_json)
    }
}

#[wasm_bindgen]
pub struct Sink(api::Sink);

#[wasm_bindgen]
impl Sink {
    #[wasm_bindgen(constructor)]
    pub fn new(root_public_hex: &str, step_keys_json: &str, invariants_json: &str, default_mode: &str, modes_json: &str) -> Result<Sink, String> {
        api::Sink::new(root_public_hex, step_keys_json, invariants_json, default_mode, modes_json).map(Sink)
    }
    pub fn guard(&mut self, request_json: &str, now_ms: f64) -> String {
        self.0.guard(request_json, now_ms)
    }
    pub fn cancel(&mut self, lock_id: &str, owner: &str, request_json: &str) -> String {
        self.0.cancel(lock_id, owner, request_json)
    }
    #[wasm_bindgen(js_name = releaseDue)]
    pub fn release_due(&mut self, now_ms: f64) -> String {
        self.0.release_due(now_ms)
    }
    #[wasm_bindgen(js_name = setMode)]
    pub fn set_mode(&mut self, action: &str, mode: &str) -> bool {
        self.0.set_mode(action, mode)
    }
    pub fn revoke(&mut self, revocation_id_hex: &str) {
        self.0.revoke(revocation_id_hex)
    }
}
