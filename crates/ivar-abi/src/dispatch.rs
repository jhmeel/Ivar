//! Request routing for the C ABI.

use ivar_api as api;
use serde_json::{json, Value};
use std::cell::RefCell;
use std::collections::BTreeMap;

enum Object {
    Core(api::Core),
    Sensor(api::LocalSensor),
    Sink(api::Sink),
}

thread_local! {
    static HANDLES: RefCell<(u64, BTreeMap<u64, Object>)> = const { RefCell::new((0, BTreeMap::new())) };
}

fn store(o: Object) -> String {
    HANDLES.with(|h| {
        let mut h = h.borrow_mut();
        h.0 += 1;
        let id = h.0;
        h.1.insert(id, o);
        json!({ "handle": id }).to_string()
    })
}

fn with<R>(handle: u64, f: impl FnOnce(&mut Object) -> R) -> Result<R, String> {
    HANDLES.with(|h| h.borrow_mut().1.get_mut(&handle).map(f).ok_or_else(|| api::err(format!("unknown handle {handle}"))))
}

fn s<'a>(a: &'a Value, k: &str) -> &'a str {
    a.get(k).and_then(Value::as_str).unwrap_or("")
}

fn n(a: &Value, k: &str) -> f64 {
    a.get(k).and_then(Value::as_f64).unwrap_or(0.0)
}

/// Values given as JSON objects are passed on as JSON text.
fn j(a: &Value, k: &str) -> String {
    match a.get(k) {
        Some(Value::String(s)) => s.clone(),
        Some(v) => v.to_string(),
        None => String::new(),
    }
}

fn wrong(kind: &str) -> String {
    api::err(format!("handle is not a {kind}"))
}

pub fn handle(input: &[u8]) -> String {
    let req: Value = match serde_json::from_slice(input) {
        Ok(v) => v,
        Err(e) => return api::err(e),
    };
    let op = s(&req, "op");
    let handle = req.get("handle").and_then(Value::as_u64).unwrap_or(0);
    let a = req.get("args").cloned().unwrap_or(Value::Null);
    let r: Result<String, String> = match op {
        "engine.version" => Ok(json!({ "version": api::engine_version() }).to_string()),
        "policy.default" => Ok(api::default_policy(n(&a, "now_ms"))),
        "policy.verify" => Ok(api::verify_policy_bundle(s(&a, "archive_base64"), &j(&a, "keyring"), n(&a, "current_version"), n(&a, "now_ms"))),
        "declare.compile" => Ok(api::compile_declarations(s(&a, "kind"), s(&a, "file"), s(&a, "text"), s(&a, "holder"))),
        "intent.mint" => Ok(api::mint_intent(s(&a, "root_seed_hex"), s(&a, "intent_id"), s(&a, "action"), s(&a, "subject"), &j(&a, "limits"), n(&a, "expiry_ms"))),
        "intent.attest" => Ok(api::attest_step(s(&a, "step_seed_hex"), s(&a, "step"), s(&a, "token"), s(&a, "root_public_key"), &j(&a, "narrowing"))),
        "intent.narrow" => Ok(api::narrow_intent(s(&a, "token"), s(&a, "root_public_key"), &j(&a, "narrowing"))),
        "intent.step_public_key" => Ok(json!({ "public_key": api::step_public_key(s(&a, "step_seed_hex")) }).to_string()),
        "replay.reverify" => Ok(api::reverify_bundle(&j(&a, "bundle"), &j(&a, "keyring"), s(&a, "redaction_key_hex"))),
        "evidence.verify" => Ok(api::verify_evidence_chain(&j(&a, "records"))),
        "core.new" => api::Core::new(&j(&a, "policy"), s(&a, "redaction_key_hex")).map(|c| store(Object::Core(c))),
        "core.process" => with(handle, |o| match o { Object::Core(c) => c.process(&j(&a, "event"), n(&a, "now_ms")), _ => wrong("core") }),
        "core.evidence" => with(handle, |o| match o { Object::Core(c) => c.evidence(), _ => wrong("core") }),
        "core.incidents" => with(handle, |o| match o { Object::Core(c) => c.incidents(), _ => wrong("core") }),
        "core.drift" => with(handle, |o| match o { Object::Core(c) => c.drift(), _ => wrong("core") }),
        "core.update_policy" => with(handle, |o| match o { Object::Core(c) => c.update_policy(&j(&a, "policy"), n(&a, "now_ms")), _ => wrong("core") }),
        "core.tick" => with(handle, |o| match o { Object::Core(c) => c.tick(n(&a, "now_ms")), _ => wrong("core") }),
        "sensor.new" => api::LocalSensor::new(&j(&a, "policy")).map(|c| store(Object::Sensor(c))),
        "sensor.decide" => with(handle, |o| match o { Object::Sensor(c) => c.decide(&j(&a, "event"), n(&a, "now_ms")), _ => wrong("sensor") }),
        "sensor.push_verdict" => with(handle, |o| match o { Object::Sensor(c) => json!({ "ok": c.push_verdict(&j(&a, "verdict")) }).to_string(), _ => wrong("sensor") }),
        "sink.new" => api::Sink::new(s(&a, "root_public_key"), &j(&a, "step_keys"), &j(&a, "invariants"), s(&a, "default_mode"), &j(&a, "modes")).map(|c| store(Object::Sink(c))),
        "sink.guard" => with(handle, |o| match o { Object::Sink(c) => c.guard(&j(&a, "request"), n(&a, "now_ms")), _ => wrong("sink") }),
        "sink.cancel" => with(handle, |o| match o { Object::Sink(c) => c.cancel(s(&a, "lock_id"), s(&a, "owner"), &j(&a, "request")), _ => wrong("sink") }),
        "sink.release_due" => with(handle, |o| match o { Object::Sink(c) => c.release_due(n(&a, "now_ms")), _ => wrong("sink") }),
        "sink.set_mode" => with(handle, |o| match o { Object::Sink(c) => json!({ "ok": c.set_mode(s(&a, "action"), s(&a, "mode")) }).to_string(), _ => wrong("sink") }),
        "free" => Ok(HANDLES.with(|h| json!({ "freed": h.borrow_mut().1.remove(&handle).is_some() }).to_string())),
        other => Err(api::err(format!("unknown op {other}"))),
    };
    r.unwrap_or_else(|e| e)
}

#[cfg(test)]
mod tests {
    use super::handle;
    use serde_json::{json, Value};

    fn call(v: Value) -> Value {
        serde_json::from_str(&handle(v.to_string().as_bytes())).unwrap()
    }

    #[test]
    fn core_round_trip() {
        let policy: Value = call(json!({"op": "policy.default", "args": {"now_ms": 0}}));
        let h = call(json!({"op": "core.new", "args": {"policy": policy, "redaction_key_hex": "00"}}))["handle"].as_u64().unwrap();
        let ev = json!({"activity_name": "ai.tool_call", "actor": {"user": {"uid": "bot", "type": "agent"}}, "ivar": {"sensor_id": "aigw", "sensor_type": "ai_gateway", "attributes": {"tool": "export_all_customers"}}});
        let out = call(json!({"op": "core.process", "handle": h, "args": {"event": ev, "now_ms": 5}}));
        assert_eq!(out["decision"], "contain");
        assert_eq!(call(json!({"op": "free", "handle": h}))["freed"], true);
        assert!(call(json!({"op": "core.process", "handle": h, "args": {}}))["error"].is_string());
    }
}
