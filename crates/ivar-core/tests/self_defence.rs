//! Section 16.1 attacks on the IVAR itself that run through the decision core.

use ivar_core::declare::compile_openapi;
use ivar_core::detect::vocabulary as v;
use ivar_core::policy::spec_default_policy;
use ivar_core::sensor::{ocsf_class as c, EventBuilder};
use ivar_core::{engine::CoreOptions, DecisionCore};
use serde_json::json;

const API: &str = "openapi: 3.0.3\npaths:\n  /profile:\n    patch:\n      requestBody:\n        content:\n          application/json:\n            schema: { type: object, properties: { name: { type: string } } }\n";

fn core(extra: &[(&str, serde_json::Value)]) -> DecisionCore {
    let mut p = spec_default_policy(0);
    p.declared = compile_openapi("api.yaml", API).unwrap().to_value();
    p.settings.insert("detection_mode".into(), json!("enforce"));
    for (k, val) in extra {
        p.settings.insert(k.to_string(), val.clone());
    }
    DecisionCore::new(p, CoreOptions::default()).unwrap()
}

fn patch(user: &str, ip: &str, established: bool, t: i64, seq: u64) -> ivar_contracts::SecurityEvent {
    let mut b = EventBuilder::new(c::HTTP_ACTIVITY, v::HTTP_REQUEST, t, "sdk-1", "app_sdk", seq).src_ip(ip).user(user, "human").http("PATCH", "/profile", &["name", "nickname"], 200);
    if established {
        b = b.attr("account_age_days", "900");
    }
    b.build()
}

/// A flood straight after a policy push cannot revert the fleet to observe;
/// only the changed rule trips, and only on legitimate looking blocks.
#[test]
fn forced_circuit_breaker() {
    let mut core = core(&[]);
    core.rule_changed("mass_assignment", 0);
    for i in 0..500u64 {
        let ev = EventBuilder::new(c::HTTP_ACTIVITY, v::HTTP_REQUEST, i as i64, "edge-1", "edge", i).src_ip("192.0.2.66").http("PATCH", "/profile", &["name", "is_admin"], 200).engine_alert("crs-942100", 0.9).build();
        core.process(ev, i as i64);
    }
    assert!(!core.breaker_mut().is_tripped("mass_assignment"), "attack flood must not trip the breaker");
    for i in 0..25u64 {
        core.process(patch(&format!("legit{i}"), &format!("198.51.100.{i}"), true, 1_000 + i as i64, 1_000 + i), 1_000 + i as i64);
    }
    assert!(core.breaker_mut().is_tripped("mass_assignment"));
    assert!(!core.breaker_mut().is_tripped("route_404"));
    let o = core.process(patch("legit99", "198.51.100.99", true, 2_000, 2_000), 2_000);
    assert!(o.observe_only.iter().any(|f| f.rule == "mass_assignment"), "tripped rule records only");
    assert!(o.findings.iter().all(|f| f.rule != "mass_assignment"));
}

/// A resident attacker is not learned as normal before the compromise assessment.
#[test]
fn baseline_poisoning() {
    let login = |dev: &str, t: i64| EventBuilder::new(c::AUTHENTICATION, v::AUTH_LOGIN, t, "sdk-1", "app_sdk", t as u64).user("alice", "human").attr("device_id", dev).status(true).build();
    let new_device_count = |core: &mut DecisionCore| (0..20).filter(|i| core.process(login("attacker-laptop", 10 + i), 10 + i).findings.iter().any(|f| f.rule == "new_device")).count();

    let mut before = core(&[]);
    before.process(login("alice-phone", 1), 1);
    assert_eq!(new_device_count(&mut before), 20, "no learning before the compromise assessment");

    let mut after = core(&[("compromise_assessment_done", json!(true))]);
    after.process(login("alice-phone", 1), 1);
    assert_eq!(new_device_count(&mut after), 1, "after assessment, a device is new once");
}
