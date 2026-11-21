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

/// Gateway collapse: when a proxy, gateway or misconfigured trust makes many
/// accounts share one source address, an attack from that address is
/// throttled, never contained, so the people behind it keep working.
#[test]
fn address_carrying_many_accounts_is_never_contained() {
    let mut core = core(&[]);
    let gw = "192.0.2.2";
    let mut seq = 0u64;
    let mut t = 0i64;
    for i in 0..12 {
        seq += 1;
        t += 100;
        let ev = EventBuilder::new(c::AUTHENTICATION, v::AUTH_LOGIN, t, "sdk-1", "app_sdk", seq).src_ip(gw).user(&format!("user{i}"), "human").status(true).attr("account_age_days", "900").build();
        core.process(ev, t);
    }
    let mut contained = false;
    for i in 0..30 {
        seq += 1;
        t += 100;
        // Decoy and mass assignment from the same address: strong, two source evidence.
        let decoy = EventBuilder::new(c::HTTP_ACTIVITY, v::HTTP_REQUEST, t, "edge-1", "edge", seq).src_ip(gw).http("GET", "/.env.backup", &[], 404).decoy("route_env").build();
        let out = core.process(decoy, t);
        seq += 1;
        let patch = EventBuilder::new(c::HTTP_ACTIVITY, v::HTTP_REQUEST, t + 1, "sdk-1", "app_sdk", seq).src_ip(gw).user(&format!("user{}", i % 12), "human").http("PATCH", "/profile", &["name", "is_admin"], 200).build();
        let out2 = core.process(patch, t + 1);
        for v in out.verdicts.iter().chain(out2.verdicts.iter()) {
            if v.entity.as_ref().map(|e| e.r#type == "ip" && e.id == gw).unwrap_or(false) && v.decision == "contain" {
                contained = true;
            }
        }
    }
    assert!(!contained, "an address carrying many accounts must be throttled, not contained");
}
