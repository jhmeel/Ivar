//! Abuse spread thin enough to slip past per address and per account limits:
//! object enumeration and distributed credential stuffing.

use ivar_core::declare::compile_openapi;
use ivar_core::detect::vocabulary as v;
use ivar_core::policy::spec_default_policy;
use ivar_core::sensor::{ocsf_class as c, EventBuilder};
use ivar_core::{engine::CoreOptions, DecisionCore};
use serde_json::json;

const API: &str = "openapi: 3.0.3\npaths:\n  /accounts/{uid}:\n    get:\n      parameters: [{ name: uid, in: path, required: true, schema: { type: string } }]\n  /login:\n    post: {}\n";

fn core() -> DecisionCore {
    let mut p = spec_default_policy(0);
    p.declared = compile_openapi("api.yaml", API).unwrap().to_value();
    p.settings.insert("detection_mode".into(), json!("enforce"));
    DecisionCore::new(p, CoreOptions::default()).unwrap()
}

fn read(session: &str, ip: &str, uid: &str, status: u32, t: i64, seq: u64) -> ivar_contracts::SecurityEvent {
    EventBuilder::new(c::HTTP_ACTIVITY, v::HTTP_REQUEST, t, "sdk-1", "app_sdk", seq).src_ip(ip).user("u7", "human").session(session).http("GET", &format!("/accounts/{uid}"), &[], status).build()
}

fn failed_login(ip: &str, account: &str, t: i64, seq: u64) -> ivar_contracts::SecurityEvent {
    EventBuilder::new(c::AUTHENTICATION, v::AUTH_LOGIN, t, "sdk-1", "app_sdk", seq).src_ip(ip).target(&format!("user:{account}")).status(false).build()
}

fn acted(out: &ivar_core::engine::EngineOutput) -> bool {
    out.verdicts.iter().any(|v| v.decision != "record" && v.decision != "allow")
}

fn fired(out: &ivar_core::engine::EngineOutput, rule: &str) -> bool {
    out.findings.iter().any(|f| f.rule == rule)
}

#[test]
fn a_session_walking_other_customers_accounts_is_stopped() {
    let mut core = core();
    let (mut stopped, mut rule) = (None, false);
    let mut sensor = ivar_core::sensor::SensorPolicy::try_from_policy(core.policy()).unwrap();
    for k in 0..60 {
        let out = core.process(read("ses-enum", "198.51.100.9", &format!("u{k}"), 403, 1_000 + k * 50, k as u64 + 1), 1_000 + k * 50);
        rule |= fired(&out, "object_enumeration");
        for v in out.verdicts.iter().cloned() {
            sensor.push_verdict(v);
        }
        if acted(&out) && stopped.is_none() {
            stopped = Some(k);
        }
    }
    assert!(rule, "the enumeration rule fired");
    let k = stopped.expect("enumerating 60 accounts is acted on");
    assert!(k < 15, "acted on after {k} refused objects");
    // The core judges after the response; what it decided must still stop
    // the session's next request at the sensor.
    let next = read("ses-enum", "198.51.100.9", "u7", 0, 5_000, 99);
    assert!(matches!(sensor.decide(&next, 5_000), ivar_core::sensor::LocalDecision::Cached(_)), "the session's next request is refused at the sensor");
}

#[test]
fn a_customer_who_mistypes_a_few_links_is_left_alone() {
    let mut core = core();
    for k in 0..5 {
        let out = core.process(read("ses-ok", "198.51.100.10", &format!("u{k}"), 404, 1_000 + k * 5_000, k as u64 + 1), 1_000 + k * 5_000);
        assert!(!acted(&out), "a handful of refusals is normal");
    }
}

#[test]
fn stuffing_from_a_hundred_addresses_is_slowed() {
    let mut core = core();
    let (mut acted_on, mut rule) = (0, false);
    for k in 0..400i64 {
        let ip = format!("203.0.113.{}", k % 100);
        let out = core.process(failed_login(&ip, &format!("user{}", k % 200), 10_000 + k * 100, k as u64 + 1), 10_000 + k * 100);
        rule |= fired(&out, "auth_stuffing_distributed");
        acted_on += acted(&out) as usize;
    }
    assert!(rule, "the distributed stuffing rule fired");
    assert!(acted_on > 0, "no attempt was slowed");
}

#[test]
fn ordinary_login_failures_across_customers_do_not_trigger_it() {
    let mut core = core();
    for k in 0..30i64 {
        let out = core.process(failed_login(&format!("192.0.2.{k}"), &format!("user{k}"), 10_000 + k * 1_000, k as u64 + 1), 10_000 + k * 1_000);
        assert!(!acted(&out), "30 scattered failures are a normal morning");
    }
}
