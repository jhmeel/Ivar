//! Section 10.2: account takeover to privilege escalation, end to end.
//! Each step is unremarkable to a per IP counter; linked together they show
//! an account takeover turning into privilege escalation.

use ivar_core::declare::compile_openapi;
use ivar_core::detect::vocabulary as v;
use ivar_core::evidence::{verify_chain, EvidenceStore};
use ivar_core::policy::spec_default_policy;
use ivar_core::sensor::{ocsf_class as c, EventBuilder};
use ivar_core::{engine::CoreOptions, DecisionCore, EngineOutput};
use serde_json::json;

const API: &str = r#"
openapi: 3.0.3
paths:
  /login: { post: { x-ivar-action: login } }
  /users/{id}:
    patch:
      x-ivar-roles: [self, admin]
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                name: { type: string }
                role: { type: string, readOnly: true }
"#;

const IP: &str = "198.51.100.23";

fn core() -> DecisionCore {
    let mut p = spec_default_policy(0);
    p.declared = compile_openapi("api.yaml", API).unwrap().to_value();
    p.settings.insert("detection_mode".into(), json!("enforce"));
    DecisionCore::new(p, CoreOptions::default()).unwrap()
}

fn step(name: &str, outs: &[EngineOutput]) -> (String, f64) {
    let last = outs.last().unwrap();
    let decision = last.decision().to_string();
    let risk = last.verdicts.iter().map(|v| v.risk).fold(0.0, f64::max);
    println!("{name}: decision={decision} risk={risk:.2}");
    (decision, risk)
}

#[test]
fn account_takeover_to_privilege_escalation() {
    let mut core = core();
    let mut seq = 0;
    let mut t = 1_000_000;
    let mut next = || {
        seq += 1;
        seq
    };

    // Step 1: IP scans 40 missing routes in five minutes (edge filter).
    let mut outs = vec![];
    for i in 0..40 {
        t += 7_000;
        let ev = EventBuilder::new(c::HTTP_ACTIVITY, v::HTTP_REQUEST, t, "edge-1", "edge", next()).src_ip(IP).http("GET", &format!("/wp-admin/{i}.php"), &[], 404).build();
        outs.push(core.process(ev, t));
    }
    let (d, r) = step("1 route scan", &outs);
    assert_eq!(d, "throttle");
    assert!((0.30..0.60).contains(&r), "{r}");

    // Step 2: the same source sprays logins across many accounts (SDK).
    let mut outs = vec![];
    for i in 0..12 {
        t += 2_000;
        let ev = EventBuilder::new(c::AUTHENTICATION, v::AUTH_LOGIN, t, "sdk-1", "app_sdk", next())
            .src_ip(IP)
            .target(&format!("user:acct{}", i % 6))
            .status(false)
            .build();
        outs.push(core.process(ev, t));
    }
    let (d, r) = step("2 spray", &outs);
    assert_eq!(d, "challenge");
    assert!((0.60..0.85).contains(&r), "{r}");

    // Step 3: one account logs in after repeated failures (SDK).
    t += 2_000;
    let ev = EventBuilder::new(c::AUTHENTICATION, v::AUTH_LOGIN, t, "sdk-1", "app_sdk", next())
        .src_ip(IP)
        .user("acct3", "human")
        .session("ses_7f3a")
        .target("user:acct3")
        .attr("account_age_days", "400")
        .status(true)
        .build();
    let o3 = core.process(ev, t);
    let (d, r) = step("3 login after failures", &[o3]);
    assert_eq!(d, "challenge", "step up verification");
    assert!((0.60..0.85).contains(&r), "{r}");

    // Step 4: that session tries to write its own role (edge schema and SDK see the same request).
    t += 5_000;
    let mk = |sensor: &str, kind: &str, s: u64| {
        EventBuilder::new(c::HTTP_ACTIVITY, v::HTTP_REQUEST, t, sensor, kind, s)
            .src_ip(IP)
            .user("acct3", "human")
            .session("ses_7f3a")
            .request_id("req-role-1")
            .attr("account_age_days", "400")
            .http("PATCH", "/users/acct3", &["role"], 0)
            .build()
    };
    let s1 = next();
    let s2 = next();
    let _edge = core.process(mk("edge-1", "edge", s1), t);
    let o4 = core.process(mk("sdk-1", "app_sdk", s2), t);
    let (d, r) = step("4 role write", &[o4.clone()]);
    assert_eq!(d, "contain");
    assert!(r >= 0.85, "{r}");
    let actions: Vec<&str> = o4.actions.iter().map(|a| a.planned.request.action.as_str()).collect();
    println!("actions: {actions:?}");
    assert!(actions.contains(&"session.revoke"), "{actions:?}");
    assert!(actions.contains(&"user.lock"), "{actions:?}");
    assert!(o4.actions.iter().all(|a| !a.planned.request.reversal_method.is_empty()));

    // Step 5: evidence is sealed and an incident opens.
    assert!(!o4.incidents.is_empty());
    let inc = core.incidents().get(&o4.incidents[0]).unwrap();
    println!("incident {} stage={} entities={}", inc.incident_id, inc.attack_stage, inc.affected_entities.len());
    assert!(verify_chain(&core.evidence().records(), None).is_ok());
}

#[test]
fn deception_hit_contains_without_two_sources() {
    let mut core = core();
    let ev = EventBuilder::new(c::API_ACTIVITY, v::AI_TOOL_CALL, 10, "aigw-1", "ai_gateway", 1)
        .user("support-bot", "agent")
        .attr("tool", "export_all_customers")
        .build();
    let o = core.process(ev, 10);
    assert_eq!(o.decision(), "contain");
    assert!(o.actions.iter().any(|a| a.planned.request.action == "agent.suspend"));
}

#[test]
fn victim_lockout_raises_protection_only() {
    let mut core = core();
    for i in 0..30 {
        let ev = EventBuilder::new(c::AUTHENTICATION, v::AUTH_LOGIN, i * 1000, "sdk-1", "app_sdk", i as u64)
            .src_ip(&format!("203.0.113.{}", i % 7))
            .target("user:ceo")
            .status(false)
            .build();
        let o = core.process(ev, i * 1000);
        for v in o.verdicts.iter().filter(|v| v.entity.as_ref().unwrap().id == "ceo") {
            assert!(v.decision == "challenge" || v.decision == "record" || v.decision == "throttle", "{}", v.decision);
        }
    }
}

#[test]
fn observe_mode_records_what_would_happen() {
    let mut p = spec_default_policy(0);
    p.declared = compile_openapi("api.yaml", API).unwrap().to_value();
    let mut core = DecisionCore::new(p, CoreOptions::default()).unwrap();
    let ev = EventBuilder::new(c::API_ACTIVITY, v::AI_TOOL_CALL, 10, "aigw-1", "ai_gateway", 1).user("bot", "agent").attr("tool", "export_all_customers").build();
    let o = core.process(ev, 10);
    assert_eq!(o.decision(), "contain");
    assert!(o.verdicts.iter().all(|v| v.mode == "observe"));
}
