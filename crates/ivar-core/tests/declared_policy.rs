//! A policy's declared intent is never silently dropped: null fields (as Go
//! and other languages write empty lists) mean empty, and a declared section
//! that does not parse refuses the policy and keeps the current one.

use ivar_core::declare::Declarations;
use ivar_core::policy::spec_default_policy;
use ivar_core::{engine::CoreOptions, DecisionCore};
use serde_json::json;

fn route() -> serde_json::Value {
    json!({"method": "PATCH", "template": "/users/{id}", "allowed_properties": ["name", "role"], "privileged_properties": ["role"], "roles": null, "business_action": "profile.update", "admin": false, "declared_in": "openapi.yaml"})
}

#[test]
fn null_sections_mean_empty_and_routes_survive() {
    let v = json!({"routes": [route()], "edges": null, "egress": null, "packages": {}, "process_profiles": null, "public_roles": null});
    let d = Declarations::parse(&v).unwrap();
    assert_eq!(d.routes.len(), 1);
    assert_eq!(d.routes[0].privileged_properties, vec!["role"]);
    assert!(d.match_route("PATCH", "/users/7").is_some());
}

#[test]
fn absent_sections_mean_empty() {
    let d = Declarations::parse(&json!({"routes": [route()]})).unwrap();
    assert_eq!(d.routes.len(), 1);
    assert!(Declarations::parse(&serde_json::Value::Null).unwrap().routes.is_empty());
}

#[test]
fn a_broken_declared_section_refuses_the_policy() {
    let mut p = spec_default_policy(0);
    p.declared = json!({"routes": "not a list"});
    assert!(DecisionCore::new(p.clone(), CoreOptions::default()).is_err(), "the core must refuse it");

    let mut good = spec_default_policy(0);
    good.declared = json!({"routes": [route()]});
    let mut core = DecisionCore::new(good, CoreOptions::default()).unwrap();
    p.version = 2;
    assert!(core.update_policy(p, 1_000).is_err(), "an update with a broken declared section is refused");
}

#[test]
fn sensors_refuse_a_broken_declared_section() {
    let mut p = spec_default_policy(0);
    p.declared = json!({"routes": [{"method": 7}]});
    assert!(ivar_core::sensor::SensorPolicy::try_from_policy(&p).is_err());
}

#[test]
fn undeclared_routes_and_methods_are_refused_only_when_opted_in() {
    use ivar_core::sensor::{ocsf_class as c, EventBuilder, LocalDecision, SensorPolicy};
    let api = "openapi: 3.0.3\npaths:\n  /accounts/{uid}:\n    get: {}\n";
    let req = |method: &str, path: &str| EventBuilder::new(c::HTTP_ACTIVITY, ivar_core::detect::vocabulary::HTTP_REQUEST, 1, "sdk-1", "app_sdk", 1).src_ip("198.51.100.7").http(method, path, &[], 0).build();
    let mut p = ivar_core::policy::spec_default_policy(0);
    p.declared = ivar_core::declare::compile_openapi("api.yaml", api).unwrap().to_value();
    p.settings.insert("detection_mode".into(), serde_json::json!("enforce"));
    let lenient = SensorPolicy::try_from_policy(&p).unwrap();
    assert!(matches!(lenient.decide(&req("DELETE", "/accounts/u1"), 1), LocalDecision::Forward), "off by default");

    p.settings.insert("refuse_undeclared_routes".into(), serde_json::json!(true));
    p.settings.insert("undeclared_route_exempt".into(), serde_json::json!(["/healthz"]));
    let strict = SensorPolicy::try_from_policy(&p).unwrap();
    assert!(matches!(strict.decide(&req("DELETE", "/accounts/u1"), 1), LocalDecision::Block(_)), "undeclared method");
    assert!(matches!(strict.decide(&req("GET", "/internal/debug"), 1), LocalDecision::Block(_)), "undeclared path");
    assert!(matches!(strict.decide(&req("GET", "/accounts/u1"), 1), LocalDecision::Forward), "declared");
    assert!(matches!(strict.decide(&req("GET", "/healthz"), 1), LocalDecision::Forward), "exempt prefix");
}
