//! A per request block never becomes a standing block on the entity: one
//! blocked request from a shared address must not lock out everyone behind
//! it. Containment and time bounded throttles do carry over.

use ivar_contracts::{EntityRef, Verdict};
use ivar_core::policy::spec_default_policy;
use ivar_core::sensor::{LocalDecision, SensorPolicy};
use ivar_core::sensor::{ocsf_class, EventBuilder};

fn verdict(decision: &str, ip: &str, expires_at: i64) -> Verdict {
    Verdict { verdict_id: format!("vrd_{decision}"), decision: decision.into(), entity: Some(EntityRef::actor("ip", ip)), risk: 0.7, reasons: vec!["test".into()], sources: vec![], policy_version: "t".into(), expires_at, mode: "enforce".into(), evidence_ids: vec![], time: 0, ladder_level: 3 }
}

fn request(ip: &str) -> ivar_contracts::SecurityEvent {
    EventBuilder::new(ocsf_class::HTTP_ACTIVITY, "http.request", 1_000, "sdk", "app_sdk", 1).src_ip(ip).http("GET", "/hello", &[], 0).build()
}

#[test]
fn per_request_block_does_not_carry_over() {
    let mut s = SensorPolicy::from_policy(&spec_default_policy(0));
    s.push_verdict(verdict("block", "192.0.2.2", 0));
    assert!(matches!(s.decide(&request("192.0.2.2"), 2_000), LocalDecision::Forward));
}

#[test]
fn containment_and_bounded_throttles_carry_over() {
    let mut s = SensorPolicy::from_policy(&spec_default_policy(0));
    s.push_verdict(verdict("contain", "198.51.100.1", 0));
    s.push_verdict(verdict("throttle", "198.51.100.2", 5_000));
    s.push_verdict(verdict("throttle", "198.51.100.3", 0));
    s.push_verdict(verdict("contain", "198.51.100.4", 1_500));
    assert!(matches!(s.decide(&request("198.51.100.1"), 2_000), LocalDecision::Cached(_)));
    assert!(matches!(s.decide(&request("198.51.100.2"), 2_000), LocalDecision::Cached(_)));
    assert!(matches!(s.decide(&request("198.51.100.3"), 2_000), LocalDecision::Forward), "an open ended throttle is not carried");
    assert!(matches!(s.decide(&request("198.51.100.4"), 2_000), LocalDecision::Forward), "expired containment is lifted");
}
