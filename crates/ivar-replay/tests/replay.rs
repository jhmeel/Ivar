//! Section 13: a replay renders only after it reproduces the live verdicts exactly.

use ivar_contracts::sign::{KeyPair, Keyring};
use ivar_core::evidence::EvidenceStore;
use ivar_core::policy::spec_default_policy;
use ivar_core::{engine::CoreOptions, DecisionCore};
use ivar_replay::library::{build_event, EventSpec, UserSpec};
use ivar_replay::{build_replay, reverify_bundle, ReplayError, ReplayRequest};
use std::collections::BTreeSet;

fn live() -> (DecisionCore, ivar_contracts::PolicyContent, KeyPair, Keyring) {
    let ek = KeyPair::ed25519_from_seed("evidence-1", [3; 32]);
    let rk = KeyPair::ed25519_from_seed("replay-1", [4; 32]);
    let mut ring = Keyring::default();
    ring.add(ek.public(), &["evidence"]);
    ring.add(rk.public(), &["replay"]);
    let mut p = spec_default_policy(0);
    p.settings.insert("detection_mode".into(), serde_json::json!("enforce"));
    let mut core = DecisionCore::new(p.clone(), CoreOptions { evidence_signer: Some(ek), ..Default::default() }).unwrap();
    for i in 0..5u32 {
        let spec = EventSpec { activity: "db.query".into(), sensor: "db-1".into(), sensor_type: "database".into(), user: Some(UserSpec { uid: "lookup-svc".into(), kind: "service".into() }), records: if i == 4 { 60_000 } else { 100 }, attrs: [("table".into(), "persons".into()), ("operation".into(), "SELECT".into())].into_iter().collect(), ..Default::default() };
        let t = 1_000 + i as i64 * 1_000;
        // Sensor clock runs 250 ms behind the core.
        core.process(build_event(&spec, i, t - 250, i as u64 + 1), t);
    }
    (core, p, rk, ring)
}

fn request<'a>(records: &'a [ivar_core::evidence::EvidenceRecord], p: &'a ivar_contracts::PolicyContent, ring: &'a Keyring, rk: &'a KeyPair) -> ReplayRequest<'a> {
    ReplayRequest {
        records,
        live_policy: p,
        counterfactual_policy: None,
        incident_id: "inc_test",
        entity_keys: BTreeSet::new(),
        keyring: Some(ring),
        redaction_key: CoreOptions::default().redaction_key,
        expected_layers: vec!["edge", "app_sdk", "host", "database"],
        signer: Some(rk),
        policy_history: Default::default(),
    }
}

#[test]
fn bundle_reproduces_and_reverifies() {
    let (core, p, rk, ring) = live();
    let records = core.evidence().records();
    let bundle = build_replay(&request(&records, &p, &ring, &rk)).unwrap();
    assert!(bundle.re_execution.matched);
    assert!(bundle.re_execution.recorded_verdicts > 0);
    assert!(bundle.frames.iter().all(|f| !f.evidence_ids.is_empty() || f.kind == "gap"), "every frame cites evidence");
    assert!(bundle.frames.windows(2).all(|w| w[0].time <= w[1].time));
    assert!(bundle.frames.iter().filter(|f| f.kind == "event").all(|f| f.clock_skew_ms == 250), "skew corrected and shown");
    assert_eq!(bundle.unobserved_layers, vec!["edge", "app_sdk", "host"]);
    let r = reverify_bundle(&bundle, Some(&ring), &CoreOptions::default().redaction_key).unwrap();
    assert!(r.matched);
}

#[test]
fn tampered_evidence_halts_and_flags() {
    let (core, p, rk, ring) = live();
    let mut records = core.evidence().records();
    records[0].payload["ivar"]["records_read"] = serde_json::json!(1);
    assert!(matches!(build_replay(&request(&records, &p, &ring, &rk)), Err(ReplayError::Evidence(_))));
}

#[test]
fn engine_or_policy_drift_halts_and_flags() {
    let (core, mut p, rk, ring) = live();
    let records = core.evidence().records();
    p.policy_version = "a-different-policy".into();
    assert!(matches!(build_replay(&request(&records, &p, &ring, &rk)), Err(ReplayError::Mismatch(_))));
}

#[test]
fn tampered_bundle_fails_in_the_viewer() {
    let (core, p, rk, ring) = live();
    let records = core.evidence().records();
    let mut bundle = build_replay(&request(&records, &p, &ring, &rk)).unwrap();
    bundle.frames[0].payload = serde_json::json!({"drawn": "by hand"});
    assert!(matches!(reverify_bundle(&bundle, Some(&ring), b""), Err(ReplayError::Signature(_))));
}

#[test]
fn counterfactual_is_labelled_and_leaves_evidence_alone() {
    let (core, p, rk, ring) = live();
    let records = core.evidence().records();
    let mut cf = p.clone();
    cf.policy_version = "before-fix".into();
    cf.invariants.clear();
    let mut req = request(&records, &p, &ring, &rk);
    req.counterfactual_policy = Some(&cf);
    let bundle = build_replay(&req).unwrap();
    assert!(bundle.counterfactual && bundle.frames.iter().all(|f| f.counterfactual));
    assert_eq!(bundle.counterfactual_policy.as_deref(), Some("before-fix"));
    assert_eq!(core.evidence().records(), records);
}

#[test]
fn replay_follows_a_policy_change_applied_live() {
    let (mut core, p, rk, ring) = live();
    let mut p2 = p.clone();
    p2.version = 2;
    p2.policy_version = "after-change".into();
    core.update_policy(p2.clone(), 9_000).unwrap();
    let spec = EventSpec { activity: "db.query".into(), sensor: "db-1".into(), sensor_type: "database".into(), user: Some(UserSpec { uid: "lookup-svc".into(), kind: "service".into() }), records: 100, ..Default::default() };
    core.process(build_event(&spec, 9, 9_500, 10), 10_000);
    let records = core.evidence().records();
    let mut req = request(&records, &p, &ring, &rk);
    assert!(build_replay(&req).is_err(), "without the history the replay cannot reproduce verdicts");
    req.policy_history.insert(2, p2);
    let bundle = build_replay(&req).unwrap();
    assert!(reverify_bundle(&bundle, Some(&ring), &CoreOptions::default().redaction_key).unwrap().matched);
}
