//! A bundle written to disk and read back must still verify: the signature
//! covers the canonical serialization, not the in memory value.

use ivar_contracts::sign::{KeyPair, Keyring};
use ivar_core::evidence::EvidenceStore;
use ivar_core::policy::spec_default_policy;
use ivar_core::{engine::CoreOptions, DecisionCore};
use ivar_replay::library::{build_event, EventSpec, UserSpec};
use ivar_replay::{build_replay, reverify_bundle, ReplayRequest};

#[test]
fn bundle_survives_a_file_round_trip() {
    let ek = KeyPair::ed25519_from_seed("evidence-1", [3; 32]);
    let rk = KeyPair::ed25519_from_seed("replay-1", [4; 32]);
    let mut ring = Keyring::default();
    ring.add(ek.public(), &["evidence"]);
    ring.add(rk.public(), &["replay"]);
    let p = spec_default_policy(0);
    let mut core = DecisionCore::new(p.clone(), CoreOptions { evidence_signer: Some(ek), ..Default::default() }).unwrap();
    for i in 0..3u32 {
        let spec = EventSpec { activity: "db.query".into(), sensor: "db-1".into(), sensor_type: "database".into(), user: Some(UserSpec { uid: "svc".into(), kind: "service".into() }), records: 100 + i as u64, ..Default::default() };
        core.process(build_event(&spec, i, 1_000 + i as i64 * 700, i as u64 + 1), 1_100 + i as i64 * 700);
    }
    let records = core.evidence().records();
    let key = CoreOptions::default().redaction_key;
    let b = build_replay(&ReplayRequest { records: &records, live_policy: &p, counterfactual_policy: None, incident_id: "inc", entity_keys: Default::default(), keyring: Some(&ring), redaction_key: key.clone(), expected_layers: vec![], signer: Some(&rk), policy_history: Default::default() }).unwrap();
    for text in [serde_json::to_string(&b).unwrap(), serde_json::to_string_pretty(&b).unwrap()] {
        let back: ivar_contracts::ReplayBundle = serde_json::from_str(&text).unwrap();
        reverify_bundle(&back, Some(&ring), &key).unwrap();
    }
}

#[test]
fn shipped_sample_bundles_verify() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../replay-viewer/samples");
    let ring: Keyring = serde_json::from_str(&std::fs::read_to_string(dir.join("keyring.json")).unwrap()).unwrap();
    let hex = std::fs::read_to_string(dir.join("redaction_key.hex")).unwrap();
    let hex = hex.trim();
    let key: Vec<u8> = (0..hex.len() / 2).map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap()).collect();
    for f in ["bundle.json", "counterfactual.json"] {
        let b: ivar_contracts::ReplayBundle = serde_json::from_str(&std::fs::read_to_string(dir.join(f)).unwrap()).unwrap();
        reverify_bundle(&b, Some(&ring), &key).unwrap_or_else(|e| panic!("{f}: {e}"));
    }
}
