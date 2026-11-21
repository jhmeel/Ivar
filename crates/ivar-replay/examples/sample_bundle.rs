//! Writes a signed sample ReplayBundle, its counterfactual twin and the
//! keyring that verifies them, so the replay viewer can be tried without a
//! live deployment.
//!
//! Usage: cargo run -p ivar-replay --example sample_bundle -- <out dir>

use ivar_contracts::sign::{KeyPair, Keyring};
use ivar_core::evidence::EvidenceStore;
use ivar_core::policy::spec_default_policy;
use ivar_core::{engine::CoreOptions, DecisionCore};
use ivar_replay::library::{build_event, EventSpec, UserSpec};
use ivar_replay::{build_replay, ReplayRequest};
use std::collections::BTreeSet;
use std::path::PathBuf;

fn spec(activity: &str, sensor: &str, sensor_type: &str, uid: &str, kind: &str) -> EventSpec {
    EventSpec { activity: activity.into(), sensor: sensor.into(), sensor_type: sensor_type.into(), src_ip: "198.51.100.7".into(), user: Some(UserSpec { uid: uid.into(), kind: kind.into() }), ..Default::default() }
}

fn main() -> anyhow::Result<()> {
    let out = PathBuf::from(std::env::args().nth(1).unwrap_or_else(|| "replay-viewer/samples".into()));
    std::fs::create_dir_all(&out)?;
    let ek = KeyPair::ed25519_from_seed("evidence-1", [3; 32]);
    let rk = KeyPair::ed25519_from_seed("replay-1", [4; 32]);
    let mut ring = Keyring::default();
    ring.add(ek.public(), &["evidence"]);
    ring.add(rk.public(), &["replay"]);
    let mut live = spec_default_policy(0);
    live.settings.insert("detection_mode".into(), serde_json::json!("enforce"));
    let mut core = DecisionCore::new(live.clone(), CoreOptions { evidence_signer: Some(ek), ..Default::default() })?;

    let mut seq = 0u64;
    let mut t = 1_000i64;
    let mut emit = |core: &mut DecisionCore, s: EventSpec, step: i64, skew: i64| {
        let mut s = s;
        seq += 1;
        t += step;
        // Per hop latency as sensors report it, for the pipeline view.
        for (hop, us) in [("sensor", 40 + seq * 3), ("ingest", 180 + seq * 7), ("core", 260 + seq * 11), ("decide", 90 + seq * 2), ("enforce", 1_200 + seq * 40)] {
            s.attrs.insert(format!("hop_{hop}_us"), us.to_string());
        }
        core.process(build_event(&s, seq as u32, t - skew, seq), t);
    };
    for i in 0..6 {
        let mut s = spec("auth.login", "app-sdk-1", "app_sdk", &format!("user{i}"), "user");
        s.success = Some(false);
        emit(&mut core, s, 400, 120);
    }
    let mut ok = spec("auth.login", "app-sdk-1", "app_sdk", "user5", "user");
    ok.success = Some(true);
    emit(&mut core, ok, 900, 120);
    for i in 0..5 {
        let mut s = spec("db.query", "db-1", "database", "lookup-svc", "service");
        s.records = if i == 4 { 60_000 } else { 100 };
        s.attrs = [("table".into(), "persons".into()), ("operation".into(), "SELECT".into())].into_iter().collect();
        emit(&mut core, s, 1_000, 250);
    }

    let records = core.evidence().records();
    let key = CoreOptions::default().redaction_key;
    let mut counterfactual = live.clone();
    counterfactual.settings.insert("detection_mode".into(), serde_json::json!("observe"));
    for (name, cf) in [("bundle.json", None), ("counterfactual.json", Some(&counterfactual))] {
        let b = build_replay(&ReplayRequest {
            records: &records,
            live_policy: &live,
            counterfactual_policy: cf,
            incident_id: "inc_sample",
            entity_keys: BTreeSet::new(),
            keyring: Some(&ring),
            redaction_key: key.clone(),
            expected_layers: vec!["edge", "app_sdk", "host", "network", "database", "identity"],
            signer: Some(&rk),
            policy_history: Default::default(),
        })?;
        std::fs::write(out.join(name), serde_json::to_string_pretty(&b)?)?;
        println!("{name}: {} frames, matched {}", b.frames.len(), b.re_execution.matched);
    }
    std::fs::write(out.join("keyring.json"), serde_json::to_string_pretty(&ring)?)?;
    std::fs::write(out.join("redaction_key.hex"), hex_encode(&key))?;
    Ok(())
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
