//! Signed policy fixtures for the SDK test suites (sdk/testdata/policy):
//! v1 observes; v2 enforces and adds the decoy route /v2-decoy, so a test can
//! see the new policy take effect; forged-v3 is signed by a key the keyring
//! does not trust.
//!
//!     cargo run -p ivar-server --example sdk_fixtures -- sdk/testdata/policy

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ivar_contracts::sign::{sign_policy, KeyPair, Keyring};
use ivar_contracts::DecoySpec;
use ivar_core::policy::spec_default_policy;
use serde_json::json;
use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    let out = PathBuf::from(std::env::args().nth(1).unwrap_or_else(|| "sdk/testdata/policy".into()));
    std::fs::create_dir_all(&out)?;
    let trusted = KeyPair::ed25519_from_seed("policy-test", [11; 32]);
    let stranger = KeyPair::ed25519_from_seed("policy-test", [12; 32]);
    let mut ring = Keyring::default();
    ring.add(trusted.public(), &["policy"]);
    std::fs::write(out.join("keyring.json"), serde_json::to_string_pretty(&ring)? + "\n")?;
    for (name, version, key) in [("v1", 1, &trusted), ("v2", 2, &trusted), ("forged-v3", 3, &stranger)] {
        let mut p = spec_default_policy(0);
        p.version = version;
        p.policy_version = format!("sdk-test-{version}");
        p.expires_at = 4_102_444_800_000; // 2100-01-01
        if version >= 2 {
            p.settings.insert("detection_mode".into(), json!("enforce"));
            p.decoys.push(DecoySpec { decoy_id: "dcy_v2".into(), kind: "route".into(), marker: "/v2-decoy".into(), issued_context: String::new(), protects: String::new() });
        }
        let archive = B64.encode(sign_policy(&p, &[key])?.to_archive()?);
        std::fs::write(out.join(format!("{name}.bundle")), archive + "\n")?;
    }
    println!("wrote {}", out.display());
    Ok(())
}
