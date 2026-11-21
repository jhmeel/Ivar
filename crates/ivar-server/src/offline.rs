//! Offline replay (section 13): build a signed ReplayBundle straight from a
//! sealed evidence file and the stored policy versions, with no running core.
//! This is what an auditor or regulator runs against an exported evidence
//! store; the bundle is built only if it reproduces every recorded verdict.

use crate::state::verify_bundle;
use crate::store::FileEvidenceStore;
use ivar_contracts::sign::{KeyPair, Keyring};
use ivar_contracts::{PolicyContent, ReplayBundle};
use ivar_core::evidence::EvidenceStore;
use ivar_replay::{build_replay, ReplayRequest};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub struct OfflineReplay<'a> {
    pub evidence: &'a Path,
    /// Directory of policy bundles by version (the core's policies-<shard>).
    pub policies: &'a Path,
    pub keyring: &'a Keyring,
    pub redaction_key: Vec<u8>,
    pub signer: &'a KeyPair,
    /// Entities to keep ("ip:198.51.100.7"); empty keeps the whole window.
    pub entities: BTreeSet<String>,
    pub incident_id: String,
    pub expected_layers: Vec<String>,
}

/// Every stored policy version that verifies against the keyring.
pub fn policy_history(dir: &Path, keyring: &Keyring) -> anyhow::Result<BTreeMap<u64, PolicyContent>> {
    let mut out = BTreeMap::new();
    for e in std::fs::read_dir(dir)? {
        let p = e?.path();
        if p.extension().map(|x| x == "bundle").unwrap_or(false) {
            let text = std::fs::read_to_string(&p)?;
            let content = verify_bundle(keyring, &text, 0, 0).map_err(|e| anyhow::anyhow!("{}: {e}", p.display()))?;
            out.insert(content.version, content);
        }
    }
    anyhow::ensure!(!out.is_empty(), "no verified policy bundles in {}", dir.display());
    Ok(out)
}

pub fn build(o: &OfflineReplay) -> anyhow::Result<ReplayBundle> {
    let store = FileEvidenceStore::open(o.evidence)?;
    let records = store.records();
    anyhow::ensure!(!records.is_empty(), "{} holds no evidence", o.evidence.display());
    let mut history = policy_history(o.policies, o.keyring)?;
    let first = *history.keys().next().expect("history");
    let live = history.remove(&first).expect("first policy");
    let layers: Vec<&str> = o.expected_layers.iter().map(String::as_str).collect();
    Ok(build_replay(&ReplayRequest {
        records: &records,
        live_policy: &live,
        counterfactual_policy: None,
        incident_id: &o.incident_id,
        entity_keys: o.entities.clone(),
        keyring: Some(o.keyring),
        redaction_key: o.redaction_key.clone(),
        expected_layers: layers,
        signer: Some(o.signer),
        policy_history: history,
    })?)
}
