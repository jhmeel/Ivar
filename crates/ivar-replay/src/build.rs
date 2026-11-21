//! Building and re verifying ReplayBundles.

use crate::frames::frames_for;
use crate::BUNDLE_VERSION;
use ivar_contracts::sign::{sign_bytes, verify_bytes, KeyPair, Keyring};
use ivar_contracts::{PolicyContent, ReExecution, ReplayBundle, SecurityEvent, Verdict, CONTRACT_VERSION};
use ivar_core::engine::CoreOptions;
use ivar_core::evidence::{verify_chain, ChainError, EvidenceKind, EvidenceRecord};
use ivar_core::{DecisionCore, ENGINE_VERSION};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    #[error("evidence flagged: {0}")]
    Evidence(#[from] ChainError),
    #[error("engine flagged: replay verdicts do not match the recorded verdicts: {0:?}")]
    Mismatch(Vec<String>),
    #[error("engine flagged: bundle was made by {bundle}, this engine is {engine}")]
    EngineVersion { bundle: String, engine: String },
    #[error("bundle signature: {0}")]
    Signature(String),
    #[error("policy: {0}")]
    Policy(String),
}

pub struct ReplayRequest<'a> {
    pub records: &'a [EvidenceRecord],
    /// The policy that judged the evidence live.
    pub live_policy: &'a PolicyContent,
    /// A different policy for a counterfactual replay.
    pub counterfactual_policy: Option<&'a PolicyContent>,
    pub incident_id: &'a str,
    pub entity_keys: BTreeSet<String>,
    pub keyring: Option<&'a Keyring>,
    pub redaction_key: Vec<u8>,
    pub expected_layers: Vec<&'a str>,
    pub signer: Option<&'a KeyPair>,
    /// Policies that took effect during the window, keyed by bundle version.
    /// A Policy evidence record switches the replay to that version at the
    /// point it was applied live.
    pub policy_history: BTreeMap<u64, PolicyContent>,
}

/// Risk scores from a re execution, keyed by the evidence id of the event.
type RiskTrail = BTreeMap<String, Vec<serde_json::Value>>;

/// Re run every recorded event through a fresh core with the given policy.
fn reexecute(records: &[EvidenceRecord], policy: &PolicyContent, history: &BTreeMap<u64, PolicyContent>, redaction_key: &[u8]) -> Result<(Vec<Verdict>, RiskTrail), ReplayError> {
    let mut core = DecisionCore::new(policy.clone(), CoreOptions { evidence_signer: None, redaction_key: redaction_key.to_vec() }).map_err(|e| ReplayError::Policy(e.to_string()))?;
    let mut out = Vec::new();
    let mut trail = RiskTrail::new();
    for r in records {
        match r.kind {
            EvidenceKind::Event => {
                let ev: SecurityEvent = serde_json::from_value(r.payload.clone()).map_err(|e| ReplayError::Policy(e.to_string()))?;
                let o = core.process_recorded(ev, r.time, &r.evidence_id);
                trail.insert(r.evidence_id.clone(), o.risks.iter().map(|x| serde_json::to_value(x).unwrap_or_default()).collect());
                out.extend(o.verdicts);
            }
            EvidenceKind::Policy => {
                if let Some(v) = r.payload.get("version").and_then(|v| v.as_u64()) {
                    let p = history.get(&v).ok_or_else(|| ReplayError::Policy(format!("policy version {v} applied live is missing from the replay history")))?;
                    core.update_policy(p.clone(), r.time).map_err(|e| ReplayError::Policy(e.to_string()))?;
                }
            }
            _ => {}
        }
    }
    Ok((out, trail))
}

fn recorded_verdicts(records: &[EvidenceRecord]) -> Vec<Verdict> {
    records.iter().filter(|r| r.kind == EvidenceKind::Verdict).filter_map(|r| serde_json::from_value(r.payload.clone()).ok()).collect()
}

/// Compare decision, risk, entity, policy version and reasons.
fn compare(recorded: &[Verdict], replayed: &[Verdict]) -> Vec<String> {
    let index: BTreeMap<&str, &Verdict> = replayed.iter().map(|v| (v.verdict_id.as_str(), v)).collect();
    let mut mismatches = Vec::new();
    for r in recorded {
        match index.get(r.verdict_id.as_str()) {
            None => mismatches.push(format!("{} not reproduced", r.verdict_id)),
            Some(p) if p.decision != r.decision || (p.risk - r.risk).abs() > 1e-9 || p.entity != r.entity || p.policy_version != r.policy_version || p.reasons != r.reasons => {
                mismatches.push(format!("{}: recorded {} at {:.2}, replayed {} at {:.2}", r.verdict_id, r.decision, r.risk, p.decision, p.risk))
            }
            _ => {}
        }
    }
    if replayed.len() != recorded.len() {
        mismatches.push(format!("recorded {} verdicts, replay produced {}", recorded.len(), replayed.len()));
    }
    mismatches
}

fn sign_bundle(b: &mut ReplayBundle, signer: Option<&KeyPair>) {
    b.signature = None;
    if let Some(k) = signer {
        let bytes = serde_json::to_vec(&b).unwrap_or_default();
        b.signature = Some(sign_bytes(k, &bytes));
    }
}

/// Build a ReplayBundle. A replay that cannot reproduce the recorded verdicts
/// is never built; it returns an error that flags the evidence or the engine.
pub fn build_replay(req: &ReplayRequest) -> Result<ReplayBundle, ReplayError> {
    let head = verify_chain(req.records, req.keyring)?;
    let recorded = recorded_verdicts(req.records);
    let (replayed, live_risks) = reexecute(req.records, req.live_policy, &req.policy_history, &req.redaction_key)?;
    let mismatches = compare(&recorded, &replayed);
    if !mismatches.is_empty() {
        return Err(ReplayError::Mismatch(mismatches));
    }
    let re_execution = ReExecution { matched: true, recorded_verdicts: recorded.len(), replayed_verdicts: replayed.len(), mismatches: vec![] };

    let (records, policy, counterfactual, risks): (Vec<EvidenceRecord>, &PolicyContent, bool, RiskTrail) = match req.counterfactual_policy {
        None => (req.records.to_vec(), req.live_policy, false, live_risks),
        Some(cf) => {
            // Counterfactual: same evidence, different policy, run only inside
            // the replay engine; the recorded evidence is never altered.
            let mut core = DecisionCore::new(cf.clone(), CoreOptions { evidence_signer: None, redaction_key: req.redaction_key.clone() }).map_err(|e| ReplayError::Policy(e.to_string()))?;
            let mut risks = RiskTrail::new();
            for r in req.records.iter().filter(|r| r.kind == EvidenceKind::Event) {
                let ev: SecurityEvent = serde_json::from_value(r.payload.clone()).map_err(|e| ReplayError::Policy(e.to_string()))?;
                let o = core.process(ev, r.time);
                risks.insert(o.evidence_id.clone(), o.risks.iter().map(|x| serde_json::to_value(x).unwrap_or_default()).collect());
            }
            // A counterfactual seals its own frames; the recorded evidence is untouched.
            use ivar_core::evidence::EvidenceStore;
            (core.evidence().records(), cf, true, risks)
        }
    };
    let (frames, unobserved_layers) = frames_for(&records, &req.entity_keys, counterfactual, &req.expected_layers, &risks);
    let evidence = req.records.iter().map(|r| serde_json::to_value(r).unwrap_or_default()).collect();
    let mut bundle = ReplayBundle {
        contract: CONTRACT_VERSION.into(),
        bundle_version: BUNDLE_VERSION,
        incident_id: req.incident_id.into(),
        engine_version: ENGINE_VERSION.into(),
        policy_version: policy.policy_version.clone(),
        plugin_versions: req.live_policy.plugin_versions.clone(),
        counterfactual,
        counterfactual_policy: req.counterfactual_policy.map(|p| p.policy_version.clone()),
        evidence_chain_head: head,
        frames,
        re_execution,
        unobserved_layers,
        evidence,
        policy: serde_json::to_value(req.live_policy).unwrap_or_default(),
        policy_history: req.policy_history.values().map(|p| serde_json::to_value(p).unwrap_or_default()).collect(),
        signature: None,
    };
    sign_bundle(&mut bundle, req.signer);
    Ok(bundle)
}

/// What a partner or regulator runs: verify the bundle signature and the
/// evidence chain, then re execute the evidence with the pinned policy and
/// check every recorded verdict, without trusting the server's rendering.
pub fn reverify_bundle(bundle: &ReplayBundle, keyring: Option<&Keyring>, redaction_key: &[u8]) -> Result<ReExecution, ReplayError> {
    if bundle.engine_version != ENGINE_VERSION {
        return Err(ReplayError::EngineVersion { bundle: bundle.engine_version.clone(), engine: ENGINE_VERSION.into() });
    }
    if let Some(ring) = keyring {
        let sig = bundle.signature.clone().ok_or_else(|| ReplayError::Signature("unsigned bundle".into()))?;
        let mut unsigned = bundle.clone();
        unsigned.signature = None;
        let bytes = serde_json::to_vec(&unsigned).unwrap_or_default();
        verify_bytes(ring, "replay", &sig, &bytes).map_err(|e| ReplayError::Signature(e.to_string()))?;
    }
    let records: Vec<EvidenceRecord> = bundle.evidence.iter().filter_map(|v| serde_json::from_value(v.clone()).ok()).collect();
    let head = verify_chain(&records, None)?;
    if head != bundle.evidence_chain_head {
        return Err(ReplayError::Evidence(ChainError::Link { seq: records.last().map(|r| r.seq).unwrap_or(0) }));
    }
    let policy: PolicyContent = serde_json::from_value(bundle.policy.clone()).map_err(|e| ReplayError::Policy(e.to_string()))?;
    let recorded = recorded_verdicts(&records);
    let history: BTreeMap<u64, PolicyContent> = bundle.policy_history.iter().filter_map(|v| serde_json::from_value::<PolicyContent>(v.clone()).ok()).map(|p| (p.version, p)).collect();
    let (replayed, _) = reexecute(&records, &policy, &history, redaction_key)?;
    let mismatches = compare(&recorded, &replayed);
    if !mismatches.is_empty() {
        return Err(ReplayError::Mismatch(mismatches));
    }
    Ok(ReExecution { matched: true, recorded_verdicts: recorded.len(), replayed_verdicts: replayed.len(), mismatches: vec![] })
}
