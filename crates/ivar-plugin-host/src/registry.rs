//! The plugin registry: one record per plugin, rule pack or policy bundle,
//! moved through the lifecycle with every transition recorded.

use crate::drift::DriftReport;
use crate::lifecycle::{Stage, Transition};
use crate::permissions::{check, RegistryPolicy};
use crate::signature::TrustRoot;
use ivar_contracts::PluginManifest;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    Plugin,
    /// Signed content can still be faulty content (CrowdStrike, July 2024).
    RulePack,
    PolicyBundle,
}

#[derive(Debug, Clone, Serialize)]
pub struct PluginRecord {
    pub name: String,
    pub version: String,
    pub kind: ArtifactKind,
    pub stage: Stage,
    pub manifest: Option<PluginManifest>,
    pub history: Vec<(Stage, String)>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum RegistryEvent {
    Rejected { name: String, reason: String },
    Disabled { name: String, reason: String },
    ReturnedToShadow { name: String, reason: String },
    Promoted { name: String, stage: Stage },
}

pub struct PluginRegistry {
    trust: TrustRoot,
    policy: RegistryPolicy,
    records: BTreeMap<String, PluginRecord>,
    pub events: Vec<RegistryEvent>,
}

impl PluginRegistry {
    pub fn new(trust: TrustRoot, policy: RegistryPolicy) -> Self {
        PluginRegistry { trust, policy, records: BTreeMap::new(), events: Vec::new() }
    }

    pub fn get(&self, name: &str) -> Option<&PluginRecord> {
        self.records.get(name)
    }

    fn step(&mut self, name: &str, t: Transition, reason: &str) -> Result<Stage, String> {
        let r = self.records.get_mut(name).ok_or("unknown plugin")?;
        let s = r.stage.next(t)?;
        r.stage = s;
        r.history.push((s, reason.to_string()));
        Ok(s)
    }

    /// Verify the signature, then check permissions. Ends in Shadow or Rejected.
    pub fn submit_plugin(&mut self, manifest_yaml: &str, artifact: &[u8], signature_b64: &str) -> Result<Stage, String> {
        let m = PluginManifest::from_yaml(manifest_yaml).map_err(|e| e.to_string())?;
        let name = m.name.clone();
        self.records.insert(name.clone(), PluginRecord { name: name.clone(), version: m.version.clone(), kind: ArtifactKind::Plugin, stage: Stage::Verify, manifest: Some(m.clone()), history: vec![(Stage::Verify, "submitted".into())] });
        if let Err(e) = self.trust.verify(&m.signature, manifest_yaml.as_bytes(), artifact, signature_b64) {
            self.step(&name, Transition::SignatureInvalid, &e.to_string())?;
            self.events.push(RegistryEvent::Rejected { name, reason: e.to_string() });
            return Ok(Stage::Rejected);
        }
        self.step(&name, Transition::SignatureValid, "signature verified")?;
        match check(&m, &self.policy) {
            Ok(()) => self.step(&name, Transition::PermissionsOk, "permissions within policy"),
            Err(v) => {
                let reason = v.join("; ");
                self.step(&name, Transition::PermissionsDenied, &reason)?;
                self.events.push(RegistryEvent::Rejected { name, reason });
                Ok(Stage::Rejected)
            }
        }
    }

    /// Rule packs and policy bundles: their signature is verified by the
    /// policy keyring before they arrive here; they then follow the same stages.
    pub fn submit_content(&mut self, kind: ArtifactKind, name: &str, version: &str, signature: Result<(), String>) -> Result<Stage, String> {
        self.records.insert(name.into(), PluginRecord { name: name.into(), version: version.into(), kind, stage: Stage::Verify, manifest: None, history: vec![(Stage::Verify, "submitted".into())] });
        match signature {
            Ok(()) => {
                self.step(name, Transition::SignatureValid, "signature verified")?;
                self.step(name, Transition::PermissionsOk, "content has no permissions")
            }
            Err(e) => {
                self.step(name, Transition::SignatureInvalid, &e)?;
                self.events.push(RegistryEvent::Rejected { name: name.into(), reason: e });
                Ok(Stage::Rejected)
            }
        }
    }

    /// Shadow results reviewed and the attack replay library passed.
    pub fn shadow_passed(&mut self, name: &str, replay_library_passed: bool) -> Result<Stage, String> {
        if !replay_library_passed {
            return Err("the attack replay library must pass before canary".into());
        }
        let s = self.step(name, Transition::ShadowPassed, "shadow and replay library passed")?;
        self.events.push(RegistryEvent::Promoted { name: name.into(), stage: s });
        Ok(s)
    }

    pub fn canary_passed(&mut self, name: &str) -> Result<Stage, String> {
        let s = self.step(name, Transition::CanaryPassed, "canary group passed")?;
        self.events.push(RegistryEvent::Promoted { name: name.into(), stage: s });
        Ok(s)
    }

    /// A crash, limit breach or undeclared access: disable and alert.
    pub fn breach(&mut self, name: &str, reason: &str) -> Result<Stage, String> {
        let s = self.step(name, Transition::Breach, reason)?;
        self.events.push(RegistryEvent::Disabled { name: name.into(), reason: reason.into() });
        Ok(s)
    }

    pub fn drift(&mut self, name: &str, report: &DriftReport) -> Result<Stage, String> {
        if !report.drifted {
            return Ok(self.records.get(name).map(|r| r.stage).ok_or("unknown plugin")?);
        }
        let reason = format!("drop rate change {:.3}, verdict distance {:.3}", report.drop_rate_change, report.verdict_distance);
        let s = self.step(name, Transition::Drift, &reason)?;
        self.events.push(RegistryEvent::ReturnedToShadow { name: name.into(), reason });
        Ok(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapter::{PluginState, WasmDetector};
    use crate::drift::compare;
    use crate::sandbox::{fixtures, WasmPlugin};
    use crate::signature::testkey;
    use ivar_contracts::DriftTolerance;
    use ivar_core::detect::vocabulary as v;
    use ivar_core::policy::spec_default_policy;
    use ivar_core::sensor::{ocsf_class, EventBuilder};
    use ivar_core::{engine::CoreOptions, DecisionCore};
    use std::sync::{Arc, Mutex};

    const MANIFEST: &str = "name: fraud-velocity\nversion: 1.0.0\ntype: detector\napi: ivar.plugin/v1\nlimits: { memory_mb: 2, cpu_ms_per_call: 20, timeout_ms: 2000 }\nsignature: sigstore\n";

    fn registry() -> (PluginRegistry, p256::ecdsa::SigningKey) {
        let k = testkey::key(3);
        let mut t = TrustRoot::default();
        t.add_key(*k.verifying_key());
        (PluginRegistry::new(t, RegistryPolicy::default()), k)
    }

    #[test]
    fn full_lifecycle_with_a_real_detector_plugin() {
        let (mut reg, k) = registry();
        let wasm = wat::parse_str(fixtures::GOOD).unwrap();
        let sig = testkey::sign(&k, MANIFEST.as_bytes(), &wasm);
        assert_eq!(reg.submit_plugin(MANIFEST, &wasm, &sig).unwrap(), Stage::Shadow);

        let state = Arc::new(Mutex::new(PluginState { stage: Some(Stage::Shadow), ..Default::default() }));
        let plugin = WasmPlugin::load(&PluginManifest::from_yaml(MANIFEST).unwrap(), &wasm).unwrap();
        let mut core = DecisionCore::new(spec_default_policy(0), CoreOptions::default()).unwrap();
        core.add_detector(Box::new(WasmDetector::new(plugin, state.clone())));
        let ev = || EventBuilder::new(ocsf_class::API_ACTIVITY, v::BUSINESS_ACTION, 1, "sdk", "app_sdk", 1).user("u1", "human").business_action("payout").build();
        let o = core.process(ev(), 1);
        assert!(o.findings.iter().all(|f| !f.rule.starts_with("fraud-velocity")), "shadow: recorded only");
        assert_eq!(state.lock().unwrap().shadow_findings.len(), 1);

        assert!(reg.shadow_passed("fraud-velocity", false).is_err());
        assert_eq!(reg.shadow_passed("fraud-velocity", true).unwrap(), Stage::Canary);
        state.lock().unwrap().stage = Some(Stage::Canary);
        let o = core.process(ev(), 2);
        assert!(o.findings.iter().any(|f| f.rule == "fraud-velocity:fraud_velocity"), "canary: enforced");
        assert_eq!(reg.canary_passed("fraud-velocity").unwrap(), Stage::Active);

        let history = state.lock().unwrap().window.clone();
        let mut benign = crate::drift::Window::default();
        for _ in 0..100 {
            benign.record(true, "benign");
        }
        assert_eq!(reg.drift("fraud-velocity", &compare(&history, &benign, &DriftTolerance::default())).unwrap(), Stage::Shadow);
    }

    #[test]
    fn tampered_or_greedy_plugins_are_rejected_and_breaches_disable() {
        let (mut reg, k) = registry();
        let wasm = wat::parse_str(fixtures::GOOD).unwrap();
        let sig = testkey::sign(&k, MANIFEST.as_bytes(), &wasm);
        let tampered = wat::parse_str(fixtures::SNEAKY).unwrap();
        assert_eq!(reg.submit_plugin(MANIFEST, &tampered, &sig).unwrap(), Stage::Rejected);
        let greedy = MANIFEST.replace("type: detector", "type: detector\npermissions:\n  network: [\"evil.example:443\"]");
        let gsig = testkey::sign(&k, greedy.as_bytes(), &wasm);
        assert_eq!(reg.submit_plugin(&greedy, &wasm, &gsig).unwrap(), Stage::Rejected);
        assert_eq!(reg.submit_plugin(MANIFEST, &wasm, &sig).unwrap(), Stage::Shadow);
        assert_eq!(reg.breach("fraud-velocity", "cpu limit").unwrap(), Stage::Disabled);
        assert!(reg.events.iter().any(|e| matches!(e, RegistryEvent::Disabled { .. })));
    }

    #[test]
    fn rule_packs_follow_the_same_stages() {
        let (mut reg, _) = registry();
        assert_eq!(reg.submit_content(ArtifactKind::RulePack, "sigma-core", "2026.11", Ok(())).unwrap(), Stage::Shadow);
        assert!(reg.canary_passed("sigma-core").is_err(), "no skipping shadow");
        assert_eq!(reg.submit_content(ArtifactKind::PolicyBundle, "payments", "2026.11.3", Err("bad signature".into())).unwrap(), Stage::Rejected);
    }
}
