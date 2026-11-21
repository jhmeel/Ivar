//! A detector plugin as a core `Detector`. In Shadow the plugin's findings
//! are only recorded for drift and replay comparison; in Canary and Active
//! they feed the risk score. Any sandbox breach is reported to the registry.

use crate::drift::Window;
use crate::lifecycle::Stage;
use crate::sandbox::{InertServices, SandboxError, WasmPlugin};
use ivar_contracts::{DetectionMethodName, Finding, SecurityEvent};
use ivar_core::detect::{actor_entities, DetectContext, Detector};
use serde::Deserialize;
use std::sync::{Arc, Mutex};

#[derive(Deserialize)]
struct PluginFinding {
    rule: String,
    #[serde(default)]
    rule_family: String,
    #[serde(default)]
    technique: String,
    confidence: f64,
    #[serde(default)]
    severity: u32,
    #[serde(default)]
    explanation: String,
    #[serde(default)]
    verdict: String,
}

/// Shared between the adapter and the registry.
#[derive(Default)]
pub struct PluginState {
    pub stage: Option<Stage>,
    pub window: Window,
    pub shadow_findings: Vec<Finding>,
    pub breach: Option<SandboxError>,
}

pub struct WasmDetector {
    plugin: WasmPlugin,
    pub state: Arc<Mutex<PluginState>>,
}

impl WasmDetector {
    pub fn new(plugin: WasmPlugin, state: Arc<Mutex<PluginState>>) -> Self {
        WasmDetector { plugin, state }
    }
}

impl Detector for WasmDetector {
    fn name(&self) -> &'static str {
        "wasm_detector_plugin"
    }
    fn method(&self) -> DetectionMethodName {
        DetectionMethodName::MachineLearning
    }
    fn detect(&mut self, ctx: &DetectContext, ev: &SecurityEvent) -> Vec<Finding> {
        let mut st = self.state.lock().expect("plugin state");
        let stage = st.stage.unwrap_or(Stage::Shadow);
        if matches!(stage, Stage::Disabled | Stage::Rejected | Stage::Verify | Stage::Check) {
            return vec![];
        }
        let input = serde_json::to_string(ev).unwrap_or_default();
        let raw = match self.plugin.call(&input, Box::new(InertServices::default())) {
            Ok((out, _logs)) => out,
            Err(e) => {
                st.breach = Some(e);
                st.window.record(false, "error");
                return vec![];
            }
        };
        let parsed: Vec<PluginFinding> = serde_json::from_str(&raw).unwrap_or_default();
        st.window.record(!parsed.is_empty() || raw.trim() == "[]", parsed.first().map(|p| p.verdict.as_str()).unwrap_or("benign"));
        let m = self.plugin.manifest();
        let findings: Vec<Finding> = parsed
            .into_iter()
            .map(|p| Finding {
                finding_id: ivar_core::ids::derive("fnd", &[ctx.evidence_id, &m.name, &p.rule]),
                rule: format!("{}:{}", m.name, p.rule),
                rule_family: if p.rule_family.is_empty() { format!("plugin.{}", m.name) } else { p.rule_family },
                technique: p.technique,
                method: DetectionMethodName::MachineLearning.to_proto() as i32,
                confidence: p.confidence.clamp(0.0, 1.0),
                severity: p.severity,
                evidence_ids: vec![ctx.evidence_id.to_string()],
                entities: actor_entities(ev),
                observation_point: format!("plugin:{}", m.name),
                time: ctx.now,
                explanation: p.explanation,
                source_event: ctx.evidence_id.to_string(),
                ..Default::default()
            })
            .collect();
        if stage.enforces() {
            findings
        } else {
            st.shadow_findings.extend(findings);
            vec![]
        }
    }
}
