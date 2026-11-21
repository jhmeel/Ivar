//! PluginManifest (signed YAML): type, permissions, resource limits, compatibility.
//! Produced by the plugin publisher, consumed by the plugin registry.

use crate::error::ContractError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PluginType {
    SensorAdapter,
    Parser,
    Detector,
    RulePack,
    Enricher,
    Responder,
    AiProvider,
    Sink,
}

impl PluginType {
    /// "Runs in" column of §14.
    pub fn runs_in(self) -> &'static str {
        match self {
            PluginType::SensorAdapter => "separate_process",
            PluginType::Parser => "wasm_sandbox",
            PluginType::Detector => "wasm_sandbox",
            PluginType::RulePack => "native_rule_engine",
            PluginType::Enricher => "wasm_sandbox",
            PluginType::Responder => "separate_process_scoped_credentials",
            PluginType::AiProvider => "separate_process",
            PluginType::Sink => "separate_process",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct PluginPermissions {
    #[serde(default)]
    pub actions: Vec<String>,
    #[serde(default)]
    pub network: Vec<String>,
    #[serde(default)]
    pub secrets: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PluginLimits {
    pub memory_mb: u64,
    pub cpu_ms_per_call: u64,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DriftTolerance {
    /// Max allowed change in drop rate versus the plugin's own history (fraction).
    pub drop_rate: f64,
    /// Max allowed total variation distance in verdict distribution.
    pub verdict_distribution: f64,
}

impl Default for DriftTolerance {
    fn default() -> Self {
        DriftTolerance { drop_rate: 0.01, verdict_distribution: 0.10 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PluginManifest {
    pub name: String,
    pub version: String,
    #[serde(rename = "type")]
    pub plugin_type: PluginType,
    pub api: String,
    #[serde(default)]
    pub permissions: PluginPermissions,
    pub limits: PluginLimits,
    pub signature: String,
    #[serde(default)]
    pub drift_tolerance: Option<DriftTolerance>,
    #[serde(default)]
    pub compatibility: Option<String>,
}

impl PluginManifest {
    pub fn from_yaml(s: &str) -> Result<Self, ContractError> {
        Ok(serde_yaml::from_str(s)?)
    }
}

