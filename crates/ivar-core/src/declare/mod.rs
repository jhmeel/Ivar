//! The declaration compiler (section 6.3).
//!
//! Teams already write down what their systems should do: OpenAPI schemas,
//! Terraform, Kubernetes manifests, IAM policies, CI workflows and lockfiles.
//! This module compiles them into an expected trust graph and a positive
//! security profile. Normal is declared, not inferred, so a resident attacker
//! cannot be learned as normal.

mod ci;
mod iam;
mod kubernetes;
mod lockfile;
mod openapi;
mod terraform;

pub use ci::compile_github_workflow;
pub use iam::compile_iam_policy;
pub use kubernetes::compile_kubernetes;
pub use lockfile::compile_npm_lockfile;
pub use openapi::{compile_openapi, Route};
pub use terraform::compile_terraform_plan;

use ivar_contracts::TrustEdge;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// A declared outbound connection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Default)]
#[serde(default)]
pub struct EgressRule {
    pub holder: String,
    pub destination: String,
    pub declared_in: String,
}

/// A pinned package with its expected provenance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct DeclaredPackage {
    pub name: String,
    pub version: String,
    pub integrity: String,
    pub resolved: String,
    pub declared_in: String,
}

/// Process profile for positive security on hosts: binaries a workload may run.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct ProcessProfile {
    pub workload: String,
    pub allowed_binaries: Vec<String>,
    pub declared_in: String,
}

/// Everything the compiler produced. Serialised into PolicyContent.declared.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct Declarations {
    pub routes: Vec<Route>,
    pub edges: Vec<TrustEdge>,
    pub egress: Vec<EgressRule>,
    pub packages: BTreeMap<String, DeclaredPackage>,
    pub process_profiles: Vec<ProcessProfile>,
    /// Roles that public signup may assign (explicit allowlist, defect F7).
    pub public_roles: Vec<String>,
}

impl Declarations {
    pub fn merge(&mut self, other: Declarations) {
        self.routes.extend(other.routes);
        self.edges.extend(other.edges);
        self.egress.extend(other.egress);
        self.packages.extend(other.packages);
        self.process_profiles.extend(other.process_profiles);
        self.public_roles.extend(other.public_roles);
        self.egress.sort();
        self.egress.dedup();
    }

    pub fn to_value(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }

    /// Parse the declared section of a policy. Null fields (as other
    /// languages write empty lists) and absent fields mean empty; anything
    /// else that does not parse is an error, so a policy with a broken
    /// declared section is refused instead of silently losing positive
    /// security.
    pub fn parse(v: &serde_json::Value) -> Result<Self, serde_json::Error> {
        let mut v = v.clone();
        strip_nulls(&mut v);
        if v.is_null() {
            return Ok(Self::default());
        }
        serde_json::from_value(v)
    }

    /// Parse a declared section that was already validated when its policy
    /// was loaded.
    pub fn from_value(v: &serde_json::Value) -> Self {
        Self::parse(v).unwrap_or_default()
    }

    /// Find the declared route for a request, if any.
    pub fn match_route(&self, method: &str, path: &str) -> Option<&Route> {
        self.routes.iter().find(|r| r.matches(method, path))
    }

    pub fn egress_declared(&self, holder: &str, destination: &str) -> bool {
        self.egress.iter().any(|e| {
            (e.holder == holder || e.holder == "*")
                && (e.destination == destination
                    || e.destination
                        .strip_prefix("*.")
                        .map(|suffix| destination.ends_with(&format!(".{suffix}")))
                        .unwrap_or(false))
        })
    }

    pub fn profile_for(&self, workload: &str) -> Option<&ProcessProfile> {
        self.process_profiles.iter().find(|p| p.workload == workload)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DeclareError {
    #[error("parse {file}: {reason}")]
    Parse { file: String, reason: String },
}

pub(crate) fn parse_err(file: &str, e: impl std::fmt::Display) -> DeclareError {
    DeclareError::Parse { file: file.to_string(), reason: e.to_string() }
}

/// Parse YAML or JSON into a JSON value.
pub(crate) fn load_doc(file: &str, text: &str) -> Result<serde_json::Value, DeclareError> {
    if let Ok(v) = serde_json::from_str(text) {
        return Ok(v);
    }
    let y: serde_yaml::Value = serde_yaml::from_str(text).map_err(|e| parse_err(file, e))?;
    serde_json::to_value(y).map_err(|e| parse_err(file, e))
}

fn strip_nulls(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::Object(m) => {
            m.retain(|_, x| !x.is_null());
            m.values_mut().for_each(strip_nulls);
        }
        serde_json::Value::Array(a) => a.iter_mut().for_each(strip_nulls),
        _ => {}
    }
}
