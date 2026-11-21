//! Kubernetes manifests compile into declared egress (NetworkPolicy) and
//! process profiles (container commands plus x ivar annotations).

use super::{load_doc, DeclareError, Declarations, EgressRule, ProcessProfile};
use serde_json::Value;

/// Accepts a multi document YAML stream.
pub fn compile_kubernetes(file: &str, text: &str) -> Result<Declarations, DeclareError> {
    let mut out = Declarations::default();
    for doc_text in text.split("\n---") {
        if doc_text.trim().is_empty() {
            continue;
        }
        let doc = load_doc(file, doc_text)?;
        let kind = doc.get("kind").and_then(Value::as_str).unwrap_or("");
        let name = doc.pointer("/metadata/name").and_then(Value::as_str).unwrap_or("").to_string();
        match kind {
            "NetworkPolicy" => {
                let app = doc
                    .pointer("/spec/podSelector/matchLabels/app")
                    .and_then(Value::as_str)
                    .unwrap_or(&name)
                    .to_string();
                for rule in doc.pointer("/spec/egress").and_then(Value::as_array).cloned().unwrap_or_default() {
                    for to in rule.get("to").and_then(Value::as_array).cloned().unwrap_or_default() {
                        let dest = to
                            .pointer("/ipBlock/cidr")
                            .and_then(Value::as_str)
                            .map(String::from)
                            .or_else(|| to.pointer("/podSelector/matchLabels/app").and_then(Value::as_str).map(|a| format!("service:{a}")))
                            .unwrap_or_default();
                        if !dest.is_empty() {
                            out.egress.push(EgressRule { holder: format!("service:{app}"), destination: dest, declared_in: file.into() });
                        }
                    }
                }
            }
            "Deployment" | "StatefulSet" | "DaemonSet" | "Pod" => {
                let annotations = doc
                    .pointer("/spec/template/metadata/annotations")
                    .or_else(|| doc.pointer("/metadata/annotations"))
                    .cloned()
                    .unwrap_or(Value::Null);
                let mut binaries: Vec<String> = annotations
                    .get("ivar.dev/allowed-binaries")
                    .and_then(Value::as_str)
                    .map(|s| s.split(',').map(|b| b.trim().to_string()).filter(|b| !b.is_empty()).collect())
                    .unwrap_or_default();
                let containers = doc
                    .pointer("/spec/template/spec/containers")
                    .or_else(|| doc.pointer("/spec/containers"))
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                for c in containers {
                    if let Some(cmd) = c.get("command").and_then(Value::as_array).and_then(|a| a.first()).and_then(Value::as_str) {
                        binaries.push(cmd.rsplit('/').next().unwrap_or(cmd).to_string());
                    }
                }
                binaries.sort();
                binaries.dedup();
                if let Some(egress) = annotations.get("ivar.dev/egress").and_then(Value::as_str) {
                    for d in egress.split(',').map(str::trim).filter(|d| !d.is_empty()) {
                        out.egress.push(EgressRule { holder: format!("service:{name}"), destination: d.into(), declared_in: file.into() });
                    }
                }
                if !binaries.is_empty() {
                    out.process_profiles.push(ProcessProfile { workload: name.clone(), allowed_binaries: binaries, declared_in: file.into() });
                }
            }
            _ => {}
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #[test]
    fn egress_and_profiles() {
        let y = r#"
apiVersion: apps/v1
kind: Deployment
metadata: { name: api }
spec:
  template:
    metadata:
      annotations:
        ivar.dev/allowed-binaries: "node"
        ivar.dev/egress: "api.stripe.com"
    spec:
      containers: [{ name: api, command: ["/usr/local/bin/node"] }]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: api-egress }
spec:
  podSelector: { matchLabels: { app: api } }
  egress:
    - to: [{ podSelector: { matchLabels: { app: postgres } } }]
"#;
        let d = super::compile_kubernetes("k8s.yaml", y).unwrap();
        assert!(d.egress_declared("service:api", "api.stripe.com"));
        assert!(d.egress_declared("service:api", "service:postgres"));
        assert!(!d.egress_declared("service:api", "evil.example"));
        assert_eq!(d.profile_for("api").unwrap().allowed_binaries, vec!["node"]);
    }
}
