//! Signatures: OWASP Core Rule Set, Suricata, Sigma and YARA rules run in the
//! sensors and existing engines (Coraza, Suricata, Falco, Tetragon). Their
//! alerts arrive in `engine_alerts`; this detector also holds the small set of
//! signature rules the core evaluates itself.

use super::{actor_entities, finding, finding_with_confidence, vocabulary as v, DetectContext, Detector};
use ivar_contracts::{DetectionMethodName, Finding, SecurityEvent};

#[derive(Default)]
pub struct SignatureDetector;

/// The keyed hash the shared indicator network uses ("ni_" + 32 hex).
pub fn indicator_hash(network_key_hex: &str, kind: &str, value: &str) -> String {
    use hmac::{Hmac, Mac};
    let key = hex::decode(network_key_hex).unwrap_or_default();
    let mut m = Hmac::<sha2::Sha256>::new_from_slice(&key).expect("hmac key");
    m.update(format!("{kind}:{value}").as_bytes());
    format!("ni_{}", &hex::encode(m.finalize().into_bytes())[..32])
}

fn shannon_entropy(s: &str) -> f64 {
    let mut counts = [0usize; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let n = s.len() as f64;
    counts.iter().filter(|c| **c > 0).map(|c| { let p = *c as f64 / n; -p * p.log2() }).sum()
}

impl Detector for SignatureDetector {
    fn name(&self) -> &'static str {
        "signatures"
    }
    fn method(&self) -> DetectionMethodName {
        DetectionMethodName::Signatures
    }
    fn detect(&mut self, ctx: &DetectContext, ev: &SecurityEvent) -> Vec<Finding> {
        let ext = ev.ext();
        let actors = actor_entities(ev);
        let mut out = Vec::new();
        if !ext.engine_alerts.is_empty() {
            let conf = if ext.engine_alert_confidence > 0.0 { Some(ext.engine_alert_confidence) } else { None };
            if let Some(mut f) = finding_with_confidence(ctx, ev, "engine_alert", actors.clone(), format!("engine alerts: {}", ext.engine_alerts.join(", ")), conf) {
                f.rule_family = format!("signature.{}", ext.sensor_type);
                out.push(f);
            }
        }
        if let Some(src) = ev.src_endpoint.as_ref().map(|s| s.ip.clone()).filter(|s| !s.is_empty()) {
            if let Some(rule) = ctx.rules.get("shared_indicator") {
                let key = rule.params.get("network_key_hex").and_then(|k| k.as_str()).unwrap_or("");
                if !key.is_empty() {
                    let h = indicator_hash(key, "ip", &src);
                    if let Some(score) = rule.params.get("hashes").and_then(|m| m.get(&h)).and_then(|s| s.as_f64()) {
                        out.extend(finding_with_confidence(ctx, ev, "shared_indicator", actors.clone(), format!("source matches a shared indicator reported by independent participants (score {score:.2})"), Some(score)));
                    }
                }
            }
        }
        let activity = ev.activity_name.as_str();
        let path = ev.process.as_ref().map(|p| p.file_path.clone()).unwrap_or_default();
        let dst = ev.dst_endpoint.as_ref().map(|d| if d.hostname.is_empty() { d.ip.clone() } else { d.hostname.clone() }).unwrap_or_default();
        if (activity == v::FILE_READ || activity == v::SECRET_READ) && v::SECRET_PATHS.iter().any(|p| path.contains(p)) {
            out.extend(finding(ctx, ev, "secret_file_read", actors.clone(), format!("read of secret path {path}")));
        }
        if activity == v::NET_CONNECT && v::METADATA_ENDPOINTS.iter().any(|m| dst == *m) {
            out.extend(finding(ctx, ev, "metadata_access", actors.clone(), format!("cloud metadata access to {dst}")));
        }
        if activity == v::DNS_QUERY {
            let q = ext.attributes.get("query").cloned().unwrap_or_default();
            let max_len = ctx.rules.param_u64("dns_tunnelling", "label_len", 40) as usize;
            let min_entropy = ctx.rules.param_f64("dns_tunnelling", "entropy", 3.8);
            if q.split('.').any(|l| l.len() >= max_len && shannon_entropy(l) >= min_entropy) {
                out.extend(finding(ctx, ev, "dns_tunnelling", actors.clone(), format!("high entropy DNS label in {q}")));
            }
        }
        if activity == v::RUNNER_MEMORY_READ {
            out.extend(finding(ctx, ev, "runner_memory_read", actors.clone(), "build runner memory read".into()));
        }
        if activity == v::SNAPSHOT_DELETE || (activity == v::BACKUP_CHANGE && ext.destructive) {
            out.extend(finding(ctx, ev, "backup_deletion", actors.clone(), "backup or snapshot destroyed".into()));
        }
        if activity == v::VM_MASS_ACTION {
            out.extend(finding(ctx, ev, "mass_vm_action", actors.clone(), "mass virtual machine action".into()));
        }
        if activity == v::DEVICE_VERSION_CHANGE && ext.attributes.get("direction").map(|d| d == "downgrade").unwrap_or(false) {
            out.extend(finding(ctx, ev, "version_downgrade", actors.clone(), "edge device software downgrade".into()));
        }
        if activity == v::AI_PROMPT && ext.attributes.get("injection_marker").map(|m| m == "true").unwrap_or(false) {
            out.extend(finding(ctx, ev, "prompt_injection_marker", actors.clone(), "prompt injection marker in model input".into()));
        }
        if activity == v::AI_PROMPT && ext.attributes.get("sensitive_data").map(|m| m == "true").unwrap_or(false) {
            out.extend(finding(ctx, ev, "ai_sensitive_data_to_model", actors, "sensitive data sent to a model".into()));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn indicator_hash_matches_the_network() {
        // Same value as indicators.Hash("00112233", "ip", "203.0.113.9") in Go.
        assert_eq!(super::indicator_hash("00112233", "ip", "203.0.113.9"), "ni_b80ec437340fef79137a85270accb191");
    }

    #[test]
    fn entropy() {
        assert!(super::shannon_entropy("aGVsbG8gd29ybGQgdGhpcyBpcyBleGZpbHRyYXRpb24") > 3.8);
        assert!(super::shannon_entropy("aaaaaaaa") < 1.0);
    }
}
