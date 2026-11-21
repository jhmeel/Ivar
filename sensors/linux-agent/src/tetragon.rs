//! Tetragon integration: TracingPolicies generated from IVAR policy, and the
//! JSON export followed and forwarded as OCSF.
//!
//! Killing a process does not always stop an operation already under way, so
//! critical rules pair the kill (Sigkill) with a denied system call
//! (Override, through an LSM hook). In observe mode the same selectors only
//! Post events.

use ivar_contracts::PolicyContent;
use ivar_core::detect::vocabulary as v;
use ivar_sensor_kit::{adapters, now_ms, Sensor};
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

fn actions(enforce: bool, deny: bool) -> Value {
    if !enforce {
        return json!([{ "action": "Post" }]);
    }
    if deny {
        json!([{ "action": "Override", "argError": -1 }, { "action": "Sigkill" }])
    } else {
        json!([{ "action": "Sigkill" }])
    }
}

fn policy(name: &str, spec: Value) -> Value {
    json!({ "apiVersion": "cilium.io/v1alpha1", "kind": "TracingPolicy", "metadata": { "name": name, "labels": { "app.kubernetes.io/managed-by": "ivar" } }, "spec": spec })
}

/// The TracingPolicies for a policy bundle, as a YAML stream.
pub fn tracing_policies(p: &PolicyContent, enforce: bool) -> String {
    let web: Vec<Value> = v::WEB_PROCESSES.iter().flat_map(|b| [format!("/usr/sbin/{b}"), format!("/usr/bin/{b}"), format!("/usr/local/bin/{b}")]).map(Value::from).collect();
    let shells: Vec<Value> = v::SHELLS.iter().filter(|s| !s.ends_with(".exe")).flat_map(|s| [format!("/bin/{s}"), format!("/usr/bin/{s}")]).map(Value::from).collect();
    let secret_paths: Vec<Value> = v::SECRET_PATHS.iter().filter(|p| p.starts_with("/etc") || p.starts_with("/proc") || p.starts_with("/var")).map(|s| Value::from(*s)).collect();
    let secret_suffixes: Vec<Value> = v::SECRET_PATHS.iter().filter(|p| !(p.starts_with("/etc") || p.starts_with("/proc") || p.starts_with("/var"))).map(|s| Value::from(*s)).collect();
    let mut docs = vec![
        // A web process may never start a shell (PHP2Shell): deny the exec and kill.
        policy("ivar-web-process-shell", json!({
            "lsmhooks": [{
                "hook": "bprm_check_security",
                "args": [{ "index": 0, "type": "linux_binprm" }],
                "selectors": [{
                    "matchBinaries": [{ "operator": "In", "values": web }],
                    "matchArgs": [{ "index": 0, "operator": "Equal", "values": shells }],
                    "matchActions": actions(enforce, true)
                }]
            }]
        })),
        // Secret files: deny the open for processes outside the allowlist.
        policy("ivar-secret-access", json!({
            "lsmhooks": [{
                "hook": "file_open",
                "args": [{ "index": 0, "type": "file" }],
                "selectors": [
                    { "matchArgs": [{ "index": 0, "operator": "Prefix", "values": secret_paths }], "matchBinaries": [{ "operator": "NotIn", "values": ["/usr/sbin/sshd", "/usr/bin/sudo", "/usr/sbin/unix_chkpwd"] }], "matchActions": actions(enforce, true) },
                    { "matchArgs": [{ "index": 0, "operator": "Postfix", "values": secret_suffixes }], "matchActions": actions(enforce, false) }
                ]
            }]
        })),
        // Cloud metadata from web processes (credential theft).
        policy("ivar-cloud-metadata", json!({
            "kprobes": [{
                "call": "tcp_connect",
                "syscall": false,
                "args": [{ "index": 0, "type": "sock" }],
                "selectors": [{
                    "matchBinaries": [{ "operator": "In", "values": web.clone() }],
                    "matchArgs": [{ "index": 0, "operator": "DAddr", "values": ["169.254.169.254", "169.254.170.2"] }],
                    "matchActions": actions(enforce, false)
                }]
            }]
        })),
        // Runner memory reads (build secret theft): any process reading another's memory.
        policy("ivar-process-memory-read", json!({
            "kprobes": [{
                "call": "sys_process_vm_readv",
                "syscall": true,
                "selectors": [{ "matchActions": actions(enforce, false) }]
            }]
        })),
    ];
    // Process profiles from the declarations: workloads may only run their declared binaries.
    let declared = ivar_core::declare::Declarations::from_value(&p.declared);
    for prof in declared.process_profiles {
        let allowed: Vec<Value> = prof.allowed_binaries.iter().flat_map(|b| [format!("/usr/bin/{b}"), format!("/usr/local/bin/{b}"), format!("/bin/{b}")]).map(Value::from).collect();
        docs.push(json!({
            "apiVersion": "cilium.io/v1alpha1",
            "kind": "TracingPolicyNamespaced",
            "metadata": { "name": format!("ivar-profile-{}", prof.workload) },
            "spec": {
                "podSelector": { "matchLabels": { "app": prof.workload } },
                "lsmhooks": [{
                    "hook": "bprm_check_security",
                    "args": [{ "index": 0, "type": "linux_binprm" }],
                    "selectors": [{ "matchArgs": [{ "index": 0, "operator": "NotEqual", "values": allowed }], "matchActions": actions(enforce, true) }]
                }]
            }
        }));
    }
    docs.iter().map(|d| serde_yaml::to_string(d).unwrap_or_default()).collect::<Vec<_>>().join("---\n")
}

/// Follow Tetragon's JSON export file and forward events.
pub fn follow(sensor: &Sensor, path: &str, stop: &AtomicBool) -> anyhow::Result<()> {
    let mut f = std::fs::File::open(path)?;
    f.seek(SeekFrom::End(0))?;
    let mut reader = BufReader::new(f);
    let mut line = String::new();
    while !stop.load(Ordering::Relaxed) {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            std::thread::sleep(Duration::from_millis(100));
            continue;
        }
        if let Some(ev) = adapters::parse("tetragon", &line, sensor.next_seq(), now_ms()) {
            sensor.emit(ev);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ivar_core::policy::spec_default_policy;

    #[test]
    fn enforce_pairs_kill_with_denied_syscall() {
        let y = tracing_policies(&spec_default_policy(0), true);
        let docs: Vec<serde_yaml::Value> = y.split("---\n").map(|d| serde_yaml::from_str(d).unwrap()).collect();
        assert!(docs.len() >= 4);
        let shell = serde_json::to_value(&docs[0]).unwrap();
        let acts = &shell["spec"]["lsmhooks"][0]["selectors"][0]["matchActions"];
        assert_eq!(acts[0]["action"], "Override");
        assert_eq!(acts[1]["action"], "Sigkill");
        let observe = tracing_policies(&spec_default_policy(0), false);
        assert!(!observe.contains("Sigkill") && observe.contains("Post"));
    }
}
