//! Tetragon JSON events (process_exec, process_kprobe, process_exit) to OCSF.
//! Tetragon also enforces in the kernel (Sigkill, Override); those actions
//! arrive as policy actions and are recorded as engine alerts.

use ivar_contracts::SecurityEvent;
use ivar_core::detect::vocabulary as v;
use ivar_core::sensor::{ocsf_class, EventBuilder};
use serde_json::Value;

fn base(b: &str) -> String {
    b.rsplit('/').next().unwrap_or(b).to_string()
}

pub fn map(e: &Value, seq: u64, now: i64) -> Option<SecurityEvent> {
    let node = e.get("node_name").and_then(Value::as_str).unwrap_or("").to_string();
    let time = e.get("time").and_then(Value::as_str).and_then(super::rfc3339_ms).unwrap_or(now);
    let sensor = format!("tetragon@{node}");
    if let Some(x) = e.get("process_exec") {
        let p = x.get("process")?;
        let parent = x.get("parent").and_then(|p| p.get("binary")).and_then(Value::as_str).unwrap_or("");
        let pod = p.pointer("/pod/name").and_then(Value::as_str).unwrap_or("");
        let workload = p.pointer("/pod/workload").and_then(Value::as_str).unwrap_or("");
        let mut ev = EventBuilder::new(ocsf_class::PROCESS_ACTIVITY, v::PROCESS_START, time, &sensor, "tetragon", seq)
            .device(pod, &node, if pod.is_empty() { "server" } else { "pod" })
            .process(p.get("pid").and_then(Value::as_u64).unwrap_or(0) as u32, &base(p.get("binary").and_then(Value::as_str).unwrap_or("")), &base(parent), p.get("binary").and_then(Value::as_str).unwrap_or(""))
            .attr("workload", workload)
            .observation_point("host")
            .build();
        if let Some(pr) = ev.process.as_mut() {
            pr.cmd_line = p.get("arguments").and_then(Value::as_str).unwrap_or("").chars().take(512).collect();
        }
        return Some(ev);
    }
    if let Some(x) = e.get("process_kprobe") {
        let p = x.get("process")?;
        let func = x.get("function_name").and_then(Value::as_str).unwrap_or("");
        let args = x.get("args").and_then(Value::as_array).cloned().unwrap_or_default();
        let path = args.iter().find_map(|a| a.pointer("/file_arg/path").and_then(Value::as_str)).unwrap_or("");
        let action = x.get("action").and_then(Value::as_str).unwrap_or("");
        let policy = x.get("policy_name").and_then(Value::as_str).unwrap_or("");
        let pod = p.pointer("/pod/name").and_then(Value::as_str).unwrap_or("");
        let (class, activity) = if func.contains("connect") {
            (ocsf_class::NETWORK_ACTIVITY, v::NET_CONNECT)
        } else {
            (ocsf_class::FILE_ACTIVITY, v::FILE_READ)
        };
        let mut b = EventBuilder::new(class, activity, time, &sensor, "tetragon", seq)
            .device(pod, &node, if pod.is_empty() { "server" } else { "pod" })
            .process(p.get("pid").and_then(Value::as_u64).unwrap_or(0) as u32, &base(p.get("binary").and_then(Value::as_str).unwrap_or("")), "", path)
            .observation_point("host");
        if let Some(sock) = args.iter().find_map(|a| a.get("sock_arg")) {
            b = b.dst(sock.get("daddr").and_then(Value::as_str).unwrap_or(""), sock.get("dport").and_then(Value::as_u64).unwrap_or(0) as u32, "");
        }
        if !policy.is_empty() {
            b = b.engine_alert(&format!("tetragon:{policy}"), if action.contains("SIGKILL") || action.contains("OVERRIDE") { 0.95 } else { 0.7 }).attr("kernel_action", action);
        }
        return Some(b.build());
    }
    None
}

#[cfg(test)]
mod tests {
    #[test]
    fn exec_and_kprobe() {
        let exec = r#"{"process_exec":{"process":{"pid":77,"binary":"/bin/sh","arguments":"-c id","pod":{"name":"web-1","workload":"web"}},"parent":{"binary":"/usr/sbin/php-fpm"}},"node_name":"n1","time":"2026-11-19T02:15:00Z"}"#;
        let ev = super::super::parse("tetragon", exec, 1, 0).unwrap();
        assert_eq!(ev.process.as_ref().unwrap().name, "sh");
        assert_eq!(ev.process.as_ref().unwrap().parent_name, "php-fpm");
        let kp = r#"{"process_kprobe":{"process":{"pid":77,"binary":"/usr/bin/cat"},"function_name":"security_file_permission","args":[{"file_arg":{"path":"/etc/shadow"}}],"action":"KPROBE_ACTION_SIGKILL","policy_name":"block-secret-reads"},"node_name":"n1"}"#;
        let ev = super::super::parse("tetragon", kp, 2, 0).unwrap();
        assert_eq!(ev.activity_name, "file.read");
        assert_eq!(ev.ext().engine_alerts, vec!["tetragon:block-secret-reads"]);
    }
}
