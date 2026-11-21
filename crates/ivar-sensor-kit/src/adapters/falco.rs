//! Falco JSON output (json_output: true) to OCSF.

use ivar_contracts::SecurityEvent;
use ivar_core::detect::vocabulary as v;
use ivar_core::sensor::{ocsf_class, EventBuilder};
use serde_json::Value;

fn confidence(priority: &str) -> f64 {
    match priority.to_ascii_lowercase().as_str() {
        "emergency" | "alert" | "critical" => 0.9,
        "error" => 0.8,
        "warning" => 0.6,
        "notice" => 0.4,
        _ => 0.2,
    }
}

pub fn map(e: &Value, seq: u64, now: i64) -> Option<SecurityEvent> {
    let rule = e.get("rule")?.as_str()?;
    let f = e.get("output_fields").cloned().unwrap_or(Value::Null);
    let s = |k: &str| f.get(k).and_then(|x| x.as_str().map(String::from).or_else(|| x.as_u64().map(|n| n.to_string()))).unwrap_or_default();
    let time = e.get("time").and_then(Value::as_str).and_then(super::rfc3339_ms).unwrap_or(now);
    let host = e.get("hostname").and_then(Value::as_str).unwrap_or("").to_string();
    let fd = s("fd.name");
    let (class, activity) = if !fd.is_empty() && (s("evt.type").contains("open") || rule.to_lowercase().contains("read")) {
        (ocsf_class::FILE_ACTIVITY, v::FILE_READ)
    } else if s("evt.type").contains("connect") {
        (ocsf_class::NETWORK_ACTIVITY, v::NET_CONNECT)
    } else {
        (ocsf_class::PROCESS_ACTIVITY, v::PROCESS_START)
    };
    let rule_id = format!("falco:{}", rule.to_lowercase().replace(' ', "_"));
    let pid = s("proc.pid").parse().unwrap_or(0);
    let mut b = EventBuilder::new(class, activity, time, &format!("falco@{host}"), "falco", seq)
        .device(&s("container.id"), &host, if s("k8s.pod.name").is_empty() { "server" } else { "pod" })
        .process(pid, &s("proc.name"), &s("proc.pname"), &fd)
        .engine_alert(&rule_id, confidence(e.get("priority").and_then(Value::as_str).unwrap_or("")))
        .attr("workload", &s("k8s.deployment.name"))
        .observation_point("host");
    if !s("user.name").is_empty() {
        b = b.user(&s("user.name"), "service");
    }
    if activity == v::NET_CONNECT {
        let ip = s("fd.sip");
        b = b.dst(&ip, s("fd.sport").parse().unwrap_or(0), "");
    }
    let mut ev = b.build();
    ev.message = e.get("output").and_then(Value::as_str).unwrap_or("").chars().take(512).collect();
    Some(ev)
}

#[cfg(test)]
mod tests {
    #[test]
    fn terminal_shell_in_container() {
        let line = r#"{"hostname":"node-1","output":"A shell was spawned","priority":"Notice","rule":"Terminal shell in container","time":"2026-11-19T02:15:00.000000000Z","output_fields":{"container.id":"abc","proc.name":"bash","proc.pname":"php-fpm","proc.pid":4242,"user.name":"www-data","k8s.pod.name":"web-1"}}"#;
        let ev = super::super::parse("falco", line, 1, 0).unwrap();
        assert_eq!(ev.activity_name, "process.start");
        assert_eq!(ev.process.as_ref().unwrap().parent_name, "php-fpm");
        assert_eq!(ev.ext().engine_alerts, vec!["falco:terminal_shell_in_container"]);
    }
}
