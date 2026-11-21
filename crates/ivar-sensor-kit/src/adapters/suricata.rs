//! Suricata EVE JSON (alert, dns, tls, flow) to OCSF.

use ivar_contracts::SecurityEvent;
use ivar_core::detect::vocabulary as v;
use ivar_core::sensor::{ocsf_class, EventBuilder};
use serde_json::Value;

pub fn map(e: &Value, seq: u64, now: i64) -> Option<SecurityEvent> {
    let kind = e.get("event_type")?.as_str()?;
    let time = e.get("timestamp").and_then(Value::as_str).map(|t| t.replace("+0000", "Z")).and_then(|t| super::rfc3339_ms(&t)).unwrap_or(now);
    let s = |k: &str| e.get(k).and_then(Value::as_str).unwrap_or("").to_string();
    let port = |k: &str| e.get(k).and_then(Value::as_u64).unwrap_or(0) as u32;
    let sensor = format!("suricata@{}", s("host"));
    let base = |class, act| {
        EventBuilder::new(class, act, time, &sensor, "suricata", seq).src_ip(&s("src_ip")).dst(&s("dest_ip"), port("dest_port"), "").observation_point("network").attr("flow_id", &e.get("flow_id").map(|f| f.to_string()).unwrap_or_default())
    };
    let ev = match kind {
        "alert" => {
            let a = e.get("alert")?;
            let sid = a.get("signature_id").and_then(Value::as_u64).unwrap_or(0);
            let sev = a.get("severity").and_then(Value::as_u64).unwrap_or(3);
            let conf = match sev {
                1 => 0.9,
                2 => 0.7,
                _ => 0.5,
            };
            let mut b = base(ocsf_class::DETECTION_FINDING, v::ENGINE_ALERT).engine_alert(&format!("suricata:{sid}"), conf);
            if a.get("action").and_then(Value::as_str) == Some("blocked") {
                b = b.attr("inline_action", "blocked");
            }
            let mut ev = b.build();
            ev.message = a.get("signature").and_then(Value::as_str).unwrap_or("").into();
            ev
        }
        "dns" => base(ocsf_class::DNS_ACTIVITY, v::DNS_QUERY).attr("query", e.pointer("/dns/rrname").and_then(Value::as_str).unwrap_or("")).build(),
        "tls" => base(ocsf_class::NETWORK_ACTIVITY, v::NET_CONNECT).attr("sni", e.pointer("/tls/sni").and_then(Value::as_str).unwrap_or("")).egress(e.pointer("/tls/sni").and_then(Value::as_str).unwrap_or("")).build(),
        "flow" => base(ocsf_class::NETWORK_ACTIVITY, v::NET_CONNECT).records(e.pointer("/flow/bytes_toserver").and_then(Value::as_u64).unwrap_or(0)).build(),
        _ => return None,
    };
    Some(ev)
}

#[cfg(test)]
mod tests {
    #[test]
    fn alert_and_dns() {
        let a = r#"{"timestamp":"2026-11-19T02:15:00.000000+0000","event_type":"alert","src_ip":"203.0.113.5","dest_ip":"10.0.0.4","dest_port":443,"alert":{"signature_id":2030000,"signature":"ET EXPLOIT","severity":1}}"#;
        let ev = super::super::parse("suricata", a, 1, 0).unwrap();
        assert_eq!(ev.ext().engine_alerts, vec!["suricata:2030000"]);
        let d = r#"{"event_type":"dns","src_ip":"10.0.0.4","dest_ip":"10.0.0.2","dns":{"rrname":"x.example"}}"#;
        assert_eq!(super::super::parse("suricata", d, 2, 0).unwrap().activity_name, "dns.query");
    }
}
