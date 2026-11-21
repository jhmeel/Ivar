//! OCSF events carried as OpenTelemetry logs (OTLP/HTTP JSON), where an
//! OpenTelemetry pipeline exists.

use super::{http, Outbound, Sink};
use serde_json::json;

pub struct OtlpLogs {
    endpoint: String,
    client: reqwest::blocking::Client,
}

impl OtlpLogs {
    pub fn new(endpoint: &str) -> Self {
        OtlpLogs { endpoint: format!("{}/v1/logs", endpoint.trim_end_matches('/')), client: http() }
    }

    pub fn body(item: &Outbound, now_nanos: u128) -> serde_json::Value {
        let (event_name, payload) = match item {
            Outbound::Event { ocsf } => ("ocsf.event", ocsf.clone()),
            Outbound::Verdict { verdict } => ("ivar.verdict", verdict.clone()),
            Outbound::Incident { incident } => ("ivar.incident", incident.clone()),
            other => ("ivar.notice", serde_json::to_value(other).unwrap_or_default()),
        };
        json!({
            "resourceLogs": [{
                "resource": { "attributes": [{ "key": "service.name", "value": { "stringValue": "ivar-core" } }] },
                "scopeLogs": [{
                    "scope": { "name": "ivar" },
                    "logRecords": [{
                        "timeUnixNano": now_nanos.to_string(),
                        "severityText": "INFO",
                        "eventName": event_name,
                        "body": { "stringValue": payload.to_string() },
                        "attributes": [{ "key": "ocsf.class_uid", "value": { "intValue": payload.get("class_uid").and_then(|v| v.as_i64()).unwrap_or(0).to_string() } }]
                    }]
                }]
            }]
        })
    }
}

impl Sink for OtlpLogs {
    fn name(&self) -> &str {
        "otlp_logs"
    }
    fn send(&mut self, item: &Outbound) -> Result<(), String> {
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        self.client.post(&self.endpoint).json(&Self::body(item, now)).send().map_err(|e| e.to_string())?.error_for_status().map(|_| ()).map_err(|e| e.to_string())
    }
}
