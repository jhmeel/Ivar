//! One sealed evidence record.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// A SecurityEvent as received: the input the replay re executes.
    Event,
    Finding,
    Risk,
    Verdict,
    ActionRequest,
    ActionReceipt,
    EdgeChange,
    Incident,
    Policy,
    Custody,
    SinkDecision,
    Tamper,
    /// A gap: an interval where no sensor observed this layer.
    Gap,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CustodyEntry {
    pub actor: String,
    pub action: String,
    pub time: i64,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvidenceRecord {
    pub seq: u64,
    pub evidence_id: String,
    pub time: i64,
    pub kind: EvidenceKind,
    pub incident_hint: String,
    pub payload: serde_json::Value,
    pub prev_hash: String,
    pub hash: String,
    pub signature: Option<ivar_contracts::BundleSignature>,
}

impl EvidenceRecord {
    /// The bytes the hash covers.
    pub fn digest_input(seq: u64, time: i64, kind: EvidenceKind, prev_hash: &str, payload: &serde_json::Value) -> Vec<u8> {
        let kind = serde_json::to_string(&kind).unwrap_or_default();
        let payload = serde_json::to_string(payload).unwrap_or_default();
        format!("ivar.evidence.v1\n{seq}\n{time}\n{kind}\n{prev_hash}\n{payload}").into_bytes()
    }
}

/// Drop every field that holds its type's default (empty string, zero, false,
/// null, empty list or map). Event payloads are protobuf messages whose
/// fields all default when absent, so this loses nothing: the event reads
/// back identical. It roughly halves what each event costs on disk.
pub fn compact(value: serde_json::Value) -> serde_json::Value {
    use serde_json::Value;
    fn empty(v: &Value) -> bool {
        match v {
            Value::Null => true,
            Value::Bool(b) => !b,
            Value::Number(n) => n.as_f64() == Some(0.0),
            Value::String(s) => s.is_empty(),
            Value::Array(a) => a.is_empty(),
            Value::Object(o) => o.is_empty(),
        }
    }
    match value {
        // `attributes` is a protobuf map, not a message: an entry with an empty
        // value is still an entry, so its contents are kept as they are.
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(k, v)| if k == "attributes" { (k, v) } else { (k, compact(v)) })
                .filter(|(_, v)| !empty(v))
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(compact).collect()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use ivar_contracts::SecurityEvent;
    use serde_json::json;

    #[test]
    fn compact_events_read_back_identical() {
        let ev: SecurityEvent = serde_json::from_value(json!({
            "class_uid": 4002, "activity_name": "http.request", "time": 5, "status_id": 1,
            "src_endpoint": { "ip": "10.0.0.1" }, "actor": { "user": { "uid": "u1" } },
            "http_request": { "http_method": "GET", "url_path": "/a", "body_keys": ["x"] },
            "ivar": { "sensor_id": "s", "sensor_seq": 3, "attributes": { "k": "" }, "value_moved": 0.0 }
        }))
        .unwrap();
        let full = serde_json::to_value(&ev).unwrap();
        let small = super::compact(full.clone());
        assert!(small.to_string().len() * 2 < full.to_string().len(), "{small}");
        let back: SecurityEvent = serde_json::from_value(small).unwrap();
        assert_eq!(back, ev, "the event reads back identical, empty attribute values included");
    }
}
