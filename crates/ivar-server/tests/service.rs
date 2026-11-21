//! The core service end to end through its HTTP API.

use axum::body::Body;
use axum::http::{Request, StatusCode};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use http_body_util::BodyExt;
use ivar_contracts::sign::{sign_policy, KeyPair, Keyring};
use ivar_core::policy::spec_default_policy;
use ivar_server::responders::Responders;
use ivar_server::state::{AppState, StartOptions};
use ivar_server::store::FileEvidenceStore;
use serde_json::{json, Value};
use std::sync::Arc;
use tower::ServiceExt;

struct Fixture {
    state: Arc<AppState>,
    policy_key: KeyPair,
    _dir: tempfile::TempDir,
}

fn bundle(version: u64, keys: &[&KeyPair], enforce: bool) -> String {
    let mut p = spec_default_policy(0);
    p.version = version;
    p.policy_version = format!("test-{version}");
    p.expires_at = i64::MAX / 2;
    if enforce {
        p.settings.insert("detection_mode".into(), json!("enforce"));
    }
    B64.encode(sign_policy(&p, keys).unwrap().to_archive().unwrap())
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let policy_key = KeyPair::ed25519_from_seed("policy-1", [1; 32]);
    let evidence_key = KeyPair::ed25519_from_seed("evidence-0", [2; 32]);
    let action_key = KeyPair::ed25519_from_seed("action-0", [3; 32]);
    let mut ring = Keyring::default();
    ring.add(policy_key.public(), &["policy"]);
    ring.add(evidence_key.public(), &["evidence"]);
    let state = AppState::start(StartOptions {
        evidence: FileEvidenceStore::open(&dir.path().join("evidence.jsonl")).unwrap(),
        policy_archive_b64: bundle(1, &[&policy_key], true),
        keyring: ring,
        evidence_key,
        redaction_key: vec![7; 16],
        public_url: "https://ivar.test".into(),
        expected_layers: vec!["edge".into(), "app_sdk".into()],
        sinks: vec![],
        responders: Responders::empty(action_key),
        shard: 0,
        shards: 1,
    })
    .unwrap();
    Fixture { state, policy_key, _dir: dir }
}

async fn call(f: &Fixture, method: &str, uri: &str, body: Value, operator: Option<&str>) -> (StatusCode, Value) {
    let mut req = Request::builder().method(method).uri(uri).header("content-type", "application/json");
    if let Some(roles) = operator {
        req = req.header("x-ivar-operator", "alice").header("x-ivar-roles", roles).header("x-ivar-hardware-2fa", "true");
    }
    let body = if body.is_string() { Body::from(body.as_str().unwrap().to_string()) } else { Body::from(body.to_string()) };
    let res = ivar_server::http::router(f.state.clone()).oneshot(req.body(body).unwrap()).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    (status, serde_json::from_slice(&bytes).unwrap_or(Value::String(String::from_utf8_lossy(&bytes).to_string())))
}

#[tokio::test]
async fn ingest_incident_replay_and_operator_rules() {
    let f = fixture();
    let tool_call = json!({"activity_name": "ai.tool_call", "actor": {"user": {"uid": "support-bot", "type": "agent"}}, "ivar": {"sensor_id": "aigw-1", "sensor_type": "ai_gateway", "sensor_seq": 1, "attributes": {"tool": "export_all_customers"}}});
    let (s, ack) = call(&f, "POST", "/v1/events", json!({"sensor_id": "aigw-1", "events": [tool_call]}), None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(ack["verdicts"][0]["decision"], "contain");

    let falco = r#"{"hostname":"node-1","priority":"Critical","rule":"Terminal shell in container","time":"2026-11-19T02:15:00Z","output_fields":{"proc.name":"sh","proc.pname":"php-fpm","proc.pid":42}}"#;
    let (s, ack) = call(&f, "POST", "/v1/adapters/falco", json!(falco), None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(ack["accepted"], 1);

    let (s, _) = call(&f, "GET", "/v1/incidents", json!(null), None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "operator identity required");
    let (s, incidents) = call(&f, "GET", "/v1/incidents", json!(null), Some("analyst")).await;
    assert_eq!(s, StatusCode::OK);
    let id = incidents[0]["incident_id"].as_str().unwrap().to_string();

    let (s, bundle) = call(&f, "GET", &format!("/v1/incidents/{id}/replay"), json!(null), Some("analyst")).await;
    assert_eq!(s, StatusCode::OK, "{bundle}");
    assert_eq!(bundle["re_execution"]["matched"], true);
    assert!(bundle["frames"].as_array().unwrap().iter().all(|fr| !fr["evidence_ids"].as_array().unwrap().is_empty() || fr["kind"] == "gap"));

    let (s, _) = call(&f, "POST", "/v1/policy", json!(bundle_forged()), Some("analyst")).await;
    assert_eq!(s, StatusCode::FORBIDDEN, "analysts may not change policy");
}

fn bundle_forged() -> String {
    bundle(2, &[&KeyPair::ed25519_from_seed("policy-1", [9; 32])], true)
}

#[tokio::test]
async fn policy_updates_are_verified_and_rollback_refused() {
    let f = fixture();
    let (s, r) = call(&f, "POST", "/v1/policy", json!(bundle_forged()), Some("incident_lead")).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "{r}");
    let (s, r) = call(&f, "POST", "/v1/policy", json!(bundle(3, &[&f.policy_key], true)), Some("incident_lead")).await;
    assert_eq!(s, StatusCode::OK, "{r}");
    let (s, _) = call(&f, "POST", "/v1/policy", json!(bundle(2, &[&f.policy_key], true)), Some("incident_lead")).await;
    assert_eq!(s, StatusCode::UNPROCESSABLE_ENTITY, "rollback");
    let (s, b) = call(&f, "GET", "/v1/policy/bundle?have=1", json!(null), None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(b.as_str().unwrap().len() > 100);
    let (s, _) = call(&f, "GET", "/metrics", json!(null), None).await;
    assert_eq!(s, StatusCode::OK);
}

#[tokio::test]
async fn sink_reports_open_incidents() {
    let f = fixture();
    let (s, r) = call(&f, "POST", "/v1/sink-decisions", json!({"subject": {"type": "session", "id": "ses_1", "role": 1}, "decision": {"outcome": {"outcome": "refused", "reason": "no intent chain"}, "open_incident": true}}), None).await;
    assert_eq!(s, StatusCode::OK);
    assert!(r["incident"].is_string());
}
