//! Who may talk to the core: sensor tokens, the operator proxy token, and
//! shard forwarding, end to end over HTTP.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ivar_contracts::sign::{sign_policy, KeyPair, Keyring};
use ivar_core::policy::spec_default_policy;
use ivar_server::access::{token_sha256, Access, SensorToken};
use ivar_server::responders::Responders;
use ivar_server::state::{AppState, StartOptions};
use ivar_server::store::FileEvidenceStore;
use serde_json::{json, Value};
use std::sync::Arc;

fn start(dir: &std::path::Path, access: Access, shard: u32, shards: u32) -> Arc<AppState> {
    let policy_key = KeyPair::ed25519_from_seed("policy-1", [1; 32]);
    let evidence_key = KeyPair::ed25519_from_seed(&format!("evidence-{shard}"), [2; 32]);
    let mut ring = Keyring::default();
    ring.add(policy_key.public(), &["policy"]);
    ring.add(evidence_key.public(), &["evidence"]);
    let mut p = spec_default_policy(0);
    p.version = 1;
    p.policy_version = "test-1".into();
    p.expires_at = i64::MAX / 2;
    AppState::start(StartOptions {
        evidence: FileEvidenceStore::open(&dir.join(format!("evidence-{shard}.jsonl"))).unwrap(),
        policy_archive_b64: B64.encode(sign_policy(&p, &[&policy_key]).unwrap().to_archive().unwrap()),
        keyring: ring,
        evidence_key,
        redaction_key: vec![7; 16],
        public_url: "https://ivar.test".into(),
        expected_layers: vec!["app_sdk".into()],
        sinks: vec![],
        responders: Responders::empty(KeyPair::ed25519_from_seed("action-0", [3; 32])),
        shard,
        shards,
        policy_dir: None,
        access,
    })
    .unwrap()
}

/// Serve a state on a free local port; returns its base URL.
async fn serve(state: Arc<AppState>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, ivar_server::http::router(state)).await.unwrap() });
    url
}

fn event(sensor: &str, ip: &str, seq: u64, path: &str) -> Value {
    json!({
        "class_uid": 4002, "category_uid": 4, "activity_id": 1, "activity_name": "http.request", "time": 1_795_000_000_000u64, "status_id": 1,
        "src_endpoint": { "ip": ip }, "http_request": { "http_method": "GET", "url_path": path },
        "ivar": { "sensor_id": sensor, "sensor_type": "app_sdk", "observation_point": "app_sdk", "sensor_seq": seq }
    })
}

async fn post(url: &str, token: Option<&str>, body: Value, headers: &[(&str, &str)]) -> (u16, Value) {
    let mut req = reqwest::Client::new().post(url).json(&body);
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let res = req.send().await.unwrap();
    (res.status().as_u16(), res.json().await.unwrap_or(Value::Null))
}

async fn get(url: &str, headers: &[(&str, &str)]) -> u16 {
    let mut req = reqwest::Client::new().get(url);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    req.send().await.unwrap().status().as_u16()
}

#[tokio::test]
async fn forged_events_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let shop = ivar_server::access::new_token();
    let access = Access::new(Some(vec![SensorToken { name: "shop".into(), sha256: token_sha256(&shop), sensors: vec!["shop-*".into()] }]), None, vec![]);
    let url = serve(start(dir.path(), access, 0, 1)).await;
    let decoy = |sensor: &str| json!({ "sensor_id": sensor, "events": [event(sensor, "203.0.113.20", 1, "/.env.backup")] });

    let (s, _) = post(&format!("{url}/v1/events"), None, decoy("shop-node"), &[]).await;
    assert_eq!(s, 401, "no token: an outsider cannot send events");
    let (s, _) = post(&format!("{url}/v1/events"), Some("ivt_guessed"), decoy("shop-node"), &[]).await;
    assert_eq!(s, 401, "a made up token is refused");
    let (s, b) = post(&format!("{url}/v1/events"), Some(&shop), decoy("edge-1"), &[]).await;
    assert_eq!(s, 403, "a shop token cannot speak for the edge: {b}");
    let mixed = json!({ "sensor_id": "shop-node", "events": [event("shop-node", "203.0.113.20", 1, "/"), event("edge-1", "203.0.113.20", 2, "/.env.backup")] });
    let (s, _) = post(&format!("{url}/v1/events"), Some(&shop), mixed, &[]).await;
    assert_eq!(s, 403, "one foreign sensor id in a batch refuses the batch");
    let (s, b) = post(&format!("{url}/v1/events"), Some(&shop), decoy("shop-node"), &[]).await;
    assert_eq!((s, b["accepted"].as_u64()), (200, Some(1)), "the shop's own token works");
    assert_eq!(get(&format!("{url}/v1/verdicts?since=0"), &[]).await, 401, "the verdict feed needs a token too");
}

#[tokio::test]
async fn operator_headers_need_the_proxy_token() {
    let dir = tempfile::tempdir().unwrap();
    let proxy = ivar_server::access::new_token();
    let digest: [u8; 32] = hex::decode(token_sha256(&proxy)).unwrap().try_into().unwrap();
    let url = serve(start(dir.path(), Access::new(None, Some(digest), vec![]), 0, 1)).await;
    let spoof = [("x-ivar-operator", "mallory"), ("x-ivar-roles", "admin,analyst"), ("x-ivar-hardware-2fa", "true")];
    assert_eq!(get(&format!("{url}/v1/evidence?from_seq=0"), &spoof).await, 401, "headers alone are not believed");
    let wrong = [spoof[0], spoof[1], spoof[2], ("x-ivar-proxy-token", "guess")];
    assert_eq!(get(&format!("{url}/v1/evidence?from_seq=0"), &wrong).await, 401, "nor with a wrong proxy token");
    let through_proxy = [("x-ivar-operator", "alice"), ("x-ivar-roles", "analyst"), ("x-ivar-hardware-2fa", "true"), ("x-ivar-proxy-token", proxy.as_str())];
    assert_eq!(get(&format!("{url}/v1/evidence?from_seq=0"), &through_proxy).await, 200, "through the proxy an analyst reads evidence");
}

#[tokio::test]
async fn every_shard_processes_what_it_owns_wherever_events_arrive() {
    let dir = tempfile::tempdir().unwrap();
    // Bind first, so every shard knows every peer's URL before it starts.
    let listeners: Vec<_> = bind_listeners(3).await;
    let peers: Vec<String> = listeners.iter().map(|l| format!("http://{}", l.local_addr().unwrap())).collect();
    let mut states = Vec::new();
    for (n, listener) in listeners.into_iter().enumerate() {
        let state = start(dir.path(), Access::new(None, None, peers.clone()), n as u32, 3);
        states.push(state.clone());
        tokio::spawn(async move { axum::serve(listener, ivar_server::http::router(state)).await.unwrap() });
    }
    let events: Vec<Value> = (0..30).map(|i| event("lb-test", &format!("10.9.0.{i}"), i + 1, "/accounts/u1")).collect();
    let (s, b) = post(&format!("{}/v1/events", peers[0]), None, json!({ "sensor_id": "lb-test", "events": events }), &[]).await;
    assert_eq!(s, 200);
    assert_eq!(b["accepted"].as_u64(), Some(30), "every event processed by its owner: {b}");
    assert_eq!(b["unrouted"].as_u64(), Some(0));
    let per_shard: Vec<u64> = states.iter().map(|st| st.inner.lock().unwrap().metrics.events_total).collect();
    assert_eq!(per_shard.iter().sum::<u64>(), 30, "each event processed exactly once: {per_shard:?}");
    assert!(per_shard.iter().all(|n| *n > 0), "and spread over every shard: {per_shard:?}");
}

async fn bind_listeners(n: usize) -> Vec<tokio::net::TcpListener> {
    let mut out = Vec::new();
    for _ in 0..n {
        out.push(tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap());
    }
    out
}
