//! HTTP API.
//!
//! Sensors: POST /v1/events, POST /v1/adapters/{engine}, GET /v1/policy/bundle,
//! POST /v1/sink-decisions. Operators: incidents, replays, drift, approvals,
//! policy upload. Health and Prometheus metrics. Operator routes expect the
//! staff SSO proxy in front to set X-Ivar-Operator, X-Ivar-Roles and
//! X-Ivar-Hardware-2fa after hardware backed 2FA.

use crate::state::{now_ms, AppState};
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use ivar_contracts::{EntityRef, SecurityEvent};
use ivar_core::evidence::EvidenceStore;
use ivar_replay::{build_replay, ReplayRequest};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

type S = State<Arc<AppState>>;

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/metrics", get(metrics))
        .route("/v1/events", post(events))
        .route("/v1/verdicts", get(verdicts))
        .route("/v1/adapters/{engine}", post(adapter))
        .route("/v1/sink-decisions", post(sink_decision))
        .route("/v1/policy/bundle", get(policy_bundle))
        .route("/v1/policy", post(policy_upload))
        .route("/v1/incidents", get(incidents))
        .route("/v1/incidents/{id}", get(incident))
        .route("/v1/incidents/{id}/replay", get(replay))
        .route("/v1/drift", get(drift))
        .route("/v1/approvals", get(approvals))
        .route("/v1/approvals/{id}", post(approve))
        .route("/v1/evidence", get(evidence))
        .with_state(state)
}

/// The API plus the operator console at /console/ when `console_dir` is set.
/// The console is static and talks only to this origin; a strict content
/// security policy keeps it that way.
pub fn router_with_console(state: Arc<AppState>, console_dir: Option<&str>) -> Router {
    let api = router(state);
    let Some(dir) = console_dir else { return api };
    use axum::http::{header, HeaderValue};
    use tower_http::set_header::SetResponseHeaderLayer;
    let console = tower_http::services::ServeDir::new(dir).append_index_html_on_directories(true);
    let csp = HeaderValue::from_static("default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'");
    api.nest_service(
        "/console",
        tower::ServiceBuilder::new()
            .layer(SetResponseHeaderLayer::overriding(header::CONTENT_SECURITY_POLICY, csp))
            .layer(SetResponseHeaderLayer::overriding(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff")))
            .layer(SetResponseHeaderLayer::overriding(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer")))
            .service(console),
    )
}

fn err(code: StatusCode, msg: impl ToString) -> Response {
    (code, Json(json!({ "error": msg.to_string() }))).into_response()
}

#[derive(Deserialize)]
struct Batch {
    #[serde(default)]
    sensor_id: String,
    #[serde(default)]
    events: Vec<Value>,
    /// The sensor's position in the verdict feed; see crate::feed.
    #[serde(default)]
    verdict_cursor: Option<u64>,
}

#[derive(Deserialize)]
struct Since {
    #[serde(default)]
    since: u64,
}

fn bearer(h: &HeaderMap) -> Option<&str> {
    h.get(axum::http::header::AUTHORIZATION).and_then(|v| v.to_str().ok())
}

/// A sensor request the access rules refuse, as an HTTP response.
fn denied(s: &AppState, d: crate::access::Denied) -> Response {
    s.inner.lock().expect("state").metrics.ingest_denied_total += 1;
    match d {
        crate::access::Denied::Unauthenticated => err(StatusCode::UNAUTHORIZED, "a valid sensor token is required"),
        crate::access::Denied::Forbidden(id) => err(StatusCode::FORBIDDEN, format!("this token may not send events for sensor {id}")),
    }
}

fn http_client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| reqwest::Client::builder().timeout(std::time::Duration::from_secs(5)).build().expect("http client"))
}

async fn events(State(s): S, h: HeaderMap, Json(b): Json<Batch>) -> Response {
    let mut evs = Vec::new();
    let mut rejected = 0u64;
    for e in b.events {
        match serde_json::from_value::<SecurityEvent>(e) {
            Ok(ev) if !ev.activity_name.is_empty() => evs.push(ev),
            _ => rejected += 1,
        }
    }
    let ids: Vec<String> = std::iter::once(b.sensor_id.clone()).filter(|x| !x.is_empty()).chain(evs.iter().map(|e| e.ext().sensor_id)).collect();
    if let Err(d) = s.access.sensor(bearer(&h), ids.iter().map(String::as_str)) {
        return denied(&s, d);
    }
    if rejected > 0 {
        s.inner.lock().expect("state").metrics.events_rejected_total += rejected;
    }
    // Events another shard owns go to it; a forwarded batch is never sent on.
    let forwarded = h.contains_key(crate::access::FORWARDED_HEADER);
    let mut by_shard: BTreeMap<u32, Vec<SecurityEvent>> = BTreeMap::new();
    if s.shards > 1 && !forwarded && !s.access.peers.is_empty() {
        let mine;
        (mine, evs) = evs.into_iter().partition(|e| crate::shard_of(e, s.shards) == s.shard);
        for e in evs {
            by_shard.entry(crate::shard_of(&e, s.shards)).or_default().push(e);
        }
        evs = mine;
    }
    let peer_calls = by_shard.into_iter().map(|(shard, batch)| {
        let url = format!("{}/v1/events", s.access.peers[shard as usize]);
        let auth = bearer(&h).map(str::to_string);
        let body = json!({ "sensor_id": b.sensor_id, "events": batch });
        let n = batch_len(&body);
        async move {
            let mut req = http_client().post(url).header(crate::access::FORWARDED_HEADER, "1").json(&body);
            if let Some(a) = auth {
                req = req.header(axum::http::header::AUTHORIZATION, a);
            }
            match req.send().await {
                Ok(r) if r.status().is_success() => r.json::<Value>().await.map_err(|_| n),
                _ => Err(n),
            }
        }
    });
    let calls: Vec<_> = peer_calls.map(tokio::spawn).collect();
    let st = s.clone();
    let cursor = b.verdict_cursor;
    let (mut accepted, mut verdicts, next) = tokio::task::spawn_blocking(move || st.ingest_with_feed(evs, cursor)).await.unwrap_or_default();
    let mut unrouted = 0u64;
    for call in calls {
        match call.await.unwrap_or(Err(0)) {
            Ok(v) => {
                accepted += v["accepted"].as_u64().unwrap_or(0);
                verdicts.extend(v["verdicts"].as_array().cloned().unwrap_or_default().into_iter().filter_map(|x| serde_json::from_value(x).ok()));
            }
            Err(n) => unrouted += n,
        }
    }
    if unrouted > 0 {
        s.inner.lock().expect("state").metrics.events_unrouted_total += unrouted;
        tracing::warn!(unrouted, "events for an unreachable shard were not processed");
    }
    Json(json!({ "accepted": accepted, "rejected": rejected, "unrouted": unrouted, "verdicts": verdicts, "verdict_cursor": next })).into_response()
}

fn batch_len(body: &Value) -> u64 {
    body["events"].as_array().map(|a| a.len() as u64).unwrap_or(0)
}

/// Standing verdicts for a sensor that has no events to send.
async fn verdicts(State(s): S, h: HeaderMap, Query(q): Query<Since>) -> Response {
    if let Err(d) = s.access.sensor(bearer(&h), std::iter::empty()) {
        return denied(&s, d);
    }
    let (verdicts, next) = s.verdicts_since(q.since);
    Json(json!({ "accepted": 0, "verdicts": verdicts, "verdict_cursor": next })).into_response()
}

async fn adapter(State(s): S, h: HeaderMap, Path(engine): Path<String>, body: String) -> Response {
    let now = now_ms();
    let evs: Vec<SecurityEvent> = body.lines().enumerate().filter_map(|(i, l)| crate::adapters::parse(&engine, l, now as u64 + i as u64, now)).collect();
    let ids: Vec<String> = evs.iter().map(|e| e.ext().sensor_id).collect();
    if let Err(d) = s.access.sensor(bearer(&h), ids.iter().map(String::as_str)) {
        return denied(&s, d);
    }
    if evs.is_empty() && !body.trim().is_empty() {
        return err(StatusCode::BAD_REQUEST, format!("no {engine} events recognised"));
    }
    let st = s.clone();
    let (accepted, verdicts) = tokio::task::spawn_blocking(move || st.ingest(evs)).await.unwrap_or_default();
    Json(json!({ "accepted": accepted, "verdicts": verdicts })).into_response()
}

#[derive(Deserialize)]
struct SinkReport {
    subject: EntityRef,
    decision: Value,
}

async fn sink_decision(State(s): S, h: HeaderMap, Json(r): Json<SinkReport>) -> Response {
    if let Err(d) = s.access.sensor(bearer(&h), std::iter::empty()) {
        return denied(&s, d);
    }
    let id = s.record_sink(r.subject, r.decision);
    Json(json!({ "incident": id })).into_response()
}

#[derive(Deserialize)]
struct Have {
    #[serde(default)]
    have: u64,
}

async fn policy_bundle(State(s): S, Query(q): Query<Have>) -> Response {
    let g = s.inner.lock().expect("state");
    if g.core.policy().version <= q.have {
        return StatusCode::NO_CONTENT.into_response();
    }
    g.policy_archive_b64.clone().into_response()
}

fn operator(h: &HeaderMap) -> Option<(String, Vec<String>, bool)> {
    let op = h.get("x-ivar-operator")?.to_str().ok()?.to_string();
    let roles = h.get("x-ivar-roles").and_then(|v| v.to_str().ok()).unwrap_or("").split(',').map(|r| r.trim().to_string()).filter(|r| !r.is_empty()).collect();
    let hw = h.get("x-ivar-hardware-2fa").and_then(|v| v.to_str().ok()) == Some("true");
    Some((op, roles, hw))
}

fn authorize(s: &AppState, h: &HeaderMap, action: &str, target: &str) -> Result<String, Response> {
    if !s.access.operator_proxy(h.get(crate::access::PROXY_TOKEN_HEADER).and_then(|v| v.to_str().ok())) {
        return Err(err(StatusCode::UNAUTHORIZED, "operator requests must come through the staff SSO proxy"));
    }
    let Some((op, roles, hw)) = operator(h) else { return Err(err(StatusCode::UNAUTHORIZED, "operator identity required")) };
    let req = ivar_core::policy::OperatorRequest { operator: op.clone(), roles, action: action.into(), target: target.into(), approvers: 1, destructive_or_fleet_wide: false, hardware_2fa: hw };
    let ok = s.inner.lock().expect("state").cedar.allow_operator(&req).unwrap_or(false);
    if ok {
        Ok(op)
    } else {
        Err(err(StatusCode::FORBIDDEN, format!("{op} may not {action}")))
    }
}

async fn policy_upload(State(s): S, h: HeaderMap, body: String) -> Response {
    if let Err(r) = authorize(&s, &h, "set_posture", "policy") {
        return r;
    }
    match s.update_policy(&body) {
        Ok(v) => Json(json!({ "applied": v })).into_response(),
        Err(e) => err(StatusCode::UNPROCESSABLE_ENTITY, format!("rejected, current policy kept: {e}")),
    }
}

async fn incidents(State(s): S, h: HeaderMap) -> Response {
    if let Err(r) = authorize(&s, &h, "read", "incidents") {
        return r;
    }
    let g = s.inner.lock().expect("state");
    Json(json!(g.core.incidents().all().collect::<Vec<_>>())).into_response()
}

async fn incident(State(s): S, h: HeaderMap, Path(id): Path<String>) -> Response {
    if let Err(r) = authorize(&s, &h, "read", &id) {
        return r;
    }
    let g = s.inner.lock().expect("state");
    match g.core.incidents().get(&id) {
        Some(i) => Json(json!(i)).into_response(),
        None => err(StatusCode::NOT_FOUND, "unknown incident"),
    }
}

#[derive(Deserialize)]
struct ReplayQuery {
    #[serde(default)]
    counterfactual_policy_version: Option<u64>,
}

async fn replay(State(s): S, h: HeaderMap, Path(id): Path<String>, Query(q): Query<ReplayQuery>) -> Response {
    if let Err(r) = authorize(&s, &h, "replay", &id) {
        return r;
    }
    let (records, history, keys, live) = {
        let g = s.inner.lock().expect("state");
        let Some(inc) = g.core.incidents().get(&id) else { return err(StatusCode::NOT_FOUND, "unknown incident") };
        let keys: BTreeSet<String> = inc.affected_entities.iter().map(|e| e.key()).collect();
        let first = g.policy_history.values().next().cloned().expect("policy history");
        (g.core.evidence().records(), g.policy_history.clone(), keys, first)
    };
    let st = s.clone();
    let result = tokio::task::spawn_blocking(move || {
        let later: BTreeMap<u64, _> = history.iter().filter(|(v, _)| **v != live.version).map(|(k, v)| (*k, v.clone())).collect();
        let cf = q.counterfactual_policy_version.and_then(|v| history.get(&v).cloned());
        let layers: Vec<&str> = st.expected_layers.iter().map(String::as_str).collect();
        build_replay(&ReplayRequest {
            records: &records,
            live_policy: &live,
            counterfactual_policy: cf.as_ref(),
            incident_id: &id,
            entity_keys: keys,
            keyring: Some(&st.keyring),
            redaction_key: st.redaction_key.clone(),
            expected_layers: layers,
            signer: Some(&st.replay_key),
            policy_history: later,
        })
    })
    .await;
    match result {
        Ok(Ok(b)) => Json(json!(b)).into_response(),
        Ok(Err(e)) => err(StatusCode::CONFLICT, format!("replay halted: {e}")),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

async fn drift(State(s): S, h: HeaderMap) -> Response {
    if let Err(r) = authorize(&s, &h, "read", "drift") {
        return r;
    }
    Json(json!(s.inner.lock().expect("state").core.drift_report())).into_response()
}

async fn approvals(State(s): S, h: HeaderMap) -> Response {
    if let Err(r) = authorize(&s, &h, "read", "approvals") {
        return r;
    }
    Json(json!(s.inner.lock().expect("state").pending)).into_response()
}

async fn approve(State(s): S, h: HeaderMap, Path(id): Path<String>) -> Response {
    let Some((op, roles, hw)) = operator(&h) else { return err(StatusCode::UNAUTHORIZED, "operator identity required") };
    match s.approve(&id, &op, roles, hw) {
        Ok(m) => Json(json!({ "status": m })).into_response(),
        Err(e) => err(StatusCode::FORBIDDEN, e),
    }
}

#[derive(Deserialize)]
struct From {
    #[serde(default)]
    from_seq: u64,
}

async fn evidence(State(s): S, h: HeaderMap, Query(q): Query<From>) -> Response {
    if let Err(r) = authorize(&s, &h, "read", "evidence") {
        return r;
    }
    let g = s.inner.lock().expect("state");
    let recs: Vec<_> = g.core.evidence().records().into_iter().filter(|r| r.seq >= q.from_seq).collect();
    Json(json!(recs)).into_response()
}

async fn metrics(State(s): S) -> Response {
    let m = s.inner.lock().expect("state").metrics.clone();
    let mut out = format!(
        "# TYPE ivar_events_total counter\nivar_events_total {}\n# TYPE ivar_actions_total counter\nivar_actions_total {}\n# TYPE ivar_ingest_seconds_total counter\nivar_ingest_seconds_total {}\n# TYPE ivar_policy_rejected_total counter\nivar_policy_rejected_total {}\n# TYPE ivar_verdicts_total counter\n",
        m.events_total, m.actions_total, m.ingest_micros_total as f64 / 1e6, m.policy_rejected_total
    );
    out.push_str(&format!(
        "# TYPE ivar_events_rejected_total counter\nivar_events_rejected_total {}\n# TYPE ivar_events_unrouted_total counter\nivar_events_unrouted_total {}\n# TYPE ivar_ingest_denied_total counter\nivar_ingest_denied_total {}\n",
        m.events_rejected_total, m.events_unrouted_total, m.ingest_denied_total
    ));
    for (d, n) in m.verdicts_by_decision {
        out.push_str(&format!("ivar_verdicts_total{{decision=\"{d}\"}} {n}\n"));
    }
    out.into_response()
}
