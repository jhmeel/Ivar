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

fn err(code: StatusCode, msg: impl ToString) -> Response {
    (code, Json(json!({ "error": msg.to_string() }))).into_response()
}

#[derive(Deserialize)]
struct Batch {
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

async fn events(State(s): S, Json(b): Json<Batch>) -> Response {
    let mut evs = Vec::new();
    for e in b.events {
        if let Ok(ev) = serde_json::from_value::<SecurityEvent>(e) {
            if ev.activity_name == "sensor.heartbeat" || !ev.activity_name.is_empty() {
                evs.push(ev);
            }
        }
    }
    let st = s.clone();
    let cursor = b.verdict_cursor;
    let (accepted, verdicts, next) = tokio::task::spawn_blocking(move || st.ingest_with_feed(evs, cursor)).await.unwrap_or_default();
    Json(json!({ "accepted": accepted, "verdicts": verdicts, "verdict_cursor": next })).into_response()
}

/// Standing verdicts for a sensor that has no events to send.
async fn verdicts(State(s): S, Query(q): Query<Since>) -> Response {
    let (verdicts, next) = s.verdicts_since(q.since);
    Json(json!({ "accepted": 0, "verdicts": verdicts, "verdict_cursor": next })).into_response()
}

async fn adapter(State(s): S, Path(engine): Path<String>, body: String) -> Response {
    let now = now_ms();
    let evs: Vec<SecurityEvent> = body.lines().enumerate().filter_map(|(i, l)| crate::adapters::parse(&engine, l, now as u64 + i as u64, now)).collect();
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

async fn sink_decision(State(s): S, Json(r): Json<SinkReport>) -> Response {
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
    for (d, n) in m.verdicts_by_decision {
        out.push_str(&format!("ivar_verdicts_total{{decision=\"{d}\"}} {n}\n"));
    }
    out.into_response()
}
