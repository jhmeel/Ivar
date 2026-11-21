//! ivar-ai-gateway: proxy for MCP servers (POST /mcp) and model APIs (POST /v1/*).
//! The calling agent is identified by the X-Agent-Id header set by the agent
//! runtime; intent tokens travel in Ivar-Intent.

mod gateway;

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use gateway::{jsonrpc_error, Decision, Gateway, GatewayConfig};
use ivar_contracts::sign::Keyring;
use ivar_sensor_kit::{now_ms, HttpUplink, Sensor, SensorConfig};
use serde_json::Value;
use std::sync::{Arc, Mutex};

struct App {
    sensor: Arc<Sensor>,
    gateway: Mutex<Gateway>,
    http: reqwest::Client,
}

fn agent(h: &HeaderMap) -> String {
    h.get("x-agent-id").and_then(|v| v.to_str().ok()).unwrap_or("unknown-agent").to_string()
}

async fn mcp(State(app): State<Arc<App>>, h: HeaderMap, Json(req): Json<Value>) -> Response {
    let intent = h.get("ivar-intent").and_then(|v| v.to_str().ok()).map(String::from);
    let d = app.gateway.lock().expect("gateway").mcp_request(&app.sensor, &agent(&h), intent.as_deref(), &req, now_ms());
    if let Decision::Refuse { code, message } = d {
        return Json(jsonrpc_error(req.get("id").unwrap_or(&Value::Null), code, &message)).into_response();
    }
    let upstream = app.gateway.lock().expect("gateway").cfg.mcp_upstream.clone();
    let resp = match app.http.post(&upstream).json(&req).send().await {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_GATEWAY, e.to_string()).into_response(),
    };
    let mut body: Value = resp.json().await.unwrap_or(Value::Null);
    if req.get("method").and_then(Value::as_str) == Some("tools/list") {
        body = app.gateway.lock().expect("gateway").rewrite_tools_list(body);
    }
    Json(body).into_response()
}

async fn model(State(app): State<Arc<App>>, Path(rest): Path<String>, h: HeaderMap, body: Bytes) -> Response {
    let parsed: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
    if let Decision::Refuse { message, .. } = app.gateway.lock().expect("gateway").model_request(&app.sensor, &agent(&h), &parsed) {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": message }))).into_response();
    }
    let upstream = app.gateway.lock().expect("gateway").cfg.llm_upstream.clone();
    let mut req = app.http.post(format!("{}/v1/{rest}", upstream.trim_end_matches('/'))).body(body.to_vec());
    for (k, v) in h.iter() {
        if !matches!(k.as_str(), "host" | "content-length" | "x-agent-id" | "ivar-intent") {
            req = req.header(k, v);
        }
    }
    match req.send().await {
        Ok(r) => {
            let status = StatusCode::from_u16(r.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            (status, r.bytes().await.unwrap_or_default()).into_response()
        }
        Err(e) => (StatusCode::BAD_GATEWAY, e.to_string()).into_response(),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let get = |n: &str| args.iter().position(|a| a == n).and_then(|i| args.get(i + 1)).cloned();
    let mut cfg = get("--config").map(|p| SensorConfig::from_file(&p)).transpose()?.unwrap_or_default();
    cfg.sensor_type = "ai_gateway".into();
    let gcfg: GatewayConfig = get("--gateway").map(|p| std::fs::read_to_string(p).map_err(anyhow::Error::from).and_then(|t| Ok(serde_yaml::from_str(&t)?))).transpose()?.unwrap_or_default();
    let keyring: Keyring = std::fs::read_to_string(&cfg.keyring_file).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
    let sensor = Arc::new(Sensor::new(cfg.clone(), keyring));
    let decoys: Vec<String> = sensor.policy().map(|p| p.decoys.into_iter().filter(|d| d.kind == "decoy_tool").map(|d| d.marker).collect()).unwrap_or_else(|| vec!["export_all_customers".into()]);
    {
        let s = sensor.clone();
        let cfg = cfg.clone();
        std::thread::spawn(move || {
            let mut up = HttpUplink::new(&cfg.core_url, &cfg.control_url);
            s.run(&mut up, &|| false);
        });
    }
    let app = Arc::new(App { sensor, gateway: Mutex::new(Gateway::new(gcfg, decoys)), http: reqwest::Client::new() });
    let router = Router::new().route("/mcp", post(mcp)).route("/v1/{*rest}", post(model)).with_state(app);
    let listen = get("--listen").unwrap_or_else(|| "0.0.0.0:8443".into());
    axum::serve(tokio::net::TcpListener::bind(&listen).await?, router).await?;
    Ok(())
}
