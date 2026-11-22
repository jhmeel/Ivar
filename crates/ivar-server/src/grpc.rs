//! gRPC ingest: sensors send OCSF SecurityEvents (section 9).

use crate::state::AppState;
use ivar_contracts::{IngestAck, PolicyRequest, PolicyResponse, SecurityEvent};
use std::sync::Arc;
use tokio_stream::StreamExt;
use tonic::{Request, Response, Status, Streaming};

pub mod pb {
    tonic::include_proto!("ivar.v1");
}

pub struct IngestService {
    pub state: Arc<AppState>,
}

/// The same sensor token rule as HTTP ingest, from the authorization metadata.
fn check(state: &AppState, auth: Option<String>, events: &[SecurityEvent]) -> Result<(), Status> {
    let ids: Vec<String> = events.iter().map(|e| e.ext().sensor_id).collect();
    state.access.sensor(auth.as_deref(), ids.iter().map(String::as_str)).map_err(|d| {
        state.inner.lock().map(|mut g| g.metrics.ingest_denied_total += 1).ok();
        match d {
            crate::access::Denied::Unauthenticated => Status::unauthenticated("a valid sensor token is required"),
            crate::access::Denied::Forbidden(id) => Status::permission_denied(format!("this token may not send events for sensor {id}")),
        }
    })
}

fn auth<T>(req: &Request<T>) -> Option<String> {
    req.metadata().get("authorization").and_then(|v| v.to_str().ok()).map(str::to_string)
}

#[tonic::async_trait]
impl pb::ingest_server::Ingest for IngestService {
    async fn send(&self, req: Request<Streaming<SecurityEvent>>) -> Result<Response<IngestAck>, Status> {
        let token = auth(&req);
        let mut stream = req.into_inner();
        let mut batch = Vec::new();
        while let Some(ev) = stream.next().await {
            batch.push(ev?);
        }
        check(&self.state, token, &batch)?;
        let s = self.state.clone();
        let (accepted, verdicts) = tokio::task::spawn_blocking(move || s.ingest(batch)).await.map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(IngestAck { accepted, verdicts }))
    }

    async fn send_one(&self, req: Request<SecurityEvent>) -> Result<Response<IngestAck>, Status> {
        let token = auth(&req);
        let s = self.state.clone();
        let ev = req.into_inner();
        check(&self.state, token, std::slice::from_ref(&ev))?;
        let (accepted, verdicts) = tokio::task::spawn_blocking(move || s.ingest(vec![ev])).await.map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(IngestAck { accepted, verdicts }))
    }

    async fn fetch_policy(&self, req: Request<PolicyRequest>) -> Result<Response<PolicyResponse>, Status> {
        use base64::{engine::general_purpose::STANDARD as B64, Engine};
        let have = req.into_inner().have_version;
        let g = self.state.inner.lock().map_err(|_| Status::internal("state"))?;
        if g.core.policy().version <= have {
            return Ok(Response::new(PolicyResponse { bundle: vec![] }));
        }
        let bundle = B64.decode(&g.policy_archive_b64).map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(PolicyResponse { bundle }))
    }
}
