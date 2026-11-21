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

#[tonic::async_trait]
impl pb::ingest_server::Ingest for IngestService {
    async fn send(&self, req: Request<Streaming<SecurityEvent>>) -> Result<Response<IngestAck>, Status> {
        let mut stream = req.into_inner();
        let mut batch = Vec::new();
        while let Some(ev) = stream.next().await {
            batch.push(ev?);
        }
        let s = self.state.clone();
        let (accepted, verdicts) = tokio::task::spawn_blocking(move || s.ingest(batch)).await.map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(IngestAck { accepted, verdicts }))
    }

    async fn send_one(&self, req: Request<SecurityEvent>) -> Result<Response<IngestAck>, Status> {
        let s = self.state.clone();
        let ev = req.into_inner();
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
