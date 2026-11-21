//! Sinks send results elsewhere (section 14, sink plugins; section 20.1):
//! OCSF to the SIEM, OpenTelemetry logs, approvals and alerts to Slack,
//! PagerDuty and Jira, and revocations to identity providers through Shared
//! Signals (CAEP). Sinks run off the decision path; a failing sink never
//! delays a verdict.

pub mod caep;
pub mod notify;
pub mod otel;
pub mod siem;

use serde::{Deserialize, Serialize};

/// One outbound item.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Outbound {
    Event { ocsf: serde_json::Value },
    Verdict { verdict: serde_json::Value },
    Incident { incident: serde_json::Value },
    ApprovalNeeded { action_request: serde_json::Value, approve_url: String },
    TimeLock { lock: serde_json::Value, cancel_url: String },
    Revocation { subject: String, reason: String, event_type: String },
    Alert { kind: String, message: String },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SinkConfig {
    /// OCSF JSON lines file (for any SIEM that tails files).
    pub ocsf_file: Option<String>,
    pub splunk_hec: Option<siem::HecConfig>,
    /// Elastic, Sentinel (Logs Ingestion API) and others that accept JSON over HTTP.
    pub http_json: Vec<siem::HttpJsonConfig>,
    pub otlp_logs_endpoint: Option<String>,
    pub slack_webhook: Option<String>,
    pub pagerduty_routing_key: Option<String>,
    pub jira: Option<notify::JiraConfig>,
    pub caep_receivers: Vec<caep::Receiver>,
}

pub trait Sink: Send {
    fn name(&self) -> &str;
    fn send(&mut self, item: &Outbound) -> Result<(), String>;
}

pub fn build(cfg: &SinkConfig, caep_key: Option<ivar_contracts::sign::KeyPair>, issuer: &str) -> Vec<Box<dyn Sink>> {
    let mut out: Vec<Box<dyn Sink>> = Vec::new();
    if let Some(p) = &cfg.ocsf_file {
        if let Ok(s) = siem::OcsfFile::open(p) {
            out.push(Box::new(s));
        }
    }
    if let Some(h) = &cfg.splunk_hec {
        out.push(Box::new(siem::SplunkHec::new(h.clone())));
    }
    for h in &cfg.http_json {
        out.push(Box::new(siem::HttpJson::new(h.clone())));
    }
    if let Some(e) = &cfg.otlp_logs_endpoint {
        out.push(Box::new(otel::OtlpLogs::new(e)));
    }
    if cfg.slack_webhook.is_some() || cfg.pagerduty_routing_key.is_some() || cfg.jira.is_some() {
        out.push(Box::new(notify::Notifier::new(cfg.slack_webhook.clone(), cfg.pagerduty_routing_key.clone(), cfg.jira.clone())));
    }
    if let Some(k) = caep_key {
        if !cfg.caep_receivers.is_empty() {
            out.push(Box::new(caep::Transmitter::new(cfg.caep_receivers.clone(), k, issuer)));
        }
    }
    out
}

pub(crate) fn http() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder().timeout(std::time::Duration::from_secs(5)).build().expect("http client")
}
