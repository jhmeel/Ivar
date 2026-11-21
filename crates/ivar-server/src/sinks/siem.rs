//! OCSF events to the SIEM: a JSON lines file, Splunk HTTP Event Collector,
//! or any JSON over HTTP ingestion endpoint (Elastic, Microsoft Sentinel).

use super::{http, Outbound, Sink};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::Write;

fn ocsf_payload(item: &Outbound) -> Option<serde_json::Value> {
    match item {
        Outbound::Event { ocsf } => Some(ocsf.clone()),
        Outbound::Verdict { verdict } => Some(serde_json::json!({ "class_uid": 2004, "class_name": "Detection Finding", "ivar_verdict": verdict })),
        Outbound::Incident { incident } => Some(serde_json::json!({ "class_uid": 2005, "class_name": "Incident Finding", "ivar_incident": incident })),
        _ => None,
    }
}

pub struct OcsfFile {
    file: File,
}

impl OcsfFile {
    pub fn open(path: &str) -> std::io::Result<Self> {
        Ok(OcsfFile { file: OpenOptions::new().create(true).append(true).open(path)? })
    }
}

impl Sink for OcsfFile {
    fn name(&self) -> &str {
        "ocsf_file"
    }
    fn send(&mut self, item: &Outbound) -> Result<(), String> {
        if let Some(p) = ocsf_payload(item) {
            writeln!(self.file, "{p}").map_err(|e| e.to_string())?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HecConfig {
    pub url: String,
    pub token_env: String,
    #[serde(default = "default_index")]
    pub index: String,
}

fn default_index() -> String {
    "ivar".into()
}

pub struct SplunkHec {
    cfg: HecConfig,
    client: reqwest::blocking::Client,
}

impl SplunkHec {
    pub fn new(cfg: HecConfig) -> Self {
        SplunkHec { cfg, client: http() }
    }
}

impl Sink for SplunkHec {
    fn name(&self) -> &str {
        "splunk_hec"
    }
    fn send(&mut self, item: &Outbound) -> Result<(), String> {
        let Some(p) = ocsf_payload(item) else { return Ok(()) };
        let token = std::env::var(&self.cfg.token_env).map_err(|_| format!("{} not set", self.cfg.token_env))?;
        let body = serde_json::json!({ "event": p, "sourcetype": "ocsf:ivar", "index": self.cfg.index });
        self.client.post(&self.cfg.url).header("Authorization", format!("Splunk {token}")).json(&body).send().map_err(|e| e.to_string())?.error_for_status().map(|_| ()).map_err(|e| e.to_string())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpJsonConfig {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub bearer_env: Option<String>,
}

pub struct HttpJson {
    cfg: HttpJsonConfig,
    client: reqwest::blocking::Client,
}

impl HttpJson {
    pub fn new(cfg: HttpJsonConfig) -> Self {
        HttpJson { cfg, client: http() }
    }
}

impl Sink for HttpJson {
    fn name(&self) -> &str {
        &self.cfg.name
    }
    fn send(&mut self, item: &Outbound) -> Result<(), String> {
        let Some(p) = ocsf_payload(item) else { return Ok(()) };
        let mut req = self.client.post(&self.cfg.url).json(&serde_json::json!([p]));
        if let Some(env) = &self.cfg.bearer_env {
            req = req.bearer_auth(std::env::var(env).map_err(|_| format!("{env} not set"))?);
        }
        req.send().map_err(|e| e.to_string())?.error_for_status().map(|_| ()).map_err(|e| e.to_string())
    }
}
