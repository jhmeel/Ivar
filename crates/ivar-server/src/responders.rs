//! Responders perform actions (section 14, responder plugins). Each runs as a
//! separate process with only its declared credentials, receives a signed
//! ActionRequest and answers with a result the core seals as an ActionReceipt.
//! Actions the sensors enforce themselves (throttle, block, step up, IP bans)
//! are carried out through the verdicts pushed back to sensors.

use ivar_contracts::sign::{seal, KeyPair};
use ivar_contracts::{ActionReceipt, ActionRequest, PluginManifest};
use ivar_core::response::receipt_for;
use ivar_plugin_host::process::ProcessPlugin;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Instant;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponderConfig {
    pub manifest: String,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    /// Environment variable names holding the declared secrets' values.
    #[serde(default)]
    pub secret_env: BTreeMap<String, String>,
}

/// Actions enforced by sensors through verdicts.
pub const SENSOR_ENFORCED: &[&str] = &["throttle", "challenge", "session.step_up", "request.block", "ip.ban", "device.block"];

pub struct Responders {
    plugins: Vec<(PluginManifest, ProcessPlugin)>,
    key: KeyPair,
}

impl Responders {
    pub fn start(configs: &[ResponderConfig], key: KeyPair) -> anyhow::Result<Self> {
        let mut plugins = Vec::new();
        for c in configs {
            let m = PluginManifest::from_yaml(&std::fs::read_to_string(&c.manifest)?)?;
            let secrets = c.secret_env.iter().filter_map(|(name, env)| std::env::var(env).ok().map(|v| (name.clone(), v))).collect();
            let args: Vec<&str> = c.args.iter().map(String::as_str).collect();
            let p = ProcessPlugin::spawn(&m, &c.command, &args, &secrets)?;
            plugins.push((m, p));
        }
        Ok(Responders { plugins, key })
    }

    pub fn empty(key: KeyPair) -> Self {
        Responders { plugins: vec![], key }
    }

    /// Carry out one approved action. Observe mode never acts.
    pub fn execute(&mut self, req: &ActionRequest, now: i64) -> ActionReceipt {
        let started = Instant::now();
        if req.mode == "observe" {
            return receipt_for(req, "skipped_observe", 0, "observe mode: recorded what would have run", now);
        }
        if SENSOR_ENFORCED.contains(&req.action.as_str()) {
            return receipt_for(req, "done", 0, "enforced by sensors through the pushed verdict", now);
        }
        let Some((m, p)) = self.plugins.iter_mut().find(|(m, _)| m.permissions.actions.iter().any(|a| a == &req.action)) else {
            return receipt_for(req, "failed", 0, &format!("no responder declares {}", req.action), now);
        };
        let env = seal(&self.key, "ivar.v1.ActionRequest", req);
        let call = serde_json::json!({ "op": "execute", "envelope": env, "request": req });
        let mut r = match p.call(&call) {
            Ok(v) => {
                let result = v.get("result").and_then(|x| x.as_str()).unwrap_or("failed").to_string();
                let verification = v.get("verification").and_then(|x| x.as_str()).unwrap_or("").to_string();
                receipt_for(req, &result, started.elapsed().as_millis() as u64, &verification, now)
            }
            Err(e) => receipt_for(req, "failed", started.elapsed().as_millis() as u64, &e.to_string(), now),
        };
        r.responder = m.name.clone();
        r
    }
}
