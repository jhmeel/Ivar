//! Service configuration (YAML).

use crate::responders::ResponderConfig;
use crate::sinks::SinkConfig;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub http_listen: String,
    pub grpc_listen: String,
    pub data_dir: String,
    /// Signed PolicyBundle archive to start from.
    pub policy_bundle: String,
    /// Keyring JSON with policy, flags, evidence, replay and action keys.
    pub keyring: String,
    /// Hex seed files for this instance's signing keys.
    pub evidence_key_seed_file: String,
    pub action_key_seed_file: String,
    pub redaction_key_hex_file: String,
    /// Public base URL, used in approval and cancellation links and as the CAEP issuer.
    pub public_url: String,
    pub shard: u32,
    pub shards: u32,
    pub sinks: SinkConfig,
    pub responders: Vec<ResponderConfig>,
    /// Path of the ai section (section 12.2), optional.
    pub ai_config: Option<String>,
    /// Platform tier layers expected for replays (full, application, visibility).
    pub expected_layers: Vec<String>,
    /// The operator console (replay-viewer) to serve at /console/, from the
    /// same origin as the API so live mode needs no cross origin access.
    /// Unset: the console bundled in the image, when present. Empty: off.
    pub console_dir: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            http_listen: "0.0.0.0:8080".into(),
            grpc_listen: "0.0.0.0:7443".into(),
            data_dir: "/var/lib/ivar".into(),
            policy_bundle: "/etc/ivar/policy.bundle".into(),
            keyring: "/etc/ivar/keyring.json".into(),
            evidence_key_seed_file: "/etc/ivar/keys/evidence.seed".into(),
            action_key_seed_file: "/etc/ivar/keys/action.seed".into(),
            redaction_key_hex_file: "/etc/ivar/keys/redaction.hex".into(),
            public_url: "https://ivar.internal".into(),
            shard: 0,
            shards: 1,
            sinks: SinkConfig::default(),
            responders: vec![],
            ai_config: None,
            expected_layers: vec!["edge".into(), "app_sdk".into(), "host".into(), "network".into(), "database".into()],
            console_dir: None,
        }
    }
}

/// Where the release image puts the operator console.
pub const BUNDLED_CONSOLE: &str = "/usr/share/ivar/console";

impl ServerConfig {
    /// The console directory to serve, if any.
    pub fn console(&self) -> Option<String> {
        self.console_with(|dir| std::path::Path::new(dir).join("index.html").is_file())
    }

    fn console_with(&self, present: impl Fn(&str) -> bool) -> Option<String> {
        match self.console_dir.as_deref() {
            Some("") => None,
            Some(dir) => Some(dir.to_string()),
            None => present(BUNDLED_CONSOLE).then(|| BUNDLED_CONSOLE.to_string()),
        }
    }

    pub fn load(path: &str) -> anyhow::Result<Self> {
        let mut cfg: Self = serde_yaml::from_str(&std::fs::read_to_string(path)?)?;
        cfg.apply_env(|k| std::env::var(k).ok())?;
        Ok(cfg)
    }

    /// Environment overrides, so one config file serves every replica.
    /// IVAR_SHARD=ordinal takes the shard from the StatefulSet pod name
    /// (ivar-core-2 is shard 2).
    pub fn apply_env(&mut self, env: impl Fn(&str) -> Option<String>) -> anyhow::Result<()> {
        if let Some(dir) = env("IVAR_CONSOLE_DIR") {
            self.console_dir = Some(dir);
        }
        if let Some(n) = env("IVAR_SHARDS") {
            self.shards = n.parse().map_err(|_| anyhow::anyhow!("IVAR_SHARDS must be a number"))?;
        }
        if let Some(s) = env("IVAR_SHARD") {
            self.shard = if s == "ordinal" {
                let host = env("HOSTNAME").unwrap_or_default();
                host.rsplit('-').next().and_then(|n| n.parse().ok()).ok_or_else(|| anyhow::anyhow!("IVAR_SHARD=ordinal needs a HOSTNAME ending in -<n>, got {host}"))?
            } else {
                s.parse().map_err(|_| anyhow::anyhow!("IVAR_SHARD must be a number or ordinal"))?
            };
        }
        if self.shards == 0 || self.shard >= self.shards {
            anyhow::bail!("shard {} is outside 0..{}", self.shard, self.shards);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shard_from_statefulset_ordinal() {
        let mut c = ServerConfig::default();
        let env = |k: &str| match k {
            "IVAR_SHARD" => Some("ordinal".to_string()),
            "IVAR_SHARDS" => Some("3".to_string()),
            "HOSTNAME" => Some("ivar-core-2".to_string()),
            _ => None,
        };
        c.apply_env(env).unwrap();
        assert_eq!((c.shard, c.shards), (2, 3));
        let mut bad = ServerConfig::default();
        assert!(bad.apply_env(|k| (k == "IVAR_SHARD").then(|| "4".to_string())).is_err(), "shard outside the range is refused");
    }

    #[test]
    fn console_defaults_to_the_bundled_copy() {
        let mut c = ServerConfig::default();
        assert_eq!(c.console_with(|_| true).as_deref(), Some(BUNDLED_CONSOLE), "served from the image when present");
        assert_eq!(c.console_with(|_| false), None, "nothing to serve outside the image");
        c.console_dir = Some("/srv/console".into());
        assert_eq!(c.console_with(|_| false).as_deref(), Some("/srv/console"), "an explicit path wins");
        c.apply_env(|k| (k == "IVAR_CONSOLE_DIR").then(String::new)).unwrap();
        assert_eq!(c.console_with(|_| true), None, "an empty value turns it off");
    }
}

pub fn read_seed(path: &str) -> anyhow::Result<[u8; 32]> {
    let text = std::fs::read_to_string(path)?;
    let bytes = hex::decode(text.trim())?;
    bytes.try_into().map_err(|_| anyhow::anyhow!("{path}: seed must be 32 bytes of hex"))
}
