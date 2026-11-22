//! Who may talk to the core.
//!
//! * Sensors: ingest, adapters, sink decisions and the verdict feed need a
//!   bearer token from `sensor_tokens_file`. Each token is bound to sensor id
//!   patterns, and every event in a batch must carry a sensor id the token
//!   may speak for, so one leaked token cannot frame traffic from another
//!   sensor. Only token hashes are stored.
//! * Operators: the operator headers are honoured only on requests that carry
//!   the staff SSO proxy's own token (`operator_proxy_token_file`), so a
//!   client that reaches the core directly cannot claim to be an operator.
//! * Shard peers: events another shard owns are forwarded to it.
//!
//! With no token files the core is open, as before, and says so at startup.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const PROXY_TOKEN_HEADER: &str = "x-ivar-proxy-token";
pub const FORWARDED_HEADER: &str = "x-ivar-forwarded";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorToken {
    pub name: String,
    /// Hex SHA-256 of the token.
    pub sha256: String,
    /// Sensor ids this token may send for: exact, or a prefix ending in `*`.
    pub sensors: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenFile {
    #[serde(default)]
    pub tokens: Vec<SensorToken>,
}

#[derive(Debug, Default)]
pub struct Access {
    sensor_tokens: Option<Vec<SensorToken>>,
    proxy_token_sha256: Option<[u8; 32]>,
    /// Base URL of each shard, by shard number.
    pub peers: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Denied {
    /// No valid token was presented.
    Unauthenticated,
    /// The token may not send for this sensor id.
    Forbidden(String),
}

fn digest(token: &str) -> [u8; 32] {
    Sha256::digest(token.trim().as_bytes()).into()
}

/// Constant time comparison of two digests.
fn same(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn matches(pattern: &str, sensor: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => sensor.starts_with(prefix),
        None => pattern == sensor,
    }
}

/// A new random token, as handed to a sensor.
pub fn new_token() -> String {
    let mut b = [0u8; 32];
    getrandom::getrandom(&mut b).expect("the system random source");
    format!("ivt_{}", hex::encode(b))
}

pub fn token_sha256(token: &str) -> String {
    hex::encode(digest(token))
}

impl Access {
    pub fn new(sensor_tokens: Option<Vec<SensorToken>>, proxy_token_sha256: Option<[u8; 32]>, peers: Vec<String>) -> Self {
        Access { sensor_tokens, proxy_token_sha256, peers }
    }

    pub fn load(sensor_tokens_file: Option<&str>, proxy_token_file: Option<&str>, peers: Vec<String>) -> anyhow::Result<Self> {
        let sensor_tokens = match sensor_tokens_file {
            Some(p) => {
                let f: TokenFile = serde_json::from_str(&std::fs::read_to_string(p).map_err(|e| anyhow::anyhow!("{p}: {e}"))?)?;
                for t in &f.tokens {
                    if hex::decode(&t.sha256).map(|b| b.len()) != Ok(32) {
                        anyhow::bail!("{p}: token {} needs a 64 character hex sha256", t.name);
                    }
                }
                Some(f.tokens)
            }
            None => None,
        };
        let proxy_token_sha256 = match proxy_token_file {
            Some(p) => {
                let text = std::fs::read_to_string(p).map_err(|e| anyhow::anyhow!("{p}: {e}"))?;
                let b: [u8; 32] = hex::decode(text.trim()).ok().and_then(|b| b.try_into().ok()).ok_or_else(|| anyhow::anyhow!("{p}: expected the hex sha256 of the proxy token"))?;
                Some(b)
            }
            None => None,
        };
        Ok(Access::new(sensor_tokens, proxy_token_sha256, peers))
    }

    pub fn ingest_open(&self) -> bool {
        self.sensor_tokens.is_none()
    }

    pub fn operators_open(&self) -> bool {
        self.proxy_token_sha256.is_none()
    }

    /// The token rule for an `Authorization: Bearer` value, if any.
    fn token(&self, bearer: Option<&str>) -> Result<Option<&SensorToken>, Denied> {
        let Some(tokens) = &self.sensor_tokens else { return Ok(None) };
        let presented = bearer.and_then(|b| b.strip_prefix("Bearer ")).map(digest).ok_or(Denied::Unauthenticated)?;
        let mut found = None;
        for t in tokens {
            let stored: [u8; 32] = hex::decode(&t.sha256).ok().and_then(|b| b.try_into().ok()).unwrap_or([0; 32]);
            if same(&stored, &presented) {
                found = Some(t);
            }
        }
        found.map(Some).ok_or(Denied::Unauthenticated)
    }

    /// A sensor request: the token must be valid and may speak for every
    /// sensor id given.
    pub fn sensor<'a>(&self, bearer: Option<&str>, sensor_ids: impl IntoIterator<Item = &'a str>) -> Result<(), Denied> {
        let Some(rule) = self.token(bearer)? else { return Ok(()) };
        for id in sensor_ids {
            if !rule.sensors.iter().any(|p| matches(p, id)) {
                return Err(Denied::Forbidden(id.to_string()));
            }
        }
        Ok(())
    }

    /// Whether operator headers on this request may be believed.
    pub fn operator_proxy(&self, presented: Option<&str>) -> bool {
        match &self.proxy_token_sha256 {
            None => true,
            Some(want) => presented.map(|p| same(want, &digest(p))).unwrap_or(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn access() -> (Access, String, String) {
        let shop = new_token();
        let edge = new_token();
        let a = Access::new(
            Some(vec![
                SensorToken { name: "shop".into(), sha256: token_sha256(&shop), sensors: vec!["shop-*".into()] },
                SensorToken { name: "edge".into(), sha256: token_sha256(&edge), sensors: vec!["edge-1".into()] },
            ]),
            Some(digest("proxy-secret")),
            vec![],
        );
        (a, shop, edge)
    }

    #[test]
    fn sensors_need_a_token_bound_to_their_id() {
        let (a, shop, edge) = access();
        assert_eq!(a.sensor(None, ["shop-node"]), Err(Denied::Unauthenticated), "no token");
        assert_eq!(a.sensor(Some("Bearer ivt_wrong"), ["shop-node"]), Err(Denied::Unauthenticated), "unknown token");
        assert_eq!(a.sensor(Some(&format!("Bearer {shop}")), ["shop-node", "shop-go"]), Ok(()), "prefix pattern");
        assert_eq!(a.sensor(Some(&format!("Bearer {shop}")), ["shop-node", "edge-1"]), Err(Denied::Forbidden("edge-1".into())), "a shop token cannot speak for the edge");
        assert_eq!(a.sensor(Some(&format!("Bearer {edge}")), ["edge-1"]), Ok(()));
        assert_eq!(a.sensor(Some(&format!("Bearer {edge}")), ["edge-10"]), Err(Denied::Forbidden("edge-10".into())), "exact ids are exact");
    }

    #[test]
    fn operator_headers_need_the_proxy_token() {
        let (a, _, _) = access();
        assert!(!a.operator_proxy(None));
        assert!(!a.operator_proxy(Some("guess")));
        assert!(a.operator_proxy(Some("proxy-secret")));
        assert!(Access::default().operator_proxy(None), "open when no proxy token is configured");
    }

    #[test]
    fn open_without_token_files() {
        let a = Access::default();
        assert!(a.ingest_open() && a.operators_open());
        assert_eq!(a.sensor(None, ["anything"]), Ok(()));
    }
}
