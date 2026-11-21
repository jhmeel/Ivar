//! Revocation out to identity providers through the OpenID Shared Signals
//! Framework (CAEP), where supported: a Security Event Token per revocation,
//! signed EdDSA and pushed to each receiver.

use super::{http, Outbound, Sink};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64U, Engine};
use ivar_contracts::sign::KeyPair;
use serde::{Deserialize, Serialize};
use serde_json::json;

pub const SESSION_REVOKED: &str = "https://schemas.openid.net/secevent/caep/event-type/session-revoked";
pub const CREDENTIAL_CHANGE: &str = "https://schemas.openid.net/secevent/caep/event-type/credential-change";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receiver {
    pub name: String,
    pub push_url: String,
    pub audience: String,
}

pub struct Transmitter {
    receivers: Vec<Receiver>,
    key: KeyPair,
    issuer: String,
    client: reqwest::blocking::Client,
}

impl Transmitter {
    pub fn new(receivers: Vec<Receiver>, key: KeyPair, issuer: &str) -> Self {
        Transmitter { receivers, key, issuer: issuer.into(), client: http() }
    }

    /// Build a signed SET (RFC 8417) for one subject.
    pub fn set(&self, audience: &str, subject: &str, event_type: &str, reason: &str, iat: i64, jti: &str) -> String {
        let header = json!({ "alg": "EdDSA", "typ": "secevent+jwt", "kid": self.key.key_id });
        let claims = json!({
            "iss": self.issuer,
            "aud": audience,
            "iat": iat,
            "jti": jti,
            "sub_id": { "format": "opaque", "id": subject },
            "events": { event_type: { "event_timestamp": iat, "initiating_entity": "policy", "reason_admin": { "en": reason } } }
        });
        let signing_input = format!("{}.{}", B64U.encode(header.to_string()), B64U.encode(claims.to_string()));
        let sig = self.key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", B64U.encode(sig))
    }
}

impl Sink for Transmitter {
    fn name(&self) -> &str {
        "caep"
    }
    fn send(&mut self, item: &Outbound) -> Result<(), String> {
        let Outbound::Revocation { subject, reason, event_type } = item else { return Ok(()) };
        let iat = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
        let jti = ivar_core::ids::derive("set", &[subject, event_type, &iat.to_string()]);
        for r in &self.receivers {
            let set = self.set(&r.audience, subject, event_type, reason, iat, &jti);
            self.client
                .post(&r.push_url)
                .header("Content-Type", "application/secevent+jwt")
                .header("Accept", "application/json")
                .body(set)
                .send()
                .map_err(|e| format!("{}: {e}", r.name))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_is_a_signed_jwt() {
        let t = Transmitter::new(vec![], KeyPair::ed25519_from_seed("caep-1", [4; 32]), "https://ivar.example");
        let jwt = t.set("https://okta.example", "kh_abc", SESSION_REVOKED, "contained", 1, "set_1");
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let claims: serde_json::Value = serde_json::from_slice(&B64U.decode(parts[1]).unwrap()).unwrap();
        assert!(claims["events"][SESSION_REVOKED].is_object());
        let mut ring = ivar_contracts::sign::Keyring::default();
        ring.add(t.key.public(), &["caep"]);
        let sig = B64U.decode(parts[2]).unwrap();
        assert!(ring.verify("caep", "caep-1", "ed25519", format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig).is_ok());
    }
}
