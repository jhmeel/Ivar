//! Data handling rules (§9): sensors never send passwords, tokens, OTPs, card
//! numbers or raw request bodies. Identifiers are keyed hashes by default, and
//! full body capture needs a time limited, audited approval.

use hmac::{Hmac, Mac};
use ivar_contracts::SecurityEvent;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::OnceLock;

type HmacSha256 = Hmac<Sha256>;

/// Keyed hash of an identifier: pseudonymised, stable per deployment key.
pub fn keyed_hash(key: &[u8], value: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac key");
    mac.update(value.as_bytes());
    format!("kh_{}", &hex::encode(mac.finalize().into_bytes())[..24])
}

fn forbidden_key() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| {
        Regex::new(r"(?i)(pass(word|wd)?|secret|token|otp|one_time|pin$|cvv|cvc|card(_?number)?|pan$|authorization|cookie|api_?key|private_?key|raw_?body|body$)").unwrap()
    })
}

fn card_like() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"\b(?:\d[ -]?){13,19}\b").unwrap())
}

fn jwt_like() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}").unwrap())
}

pub fn luhn(digits: &str) -> bool {
    let ds: Vec<u32> = digits.chars().filter_map(|c| c.to_digit(10)).collect();
    if ds.len() < 13 {
        return false;
    }
    let sum: u32 = ds
        .iter()
        .rev()
        .enumerate()
        .map(|(i, d)| if i % 2 == 1 { let x = d * 2; if x > 9 { x - 9 } else { x } } else { *d })
        .sum();
    sum % 10 == 0
}

/// Scrub a free text value: card numbers and bearer tokens are replaced.
pub fn scrub_value(v: &str) -> String {
    let v = card_like().replace_all(v, |c: &regex::Captures| {
        if luhn(&c[0]) { "[REDACTED:card]".to_string() } else { c[0].to_string() }
    });
    jwt_like().replace_all(&v, "[REDACTED:token]").to_string()
}

/// A time limited, audited approval for full body capture.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CaptureGrant {
    pub grant_id: String,
    pub granted_by: String,
    pub reason: String,
    pub scope: String,
    pub expires_at: i64,
    pub audit_evidence_id: String,
}

impl CaptureGrant {
    pub fn active(&self, now: i64, scope: &str) -> bool {
        now < self.expires_at && !self.audit_evidence_id.is_empty() && (self.scope == "*" || self.scope == scope)
    }
}

/// Attributes that carry user identifiers and are keyed hashed like actor ids,
/// so comparisons between them still work after redaction.
pub const IDENTIFIER_ATTRIBUTES: &[&str] = &["grantee", "record_owner", "account"];

pub struct Redactor {
    pub key: Vec<u8>,
    pub hash_identifiers: bool,
}

impl Redactor {
    pub fn new(key: &[u8]) -> Self {
        Redactor { key: key.to_vec(), hash_identifiers: true }
    }

    pub fn id(&self, v: &str) -> String {
        if v.is_empty() || v.starts_with("kh_") || !self.hash_identifiers {
            v.to_string()
        } else {
            keyed_hash(&self.key, v)
        }
    }

    /// Apply the data handling rules to an event in place. Returns the names
    /// of fields that were removed.
    pub fn apply(&self, ev: &mut SecurityEvent, grant: Option<&CaptureGrant>, now: i64) -> Vec<String> {
        let mut removed = Vec::new();
        if let Some(actor) = ev.actor.as_mut() {
            if let Some(u) = actor.user.as_mut() {
                u.uid = self.id(&u.uid);
                u.name = self.id(&u.name);
            }
        }
        if let Some(p) = ev.process.as_mut() {
            p.cmd_line = scrub_value(&p.cmd_line);
        }
        ev.message = scrub_value(&ev.message);
        if let Some(ext) = ev.ivar.as_mut() {
            for k in IDENTIFIER_ATTRIBUTES {
                if let Some(v) = ext.attributes.get_mut(*k) {
                    *v = self.id(v);
                }
            }
            let capture_allowed = grant.map(|g| g.active(now, &ext.sensor_id)).unwrap_or(false);
            let keys: Vec<String> = ext.attributes.keys().cloned().collect();
            for k in keys {
                if k == "token_fp" || k == "context" || k == "tool" || k == "env_var" {
                    // fingerprints and names, not secret values
                    continue;
                }
                if k == "captured_body" && capture_allowed {
                    continue;
                }
                if forbidden_key().is_match(&k) {
                    ext.attributes.remove(&k);
                    removed.push(k);
                } else if let Some(v) = ext.attributes.get_mut(&k) {
                    *v = scrub_value(v);
                }
            }
            if !ext.target_entity.is_empty() {
                if let Some((t, id)) = ext.target_entity.split_once(':') {
                    if t == "user" {
                        ext.target_entity = format!("user:{}", self.id(id));
                    }
                }
            }
        }
        removed
    }
}

#[cfg(test)]
mod t {
    use super::*;
    #[test]
    fn scrubs_cards_and_tokens() {
        assert!(scrub_value("pay 4111 1111 1111 1111 now").contains("[REDACTED:card]"));
        assert!(!scrub_value("order 1234567890123").contains("REDACTED"));
        assert!(scrub_value("Bearer eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.SflKxwRJSMeKKF2QT4").contains("[REDACTED:token]"));
    }
    #[test]
    fn removes_forbidden_attributes() {
        let mut ev = SecurityEvent::default();
        let mut ext = ivar_contracts::IvarExtension::default();
        ext.attributes.insert("password".into(), "x".into());
        ext.attributes.insert("otp".into(), "1".into());
        ext.attributes.insert("route".into(), "/a".into());
        ev.ivar = Some(ext);
        let r = Redactor::new(b"k");
        let removed = r.apply(&mut ev, None, 0);
        assert_eq!(removed.len(), 2);
        assert!(ev.ext().attributes.contains_key("route"));
    }
}
