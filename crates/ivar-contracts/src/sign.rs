//! Crypto agile signing (principle 7).
//!
//! Every signature names its algorithm and key id, so a post quantum algorithm
//! can be added to the keyring without changing any contract. Ed25519 is the
//! algorithm implemented today.

use crate::{BundleSignature, ContractError, PolicyBundle, PolicyContent, SignedEnvelope};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ed25519_dalek::{Signer as _, SigningKey, Verifier as _, VerifyingKey};
use prost::Message;
use std::collections::BTreeMap;

pub const ALG_ED25519: &str = "ed25519";

#[derive(Clone)]
pub struct KeyPair {
    pub key_id: String,
    pub alg: String,
    signing: SigningKey,
}

impl KeyPair {
    pub fn ed25519_from_seed(key_id: &str, seed: [u8; 32]) -> Self {
        KeyPair { key_id: key_id.into(), alg: ALG_ED25519.into(), signing: SigningKey::from_bytes(&seed) }
    }
    pub fn public(&self) -> PublicKey {
        PublicKey { key_id: self.key_id.clone(), alg: self.alg.clone(), bytes: self.signing.verifying_key().to_bytes().to_vec() }
    }
    pub fn seed_hex(&self) -> String {
        hex::encode(self.signing.to_bytes())
    }
    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        self.signing.sign(msg).to_bytes().to_vec()
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct PublicKey {
    pub key_id: String,
    pub alg: String,
    #[serde(with = "hexbytes")]
    pub bytes: Vec<u8>,
}

mod hexbytes {
    pub fn serialize<S: serde::Serializer>(b: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(b))
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s: String = serde::Deserialize::deserialize(d)?;
        hex::decode(s).map_err(serde::de::Error::custom)
    }
}

/// Trusted public keys by key id, with a role (policy, flags, plugin, evidence, action).
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct Keyring {
    pub keys: BTreeMap<String, (PublicKey, Vec<String>)>,
}

impl Keyring {
    pub fn add(&mut self, key: PublicKey, roles: &[&str]) {
        self.keys.insert(key.key_id.clone(), (key, roles.iter().map(|r| r.to_string()).collect()));
    }

    pub fn verify(&self, role: &str, key_id: &str, alg: &str, msg: &[u8], sig: &[u8]) -> Result<(), ContractError> {
        let (key, roles) = self
            .keys
            .get(key_id)
            .ok_or_else(|| ContractError::Signature(format!("unknown key {key_id}")))?;
        if !roles.iter().any(|r| r == role) {
            return Err(ContractError::Signature(format!("key {key_id} not trusted for role {role}")));
        }
        if key.alg != alg {
            return Err(ContractError::Signature(format!("algorithm mismatch for {key_id}")));
        }
        match alg {
            ALG_ED25519 => {
                let vk_bytes: [u8; 32] = key.bytes.as_slice().try_into().map_err(|_| ContractError::Signature("bad key".into()))?;
                let vk = VerifyingKey::from_bytes(&vk_bytes).map_err(|e| ContractError::Signature(e.to_string()))?;
                let sig_bytes: [u8; 64] = sig.try_into().map_err(|_| ContractError::Signature("bad signature length".into()))?;
                let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
                vk.verify(msg, &sig).map_err(|e| ContractError::Signature(e.to_string()))
            }
            other => Err(ContractError::Signature(format!("unsupported algorithm {other}"))),
        }
    }
}

/// Sign a protobuf message into a SignedEnvelope (ActionRequest, ActionReceipt).
pub fn seal<M: Message>(key: &KeyPair, payload_type: &str, msg: &M) -> SignedEnvelope {
    let payload = msg.encode_to_vec();
    let mut to_sign = payload_type.as_bytes().to_vec();
    to_sign.push(0);
    to_sign.extend_from_slice(&payload);
    SignedEnvelope {
        alg: key.alg.clone(),
        key_id: key.key_id.clone(),
        signature: key.sign(&to_sign),
        payload,
        payload_type: payload_type.into(),
    }
}

pub fn open<M: Message + Default>(ring: &Keyring, role: &str, env: &SignedEnvelope) -> Result<M, ContractError> {
    let mut to_sign = env.payload_type.as_bytes().to_vec();
    to_sign.push(0);
    to_sign.extend_from_slice(&env.payload);
    ring.verify(role, &env.key_id, &env.alg, &to_sign, &env.signature)?;
    M::decode(env.payload.as_slice()).map_err(|e| ContractError::Signature(e.to_string()))
}

/// Build and sign a PolicyBundle with one or more policy keys.
pub fn sign_policy(content: &PolicyContent, keys: &[&KeyPair]) -> Result<PolicyBundle, ContractError> {
    let content_bytes = serde_json::to_vec_pretty(content)?;
    let signatures = keys
        .iter()
        .map(|k| BundleSignature { alg: k.alg.clone(), key_id: k.key_id.clone(), sig: B64.encode(k.sign(&content_bytes)) })
        .collect();
    Ok(PolicyBundle { content_bytes, content: content.clone(), signatures })
}

/// Verify a PolicyBundle: every listed signature must verify against a policy
/// key, and a bundle that weakens protection needs at least two distinct
/// named policy keys (§16).
pub fn verify_policy(ring: &Keyring, bundle: &PolicyBundle) -> Result<usize, ContractError> {
    let mut valid = std::collections::BTreeSet::new();
    for s in &bundle.signatures {
        let sig = B64.decode(&s.sig).map_err(|e| ContractError::Signature(e.to_string()))?;
        ring.verify("policy", &s.key_id, &s.alg, &bundle.content_bytes, &sig)?;
        valid.insert(s.key_id.clone());
    }
    if valid.is_empty() {
        return Err(ContractError::Signature("unsigned policy bundle".into()));
    }
    let parsed: PolicyContent = serde_json::from_slice(&bundle.content_bytes)?;
    if parsed != bundle.content {
        return Err(ContractError::Signature("content does not match signed bytes".into()));
    }
    if parsed.weakens_protection && valid.len() < 2 {
        return Err(ContractError::Signature(
            "a policy change that weakens protection needs signatures from at least two named policy keys".into(),
        ));
    }
    Ok(valid.len())
}

pub fn sign_bytes(key: &KeyPair, bytes: &[u8]) -> BundleSignature {
    BundleSignature { alg: key.alg.clone(), key_id: key.key_id.clone(), sig: B64.encode(key.sign(bytes)) }
}

pub fn verify_bytes(ring: &Keyring, role: &str, sig: &BundleSignature, bytes: &[u8]) -> Result<(), ContractError> {
    let raw = B64.decode(&sig.sig).map_err(|e| ContractError::Signature(e.to_string()))?;
    ring.verify(role, &sig.key_id, &sig.alg, bytes, &raw)
}
