//! Plugin signatures ("signature: sigstore" in the manifest).
//!
//! Plugins are signed with Sigstore cosign in key mode (see
//! scripts/sign-plugin.sh), over the statement built by `signing_payload`, binding
//! the manifest and the artifact by digest. Verification is ECDSA P-256 with
//! SHA-256 against the registry's trusted cosign public keys, so it works
//! offline. Keyless (Fulcio and Rekor) bundles are verified by the control
//! plane before a plugin reaches this registry.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{DerSignature, Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use sha2::{Digest, Sha256};

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum SignatureError {
    #[error("manifest names signature scheme {0}, only sigstore is accepted")]
    Scheme(String),
    #[error("no trusted key verifies this plugin")]
    Untrusted,
    #[error("malformed signature or key: {0}")]
    Malformed(String),
}

/// The statement that is signed: manifest and artifact, by digest.
pub fn signing_payload(manifest_yaml: &[u8], artifact: &[u8]) -> Vec<u8> {
    format!(
        "ivar.plugin.v1\nmanifest sha256:{}\nartifact sha256:{}\n",
        hex::encode(Sha256::digest(manifest_yaml)),
        hex::encode(Sha256::digest(artifact))
    )
    .into_bytes()
}

/// Trusted cosign public keys (PEM).
#[derive(Clone, Default)]
pub struct TrustRoot {
    keys: Vec<VerifyingKey>,
}

impl TrustRoot {
    pub fn add_pem(&mut self, pem: &str) -> Result<(), SignatureError> {
        let k = VerifyingKey::from_public_key_pem(pem).map_err(|e| SignatureError::Malformed(e.to_string()))?;
        self.keys.push(k);
        Ok(())
    }

    pub fn add_key(&mut self, key: VerifyingKey) {
        self.keys.push(key);
    }

    /// `signature_b64` is cosign's base64 output (DER, or raw 64 byte r||s).
    pub fn verify(&self, scheme: &str, manifest_yaml: &[u8], artifact: &[u8], signature_b64: &str) -> Result<(), SignatureError> {
        if scheme != "sigstore" {
            return Err(SignatureError::Scheme(scheme.into()));
        }
        let raw = B64.decode(signature_b64.trim()).map_err(|e| SignatureError::Malformed(e.to_string()))?;
        let sig: Signature = match DerSignature::try_from(raw.as_slice()) {
            Ok(der) => Signature::try_from(der).map_err(|e| SignatureError::Malformed(e.to_string()))?,
            Err(_) => Signature::try_from(raw.as_slice()).map_err(|e| SignatureError::Malformed(e.to_string()))?,
        };
        let payload = signing_payload(manifest_yaml, artifact);
        if self.keys.iter().any(|k| k.verify(&payload, &sig).is_ok()) {
            Ok(())
        } else {
            Err(SignatureError::Untrusted)
        }
    }
}

#[cfg(test)]
pub(crate) mod testkey {
    use p256::ecdsa::{signature::Signer, DerSignature, SigningKey};

    pub fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32].into()).unwrap()
    }

    /// What cosign sign-blob produces: base64 of a DER ECDSA signature.
    pub fn sign(k: &SigningKey, manifest: &[u8], artifact: &[u8]) -> String {
        use base64::Engine;
        let sig: DerSignature = k.sign(&super::signing_payload(manifest, artifact));
        base64::engine::general_purpose::STANDARD.encode(sig.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifies_and_rejects() {
        let k = testkey::key(7);
        let mut root = TrustRoot::default();
        root.add_key(*k.verifying_key());
        let sig = testkey::sign(&k, b"m", b"a");
        assert!(root.verify("sigstore", b"m", b"a", &sig).is_ok());
        assert_eq!(root.verify("sigstore", b"m", b"tampered", &sig), Err(SignatureError::Untrusted));
        assert!(matches!(root.verify("none", b"m", b"a", &sig), Err(SignatureError::Scheme(_))));
        let other = testkey::sign(&testkey::key(8), b"m", b"a");
        assert_eq!(root.verify("sigstore", b"m", b"a", &other), Err(SignatureError::Untrusted));
    }
}
