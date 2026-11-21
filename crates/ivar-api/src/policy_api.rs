//! Policy loading for SDKs: the spec default policy, and verification of a
//! signed PolicyBundle archive against a keyring. An invalid signature is
//! rejected and the caller keeps its current policy (section 11.2).

use crate::err;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ivar_contracts::sign::{verify_policy, Keyring};
use ivar_contracts::PolicyBundle;
pub fn default_policy(now_ms: f64) -> String {
    serde_json::to_string(&ivar_core::policy::spec_default_policy(now_ms as i64)).unwrap_or_else(err)
}

/// Returns the verified PolicyContent JSON, or an error. `current_version`
/// blocks rollback to an older signed bundle; `now_ms` rejects expired ones.
pub fn verify_policy_bundle(archive_base64: &str, keyring_json: &str, current_version: f64, now_ms: f64) -> String {
    let run = || -> Result<String, String> {
        let bytes = B64.decode(archive_base64.trim()).map_err(err)?;
        let bundle = PolicyBundle::from_archive(&bytes).map_err(err)?;
        let ring: Keyring = serde_json::from_str(keyring_json).map_err(err)?;
        verify_policy(&ring, &bundle).map_err(err)?;
        if (bundle.content.version as f64) < current_version {
            return Err(err("rollback to an older signed policy refused"));
        }
        if (bundle.content.expires_at as f64) < now_ms {
            return Err(err("expired policy bundle refused"));
        }
        serde_json::to_string(&bundle.content).map_err(err)
    };
    run().unwrap_or_else(|e| e)
}
