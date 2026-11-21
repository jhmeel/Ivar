//! Replay verification in the viewer's own browser (section 13.1): a partner
//! or regulator does not have to trust the server's rendering.

use crate::err;
use ivar_contracts::sign::Keyring;
use ivar_contracts::ReplayBundle;
use ivar_core::evidence::{verify_chain, EvidenceRecord};
pub fn reverify_bundle(bundle_json: &str, keyring_json: &str, redaction_key_hex: &str) -> String {
    let run = || -> Result<String, String> {
        let bundle: ReplayBundle = serde_json::from_str(bundle_json).map_err(err)?;
        let ring: Option<Keyring> = if keyring_json.trim().is_empty() { None } else { Some(serde_json::from_str(keyring_json).map_err(err)?) };
        let key = hex::decode(redaction_key_hex).map_err(err)?;
        let r = ivar_replay::reverify_bundle(&bundle, ring.as_ref(), &key).map_err(err)?;
        serde_json::to_string(&r).map_err(err)
    };
    run().unwrap_or_else(|e| e)
}
pub fn verify_evidence_chain(records_json: &str) -> String {
    let run = || -> Result<String, String> {
        let records: Vec<EvidenceRecord> = serde_json::from_str(records_json).map_err(err)?;
        let head = verify_chain(&records, None).map_err(err)?;
        Ok(serde_json::json!({ "head": head }).to_string())
    };
    run().unwrap_or_else(|e| e)
}
