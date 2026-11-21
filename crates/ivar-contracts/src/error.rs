//! Errors raised while encoding, decoding or verifying contracts.

#[derive(Debug, thiserror::Error)]
pub enum ContractError {
    #[error("archive: {0}")]
    Archive(String),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("yaml: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("signature: {0}")]
    Signature(String),
}
