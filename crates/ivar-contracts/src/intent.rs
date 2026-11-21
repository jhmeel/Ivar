//! IntentToken: intent type, chain of prior steps, allowed action, limits and
//! expiry, where each step may only narrow it. The token itself is a Biscuit
//! (see ivar_core::intent); this struct is the decoded, readable view.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IntentClaims {
    pub intent_type: String,
    pub chain: Vec<String>,
    pub allowed_action: String,
    pub limits: BTreeMap<String, f64>,
    pub expiry: i64,
    pub subject: String,
}

