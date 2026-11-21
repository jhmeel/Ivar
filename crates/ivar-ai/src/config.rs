//! AI configuration, per role (section 12.2):
//!
//! ai:
//!   autonomy: advise
//!   providers:
//!     local:  { type: openai_compatible, endpoint: https://llm.internal/v1 }
//!     hosted: { type: anthropic, secret_ref: vault://ivar/ai-key }
//!   routing: { triage: hosted, investigation: local, response_advice: local }
//!   limits: { monthly_budget_usd: 2000, max_requests_per_minute: 120 }
//!   redact: [email, ip, account_id, secrets]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Autonomy {
    /// A0 Off: nothing. Regulated or air gapped environments.
    Off,
    /// A1 Advise: summarise, rank and explain. Default.
    Advise,
    /// A2 Propose: prepare actions for approval. Mature security teams.
    Propose,
    /// A3 Bounded action: trigger pre approved actions up to level 3.
    Bounded,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProviderConfig {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub secret_ref: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    /// USD per million input and output tokens, for spend tracking.
    #[serde(default)]
    pub price_per_mtok: Option<(f64, f64)>,
    /// A vetted local model kept ready (section 12.2): used when a hosted
    /// model refuses forensic content.
    #[serde(default)]
    pub vetted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Limits {
    pub monthly_budget_usd: f64,
    pub max_requests_per_minute: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AiConfig {
    pub autonomy: Autonomy,
    pub providers: BTreeMap<String, ProviderConfig>,
    /// Role name to provider name.
    pub routing: BTreeMap<String, String>,
    pub limits: Limits,
    pub redact: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Wrapper {
    ai: AiConfig,
}

impl AiConfig {
    pub fn from_yaml(text: &str) -> Result<Self, serde_yaml::Error> {
        Ok(serde_yaml::from_str::<Wrapper>(text)?.ai)
    }

    pub fn provider_for(&self, role: &str) -> Option<(&str, &ProviderConfig)> {
        let name = self.routing.get(role)?;
        self.providers.get_key_value(name).map(|(k, v)| (k.as_str(), v))
    }

    /// The vetted local model, if one is configured.
    pub fn vetted_local(&self) -> Option<(&str, &ProviderConfig)> {
        self.providers.iter().find(|(_, p)| p.kind == "openai_compatible").map(|(k, v)| (k.as_str(), v))
    }
}

#[cfg(test)]
pub(crate) const SPEC_YAML: &str = "ai:\n  autonomy: advise\n  providers:\n    local:  { type: openai_compatible, endpoint: https://llm.internal/v1 }\n    hosted: { type: anthropic, secret_ref: vault://ivar/ai-key }\n  routing:\n    triage: hosted\n    investigation: local\n    response_advice: local\n  limits: { monthly_budget_usd: 2000, max_requests_per_minute: 120 }\n  redact: [email, ip, account_id, secrets]\n";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_spec_example() {
        let c = AiConfig::from_yaml(SPEC_YAML).unwrap();
        assert_eq!(c.autonomy, Autonomy::Advise);
        assert_eq!(c.provider_for("triage").unwrap().1.kind, "anthropic");
        assert_eq!(c.provider_for("investigation").unwrap().0, "local");
        assert_eq!(c.limits.max_requests_per_minute, 120);
        assert_eq!(c.redact, vec!["email", "ip", "account_id", "secrets"]);
    }
}
