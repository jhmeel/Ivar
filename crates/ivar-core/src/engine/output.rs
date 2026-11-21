//! What one call to the core produced.

use crate::response::PlannedAction;
use crate::safeguards::ReviewOutcome;
use ivar_contracts::{EntityRisk, Finding, Verdict};

#[derive(Debug, Clone, PartialEq)]
pub struct ReviewedAction {
    pub planned: PlannedAction,
    pub review: ReviewOutcome,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct EngineOutput {
    pub evidence_id: String,
    pub findings: Vec<Finding>,
    pub risks: Vec<EntityRisk>,
    pub verdicts: Vec<Verdict>,
    pub actions: Vec<ReviewedAction>,
    pub incidents: Vec<String>,
    /// Findings from rules in observe mode: what they would have done.
    pub observe_only: Vec<Finding>,
}

impl EngineOutput {
    /// The strongest decision for the request that produced this output.
    pub fn decision(&self) -> &str {
        const ORDER: [&str; 7] = ["allow", "record", "throttle", "challenge", "block", "refuse", "contain"];
        self.verdicts
            .iter()
            .map(|v| v.decision.as_str())
            .max_by_key(|d| ORDER.iter().position(|o| o == d).unwrap_or(0))
            .unwrap_or("allow")
    }
}
