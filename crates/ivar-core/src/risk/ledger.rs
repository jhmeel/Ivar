//! Per entity record of the findings that raised its risk.

use ivar_contracts::{DetectionMethod, EntityRef};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Contribution {
    pub finding_id: String,
    pub family: String,
    /// c times w.
    pub weighted: f64,
    pub confidence: f64,
    pub time: i64,
    /// Independence key: the underlying event, so the edge filter and the SDK
    /// reporting the same request count once.
    pub source_event: String,
    pub observation_point: String,
    pub method: i32,
    pub deception: bool,
    pub critical: bool,
}

impl Contribution {
    pub fn is_ml(&self) -> bool {
        self.method == DetectionMethod::MachineLearning as i32
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EntityLedger {
    pub entity: EntityRef,
    /// Findings where the entity acted.
    pub acted: Vec<Contribution>,
    /// Findings where the entity was only targeted.
    pub targeted: Vec<Contribution>,
}
