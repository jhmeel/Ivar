//! Risk bands and the evidence each band requires (section 10.1).
//!
//! | Risk score   | Default response              | Evidence required          |
//! | below 0.30   | Record only                   | Any                        |
//! | 0.30 to 0.59 | Throttle and watch closely    | One source                 |
//! | 0.60 to 0.84 | Challenge or block the request| One high confidence source |
//! | 0.85 and up  | Contain the entity            | Two independent sources    |
//!
//! A deception hit or a critical positive security violation can skip these
//! bands, because legitimate users should never trigger either.

use crate::risk::RiskAssessment;
use ivar_contracts::Thresholds;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Band {
    Record,
    Throttle,
    ChallengeOrBlock,
    Contain,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Record,
    Throttle,
    Challenge,
    Block,
    Contain,
    Refuse,
}

impl Decision {
    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Record => "record",
            Decision::Throttle => "throttle",
            Decision::Challenge => "challenge",
            Decision::Block => "block",
            Decision::Contain => "contain",
            Decision::Refuse => "refuse",
        }
    }

    /// Rung of the response ladder (section 11).
    pub fn ladder_level(self) -> u32 {
        match self {
            Decision::Allow | Decision::Record => 0,
            Decision::Throttle => 1,
            Decision::Challenge => 2,
            Decision::Block | Decision::Refuse => 3,
            Decision::Contain => 4,
        }
    }
}

pub struct DecisionInput<'a> {
    pub assessment: &'a RiskAssessment,
    pub thresholds: &'a Thresholds,
    /// The event is a login, signup, reset or other step that can be challenged.
    pub challengeable: bool,
}

fn band_for(score: f64, throttle: f64, challenge: f64, contain: f64) -> Band {
    if score >= contain {
        Band::Contain
    } else if score >= challenge {
        Band::ChallengeOrBlock
    } else if score >= throttle {
        Band::Throttle
    } else {
        Band::Record
    }
}

/// Map one entity's risk to a decision, with the reasons behind it.
pub fn decide(input: &DecisionInput) -> (Decision, Band, Vec<String>) {
    let r = &input.assessment.risk;
    let t = input.thresholds;
    let fast = band_for(r.fast_score, t.throttle, t.challenge, t.contain);
    let slow = band_for(r.slow_score, t.slow_throttle, t.slow_challenge, t.slow_contain);
    let band = fast.max(slow);
    let mut reasons = Vec::new();
    let middle = if input.challengeable { Decision::Challenge } else { Decision::Block };

    let mut decision = match band {
        Band::Record => Decision::Record,
        Band::Throttle if r.independent_sources >= 1 => Decision::Throttle,
        Band::Throttle => Decision::Record,
        Band::ChallengeOrBlock if r.has_high_confidence_source => middle,
        Band::ChallengeOrBlock => {
            reasons.push("no high confidence source: held at throttle".into());
            Decision::Throttle
        }
        Band::Contain if r.independent_sources >= 2 => Decision::Contain,
        Band::Contain => {
            reasons.push("one independent source: containment needs two".into());
            if r.has_high_confidence_source { middle } else { Decision::Throttle }
        }
    };

    if r.critical_positive_security && decision < Decision::Block {
        reasons.push("critical positive security violation skips the bands".into());
        decision = Decision::Block;
    }
    if r.deception_hit && decision < Decision::Contain {
        reasons.push("deception hit skips the bands".into());
        decision = Decision::Contain;
    }
    if input.assessment.ml_only && decision > Decision::Throttle {
        reasons.push("machine learning alone cannot block".into());
        decision = Decision::Throttle;
    }
    if r.target_only && decision > Decision::Challenge {
        reasons.push("target side evidence raises protection only".into());
        decision = Decision::Challenge;
    }
    if r.target_only && decision == Decision::Throttle {
        decision = Decision::Challenge;
    }
    (decision, band, reasons)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ivar_contracts::EntityRisk;

    fn a(score: f64, sources: u32, high: bool) -> RiskAssessment {
        RiskAssessment {
            risk: EntityRisk { score, fast_score: score, slow_score: score * 0.5, independent_sources: sources, has_high_confidence_source: high, ..Default::default() },
            ml_only: false,
        }
    }

    fn run(x: &RiskAssessment, challengeable: bool) -> Decision {
        decide(&DecisionInput { assessment: x, thresholds: &Thresholds::spec_defaults(), challengeable }).0
    }

    #[test]
    fn bands_with_evidence_requirements() {
        assert_eq!(run(&a(0.2, 1, false), false), Decision::Record);
        assert_eq!(run(&a(0.35, 1, false), false), Decision::Throttle);
        assert_eq!(run(&a(0.7, 1, true), true), Decision::Challenge);
        assert_eq!(run(&a(0.7, 1, true), false), Decision::Block);
        assert_eq!(run(&a(0.7, 1, false), false), Decision::Throttle);
        assert_eq!(run(&a(0.9, 2, true), false), Decision::Contain);
        assert_eq!(run(&a(0.9, 1, true), false), Decision::Block);
    }

    #[test]
    fn skips_and_caps() {
        let mut d = a(0.1, 1, true);
        d.risk.deception_hit = true;
        assert_eq!(run(&d, false), Decision::Contain);
        let mut m = a(0.95, 3, true);
        m.ml_only = true;
        assert_eq!(run(&m, false), Decision::Throttle);
        let mut t = a(0.95, 3, true);
        t.risk.target_only = true;
        assert_eq!(run(&t, false), Decision::Challenge);
    }
}
