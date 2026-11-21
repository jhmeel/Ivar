//! The risk engine: holds one ledger per entity and scores it on the fast and
//! slow timescales.

use super::ledger::{Contribution, EntityLedger};
use ivar_contracts::{DetectionMethodName, EntityRef, EntityRisk, EntityRole, Finding, Thresholds};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Contributions below this weight on the slow timescale are dropped.
const NEGLIGIBLE: f64 = 1e-4;
/// A contribution counts as an independent source while it still weighs this much.
const SOURCE_FLOOR: f64 = 0.01;

/// Decayed weight of one contribution at time `now` for half life `h_ms`.
fn decayed(c: &Contribution, now: i64, h_ms: i64) -> f64 {
    let dt = (now - c.time).max(0) as f64;
    c.weighted * 2f64.powf(-dt / h_ms as f64)
}

/// R_e(k)(t): only the strongest finding in each family counts.
pub fn family_score(items: &[Contribution], now: i64, h_ms: i64) -> f64 {
    let mut best: BTreeMap<&str, f64> = BTreeMap::new();
    for c in items {
        let w = decayed(c, now, h_ms);
        let e = best.entry(c.family.as_str()).or_insert(0.0);
        if w > *e {
            *e = w;
        }
    }
    1.0 - best.values().map(|m| 1.0 - m.min(1.0)).product::<f64>()
}

/// The risk of one entity with the facts the policy decision needs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RiskAssessment {
    pub risk: EntityRisk,
    /// All live evidence is machine learning: advisory only.
    pub ml_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskEngine {
    ledgers: BTreeMap<String, EntityLedger>,
    pub half_life_fast_ms: i64,
    pub half_life_slow_ms: i64,
    pub high_confidence: f64,
    weights: BTreeMap<DetectionMethodName, f64>,
}

/// Default weight w per detection method. Tuned per environment in observe mode.
pub fn default_weights() -> BTreeMap<DetectionMethodName, f64> {
    use DetectionMethodName::*;
    [
        (Signatures, 1.0),
        (PositiveSecurity, 1.0),
        (BehaviourBaselines, 0.7),
        (SequenceCorrelation, 0.9),
        (MachineLearning, 0.5),
        (Deception, 1.0),
        (DeclaredIntentDrift, 0.5),
        (ConsequenceInvariants, 1.0),
    ]
    .into_iter()
    .collect()
}

fn method_name(m: i32) -> Option<DetectionMethodName> {
    use ivar_contracts::DetectionMethod as P;
    use DetectionMethodName::*;
    Some(match P::try_from(m).ok()? {
        P::Signatures => Signatures,
        P::PositiveSecurity => PositiveSecurity,
        P::BehaviourBaselines => BehaviourBaselines,
        P::SequenceCorrelation => SequenceCorrelation,
        P::MachineLearning => MachineLearning,
        P::Deception => Deception,
        P::DeclaredIntentDrift => DeclaredIntentDrift,
        P::ConsequenceInvariants => ConsequenceInvariants,
        P::Unspecified => return None,
    })
}

impl RiskEngine {
    pub fn new(t: &Thresholds, weights: &BTreeMap<DetectionMethodName, f64>) -> Self {
        let mut w = default_weights();
        w.extend(weights.iter().map(|(k, v)| (*k, *v)));
        RiskEngine {
            ledgers: BTreeMap::new(),
            half_life_fast_ms: t.half_life_fast_secs.max(1) as i64 * 1000,
            half_life_slow_ms: t.half_life_slow_secs.max(1) as i64 * 1000,
            high_confidence: t.high_confidence,
            weights: w,
        }
    }

    pub fn default_method_weights() -> BTreeMap<DetectionMethodName, f64> {
        default_weights()
    }

    pub fn weight(&self, method: i32) -> f64 {
        method_name(method).and_then(|m| self.weights.get(&m).copied()).unwrap_or(0.5)
    }

    /// Add a finding to every entity named in it, by role.
    pub fn add(&mut self, f: &Finding) {
        let w = self.weight(f.method);
        let c = Contribution {
            finding_id: f.finding_id.clone(),
            family: f.rule_family.clone(),
            weighted: (f.confidence * w).clamp(0.0, 1.0),
            confidence: f.confidence,
            time: f.time,
            source_event: f.source_event.clone(),
            observation_point: f.observation_point.clone(),
            method: f.method,
            deception: f.deception_hit,
            critical: f.critical_positive_security,
        };
        for e in &f.entities {
            let ledger = self.ledgers.entry(e.key()).or_insert_with(|| EntityLedger {
                entity: EntityRef { role: EntityRole::Unspecified as i32, ..e.clone() },
                ..Default::default()
            });
            let list = if e.role == EntityRole::Target as i32 { &mut ledger.targeted } else { &mut ledger.acted };
            if !list.iter().any(|x| x.finding_id == c.finding_id) {
                list.push(c.clone());
            }
        }
    }

    /// Drop evidence that no longer counts on either timescale.
    pub fn prune(&mut self, now: i64) {
        let h = self.half_life_slow_ms;
        for l in self.ledgers.values_mut() {
            l.acted.retain(|c| decayed(c, now, h) >= NEGLIGIBLE);
            l.targeted.retain(|c| decayed(c, now, h) >= NEGLIGIBLE);
        }
        self.ledgers.retain(|_, l| !l.acted.is_empty() || !l.targeted.is_empty());
    }

    pub fn ledger(&self, key: &str) -> Option<&EntityLedger> {
        self.ledgers.get(key)
    }

    pub fn entities(&self) -> impl Iterator<Item = &String> {
        self.ledgers.keys()
    }

    pub fn assess(&self, key: &str, now: i64) -> RiskAssessment {
        let Some(l) = self.ledgers.get(key) else {
            let (t, id) = key.split_once(':').unwrap_or(("unknown", key));
            return RiskAssessment { risk: EntityRisk { entity: Some(EntityRef::actor(t, id)), time: now, ..Default::default() }, ml_only: false };
        };
        let acted_fast = family_score(&l.acted, now, self.half_life_fast_ms);
        let acted_slow = family_score(&l.acted, now, self.half_life_slow_ms);
        let target_only = l.acted.is_empty() && !l.targeted.is_empty();
        let (fast, slow) = if target_only {
            (family_score(&l.targeted, now, self.half_life_fast_ms), family_score(&l.targeted, now, self.half_life_slow_ms))
        } else {
            (acted_fast, acted_slow)
        };
        let live: Vec<&Contribution> = l.acted.iter().filter(|c| decayed(c, now, self.half_life_slow_ms) >= SOURCE_FLOOR).collect();
        let sources: BTreeSet<&str> = live.iter().map(|c| c.source_event.as_str()).collect();
        let mut contributing: Vec<String> = live.iter().map(|c| c.finding_id.clone()).collect();
        contributing.sort();
        let ml_only = !live.is_empty() && live.iter().all(|c| c.is_ml());
        RiskAssessment {
            risk: EntityRisk {
                entity: Some(l.entity.clone()),
                score: fast.max(slow),
                fast_score: fast,
                slow_score: slow,
                contributing_findings: contributing,
                independent_sources: sources.len() as u32,
                has_high_confidence_source: live.iter().any(|c| c.confidence >= self.high_confidence && !c.is_ml()),
                deception_hit: live.iter().any(|c| c.deception),
                critical_positive_security: live.iter().any(|c| c.critical),
                time: now,
                target_only,
            },
            ml_only,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ivar_contracts::DetectionMethod;

    fn f(id: &str, family: &str, c: f64, t: i64, src: &str, entity: EntityRef) -> Finding {
        Finding {
            finding_id: id.into(),
            rule_family: family.into(),
            confidence: c,
            time: t,
            source_event: src.into(),
            method: DetectionMethod::PositiveSecurity as i32,
            entities: vec![entity],
            ..Default::default()
        }
    }

    fn engine() -> RiskEngine {
        RiskEngine::new(&Thresholds::spec_defaults(), &BTreeMap::new())
    }

    #[test]
    fn family_grouping_stops_weak_repeated_signals() {
        let mut r = engine();
        let ip = EntityRef::actor("ip", "203.0.113.9");
        for i in 0..40 {
            r.add(&f(&format!("f{i}"), "recon.route_scan", 0.05, 0, &format!("e{i}"), ip.clone()));
        }
        let a = r.assess("ip:203.0.113.9", 0);
        assert!((a.risk.score - 0.05).abs() < 1e-9, "grouped score {}", a.risk.score);
        let ungrouped = 1.0 - 0.95f64.powi(40);
        assert!((ungrouped - 0.87).abs() < 0.01);
    }

    #[test]
    fn decay_on_two_timescales() {
        let mut r = engine();
        let u = EntityRef::actor("user", "u1");
        r.add(&f("a", "x", 0.8, 0, "e1", u.clone()));
        let half = r.half_life_fast_ms;
        let a = r.assess("user:u1", half);
        assert!((a.risk.fast_score - 0.4).abs() < 1e-9);
        assert!(a.risk.slow_score > 0.79);
        assert_eq!(a.risk.score, a.risk.slow_score);
    }

    #[test]
    fn targets_are_scored_but_flagged() {
        let mut r = engine();
        r.add(&f("a", "credential.spray", 0.7, 0, "e1", EntityRef::target("user", "ceo")));
        let a = r.assess("user:ceo", 0);
        assert!(a.risk.target_only && a.risk.score > 0.6);
    }

    #[test]
    fn same_request_counts_once() {
        let mut r = engine();
        let s = EntityRef::actor("session", "s1");
        r.add(&f("edge", "privesc.role_write", 0.95, 0, "req:r1", s.clone()));
        r.add(&f("sdk", "privesc.role_write", 0.95, 0, "req:r1", s.clone()));
        assert_eq!(r.assess("session:s1", 0).risk.independent_sources, 1);
        r.add(&f("login", "credential.spray_success", 0.4, 0, "req:r0", s));
        assert_eq!(r.assess("session:s1", 0).risk.independent_sources, 2);
    }
}
