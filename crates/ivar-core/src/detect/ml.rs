//! Machine learning: scores unusual combinations of signals. Hard to explain,
//! so it is advisory only: it raises suspicion but can never block alone
//! (the policy decision caps ML only evidence at the throttle rung).
//!
//! The model is a streaming per entity z score over a small feature vector,
//! deterministic so a replay reproduces it.

use super::{actor_entities, finding_with_confidence, DetectContext, Detector};
use ivar_contracts::{DetectionMethodName, Finding, SecurityEvent};
use std::collections::BTreeMap;

const FEATURES: usize = 4;
const MIN_SAMPLES: f64 = 30.0;

#[derive(Default, Clone)]
struct Stats {
    last: i64,
    n: f64,
    mean: [f64; FEATURES],
    m2: [f64; FEATURES],
}

impl Stats {
    fn update(&mut self, x: &[f64; FEATURES]) {
        self.n += 1.0;
        for i in 0..FEATURES {
            let d = x[i] - self.mean[i];
            self.mean[i] += d / self.n;
            self.m2[i] += d * (x[i] - self.mean[i]);
        }
    }
    fn score(&self, x: &[f64; FEATURES]) -> f64 {
        if self.n < MIN_SAMPLES {
            return 0.0;
        }
        let mut z2 = 0.0;
        for i in 0..FEATURES {
            let var = (self.m2[i] / (self.n - 1.0)).max(1e-6);
            z2 += (x[i] - self.mean[i]).powi(2) / var;
        }
        let z = (z2 / FEATURES as f64).sqrt();
        1.0 - (-z / 3.0).exp()
    }
}

#[derive(Default)]
pub struct MlDetector {
    stats: BTreeMap<String, Stats>,
}

fn features(ev: &SecurityEvent) -> [f64; FEATURES] {
    let ext = ev.ext();
    let hour = ((ev.time / 3_600_000) % 24) as f64;
    [
        hour,
        (ext.records_read as f64 + 1.0).ln(),
        (ext.value_moved + 1.0).ln(),
        ev.http_response.as_ref().map(|r| r.code as f64 / 100.0).unwrap_or(0.0),
    ]
}

impl Detector for MlDetector {
    fn evict_idle(&mut self, before: i64) {
        self.stats.retain(|_, s| s.last >= before);
    }
    fn name(&self) -> &'static str {
        "machine_learning"
    }
    fn method(&self) -> DetectionMethodName {
        DetectionMethodName::MachineLearning
    }
    fn detect(&mut self, ctx: &DetectContext, ev: &SecurityEvent) -> Vec<Finding> {
        let Some(subject) = ev.actor.as_ref().and_then(|a| a.user.as_ref()).map(|u| u.uid.clone()).filter(|u| !u.is_empty()) else {
            return vec![];
        };
        let x = features(ev);
        let stats = self.stats.entry(subject.clone()).or_default();
        stats.last = ctx.now;
        let score = stats.score(&x);
        if ctx.baselines_may_learn {
            stats.update(&x);
        }
        if score >= ctx.rules.param_f64("ml_anomaly", "threshold", 0.8) {
            return finding_with_confidence(ctx, ev, "ml_anomaly", actor_entities(ev), format!("unusual signal combination for {subject} (score {score:.2})"), Some(score * 0.5))
                .into_iter()
                .collect();
        }
        vec![]
    }
}

#[cfg(test)]
mod eviction {
    use super::*;

    #[test]
    fn idle_entities_are_forgotten_active_ones_kept() {
        let mut d = MlDetector::default();
        d.stats.insert("idle".into(), Stats { last: 1_000, ..Default::default() });
        d.stats.insert("active".into(), Stats { last: 9_000, ..Default::default() });
        d.evict_idle(5_000);
        assert!(!d.stats.contains_key("idle"));
        assert!(d.stats.contains_key("active"));
    }
}
