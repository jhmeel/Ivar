//! Drift monitoring. Signing and sandboxing protect the host, not the
//! verdict: a detector that always returns benign, or a parser that drops 5%
//! of events, passes both checks. Each plugin is watched for drift in its
//! drop rate and verdict distribution against its own history and its replay
//! results; drift beyond its declared tolerance moves it back to shadow mode.

use ivar_contracts::DriftTolerance;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default)]
pub struct Window {
    pub inputs: u64,
    pub outputs: u64,
    pub verdicts: BTreeMap<String, u64>,
}

impl Window {
    pub fn record(&mut self, produced_output: bool, verdict: &str) {
        self.inputs += 1;
        if produced_output {
            self.outputs += 1;
        }
        *self.verdicts.entry(verdict.to_string()).or_insert(0) += 1;
    }

    pub fn drop_rate(&self) -> f64 {
        if self.inputs == 0 {
            0.0
        } else {
            1.0 - self.outputs as f64 / self.inputs as f64
        }
    }

    fn distribution(&self) -> BTreeMap<String, f64> {
        let total: u64 = self.verdicts.values().sum();
        self.verdicts.iter().map(|(k, v)| (k.clone(), *v as f64 / total.max(1) as f64)).collect()
    }
}

/// Total variation distance between two verdict distributions.
pub fn tvd(a: &Window, b: &Window) -> f64 {
    let (da, db) = (a.distribution(), b.distribution());
    let keys: std::collections::BTreeSet<&String> = da.keys().chain(db.keys()).collect();
    keys.iter().map(|k| (da.get(*k).unwrap_or(&0.0) - db.get(*k).unwrap_or(&0.0)).abs()).sum::<f64>() / 2.0
}

#[derive(Debug, Clone, PartialEq)]
pub struct DriftReport {
    pub drop_rate_change: f64,
    pub verdict_distance: f64,
    pub drifted: bool,
}

/// Compare the current window with the plugin's history (or replay baseline).
pub fn compare(history: &Window, current: &Window, tol: &DriftTolerance) -> DriftReport {
    let drop_rate_change = (current.drop_rate() - history.drop_rate()).abs();
    let verdict_distance = tvd(history, current);
    DriftReport { drop_rate_change, verdict_distance, drifted: drop_rate_change > tol.drop_rate || verdict_distance > tol.verdict_distribution }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window(n: u64, dropped: u64, malicious: u64) -> Window {
        let mut w = Window::default();
        for i in 0..n {
            w.record(i >= dropped, if i < malicious { "malicious" } else { "benign" });
        }
        w
    }

    #[test]
    fn silent_plugins_drift() {
        let tol = DriftTolerance::default();
        let history = window(1000, 0, 50);
        assert!(!compare(&history, &window(1000, 2, 48), &tol).drifted);
        assert!(compare(&history, &window(1000, 50, 50), &tol).drifted, "parser drops 5 percent");
        let always_benign = window(1000, 0, 0);
        let r = compare(&history, &always_benign, &DriftTolerance { drop_rate: 0.01, verdict_distribution: 0.02 });
        assert!(r.drifted, "detector that always returns benign");
    }
}
