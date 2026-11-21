//! Tamper detection: a sensor that stops reporting raises an alert within 60 seconds.

use std::collections::{BTreeMap, BTreeSet};

pub const TAMPER_AFTER_MS: i64 = 60_000;

#[derive(Debug, Clone, Default)]
pub struct TamperMonitor {
    last_seen: BTreeMap<String, i64>,
    alerted: BTreeSet<String>,
}

impl TamperMonitor {
    pub fn seen(&mut self, sensor_id: &str, now: i64) {
        self.last_seen.insert(sensor_id.into(), now);
        self.alerted.remove(sensor_id);
    }

    /// Sensors silent for 60 seconds or more, each reported once per silence.
    pub fn check(&mut self, now: i64) -> Vec<String> {
        let mut out = Vec::new();
        for (s, t) in &self.last_seen {
            if now - t >= TAMPER_AFTER_MS && self.alerted.insert(s.clone()) {
                out.push(s.clone());
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn silent_sensor_alerts_once() {
        let mut m = super::TamperMonitor::default();
        m.seen("edge-1", 0);
        m.seen("sdk-1", 50_000);
        assert_eq!(m.check(60_000), vec!["edge-1"]);
        assert!(m.check(70_000).is_empty());
        m.seen("edge-1", 80_000);
        assert_eq!(m.check(140_000), vec!["edge-1", "sdk-1"]);
    }
}
