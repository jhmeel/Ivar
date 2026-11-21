//! Blast radius budget: automatic containment stops if it would affect more
//! than AUTO_CONTAIN_MAX_USERS_PCT (0.5 percent) of active users in 10
//! minutes. The budget counts established accounts and is split by confidence
//! class, so containing throwaway accounts cannot use it up (section 16.1,
//! budget exhaustion).

use crate::time::MINUTE_MS;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const WINDOW_MS: i64 = 10 * MINUTE_MS;
const ACTIVE_WINDOW_MS: i64 = 24 * 60 * MINUTE_MS;

#[derive(Debug, Clone, Default)]
pub struct BlastRadiusBudget {
    pct: f64,
    /// Containments of established accounts per confidence class.
    spent: BTreeMap<String, VecDeque<i64>>,
    active: BTreeMap<String, i64>,
}

impl BlastRadiusBudget {
    pub fn new(pct: f64) -> Self {
        BlastRadiusBudget { pct, ..Default::default() }
    }

    /// Record an active user so the budget follows real traffic.
    pub fn seen_user(&mut self, user: &str, now: i64) {
        self.active.insert(user.to_string(), now);
    }

    pub fn active_users(&mut self, now: i64) -> usize {
        self.active.retain(|_, t| now - *t <= ACTIVE_WINDOW_MS);
        self.active.len()
    }

    /// How many established accounts one confidence class may contain per window.
    pub fn limit(&mut self, now: i64) -> usize {
        let active = self.active_users(now) as f64;
        ((active * self.pct / 100.0).floor() as usize).max(1)
    }

    /// Try to spend budget. Accounts that are not established never count.
    pub fn try_spend(&mut self, confidence_class: &str, established: bool, now: i64) -> bool {
        if !established {
            return true;
        }
        let limit = self.limit(now);
        let q = self.spent.entry(confidence_class.to_string()).or_default();
        while q.front().map(|t| now - t > WINDOW_MS).unwrap_or(false) {
            q.pop_front();
        }
        if q.len() >= limit {
            return false;
        }
        q.push_back(now);
        true
    }

    pub fn classes(&self) -> BTreeSet<String> {
        self.spent.keys().cloned().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn half_a_percent_per_class_and_throwaways_do_not_count() {
        let mut b = BlastRadiusBudget::new(0.5);
        for i in 0..1000 {
            b.seen_user(&format!("u{i}"), 0);
        }
        assert_eq!(b.limit(0), 5);
        for _ in 0..500 {
            assert!(b.try_spend("two_source", false, 1));
        }
        for _ in 0..5 {
            assert!(b.try_spend("two_source", true, 1));
        }
        assert!(!b.try_spend("two_source", true, 2));
        assert!(b.try_spend("deception", true, 2));
        assert!(b.try_spend("two_source", true, 2 + WINDOW_MS + 1));
    }
}
