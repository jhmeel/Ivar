//! Circuit breaker: only the rule that changed returns to observe mode, and
//! only when blocks of legitimate looking traffic or application errors spike
//! after the change, so an attack flood cannot switch off the fleet.

use crate::time::MINUTE_MS;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const WINDOW_MS: i64 = 10 * MINUTE_MS;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BreakerEvent {
    /// A block on an established, otherwise clean entity.
    LegitimateLookingBlock,
    /// A 5xx from the application after a block decision.
    ApplicationError,
    /// A block on a high risk or unestablished source: never counts.
    AttackBlock,
}

#[derive(Debug, Clone, Default)]
pub struct CircuitBreaker {
    /// rule id to the time its content last changed
    changed_at: BTreeMap<String, i64>,
    events: BTreeMap<String, VecDeque<i64>>,
    tripped: BTreeSet<String>,
    pub threshold: usize,
}

impl CircuitBreaker {
    pub fn new(threshold: usize) -> Self {
        CircuitBreaker { threshold, ..Default::default() }
    }

    pub fn rule_changed(&mut self, rule: &str, now: i64) {
        self.changed_at.insert(rule.into(), now);
        self.events.remove(rule);
        self.tripped.remove(rule);
    }

    /// Record an outcome for a rule. Returns true when this trips the rule.
    pub fn record(&mut self, rule: &str, ev: BreakerEvent, now: i64) -> bool {
        if ev == BreakerEvent::AttackBlock {
            return false;
        }
        let Some(changed) = self.changed_at.get(rule).copied() else { return false };
        if now - changed > WINDOW_MS * 6 {
            return false;
        }
        let q = self.events.entry(rule.into()).or_default();
        q.push_back(now);
        while q.front().map(|t| now - t > WINDOW_MS).unwrap_or(false) {
            q.pop_front();
        }
        if q.len() >= self.threshold && self.tripped.insert(rule.into()) {
            return true;
        }
        false
    }

    pub fn is_tripped(&self, rule: &str) -> bool {
        self.tripped.contains(rule)
    }

    pub fn tripped(&self) -> impl Iterator<Item = &String> {
        self.tripped.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attack_flood_cannot_trip_and_only_changed_rule_trips() {
        let mut b = CircuitBreaker::new(5);
        b.rule_changed("mass_assignment", 0);
        for i in 0..1000 {
            assert!(!b.record("mass_assignment", BreakerEvent::AttackBlock, i));
        }
        for i in 0..10 {
            assert!(!b.record("route_404", BreakerEvent::LegitimateLookingBlock, i));
        }
        let mut tripped = false;
        for i in 0..5 {
            tripped |= b.record("mass_assignment", BreakerEvent::LegitimateLookingBlock, i);
        }
        assert!(tripped && b.is_tripped("mass_assignment") && !b.is_tripped("route_404"));
    }
}
