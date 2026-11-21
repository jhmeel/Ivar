//! Sliding window accounting for each invariant and scope.

use ivar_contracts::{Invariant, InvariantScope, MeasuredOutcome};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum InvariantCheck {
    /// Within every limit and below every lock threshold.
    Within,
    /// Would breach a limit.
    Breach { invariant_id: String, used: f64, limit: f64, action_on_breach: String },
    /// Within limits but above a time lock threshold: hold for the delay.
    Hold { invariant_id: String, delay_secs: u64, owners: Vec<String> },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Ledger {
    /// (time, amount, held)
    entries: VecDeque<(i64, f64, bool)>,
}

impl Ledger {
    fn trim(&mut self, now: i64, window_ms: i64) {
        while self.entries.front().map(|(t, _, _)| now - t > window_ms).unwrap_or(false) {
            self.entries.pop_front();
        }
    }
    fn used(&self) -> f64 {
        self.entries.iter().map(|(_, a, _)| a).sum()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InvariantEngine {
    invariants: Vec<Invariant>,
    ledgers: BTreeMap<String, Ledger>,
}

pub struct Measured<'a> {
    pub action: &'a str,
    pub identity: &'a str,
    pub business: &'a str,
    pub value_moved: f64,
    pub records_read: f64,
    pub destructive: bool,
}

impl InvariantEngine {
    pub fn new(invariants: Vec<Invariant>) -> Self {
        InvariantEngine { invariants, ledgers: BTreeMap::new() }
    }

    pub fn invariants(&self) -> &[Invariant] {
        &self.invariants
    }

    fn amount(inv: &Invariant, m: &Measured) -> f64 {
        match inv.measured_outcome {
            MeasuredOutcome::ValueMoved => m.value_moved,
            MeasuredOutcome::RecordsRead => m.records_read,
            MeasuredOutcome::DestructiveOperations => {
                if m.destructive {
                    1.0
                } else {
                    0.0
                }
            }
        }
    }

    fn key(inv: &Invariant, m: &Measured) -> String {
        let scope = match inv.scope {
            InvariantScope::Identity => m.identity,
            InvariantScope::Business => m.business,
            InvariantScope::Global => "*",
        };
        format!("{}|{}", inv.invariant_id, scope)
    }

    fn applies(inv: &Invariant, m: &Measured) -> bool {
        (inv.action == "*" || inv.action == m.action) && Self::amount(inv, m) > 0.0
    }

    /// Check an action without recording it.
    pub fn check(&mut self, m: &Measured, now: i64) -> InvariantCheck {
        let mut hold = None;
        for inv in &self.invariants {
            if !Self::applies(inv, m) {
                continue;
            }
            let amount = Self::amount(inv, m);
            let ledger = self.ledgers.entry(Self::key(inv, m)).or_default();
            ledger.trim(now, inv.window_secs as i64 * 1000);
            let used = ledger.used();
            if used + amount > inv.limit {
                return InvariantCheck::Breach { invariant_id: inv.invariant_id.clone(), used: used + amount, limit: inv.limit, action_on_breach: inv.action_on_breach.clone() };
            }
            if let Some(lock) = &inv.time_lock {
                if amount > lock.threshold && hold.is_none() {
                    hold = Some(InvariantCheck::Hold { invariant_id: inv.invariant_id.clone(), delay_secs: lock.delay_secs, owners: lock.cancelling_owners.clone() });
                }
            }
        }
        hold.unwrap_or(InvariantCheck::Within)
    }

    /// Record an action that executes, or is held (held actions count too).
    pub fn record(&mut self, m: &Measured, now: i64, held: bool) {
        let keys: Vec<(String, f64)> = self
            .invariants
            .iter()
            .filter(|inv| Self::applies(inv, m))
            .map(|inv| (Self::key(inv, m), Self::amount(inv, m)))
            .collect();
        for (k, a) in keys {
            self.ledgers.entry(k).or_default().entries.push_back((now, a, held));
        }
    }

    /// A cancelled held action stops counting against the limit.
    pub fn release(&mut self, m: &Measured, held_at: i64) {
        let keys: Vec<(String, f64)> = self
            .invariants
            .iter()
            .filter(|inv| Self::applies(inv, m))
            .map(|inv| (Self::key(inv, m), Self::amount(inv, m)))
            .collect();
        for (k, a) in keys {
            if let Some(l) = self.ledgers.get_mut(&k) {
                if let Some(pos) = l.entries.iter().position(|(t, x, h)| *t == held_at && *x == a && *h) {
                    l.entries.remove(pos);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::spec_default_policy;

    fn payout(v: f64) -> Measured<'static> {
        Measured { action: "payout", identity: "svc", business: "acme", value_moved: v, records_read: 0.0, destructive: false }
    }

    #[test]
    fn held_actions_count_against_the_limit() {
        let mut e = InvariantEngine::new(spec_default_policy(0).invariants);
        assert_eq!(e.check(&payout(1_000.0), 0), InvariantCheck::Within);
        let big = payout(60_000.0);
        assert!(matches!(e.check(&big, 0), InvariantCheck::Hold { delay_secs: 1800, .. }));
        for i in 0..16 {
            e.record(&big, i, true);
        }
        assert!(matches!(e.check(&big, 20), InvariantCheck::Breach { .. }), "16 held x 60k = 960k, next breaches 1m");
        e.release(&big, 0);
        assert!(matches!(e.check(&big, 20), InvariantCheck::Hold { .. }));
    }

    #[test]
    fn per_identity_data_budget() {
        let mut e = InvariantEngine::new(spec_default_policy(0).invariants);
        let read = |n: f64| Measured { action: "db.query", identity: "lookup-svc", business: "x", value_moved: 0.0, records_read: n, destructive: false };
        e.record(&read(9_000.0), 0, false);
        assert!(matches!(e.check(&read(2_000.0), 1), InvariantCheck::Breach { ref action_on_breach, .. } if action_on_breach == "suspend_identity"));
    }
}
