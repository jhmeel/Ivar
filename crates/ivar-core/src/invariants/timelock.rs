//! The time lock queue (figure 5). Intent and invariant checks run before any
//! delay, so a time lock only ever holds actions that are already legitimate
//! and within limits. Any one owner can cancel; this holds even when both
//! approvers' machines are compromised.

use crate::ids;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeLockState {
    Held,
    Executed,
    Cancelled,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HeldAction {
    pub lock_id: String,
    pub action: String,
    pub subject: String,
    pub value: f64,
    pub held_at: i64,
    pub release_at: i64,
    pub owners: Vec<String>,
    pub invariant_id: String,
    pub state: TimeLockState,
    pub cancelled_by: Option<String>,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TimeLockQueue {
    held: BTreeMap<String, HeldAction>,
}

impl TimeLockQueue {
    #[allow(clippy::too_many_arguments)]
    pub fn hold(&mut self, action: &str, subject: &str, value: f64, invariant_id: &str, delay_secs: u64, owners: Vec<String>, payload: serde_json::Value, now: i64) -> HeldAction {
        let lock_id = ids::derive("tlk", &[action, subject, &value.to_string(), &now.to_string(), &payload.to_string()]);
        let h = HeldAction {
            lock_id: lock_id.clone(),
            action: action.into(),
            subject: subject.into(),
            value,
            held_at: now,
            release_at: now + delay_secs as i64 * 1000,
            owners,
            invariant_id: invariant_id.into(),
            state: TimeLockState::Held,
            cancelled_by: None,
            payload,
        };
        self.held.insert(lock_id, h.clone());
        h
    }

    /// Any one listed owner can cancel while the action is held.
    pub fn cancel(&mut self, lock_id: &str, owner: &str) -> Result<HeldAction, String> {
        let h = self.held.get_mut(lock_id).ok_or("unknown time lock")?;
        if h.state != TimeLockState::Held {
            return Err(format!("time lock is already {:?}", h.state));
        }
        if !h.owners.iter().any(|o| o == owner) {
            return Err(format!("{owner} is not a cancelling owner"));
        }
        h.state = TimeLockState::Cancelled;
        h.cancelled_by = Some(owner.into());
        Ok(h.clone())
    }

    /// Actions whose delay has ended without a cancellation.
    pub fn due(&mut self, now: i64) -> Vec<HeldAction> {
        let mut out = Vec::new();
        for h in self.held.values_mut() {
            if h.state == TimeLockState::Held && now >= h.release_at {
                h.state = TimeLockState::Executed;
                out.push(h.clone());
            }
        }
        out
    }

    pub fn get(&self, lock_id: &str) -> Option<&HeldAction> {
        self.held.get(lock_id)
    }

    pub fn pending(&self) -> impl Iterator<Item = &HeldAction> {
        self.held.values().filter(|h| h.state == TimeLockState::Held)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn owner_cancels_or_delay_ends() {
        let mut q = TimeLockQueue::default();
        let a = q.hold("payout", "s", 60_000.0, "hot_wallet_outflow", 1800, vec!["user:o1".into(), "user:o2".into()], serde_json::Value::Null, 0);
        assert!(q.cancel(&a.lock_id, "user:mallory").is_err());
        assert!(q.due(1_799_999).is_empty());
        let b = q.hold("payout", "s", 70_000.0, "hot_wallet_outflow", 1800, vec!["user:o1".into()], serde_json::Value::Null, 1);
        assert_eq!(q.cancel(&b.lock_id, "user:o1").unwrap().state, TimeLockState::Cancelled);
        let due = q.due(1_800_001);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].lock_id, a.lock_id);
    }
}
