//! Invariant (signed, inside PolicyBundle): measured outcome, window, limit,
//! time lock, approvers, action on breach. Produced by the control plane,
//! consumed by the risk engine and enforcement points.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum MeasuredOutcome {
    ValueMoved,
    RecordsRead,
    DestructiveOperations,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum InvariantScope {
    /// Per acting identity (e.g. per identity data budget, Denmark CPR).
    Identity,
    /// Per business / tenant.
    Business,
    /// Whole estate.
    Global,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TimeLock {
    /// Actions whose single measured value is above this threshold wait `delay_secs`.
    pub threshold: f64,
    /// 30 minutes by default for large hot wallet outflows (§11.1).
    pub delay_secs: u64,
    /// Any one of these owners can cancel.
    pub cancelling_owners: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Invariant {
    pub invariant_id: String,
    /// Business action this invariant guards (payout, export, snapshot_delete, ...). "*" = any.
    pub action: String,
    pub measured_outcome: MeasuredOutcome,
    pub scope: InvariantScope,
    pub window_secs: u64,
    pub limit: f64,
    pub time_lock: Option<TimeLock>,
    pub approvers: Vec<String>,
    pub action_on_breach: String,
}

