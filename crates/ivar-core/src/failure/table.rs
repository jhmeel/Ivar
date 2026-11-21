//! The failure table, declared so operators read it the way they read policy.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    CoreUnreachable,
    EdgeFilterCrashOrTimeout,
    AdminRouteCheckFails,
    FlagStoreUnavailable,
    KillSwitchStateMissingAtStartup,
    PolicySignatureInvalid,
    SensorStopsReporting,
    FailOpenBudgetExceeded,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct FailureBehaviour {
    pub failure: Failure,
    pub behaviour: &'static str,
    pub reason: &'static str,
}

pub const FAILURE_TABLE: &[FailureBehaviour] = &[
    FailureBehaviour { failure: Failure::CoreUnreachable, behaviour: "Sensors keep enforcing their last signed policy and buffer events", reason: "Protection continues during an outage" },
    FailureBehaviour { failure: Failure::EdgeFilterCrashOrTimeout, behaviour: "Public traffic fails open within a fail open budget and raises an alert, and every request that timed out is flagged and inspected again asynchronously", reason: "A security fault should not stop payments" },
    FailureBehaviour { failure: Failure::AdminRouteCheckFails, behaviour: "Request fails closed", reason: "Admin access is too sensitive to allow unchecked" },
    FailureBehaviour { failure: Failure::FlagStoreUnavailable, behaviour: "Use the last signed state saved on disk", reason: "Corrects defect F1" },
    FailureBehaviour { failure: Failure::KillSwitchStateMissingAtStartup, behaviour: "Hold the safest state and alert", reason: "A restart must never reopen payouts" },
    FailureBehaviour { failure: Failure::PolicySignatureInvalid, behaviour: "Reject the update and keep the current policy", reason: "A compromised channel cannot weaken protection" },
    FailureBehaviour { failure: Failure::SensorStopsReporting, behaviour: "Raise a tamper alert within 60 seconds", reason: "Silence may be the attack" },
    FailureBehaviour { failure: Failure::FailOpenBudgetExceeded, behaviour: "Traffic on the affected routes is throttled to a safe rate and on call is paged", reason: "Requests crafted to time out the filter may be an attempt to bypass it" },
];

pub fn behaviour_for(f: Failure) -> &'static FailureBehaviour {
    FAILURE_TABLE.iter().find(|b| b.failure == f).expect("every failure has a behaviour")
}
