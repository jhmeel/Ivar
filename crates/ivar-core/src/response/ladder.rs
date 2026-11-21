//! The response ladder table.

use crate::time::{HOUR_MS, MINUTE_MS};
use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Trigger {
    Automatic,
    AutomaticAtHighConfidence,
    PlaybookOrOnCall,
    IncidentLeadOrNarrowPlaybook,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Expiry {
    NotApplicable,
    Fixed(i64),
    PerSession,
    PerRequest,
    /// One hour, doubling on repeat.
    Doubling(i64),
    UntilReviewed,
    UntilReversed,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Rung {
    pub level: u32,
    pub action: &'static str,
    pub examples: &'static str,
    pub trigger: Trigger,
    pub expiry: Expiry,
}

pub const LADDER: [Rung; 7] = [
    Rung { level: 0, action: "Record", examples: "Log the event and raise the entity's risk", trigger: Trigger::Automatic, expiry: Expiry::NotApplicable },
    Rung { level: 1, action: "Slow", examples: "Throttle or delay responses", trigger: Trigger::Automatic, expiry: Expiry::Fixed(15 * MINUTE_MS) },
    Rung { level: 2, action: "Challenge", examples: "OTP, passkey or step up verification", trigger: Trigger::Automatic, expiry: Expiry::PerSession },
    Rung { level: 3, action: "Block request", examples: "Reject one request, query or connection", trigger: Trigger::Automatic, expiry: Expiry::PerRequest },
    Rung { level: 4, action: "Contain identity", examples: "Ban an IP, revoke a session, suspend an API key", trigger: Trigger::AutomaticAtHighConfidence, expiry: Expiry::Doubling(HOUR_MS) },
    Rung { level: 5, action: "Isolate workload", examples: "Kill a process, quarantine a host or pod", trigger: Trigger::PlaybookOrOnCall, expiry: Expiry::UntilReviewed },
    Rung { level: 6, action: "Business kill switch", examples: "Close registration, halt payouts, enter lockdown", trigger: Trigger::IncidentLeadOrNarrowPlaybook, expiry: Expiry::UntilReversed },
];

impl Rung {
    /// Expiry time for an action taken now. `repeats` is how many times this
    /// entity was contained before. Zero means no automatic expiry.
    pub fn expires_at(&self, now: i64, repeats: u32) -> i64 {
        match self.expiry {
            Expiry::Fixed(ms) => now + ms,
            Expiry::Doubling(ms) => now + ms * (1i64 << repeats.min(16)),
            Expiry::PerRequest | Expiry::PerSession | Expiry::NotApplicable | Expiry::UntilReviewed | Expiry::UntilReversed => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn containment_doubles_on_repeat() {
        assert_eq!(LADDER[4].expires_at(0, 0), HOUR_MS);
        assert_eq!(LADDER[4].expires_at(0, 2), 4 * HOUR_MS);
        assert_eq!(LADDER[1].expires_at(0, 9), 15 * MINUTE_MS);
    }
}
