//! Intent, invariant and time lock checks on an irreversible action.

use crate::config::IntentBindingMode;
use crate::intent::{IntentError, IntentVerifier, VerifyRequest};
use crate::invariants::{HeldAction, InvariantCheck, InvariantEngine, Measured, TimeLockQueue};
use ivar_contracts::IntentClaims;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SinkRequest {
    pub action: String,
    /// Session or principal presenting the token.
    pub subject: String,
    /// Acting identity for per identity invariants.
    pub identity: String,
    pub business: String,
    pub value_moved: f64,
    pub records_read: f64,
    pub destructive: bool,
    pub intent_token: Option<String>,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum SinkOutcome {
    Executes { claims: Option<IntentClaims> },
    /// No valid intent chain: refused and an incident opened.
    Refused { reason: String },
    /// A consequence invariant would be breached.
    BlockedAlert { invariant_id: String, used: f64, limit: f64, action_on_breach: String },
    /// Above the lock threshold: held for the delay, cancellable by any owner.
    Held { lock: HeldAction },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SinkDecision {
    pub outcome: SinkOutcome,
    pub intent_mode: IntentBindingMode,
    /// In observe mode: what the sink would have refused.
    pub would_refuse: Option<String>,
    pub open_incident: bool,
}

/// What a sink remembers between calls: intents already used, the running
/// totals behind consequence limits, and actions held by a time lock.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SinkState {
    pub consumed: Vec<(String, i64)>,
    pub ledgers: serde_json::Value,
    pub locks: TimeLockQueue,
}

pub struct ActionSink {
    verifier: IntentVerifier,
    invariants: InvariantEngine,
    locks: TimeLockQueue,
    default_mode: IntentBindingMode,
    modes: BTreeMap<String, IntentBindingMode>,
}

impl ActionSink {
    /// Export what this sink remembers, for a host that serves each request
    /// from a fresh process and keeps the state itself.
    pub fn state(&self) -> SinkState {
        SinkState { consumed: self.verifier.consumed(), ledgers: self.invariants.export_ledgers(), locks: self.locks.clone() }
    }

    /// Take up state exported by an earlier `state`.
    pub fn restore(&mut self, s: SinkState) {
        self.verifier.restore_consumed(s.consumed);
        self.invariants.import_ledgers(s.ledgers);
        self.locks = s.locks;
    }

    pub fn new(verifier: IntentVerifier, invariants: InvariantEngine, default_mode: IntentBindingMode, modes: BTreeMap<String, IntentBindingMode>) -> Self {
        ActionSink { verifier, invariants, locks: TimeLockQueue::default(), default_mode, modes }
    }

    pub fn mode(&self, action: &str) -> IntentBindingMode {
        self.modes.get(action).copied().unwrap_or(self.default_mode)
    }

    pub fn set_mode(&mut self, action: &str, mode: IntentBindingMode) {
        self.modes.insert(action.into(), mode);
    }

    pub fn verifier_mut(&mut self) -> &mut IntentVerifier {
        &mut self.verifier
    }

    pub fn locks(&self) -> &TimeLockQueue {
        &self.locks
    }

    fn measured<'a>(r: &'a SinkRequest) -> Measured<'a> {
        Measured { action: &r.action, identity: &r.identity, business: &r.business, value_moved: r.value_moved, records_read: r.records_read, destructive: r.destructive }
    }

    pub fn guard(&mut self, r: &SinkRequest, now: i64) -> SinkDecision {
        let mode = self.mode(&r.action);
        let mut would_refuse = None;
        let mut claims = None;

        // 1. Intent valid?
        if mode != IntentBindingMode::Off {
            let measures: BTreeMap<String, i64> = [("amount".to_string(), r.value_moved.round() as i64), ("records".to_string(), r.records_read.round() as i64)].into_iter().collect();
            let vr = VerifyRequest { token: r.intent_token.as_deref(), action: &r.action, subject: &r.subject, measures: &measures, now_ms: now };
            match self.verifier.verify_and_consume(&vr) {
                Ok(c) => claims = Some(c),
                Err(e) => {
                    let reason = describe(&e);
                    if mode == IntentBindingMode::Enforce {
                        return SinkDecision { outcome: SinkOutcome::Refused { reason }, intent_mode: mode, would_refuse: None, open_incident: true };
                    }
                    would_refuse = Some(reason);
                }
            }
        }

        // 2. Within limit?  3. Above lock?
        let m = Self::measured(r);
        let outcome = match self.invariants.check(&m, now) {
            InvariantCheck::Breach { invariant_id, used, limit, action_on_breach } => {
                return SinkDecision { outcome: SinkOutcome::BlockedAlert { invariant_id, used, limit, action_on_breach }, intent_mode: mode, would_refuse, open_incident: true };
            }
            InvariantCheck::Hold { invariant_id, delay_secs, owners } => {
                self.invariants.record(&m, now, true);
                let value = if r.value_moved > 0.0 { r.value_moved } else { r.records_read };
                let lock = self.locks.hold(&r.action, &r.subject, value, &invariant_id, delay_secs, owners, r.payload.clone(), now);
                SinkOutcome::Held { lock }
            }
            InvariantCheck::Within => {
                self.invariants.record(&m, now, false);
                SinkOutcome::Executes { claims }
            }
        };
        SinkDecision { outcome, intent_mode: mode, open_incident: would_refuse.is_some(), would_refuse }
    }

    /// Any one owner cancels a held action; it stops counting against the limit.
    pub fn cancel(&mut self, lock_id: &str, owner: &str, request: &SinkRequest) -> Result<HeldAction, String> {
        let h = self.locks.cancel(lock_id, owner)?;
        self.invariants.release(&Self::measured(request), h.held_at);
        Ok(h)
    }

    /// Held actions whose delay ended: they execute now.
    pub fn release_due(&mut self, now: i64) -> Vec<HeldAction> {
        self.locks.due(now)
    }
}

fn describe(e: &IntentError) -> String {
    match e {
        IntentError::Missing => "no intent chain: a valid credential with no business reason behind it".into(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{IntentIssuer, Narrowing, StepAttestor};
    use crate::policy::spec_default_policy;

    fn sink(mode: IntentBindingMode) -> (ActionSink, IntentIssuer, Vec<StepAttestor>) {
        let issuer = IntentIssuer::from_seed(&[1; 32]).unwrap();
        let steps: Vec<StepAttestor> = ["authenticated_session", "ledger_entry", "payout_instruction"]
            .iter()
            .enumerate()
            .map(|(i, s)| StepAttestor::from_seed(s, &[i as u8 + 2; 32]).unwrap())
            .collect();
        let keys = steps.iter().map(|s| (s.step.clone(), s.public_key_hex())).collect();
        let v = IntentVerifier::new(&issuer.public_key_hex(), keys);
        let s = ActionSink::new(v, InvariantEngine::new(spec_default_policy(0).invariants), mode, BTreeMap::new());
        (s, issuer, steps)
    }

    fn token(issuer: &IntentIssuer, steps: &[StepAttestor], id: &str, limit: i64) -> String {
        let mut t = issuer.mint(id, "payout", "ses_1", &[("amount".to_string(), limit)].into_iter().collect(), 10_000_000).unwrap();
        for s in steps {
            t = s.attest(&t, &issuer.public_key_hex(), &Narrowing::default()).unwrap();
        }
        t
    }

    fn req(value: f64, token: Option<String>) -> SinkRequest {
        SinkRequest { action: "payout".into(), subject: "ses_1".into(), identity: "svc".into(), business: "acme".into(), value_moved: value, intent_token: token, ..Default::default() }
    }

    #[test]
    fn figure_5_paths() {
        let (mut s, issuer, steps) = sink(IntentBindingMode::Enforce);
        // Attacker: valid stolen login, no intent chain.
        let d = s.guard(&req(100.0, None), 1);
        assert!(matches!(d.outcome, SinkOutcome::Refused { .. }) && d.open_incident);
        // Legitimate and small: executes.
        let d = s.guard(&req(100.0, Some(token(&issuer, &steps, "i1", 5_000))), 2);
        assert!(matches!(d.outcome, SinkOutcome::Executes { claims: Some(_) }));
        // Legitimate and large: held for the 30 minute delay.
        let big = req(60_000.0, Some(token(&issuer, &steps, "i2", 100_000)));
        let d = s.guard(&big, 3);
        let SinkOutcome::Held { lock } = d.outcome else { panic!("expected hold") };
        assert_eq!(lock.release_at, 3 + 1_800_000);
        assert!(s.cancel(&lock.lock_id, "user:treasury-owner-1", &big).is_ok());
    }

    #[test]
    fn observe_mode_shows_what_it_would_refuse() {
        let (mut s, _, _) = sink(IntentBindingMode::Observe);
        let d = s.guard(&req(100.0, None), 1);
        assert!(matches!(d.outcome, SinkOutcome::Executes { claims: None }));
        assert!(d.would_refuse.is_some());
    }
}
