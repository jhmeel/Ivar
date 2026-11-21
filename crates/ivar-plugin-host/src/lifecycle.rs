//! The activation lifecycle (figure 8): a plugin earns activation stage by
//! stage and is removed on any breach.
//!
//! Verify (signature) to Check (permissions) to Shadow (records only) to
//! Canary (small group) to Active (full fleet). Signature or permission
//! failure ends in Rejected. A crash, limit or access breach in Shadow,
//! Canary or Active ends in Disabled with an alert. Verdict drift beyond
//! tolerance in Canary or Active returns the plugin to Shadow.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Stage {
    Verify,
    Check,
    Shadow,
    Canary,
    Active,
    Rejected,
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transition {
    SignatureValid,
    SignatureInvalid,
    PermissionsOk,
    PermissionsDenied,
    /// Shadow results and the attack replay library passed.
    ShadowPassed,
    CanaryPassed,
    Breach,
    Drift,
}

impl Stage {
    pub fn next(self, t: Transition) -> Result<Stage, String> {
        use Stage::*;
        use Transition::*;
        let s = match (self, t) {
            (Verify, SignatureValid) => Check,
            (Verify, SignatureInvalid) => Rejected,
            (Check, PermissionsOk) => Shadow,
            (Check, PermissionsDenied) => Rejected,
            (Shadow, ShadowPassed) => Canary,
            (Canary, CanaryPassed) => Active,
            (Shadow | Canary | Active, Breach) => Disabled,
            (Canary | Active, Drift) => Shadow,
            (Shadow, Drift) => Shadow,
            (s, t) => return Err(format!("{t:?} is not allowed in stage {s:?}")),
        };
        Ok(s)
    }

    /// Whether the plugin's output affects decisions.
    pub fn enforces(self) -> bool {
        matches!(self, Stage::Canary | Stage::Active)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn figure_8() {
        let s = Stage::Verify.next(Transition::SignatureValid).unwrap().next(Transition::PermissionsOk).unwrap();
        assert_eq!(s, Stage::Shadow);
        assert!(!s.enforces());
        let a = s.next(Transition::ShadowPassed).unwrap().next(Transition::CanaryPassed).unwrap();
        assert_eq!(a, Stage::Active);
        assert_eq!(a.next(Transition::Drift).unwrap(), Stage::Shadow);
        assert_eq!(a.next(Transition::Breach).unwrap(), Stage::Disabled);
        assert_eq!(Stage::Verify.next(Transition::SignatureInvalid).unwrap(), Stage::Rejected);
        assert!(Stage::Rejected.next(Transition::ShadowPassed).is_err());
        assert!(Stage::Shadow.next(Transition::CanaryPassed).is_err(), "no skipping canary");
    }
}
