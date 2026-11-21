//! The IVAR settings table (section 15) and its resolver.

use super::flags::SignedFlag;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DetectionMode {
    Observe,
    Enforce,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum AiAutonomy {
    /// A0: nothing.
    Off,
    /// A1: summarise, rank and explain. Default.
    Advise,
    /// A2: prepare actions for approval.
    Propose,
    /// A3: trigger pre approved actions up to level 3.
    Bounded,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimePosture {
    Standard,
    Payments,
    Lockdown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IntentBindingMode {
    Off,
    Observe,
    Enforce,
}

/// The three security profiles of the existing hardening guide.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    Standard,
    Payments,
    Lockdown,
}

macro_rules! str_enum {
    ($t:ty { $($v:ident => $s:literal),* }) => {
        impl $t {
            pub fn as_str(self) -> &'static str { match self { $(Self::$v => $s),* } }
            pub fn parse(s: &str) -> Option<Self> { match s.trim().to_ascii_lowercase().as_str() { $($s => Some(Self::$v),)* _ => None } }
        }
    };
}
str_enum!(DetectionMode { Observe => "observe", Enforce => "enforce" });
str_enum!(AiAutonomy { Off => "off", Advise => "advise", Propose => "propose", Bounded => "bounded" });
str_enum!(RuntimePosture { Standard => "standard", Payments => "payments", Lockdown => "lockdown" });
str_enum!(IntentBindingMode { Off => "off", Observe => "observe", Enforce => "enforce" });
str_enum!(Profile { Standard => "standard", Payments => "payments", Lockdown => "lockdown" });

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Settings {
    /// DETECTION_MODE: whether sensors block or only record. Runtime.
    pub detection_mode: DetectionMode,
    /// AUTO_CONTAIN_MAX_USERS_PCT: blast radius budget for automatic containment.
    pub auto_contain_max_users_pct: f64,
    /// AI_AUTONOMY: how far the AI layer may act.
    pub ai_autonomy: AiAutonomy,
    /// EVIDENCE_RETENTION: minimum searchable evidence retention, in days.
    pub evidence_retention_days: u32,
    /// RUNTIME_POSTURE: signed, fleet wide posture. Runtime.
    pub runtime_posture: RuntimePosture,
    /// INTENT_BINDING: default mode. Runtime, per action type.
    pub intent_binding: IntentBindingMode,
    pub intent_binding_per_action: BTreeMap<String, IntentBindingMode>,
    /// TIME_LOCKS: path of the structured file with threshold, delay and
    /// cancelling owners for each irreversible action.
    pub time_locks_file: String,
    /// FAIL_OPEN_BUDGET_PCT: share of requests per route that may pass
    /// uninspected before throttling.
    pub fail_open_budget_pct: f64,
    /// RISK_HALF_LIVES: fast and slow decay for risk scoring, in seconds.
    pub risk_half_life_fast_secs: u64,
    pub risk_half_life_slow_secs: u64,
    /// The compromise assessment is done, so baselines may learn (section 19, phase 1 exit).
    pub compromise_assessment_done: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SettingsWarning {
    pub setting: String,
    pub message: String,
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ConfigError {
    #[error("{setting}: {message}")]
    Invalid { setting: String, message: String },
}

fn invalid(setting: &str, message: impl Into<String>) -> ConfigError {
    ConfigError::Invalid { setting: setting.into(), message: message.into() }
}

/// Parse "30m", "7d", "12h", "45s" or plain seconds.
pub fn parse_duration_secs(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num, mult) = match s.chars().last()? {
        's' => (&s[..s.len() - 1], 1),
        'm' => (&s[..s.len() - 1], 60),
        'h' => (&s[..s.len() - 1], 3600),
        'd' => (&s[..s.len() - 1], 86_400),
        c if c.is_ascii_digit() => (s, 1),
        _ => return None,
    };
    num.trim().parse::<u64>().ok().map(|n| n * mult)
}

impl Settings {
    pub fn spec_defaults() -> Self {
        Settings {
            detection_mode: DetectionMode::Observe,
            auto_contain_max_users_pct: 0.5,
            ai_autonomy: AiAutonomy::Advise,
            evidence_retention_days: 400,
            runtime_posture: RuntimePosture::Standard,
            intent_binding: IntentBindingMode::Observe,
            intent_binding_per_action: BTreeMap::new(),
            time_locks_file: "time-locks.yaml".into(),
            fail_open_budget_pct: 0.1,
            risk_half_life_fast_secs: 30 * 60,
            risk_half_life_slow_secs: 7 * 86_400,
            compromise_assessment_done: false,
        }
    }

    /// Profile defaults. Payments and lockdown start stricter.
    pub fn for_profile(p: Profile) -> Self {
        let mut s = Self::spec_defaults();
        match p {
            Profile::Standard => {}
            Profile::Payments => {
                s.runtime_posture = RuntimePosture::Payments;
            }
            Profile::Lockdown => {
                s.runtime_posture = RuntimePosture::Lockdown;
                s.detection_mode = DetectionMode::Enforce;
            }
        }
        s
    }

    pub fn intent_mode(&self, action: &str) -> IntentBindingMode {
        self.intent_binding_per_action.get(action).copied().unwrap_or(self.intent_binding)
    }

    /// Resolve order: profile default, environment override, hard limits and
    /// cross checks, then signed runtime flags (already verified by the
    /// FlagResolver; only runtime settings may be flagged).
    pub fn resolve(
        profile: Profile,
        env: &BTreeMap<String, String>,
        runtime_flags: &[SignedFlag],
    ) -> Result<(Settings, Vec<SettingsWarning>), ConfigError> {
        let mut s = Self::for_profile(profile);
        let mut warnings = Vec::new();

        for (k, v) in env {
            match k.as_str() {
                "DETECTION_MODE" => s.detection_mode = DetectionMode::parse(v).ok_or_else(|| invalid(k, "observe or enforce"))?,
                "AUTO_CONTAIN_MAX_USERS_PCT" => s.auto_contain_max_users_pct = v.trim().parse().map_err(|_| invalid(k, "a number"))?,
                "AI_AUTONOMY" => s.ai_autonomy = AiAutonomy::parse(v).ok_or_else(|| invalid(k, "off, advise, propose or bounded"))?,
                "EVIDENCE_RETENTION" => {
                    if v.trim() == "forever" {
                        // Defect F9: `forever` is limited to the two ban settings.
                        return Err(invalid(k, "`forever` is only allowed on the two ban settings"));
                    }
                    s.evidence_retention_days = (parse_duration_secs(v).ok_or_else(|| invalid(k, "a duration such as 400d"))? / 86_400) as u32;
                }
                "RUNTIME_POSTURE" => s.runtime_posture = RuntimePosture::parse(v).ok_or_else(|| invalid(k, "standard, payments or lockdown"))?,
                "INTENT_BINDING" => {
                    for part in v.split(',') {
                        match part.split_once('=') {
                            Some((action, mode)) => {
                                let m = IntentBindingMode::parse(mode).ok_or_else(|| invalid(k, "off, observe or enforce"))?;
                                s.intent_binding_per_action.insert(action.trim().to_string(), m);
                            }
                            None => s.intent_binding = IntentBindingMode::parse(part).ok_or_else(|| invalid(k, "off, observe or enforce"))?,
                        }
                    }
                }
                "TIME_LOCKS" => s.time_locks_file = v.clone(),
                "FAIL_OPEN_BUDGET_PCT" => s.fail_open_budget_pct = v.trim().parse().map_err(|_| invalid(k, "a number"))?,
                "RISK_HALF_LIVES" => {
                    let (a, b) = v.split_once(',').ok_or_else(|| invalid(k, "fast,slow such as 30m,7d"))?;
                    s.risk_half_life_fast_secs = parse_duration_secs(a).ok_or_else(|| invalid(k, "fast half life"))?;
                    s.risk_half_life_slow_secs = parse_duration_secs(b).ok_or_else(|| invalid(k, "slow half life"))?;
                }
                "COMPROMISE_ASSESSMENT_DONE" => s.compromise_assessment_done = v.trim() == "true",
                _ => {}
            }
        }

        s.check_limits(&mut warnings)?;

        for f in runtime_flags {
            match f.name.as_str() {
                "DETECTION_MODE" => s.detection_mode = DetectionMode::parse(&f.value).ok_or_else(|| invalid(&f.name, "observe or enforce"))?,
                "RUNTIME_POSTURE" => s.runtime_posture = RuntimePosture::parse(&f.value).ok_or_else(|| invalid(&f.name, "standard, payments or lockdown"))?,
                "INTENT_BINDING" => s.intent_binding = IntentBindingMode::parse(&f.value).ok_or_else(|| invalid(&f.name, "off, observe or enforce"))?,
                n if n.starts_with("INTENT_BINDING.") => {
                    let action = n.trim_start_matches("INTENT_BINDING.");
                    s.intent_binding_per_action.insert(action.into(), IntentBindingMode::parse(&f.value).ok_or_else(|| invalid(n, "off, observe or enforce"))?);
                }
                _ => {}
            }
        }
        Ok((s, warnings))
    }

    fn check_limits(&self, warnings: &mut Vec<SettingsWarning>) -> Result<(), ConfigError> {
        if !(self.auto_contain_max_users_pct > 0.0 && self.auto_contain_max_users_pct <= 5.0) {
            return Err(invalid("AUTO_CONTAIN_MAX_USERS_PCT", "must be above 0 and at most 5"));
        }
        if !(0.0..=1.0).contains(&self.fail_open_budget_pct) {
            return Err(invalid("FAIL_OPEN_BUDGET_PCT", "must be between 0 and 1"));
        }
        if self.evidence_retention_days < 90 {
            return Err(invalid("EVIDENCE_RETENTION", "evidence must stay searchable well beyond 90 days"));
        }
        if self.evidence_retention_days < 400 {
            warnings.push(SettingsWarning { setting: "EVIDENCE_RETENTION".into(), message: "below the 400 day default; espionage dwell time is 122 days".into() });
        }
        if self.risk_half_life_fast_secs == 0 || self.risk_half_life_fast_secs >= self.risk_half_life_slow_secs {
            return Err(invalid("RISK_HALF_LIVES", "the fast half life must be shorter than the slow one"));
        }
        if self.ai_autonomy == AiAutonomy::Bounded && !self.compromise_assessment_done {
            warnings.push(SettingsWarning { setting: "AI_AUTONOMY".into(), message: "bounded autonomy before the compromise assessment".into() });
        }
        Ok(())
    }

    pub fn to_map(&self) -> BTreeMap<String, serde_json::Value> {
        let v = serde_json::to_value(self).unwrap_or_default();
        v.as_object().cloned().unwrap_or_default().into_iter().collect()
    }

    pub fn from_map(m: &BTreeMap<String, serde_json::Value>) -> Self {
        let mut base = serde_json::to_value(Self::spec_defaults()).unwrap_or_default();
        if let Some(obj) = base.as_object_mut() {
            for (k, v) in m {
                obj.insert(k.clone(), v.clone());
            }
        }
        serde_json::from_value(base).unwrap_or_else(|_| Self::spec_defaults())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect()
    }

    #[test]
    fn defaults_match_the_settings_table() {
        let s = Settings::spec_defaults();
        assert_eq!(s.detection_mode, DetectionMode::Observe);
        assert_eq!(s.auto_contain_max_users_pct, 0.5);
        assert_eq!(s.ai_autonomy, AiAutonomy::Advise);
        assert_eq!(s.evidence_retention_days, 400);
        assert_eq!(s.fail_open_budget_pct, 0.1);
        assert_eq!((s.risk_half_life_fast_secs, s.risk_half_life_slow_secs), (1800, 604_800));
    }

    #[test]
    fn env_override_then_limits_then_flags() {
        let (s, _) = Settings::resolve(Profile::Standard, &env(&[("INTENT_BINDING", "observe,payout=enforce"), ("RISK_HALF_LIVES", "15m,3d")]), &[]).unwrap();
        assert_eq!(s.intent_mode("payout"), IntentBindingMode::Enforce);
        assert_eq!(s.intent_mode("deploy"), IntentBindingMode::Observe);
        assert_eq!(s.risk_half_life_fast_secs, 900);
        assert!(Settings::resolve(Profile::Standard, &env(&[("EVIDENCE_RETENTION", "30d")]), &[]).is_err());
        assert!(Settings::resolve(Profile::Standard, &env(&[("EVIDENCE_RETENTION", "forever")]), &[]).is_err());
        assert!(Settings::resolve(Profile::Standard, &env(&[("AUTO_CONTAIN_MAX_USERS_PCT", "50")]), &[]).is_err());
        let flag = SignedFlag { name: "RUNTIME_POSTURE".into(), value: "lockdown".into(), version: 2, issued_at: 0, signature: None };
        let (s, _) = Settings::resolve(Profile::Standard, &BTreeMap::new(), &[flag]).unwrap();
        assert_eq!(s.runtime_posture, RuntimePosture::Lockdown);
    }
}
