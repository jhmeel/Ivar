//! Behaviour baselines: learn normal activity per user, key, service and host.
//! Best at stolen credentials, insider misuse and data theft; slow, patient
//! attackers can blend in. Baselines learn only after the compromise
//! assessment, so a resident attacker is not learned as normal (section 16.1).

use super::{actor_entities, finding, vocabulary as v, DetectContext, Detector};
use crate::time::SECOND_MS;
use ivar_contracts::{DetectionMethodName, Finding, SecurityEvent};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Default)]
struct Profile {
    last: i64,
    devices: BTreeSet<String>,
    remote_tools: BTreeSet<String>,
    workflows_changed: u64,
}

#[derive(Default)]
pub struct BaselineDetector {
    profiles: BTreeMap<String, Profile>,
    /// Phone numbers with a recent SIM swap: subscriber hash to swap time.
    sim_swaps: BTreeMap<String, i64>,
}

impl BaselineDetector {
    fn subject(ev: &SecurityEvent) -> Option<String> {
        ev.actor.as_ref().and_then(|a| a.user.as_ref()).map(|u| u.uid.clone()).filter(|u| !u.is_empty())
    }
}

impl Detector for BaselineDetector {
    fn evict_idle(&mut self, before: i64) {
        self.profiles.retain(|_, p| p.last >= before);
        self.sim_swaps.retain(|_, t| *t >= before);
    }
    fn name(&self) -> &'static str {
        "behaviour_baselines"
    }
    fn method(&self) -> DetectionMethodName {
        DetectionMethodName::BehaviourBaselines
    }
    fn detect(&mut self, ctx: &DetectContext, ev: &SecurityEvent) -> Vec<Finding> {
        let mut out = Vec::new();
        let ext = ev.ext();
        let actors = actor_entities(ev);
        let learn = ctx.baselines_may_learn;

        if ev.activity_name == v::SIM_SWAP_SIGNAL {
            if let Some(sub) = ext.attributes.get("subscriber") {
                self.sim_swaps.insert(sub.clone(), ext.attributes.get("swapped_at").and_then(|t| t.parse().ok()).unwrap_or(ctx.now));
            }
            return out;
        }
        if let Some(sub) = ext.attributes.get("subscriber") {
            if let Some(swapped) = self.sim_swaps.get(sub) {
                let window = ctx.rules.param_u64("sim_swap_sensitive_action", "window_secs", 172_800) as i64 * SECOND_MS;
                let actions = ctx.rules.param_strings("sim_swap_sensitive_action", "actions");
                let sensitive = actions.iter().any(|a| a == &ext.business_action) || ev.activity_name == v::AUTH_PASSWORD_RESET;
                if sensitive && ctx.now - swapped <= window {
                    out.extend(finding(ctx, ev, "sim_swap_sensitive_action", actors.clone(), format!("{} soon after a SIM swap", ext.business_action)));
                }
            }
        }

        if let Some(t) = ctx.trust {
            if t.new_context {
                out.extend(finding(ctx, ev, "token_new_context", actors.clone(), format!("credential on edge {} presented from a new context", t.edge_id)));
            }
            if t.bulk_anomaly {
                out.extend(finding(ctx, ev, "bulk_read_anomaly", actors.clone(), format!("bulk read far above the usage profile of {}", t.edge_id)));
            }
        }

        let Some(subject) = Self::subject(ev) else { return out };
        let known = self.profiles.contains_key(&subject);
        let profile = self.profiles.entry(subject.clone()).or_default();
        profile.last = ctx.now;
        if let Some(device) = ext.attributes.get("device_id") {
            if known && !profile.devices.contains(device) && ev.activity_name == v::AUTH_LOGIN && ev.status_id == 1 {
                out.extend(finding(ctx, ev, "new_device", actors.clone(), format!("{subject} signed in from a new device")));
            }
            if learn {
                profile.devices.insert(device.clone());
            }
        }
        match ev.activity_name.as_str() {
            v::REMOTE_SESSION => {
                let tool = ext.attributes.get("tool").cloned().unwrap_or_default();
                if !profile.remote_tools.contains(&tool) {
                    out.extend(finding(ctx, ev, "new_remote_session", actors.clone(), format!("new remote session via {tool}")));
                }
                if learn {
                    profile.remote_tools.insert(tool);
                }
            }
            v::DEVICE_ADMIN_CREATE => {
                out.extend(finding(ctx, ev, "new_admin_account", actors.clone(), "new admin account created".into()));
            }
            v::APP_SECRET_CREATE => {
                out.extend(finding(ctx, ev, "new_app_secret", actors.clone(), "new application secret created".into()));
            }
            v::WORKFLOW_CHANGE => {
                if profile.workflows_changed == 0 || !learn {
                    out.extend(finding(ctx, ev, "workflow_change", actors.clone(), "CI workflow changed".into()));
                }
                profile.workflows_changed += 1;
            }
            _ => {}
        }
        out
    }
}
