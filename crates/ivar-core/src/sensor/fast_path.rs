//! The sensor local decision: known bad requests are blocked in the sensor.

use crate::declare::Declarations;
use crate::detect::vocabulary as v;
use crate::ids;
use ivar_contracts::{EntityRef, PolicyContent, SecurityEvent, Verdict};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub enum LocalDecision {
    /// Known attack: block here, no round trip.
    Block(Verdict),
    /// A cached verdict from the core still applies to this entity.
    Cached(Verdict),
    /// Forward to the core for correlation and scoring.
    Forward,
}

/// The part of a signed policy bundle a sensor enforces on its own.
pub struct SensorPolicy {
    policy_version: String,
    decoy_routes: BTreeMap<String, String>,
    declared: Declarations,
    /// Engine rule ids that are blocked locally (critical CRS, Suricata drop rules ...).
    block_alerts: Vec<String>,
    /// Verdicts pushed by the core: entity key to verdict.
    verdicts: BTreeMap<String, Verdict>,
    pub enforce: bool,
}

impl SensorPolicy {
    /// Build from a verified policy, refusing one whose declared intent does
    /// not parse: a sensor never runs without the positive security its
    /// policy declares.
    pub fn try_from_policy(p: &PolicyContent) -> Result<Self, String> {
        Declarations::parse(&p.declared).map_err(|e| format!("declared intent does not parse: {e}"))?;
        Ok(Self::from_policy(p))
    }

    pub fn from_policy(p: &PolicyContent) -> Self {
        let decoy_routes = p.decoys.iter().filter(|d| d.kind == "route").map(|d| (d.marker.clone(), d.decoy_id.clone())).collect();
        let block_alerts = p
            .settings
            .get("sensor_block_alerts")
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
            .unwrap_or_default();
        let enforce = p.settings.get("detection_mode").and_then(|v| v.as_str()) == Some("enforce");
        SensorPolicy {
            policy_version: p.policy_version.clone(),
            decoy_routes,
            declared: Declarations::from_value(&p.declared),
            block_alerts,
            verdicts: BTreeMap::new(),
            enforce,
        }
    }

    /// Adopt a newer verified policy, keeping the verdicts already cached so
    /// enforcement does not lapse while the next ones arrive.
    pub fn replace_policy(&mut self, p: &PolicyContent) -> Result<(), String> {
        let mut next = Self::try_from_policy(p)?;
        next.verdicts = std::mem::take(&mut self.verdicts);
        *self = next;
        Ok(())
    }

    /// Whether a core verdict applies to the entity's later requests. Level 3
    /// blocks only the request it judged (reversal none, per request), so it
    /// never carries over; containment (level 4) holds until it expires or
    /// is reversed; throttles and challenges carry over only while they have
    /// an expiry, so no response short of containment is open ended.
    fn carries_over(v: &Verdict, now: i64) -> bool {
        match v.decision.as_str() {
            "contain" => v.expires_at == 0 || v.expires_at > now,
            "throttle" | "challenge" => v.expires_at > now,
            _ => false,
        }
    }

    pub fn push_verdict(&mut self, v: Verdict) {
        if let Some(e) = &v.entity {
            self.verdicts.insert(e.key(), v);
        }
    }

    fn verdict(&self, decision: &str, reason: &str, entity: EntityRef, ev: &SecurityEvent, now: i64) -> Verdict {
        let ext = ev.ext();
        Verdict {
            verdict_id: ids::derive("vrd", &[&ext.sensor_id, &ext.sensor_seq.to_string(), reason]),
            decision: decision.into(),
            entity: Some(entity),
            risk: 1.0,
            reasons: vec![reason.into()],
            sources: vec![ext.sensor_type.clone()],
            policy_version: self.policy_version.clone(),
            expires_at: 0,
            mode: if self.enforce { "enforce".into() } else { "observe".into() },
            evidence_ids: vec![],
            time: now,
            ladder_level: 3,
        }
    }

    pub fn decide(&self, ev: &SecurityEvent, now: i64) -> LocalDecision {
        let ext = ev.ext();
        let ip = ev.src_endpoint.as_ref().map(|s| s.ip.clone()).unwrap_or_default();
        let entity = EntityRef::actor("ip", &ip);
        for key in crate::detect::actor_entities(ev).iter().map(|e| e.key()) {
            if let Some(v) = self.verdicts.get(&key) {
                if Self::carries_over(v, now) {
                    return LocalDecision::Cached(v.clone());
                }
            }
        }
        if let Some(rule) = ext.engine_alerts.iter().find(|a| self.block_alerts.contains(a)) {
            return LocalDecision::Block(self.verdict("block", &format!("known_attack:{rule}"), entity, ev, now));
        }
        if let Some(req) = &ev.http_request {
            let path = req.url_path.split('?').next().unwrap_or("");
            if let Some(decoy) = self.decoy_routes.get(path) {
                return LocalDecision::Block(self.verdict("block", &format!("decoy_route:{decoy}"), entity, ev, now));
            }
            if let Some(route) = self.declared.match_route(&req.http_method, &req.url_path) {
                let roles = ev.actor.as_ref().map(|a| a.authorizations.clone()).unwrap_or_default();
                let privileged_write = req.body_keys.iter().any(|k| route.privileged_properties.contains(k))
                    && !route.roles.iter().any(|r| r != "self" && roles.split(',').any(|x| x.trim() == r));
                if privileged_write {
                    return LocalDecision::Block(self.verdict("block", "privileged_field_write", entity, ev, now));
                }
            }
        }
        if ev.activity_name == v::PROCESS_START {
            if let Some(p) = &ev.process {
                if v::SHELLS.contains(&p.name.as_str()) && v::WEB_PROCESSES.contains(&p.parent_name.as_str()) {
                    let proc = EntityRef::actor("process", &format!("{}/{}", ev.device.as_ref().map(|d| d.hostname.as_str()).unwrap_or(""), p.pid));
                    return LocalDecision::Block(self.verdict("block", "web_process_shell", proc, ev, now));
                }
            }
        }
        LocalDecision::Forward
    }
}
