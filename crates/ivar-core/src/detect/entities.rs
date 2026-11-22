//! Which entities acted in an event, and which were only targeted.
//! Each finding raises risk on the entities that acted (section 10.1):
//! the IP, user, session, API key, device, process, host and service.

use ivar_contracts::{EntityRef, SecurityEvent};

pub fn actor_entities(ev: &SecurityEvent) -> Vec<EntityRef> {
    let mut out = Vec::new();
    let ext = ev.ext();
    if let Some(src) = &ev.src_endpoint {
        if !src.ip.is_empty() {
            out.push(EntityRef::actor("ip", &src.ip));
        }
    }
    if let Some(actor) = &ev.actor {
        if let Some(u) = &actor.user {
            if !u.uid.is_empty() {
                let t = match u.r#type.as_str() {
                    "agent" => "agent",
                    "service" => "service",
                    "token" | "api_key" => "api_key",
                    _ => "user",
                };
                out.push(EntityRef::actor(t, &u.uid));
            }
        }
        if let Some(s) = &actor.session {
            if !s.uid.is_empty() {
                out.push(EntityRef::actor("session", &s.uid));
            }
        }
        if !actor.app_name.is_empty() {
            out.push(EntityRef::actor("service", &actor.app_name));
        }
    }
    if let Some(k) = ext.attributes.get("api_key") {
        out.push(EntityRef::actor("api_key", k));
    }
    if let Some(g) = ext.attributes.get("oauth_grant") {
        out.push(EntityRef::actor("oauth_grant", g));
    }
    if let Some(d) = ext.attributes.get("device_id") {
        out.push(EntityRef::actor("device", d));
    }
    if let Some(dev) = &ev.device {
        if let Some(p) = &ev.process {
            if p.pid != 0 {
                out.push(EntityRef::actor("process", &format!("{}/{}", dev.hostname, p.pid)));
            }
        }
        if !dev.hostname.is_empty() {
            out.push(EntityRef::actor("host", &dev.hostname));
        }
    }
    out.sort_by_cached_key(|e| e.key());
    out.dedup_by(|a, b| a.r#type == b.r#type && a.id == b.id && a.role == b.role);
    out
}

pub fn target_entities(ev: &SecurityEvent) -> Vec<EntityRef> {
    let ext = ev.ext();
    ext.target_entity
        .split(',')
        .filter_map(|t| t.split_once(':'))
        .map(|(t, id)| EntityRef::target(t, id))
        .collect()
}
