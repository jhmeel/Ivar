//! Turning an event into a trust graph observation.

use crate::detect::vocabulary as v;
use crate::trust::Observation;
use ivar_contracts::{EntityRef, SecurityEvent};

/// The identity that used trust in this event, most specific first.
pub fn holder(ev: &SecurityEvent) -> Option<EntityRef> {
    let ext = ev.ext();
    if let Some(k) = ext.attributes.get("api_key") {
        return Some(EntityRef::actor("api_key", k));
    }
    if let Some(g) = ext.attributes.get("oauth_grant") {
        return Some(EntityRef::actor("oauth_grant", g));
    }
    let actor = ev.actor.as_ref()?;
    if let Some(u) = &actor.user {
        if !u.uid.is_empty() && matches!(u.r#type.as_str(), "agent" | "service" | "token" | "api_key") {
            let t = if u.r#type == "token" { "api_key" } else { u.r#type.as_str() };
            return Some(EntityRef::actor(t, &u.uid));
        }
    }
    if !actor.app_name.is_empty() {
        return Some(EntityRef::actor("service", &actor.app_name));
    }
    if let Some(u) = &actor.user {
        if !u.uid.is_empty() {
            return Some(EntityRef::actor("user", &u.uid));
        }
    }
    None
}

/// The trust relationship this event used, if it used one.
pub fn observation(ev: &SecurityEvent, now: i64) -> Option<Observation> {
    let ext = ev.ext();
    let holder = holder(ev)?;
    let attr = |k: &str| ext.attributes.get(k).cloned().unwrap_or_default();
    let (resource, permission) = match ev.activity_name.as_str() {
        v::DB_QUERY => (format!("db:{}", attr("table")), attr("operation").to_lowercase()),
        v::SECRET_READ => (format!("secret:{}", attr("secret")), "read".into()),
        v::AI_TOOL_CALL => (format!("tool:{}", attr("tool")), "call".into()),
        v::NET_CONNECT => {
            let d = ev.dst_endpoint.as_ref()?;
            let dest = if d.hostname.is_empty() { d.ip.clone() } else { d.hostname.clone() };
            (format!("net:{dest}"), "connect".into())
        }
        v::CLOUD_AUDIT | v::IAM_GRANT | v::OAUTH_GRANT => (attr("resource"), attr("operation")),
        v::BUSINESS_ACTION => (format!("action:{}", ext.business_action), "invoke".into()),
        v::HTTP_REQUEST if holder.r#type != "user" => {
            let r = ev.http_request.as_ref()?;
            (if ext.declared_route.is_empty() { r.url_path.clone() } else { ext.declared_route.clone() }, r.http_method.to_lowercase())
        }
        _ => return None,
    };
    if resource.is_empty() {
        return None;
    }
    let context = ext
        .attributes
        .get("device_id")
        .cloned()
        .or_else(|| ev.src_endpoint.as_ref().map(|s| s.ip.clone()))
        .unwrap_or_default();
    Some(Observation {
        holder,
        resource,
        permission,
        context,
        records: ext.records_read as f64,
        action: ev.activity_name.clone(),
        time: now,
    })
}
