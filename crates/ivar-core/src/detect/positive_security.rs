//! Positive security: allow only what OpenAPI schemas, roles and process
//! profiles permit. Best at mass assignment, role writes and unexpected
//! binaries; needs accurate schemas and profiles.

use super::{actor_entities, finding, vocabulary as v, DetectContext, Detector};
use ivar_contracts::{DetectionMethodName, Finding, SecurityEvent};

#[derive(Default)]
pub struct PositiveSecurityDetector;

impl PositiveSecurityDetector {
    fn http(&self, ctx: &DetectContext, ev: &SecurityEvent, out: &mut Vec<Finding>) {
        let Some(req) = &ev.http_request else { return };
        let actors = actor_entities(ev);
        let status = ev.http_response.as_ref().map(|r| r.code).unwrap_or(0);
        let route = ctx.declared.match_route(&req.http_method, &req.url_path);
        let Some(route) = route else {
            if ctx.declared.routes.is_empty() {
                return;
            }
            if status == 0 || status == 404 || status == 405 {
                out.extend(finding(ctx, ev, "route_404", actors, format!("{} {} is not in the schema", req.http_method, req.url_path)));
            } else if (200..300).contains(&status) {
                out.extend(finding(ctx, ev, "shadow_route", actors, format!("{} {} answered but is missing from the schema", req.http_method, req.url_path)));
            }
            return;
        };
        let roles: Vec<String> = ev
            .actor
            .as_ref()
            .map(|a| a.authorizations.split(',').map(|r| r.trim().to_string()).filter(|r| !r.is_empty()).collect())
            .unwrap_or_default();
        for key in &req.body_keys {
            if route.privileged_properties.iter().any(|p| p == key) {
                let allowed = !route.roles.is_empty() && route.roles.iter().any(|r| r != "self" && roles.contains(r));
                if !allowed {
                    out.extend(finding(ctx, ev, "privileged_field_write", actors.clone(), format!("write to privileged field `{key}` on {}", route.template)));
                }
            } else if !route.allowed_properties.iter().any(|p| p == key) {
                out.extend(finding(ctx, ev, "mass_assignment", actors.clone(), format!("undeclared field `{key}` on {}", route.template)));
            }
        }
        if let Some(owner) = ev.ext().attributes.get("record_owner") {
            let me = ev.actor.as_ref().and_then(|a| a.user.as_ref()).map(|u| u.uid.clone()).unwrap_or_default();
            if !owner.is_empty() && !me.is_empty() && owner != &me && !roles.iter().any(|r| r == "admin" || r == "support") {
                out.extend(finding(ctx, ev, "cross_tenant_access", actors, format!("access to another user's record on {}", route.template)));
            }
        }
    }

    fn process(&self, ctx: &DetectContext, ev: &SecurityEvent, out: &mut Vec<Finding>) {
        let Some(p) = &ev.process else { return };
        let actors = actor_entities(ev);
        let name = p.name.rsplit('/').next().unwrap_or(&p.name);
        let parent = p.parent_name.rsplit('/').next().unwrap_or(&p.parent_name);
        if v::SHELLS.contains(&name) && v::WEB_PROCESSES.contains(&parent) {
            out.extend(finding(ctx, ev, "web_process_shell", actors.clone(), format!("web process {parent} started shell {name}")));
            return;
        }
        let workload = ev.ext().attributes.get("workload").cloned().unwrap_or_default();
        if let Some(profile) = ctx.declared.profile_for(&workload) {
            if !profile.allowed_binaries.iter().any(|b| b == name) {
                out.extend(finding(ctx, ev, "unexpected_binary", actors, format!("{name} is not in the process profile of {workload} ({})", profile.declared_in)));
            }
        }
    }

    fn supply_chain(&self, ctx: &DetectContext, ev: &SecurityEvent, out: &mut Vec<Finding>) {
        let ext = ev.ext();
        let actors = actor_entities(ev);
        let name = ext.attributes.get("package").cloned().unwrap_or_default();
        let version = ext.attributes.get("version").cloned().unwrap_or_default();
        let integrity = ext.attributes.get("integrity").cloned().unwrap_or_default();
        match ctx.declared.packages.get(&name) {
            Some(pinned) if pinned.version != version || (!pinned.integrity.is_empty() && pinned.integrity != integrity) => {
                out.extend(finding(ctx, ev, "package_integrity_mismatch", actors, format!("{name}@{version} does not match the lockfile pin {}@{}", pinned.name, pinned.version)));
            }
            None if !ctx.declared.packages.is_empty() => {
                out.extend(finding(ctx, ev, "package_unpinned", actors, format!("{name}@{version} is not pinned in any lockfile")));
            }
            _ => {}
        }
    }

    fn egress(&self, ctx: &DetectContext, ev: &SecurityEvent, out: &mut Vec<Finding>) {
        let ext = ev.ext();
        if ext.egress_destination.is_empty() {
            return;
        }
        let holder = ext.attributes.get("holder").cloned().unwrap_or_default();
        if ext.sensor_type == "build_runner" && !ctx.declared.egress_declared(&holder, &ext.egress_destination) {
            out.extend(finding(ctx, ev, "build_undeclared_egress", actor_entities(ev), format!("build egress to {} is not declared (default deny)", ext.egress_destination)));
        }
    }

    fn allowlists(&self, ctx: &DetectContext, ev: &SecurityEvent, out: &mut Vec<Finding>) {
        let ext = ev.ext();
        let actors = actor_entities(ev);
        let tool = ext.attributes.get("tool").cloned().unwrap_or_default();
        match ev.activity_name.as_str() {
            v::REMOTE_SESSION => {
                let allow = ctx.rules.param_strings("remote_tool_not_allowlisted", "allowlist");
                if !allow.is_empty() && !allow.contains(&tool) {
                    out.extend(finding(ctx, ev, "remote_tool_not_allowlisted", actors, format!("remote access tool {tool} is not allowlisted")));
                }
            }
            v::EXTENSION_INSTALL => {
                let allow = ctx.rules.param_strings("extension_not_allowlisted", "allowlist");
                let ext_name = ext.attributes.get("extension").cloned().unwrap_or_default();
                if !allow.is_empty() && !allow.contains(&ext_name) {
                    out.extend(finding(ctx, ev, "extension_not_allowlisted", actors, format!("extension {ext_name} is not allowlisted")));
                }
            }
            v::DATASET_LOAD => {
                if ext.attributes.get("code_execution").map(|c| c == "true").unwrap_or(false) {
                    out.extend(finding(ctx, ev, "code_exec_during_load", actors, "code executed while loading data or a model".into()));
                }
            }
            v::IAM_GRANT | v::OAUTH_GRANT => {
                let grantee = ext.attributes.get("grantee").cloned().unwrap_or_default();
                let granter = ev.actor.as_ref().and_then(|a| a.user.as_ref()).map(|u| u.uid.clone()).unwrap_or_default();
                if !grantee.is_empty() && grantee == granter {
                    out.extend(finding(ctx, ev, "app_self_granted_role", actors, format!("{granter} granted itself {}", ext.attributes.get("role").cloned().unwrap_or_default())));
                }
            }
            _ => {}
        }
    }

    fn trust(&self, ctx: &DetectContext, ev: &SecurityEvent, out: &mut Vec<Finding>) {
        let Some(t) = ctx.trust else { return };
        let actors = actor_entities(ev);
        if t.outside_purpose {
            let rule = if ev.activity_name == v::AI_TOOL_CALL { "agent_tool_outside_scope" } else { "outside_delegated_purpose" };
            out.extend(finding(ctx, ev, rule, actors.clone(), format!("trust edge {} used outside its delegated purpose", t.edge_id)));
        }
        if t.expired_or_revoked {
            out.extend(finding(ctx, ev, "revoked_credential_use", actors, format!("revoked or expired trust edge {} presented", t.edge_id)));
        }
    }
}

impl Detector for PositiveSecurityDetector {
    fn name(&self) -> &'static str {
        "positive_security"
    }
    fn method(&self) -> DetectionMethodName {
        DetectionMethodName::PositiveSecurity
    }
    fn detect(&mut self, ctx: &DetectContext, ev: &SecurityEvent) -> Vec<Finding> {
        let mut out = Vec::new();
        match ev.activity_name.as_str() {
            v::HTTP_REQUEST | v::BUSINESS_ACTION => self.http(ctx, ev, &mut out),
            v::PROCESS_START => self.process(ctx, ev, &mut out),
            v::PACKAGE_INSTALL => self.supply_chain(ctx, ev, &mut out),
            _ => {}
        }
        self.egress(ctx, ev, &mut out);
        self.allowlists(ctx, ev, &mut out);
        self.trust(ctx, ev, &mut out);
        out
    }
}
