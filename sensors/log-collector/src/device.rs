//! Device audit logs to OCSF: FortiGate, Cisco IOS and SD WAN, and generic
//! key=value appliances. Edge devices lack host telemetry, so these logs are
//! the early warning for new admins, logins and software downgrades.

use ivar_contracts::SecurityEvent;
use ivar_core::detect::vocabulary as v;
use ivar_core::sensor::ocsf_class;
use ivar_sensor_kit::Sensor;
use regex::Regex;
use std::collections::BTreeMap;
use std::sync::OnceLock;

fn kv() -> &'static Regex {
    static R: OnceLock<Regex> = OnceLock::new();
    R.get_or_init(|| Regex::new(r#"(\w+)=("[^"]*"|\S+)"#).unwrap())
}

pub fn pairs(msg: &str) -> BTreeMap<String, String> {
    kv().captures_iter(msg).map(|c| (c[1].to_string(), c[2].trim_matches('"').to_string())).collect()
}

fn version_tuple(v: &str) -> Vec<u64> {
    v.split(|c: char| !c.is_ascii_digit()).filter(|s| !s.is_empty()).filter_map(|s| s.parse().ok()).collect()
}

#[derive(Default)]
pub struct DeviceState {
    versions: BTreeMap<String, String>,
}

impl DeviceState {
    fn version_change(&mut self, s: &Sensor, host: &str, version: &str, user: &str) -> SecurityEvent {
        let prev = self.versions.insert(host.to_string(), version.to_string());
        let direction = match &prev {
            Some(p) if version_tuple(version) < version_tuple(p) => "downgrade",
            Some(p) if version_tuple(version) > version_tuple(p) => "upgrade",
            _ => "same",
        };
        let mut b = s.event(ocsf_class::APPLICATION_LIFECYCLE, v::DEVICE_VERSION_CHANGE).device(host, host, "appliance").attr("to", version).attr("from", prev.as_deref().unwrap_or("")).attr("direction", direction);
        if !user.is_empty() {
            b = b.user(user, "human");
        }
        b.build()
    }

    pub fn map(&mut self, s: &Sensor, host: &str, msg: &str) -> SecurityEvent {
        let p = pairs(msg);
        let g = |k: &str| p.get(k).cloned().unwrap_or_default();
        // FortiGate
        if p.contains_key("logid") {
            let user = g("user");
            let src = [g("srcip"), g("ui").rsplit('(').next().unwrap_or("").trim_end_matches(')').to_string()].into_iter().find(|x| x.parse::<std::net::IpAddr>().is_ok()).unwrap_or_default();
            if g("cfgpath") == "system.admin" && g("action") == "Add" {
                return s.event(ocsf_class::ACCOUNT_CHANGE, v::DEVICE_ADMIN_CREATE).device(host, host, "appliance").user(&user, "human").attr("new_admin", &g("cfgobj")).build();
            }
            if !g("version").is_empty() && (g("action").contains("upgrade") || g("logdesc").to_lowercase().contains("firmware")) {
                return self.version_change(s, host, &g("version"), &user);
            }
            if g("action") == "login" || g("logdesc").to_lowercase().contains("login") {
                let ok = g("status") == "success";
                let mut b = s.event(ocsf_class::AUTHENTICATION, v::AUTH_LOGIN).device(host, host, "appliance").status(ok);
                if !src.is_empty() {
                    b = b.src_ip(&src);
                }
                b = if ok { b.user(&user, "human") } else { b.target(&format!("user:{user}")) };
                return b.build();
            }
        }
        // Cisco IOS and SD WAN
        if msg.contains("%SEC_LOGIN-5-LOGIN_SUCCESS") || msg.contains("%SEC_LOGIN-4-LOGIN_FAILED") {
            let ok = msg.contains("SUCCESS");
            let user = msg.split("[user: ").nth(1).and_then(|r| r.split(']').next()).unwrap_or("").to_string();
            let src = msg.split("[Source: ").nth(1).and_then(|r| r.split(']').next()).unwrap_or("").to_string();
            let mut b = s.event(ocsf_class::AUTHENTICATION, v::AUTH_LOGIN).device(host, host, "appliance").status(ok);
            if !src.is_empty() {
                b = b.src_ip(&src);
            }
            return if ok { b.user(&user, "human").build() } else { b.target(&format!("user:{user}")).build() };
        }
        if msg.contains("%AAA-5-USER_ADD") || msg.contains("username") && msg.contains("privilege 15") {
            return s.event(ocsf_class::ACCOUNT_CHANGE, v::DEVICE_ADMIN_CREATE).device(host, host, "appliance").build();
        }
        if let Some(ver) = msg.split("Version ").nth(1).map(|r| r.split([',', ' ']).next().unwrap_or("").to_string()).filter(|v| !v.is_empty()) {
            return self.version_change(s, host, &ver, "");
        }
        // Hypervisors and backup systems (management plane): vCenter and ESXi,
        // Proxmox, Veeam. Destructive operations become destructive events so
        // consequence invariants and the backup deletion rule see them.
        let lower = msg.to_lowercase();
        let user = msg.split("User ").nth(1).or_else(|| msg.split("user=").nth(1)).map(|r| r.split([' ', '@', ',']).next().unwrap_or("").to_string()).unwrap_or_default();
        let destructive = [
            ("removesnapshot", v::SNAPSHOT_DELETE), ("snapshot removed", v::SNAPSHOT_DELETE), ("vmremovedevent", v::VM_MASS_ACTION), ("destroy vm", v::VM_MASS_ACTION), ("qmdestroy", v::VM_MASS_ACTION),
            ("delsnapshot", v::SNAPSHOT_DELETE), ("backup job was deleted", v::BACKUP_CHANGE), ("restore point deleted", v::SNAPSHOT_DELETE), ("backup files deleted", v::BACKUP_CHANGE), ("immutability", v::BACKUP_CHANGE),
        ];
        if let Some((_, act)) = destructive.iter().find(|(k, _)| lower.contains(k)) {
            let mut b = s.event(ocsf_class::API_ACTIVITY, act).device(host, host, "hypervisor").destructive().attr("operation", &msg.chars().take(200).collect::<String>());
            if !user.is_empty() {
                b = b.user(&user, "human");
            }
            return b.build();
        }
        // Anything else is kept as a generic log event.
        let mut ev = s.event(ocsf_class::API_ACTIVITY, "device.log").device(host, host, "appliance").build();
        ev.message = msg.chars().take(1024).collect();
        ev
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ivar_contracts::sign::Keyring;
    use ivar_sensor_kit::SensorConfig;

    #[test]
    fn edge_device_signals() {
        let s = Sensor::new(SensorConfig { state_dir: std::env::temp_dir().join("ivar-logc").display().to_string(), ..Default::default() }, Keyring::default());
        let mut d = DeviceState::default();
        let e = d.map(&s, "fw-1", r#"logid="0100044547" type="event" subtype="system" user="admin" action="Add" cfgpath="system.admin" cfgobj="backdoor""#);
        assert_eq!(e.activity_name, "device.admin_create");
        d.map(&s, "rtr-1", "%SYS-6-BOOTTIME: Cisco IOS XE Software, Version 17.12.4, RELEASE");
        let e = d.map(&s, "rtr-1", "%SYS-6-BOOTTIME: Cisco IOS XE Software, Version 17.3.1, RELEASE");
        assert_eq!(e.ext().attributes["direction"], "downgrade");
        let e = d.map(&s, "rtr-1", "%SEC_LOGIN-4-LOGIN_FAILED: Login failed [user: admin] [Source: 203.0.113.7]");
        assert_eq!(e.status_id, 2);
        assert_eq!(e.src_endpoint.unwrap().ip, "203.0.113.7");
        let mut core = ivar_core::DecisionCore::new(ivar_core::policy::spec_default_policy(0), Default::default()).unwrap();
        let o = core.process(d.map(&s, "rtr-2", "Version 17.12.1"), 1);
        assert!(o.findings.is_empty());
        let o = core.process(d.map(&s, "rtr-2", "Version 16.9.1"), 2);
        assert!(o.findings.iter().any(|f| f.rule == "version_downgrade"));
        let e = d.map(&s, "vc-1", "Task: Remove snapshot, RemoveSnapshot_Task on vm db-01 User admin@vsphere.local");
        assert!(e.ext().destructive && e.activity_name == "snapshot.delete");
        let e = d.map(&s, "veeam-1", "Backup job was deleted: Nightly-SQL by user=ops");
        assert!(e.ext().destructive);
    }
}
