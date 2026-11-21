//! Platform independent mapping from Windows observations to OCSF.

#![cfg_attr(not(windows), allow(dead_code))]

use ivar_contracts::SecurityEvent;
use ivar_core::detect::vocabulary as v;
use ivar_core::sensor::ocsf_class;
use ivar_sensor_kit::Sensor;

#[derive(Debug, Clone, PartialEq)]
pub struct WinProcess {
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct WinLogon {
    pub event_id: u32,
    pub user: String,
    pub ip: String,
    pub logon_type: String,
    pub record_id: u64,
}

pub fn process_event(s: &Sensor, host: &str, p: &WinProcess, parent: &str) -> SecurityEvent {
    s.event(ocsf_class::PROCESS_ACTIVITY, v::PROCESS_START).device(host, host, "server").process(p.pid, &p.name.to_lowercase(), &parent.to_lowercase(), "").build()
}

pub fn connection_event(s: &Sensor, host: &str, pid: u32, owner: &str, remote: &str, port: u16) -> SecurityEvent {
    s.event(ocsf_class::NETWORK_ACTIVITY, v::NET_CONNECT).device(host, host, "server").process(pid, &owner.to_lowercase(), "", "").dst(remote, port as u32, "").egress(remote).build()
}

pub fn logon_event(s: &Sensor, host: &str, l: &WinLogon) -> SecurityEvent {
    let (activity, success) = match l.event_id {
        4624 => (v::AUTH_LOGIN, true),
        4625 => (v::AUTH_LOGIN, false),
        4720 => (v::DEVICE_ADMIN_CREATE, true),
        _ => (v::AUTH_LOGIN, true),
    };
    let mut b = s.event(ocsf_class::AUTHENTICATION, activity).device(host, host, "server").status(success).attr("logon_type", &l.logon_type).attr("record_id", &l.record_id.to_string());
    if !l.ip.is_empty() && l.ip != "-" {
        b = b.src_ip(&l.ip);
    }
    if success {
        b = b.user(&l.user, "human");
    } else {
        b = b.target(&format!("user:{}", l.user));
    }
    b.build()
}

pub fn service_event(s: &Sensor, host: &str, service: &str, image: &str) -> SecurityEvent {
    s.event(ocsf_class::PROCESS_ACTIVITY, v::PROCESS_START).device(host, host, "server").process(0, &service.to_lowercase(), "services.exe", image).attr("new_service", "true").build()
}

/// Pull a field out of a rendered event XML (`<Data Name="X">value</Data>`).
pub fn xml_data(xml: &str, name: &str) -> String {
    let key = format!("Name='{name}'>");
    let key2 = format!("Name=\"{name}\">");
    for k in [key, key2] {
        if let Some(i) = xml.find(&k) {
            let rest = &xml[i + k.len()..];
            return rest.split('<').next().unwrap_or("").to_string();
        }
    }
    String::new()
}

pub fn xml_system(xml: &str, tag: &str) -> String {
    let open = format!("<{tag}>");
    xml.find(&open).map(|i| xml[i + open.len()..].split('<').next().unwrap_or("").to_string()).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ivar_contracts::sign::Keyring;
    use ivar_sensor_kit::SensorConfig;

    #[test]
    fn maps_logons_and_processes() {
        let s = Sensor::new(SensorConfig { state_dir: std::env::temp_dir().join("ivar-win-test").display().to_string(), ..Default::default() }, Keyring::default());
        let xml = "<Event><System><EventID>4625</EventID><EventRecordID>77</EventRecordID></System><EventData><Data Name='TargetUserName'>Administrator</Data><Data Name='IpAddress'>203.0.113.9</Data><Data Name='LogonType'>10</Data></EventData></Event>";
        let l = WinLogon { event_id: xml_system(xml, "EventID").parse().unwrap(), user: xml_data(xml, "TargetUserName"), ip: xml_data(xml, "IpAddress"), logon_type: xml_data(xml, "LogonType"), record_id: 77 };
        let ev = logon_event(&s, "dc1", &l);
        assert_eq!(ev.status_id, 2);
        assert_eq!(ev.ext().target_entity, "user:Administrator");
        let p = process_event(&s, "web1", &WinProcess { pid: 9, ppid: 4, name: "cmd.exe".into() }, "w3wp.exe");
        assert_eq!(p.process.as_ref().unwrap().parent_name, "w3wp.exe");
    }
}
