//! Helpers to build OCSF SecurityEvents with the IVAR extension.

use ivar_contracts::*;

/// OCSF class uids used by the sensors.
pub mod ocsf_class {
    pub const HTTP_ACTIVITY: u32 = 4002;
    pub const AUTHENTICATION: u32 = 3002;
    pub const ACCOUNT_CHANGE: u32 = 3001;
    pub const PROCESS_ACTIVITY: u32 = 1007;
    pub const FILE_ACTIVITY: u32 = 1001;
    pub const NETWORK_ACTIVITY: u32 = 4001;
    pub const DNS_ACTIVITY: u32 = 4003;
    pub const API_ACTIVITY: u32 = 6003;
    pub const DATASTORE_ACTIVITY: u32 = 6005;
    pub const DETECTION_FINDING: u32 = 2004;
    pub const APPLICATION_LIFECYCLE: u32 = 6002;
}

fn category_of(class_uid: u32) -> u32 {
    class_uid / 1000
}

/// Fluent builder used by every sensor adapter.
pub struct EventBuilder {
    ev: SecurityEvent,
}

impl EventBuilder {
    pub fn new(class_uid: u32, activity: &str, time: i64, sensor_id: &str, sensor_type: &str, seq: u64) -> Self {
        let ev = SecurityEvent {
            class_uid,
            category_uid: category_of(class_uid),
            activity_id: 1,
            type_uid: class_uid as u64 * 100 + 1,
            time,
            severity_id: 1,
            status_id: 1,
            activity_name: activity.into(),
            metadata: Some(OcsfMetadata {
                version: OCSF_VERSION.into(),
                product: Some(OcsfProduct { name: "ivar".into(), vendor_name: "ivar".into(), version: env!("CARGO_PKG_VERSION").into() }),
                profiles: vec![],
                extensions: vec![OcsfExtension { name: OCSF_EXTENSION_NAME.into(), uid: OCSF_EXTENSION_UID.into(), version: OCSF_EXTENSION_VERSION.into() }],
                uid: String::new(),
                correlation_uid: String::new(),
            }),
            ivar: Some(IvarExtension { sensor_id: sensor_id.into(), sensor_type: sensor_type.into(), observation_point: sensor_type.into(), sensor_seq: seq, ..Default::default() }),
            ..Default::default()
        };
        EventBuilder { ev }
    }

    fn ext(&mut self) -> &mut IvarExtension {
        self.ev.ivar.get_or_insert_with(Default::default)
    }

    pub fn src_ip(mut self, ip: &str) -> Self {
        self.ev.src_endpoint.get_or_insert_with(Default::default).ip = ip.into();
        self
    }
    pub fn dst(mut self, ip: &str, port: u32, hostname: &str) -> Self {
        let d = self.ev.dst_endpoint.get_or_insert_with(Default::default);
        d.ip = ip.into();
        d.port = port;
        d.hostname = hostname.into();
        self
    }
    pub fn user(mut self, uid: &str, kind: &str) -> Self {
        let a = self.ev.actor.get_or_insert_with(Default::default);
        a.user = Some(OcsfUser { uid: uid.into(), name: String::new(), r#type: kind.into(), org_uid: String::new() });
        self
    }
    pub fn roles(mut self, roles: &str) -> Self {
        self.ev.actor.get_or_insert_with(Default::default).authorizations = roles.into();
        self
    }
    pub fn session(mut self, uid: &str) -> Self {
        self.ev.actor.get_or_insert_with(Default::default).session = Some(OcsfSession { uid: uid.into(), is_new: false, issuer: String::new() });
        self
    }
    pub fn app(mut self, name: &str) -> Self {
        self.ev.actor.get_or_insert_with(Default::default).app_name = name.into();
        self
    }
    pub fn device(mut self, uid: &str, hostname: &str, kind: &str) -> Self {
        self.ev.device = Some(OcsfDevice { uid: uid.into(), hostname: hostname.into(), r#type: kind.into(), region: String::new() });
        self
    }
    pub fn process(mut self, pid: u32, name: &str, parent: &str, file_path: &str) -> Self {
        self.ev.process = Some(OcsfProcess { pid, name: name.into(), parent_name: parent.into(), file_path: file_path.into(), ..Default::default() });
        self
    }
    pub fn http(mut self, method: &str, path: &str, body_keys: &[&str], status: u32) -> Self {
        self.ev.http_request = Some(OcsfHttpRequest { http_method: method.into(), url_path: path.into(), user_agent: String::new(), body_keys: body_keys.iter().map(|s| s.to_string()).collect() });
        self.ev.http_response = Some(OcsfHttpResponse { code: status, latency_ms: 0 });
        self
    }
    pub fn status(mut self, success: bool) -> Self {
        self.ev.status_id = if success { 1 } else { 2 };
        self.ev.status = if success { "Success".into() } else { "Failure".into() };
        self
    }
    pub fn target(mut self, entity: &str) -> Self {
        self.ext().target_entity = entity.into();
        self
    }
    pub fn request_id(mut self, id: &str) -> Self {
        self.ext().request_id = id.into();
        self
    }
    pub fn business_action(mut self, a: &str) -> Self {
        self.ext().business_action = a.into();
        self
    }
    pub fn intent(mut self, token: &str) -> Self {
        self.ext().intent_token = token.into();
        self
    }
    pub fn observation_point(mut self, p: &str) -> Self {
        self.ext().observation_point = p.into();
        self
    }
    pub fn attr(mut self, k: &str, v: &str) -> Self {
        self.ext().attributes.insert(k.into(), v.into());
        self
    }
    pub fn engine_alert(mut self, rule: &str, confidence: f64) -> Self {
        let e = self.ext();
        e.engine_alerts.push(rule.into());
        e.engine_alert_confidence = confidence;
        self
    }
    pub fn value(mut self, v: f64) -> Self {
        self.ext().value_moved = v;
        self
    }
    pub fn records(mut self, n: u64) -> Self {
        self.ext().records_read = n;
        self
    }
    pub fn destructive(mut self) -> Self {
        self.ext().destructive = true;
        self
    }
    pub fn egress(mut self, dest: &str) -> Self {
        self.ext().egress_destination = dest.into();
        self
    }
    pub fn tenant(mut self, t: &str) -> Self {
        self.ext().tenant = t.into();
        self
    }
    pub fn decoy(mut self, id: &str) -> Self {
        let e = self.ext();
        e.decoy_touched = true;
        e.decoy_id = id.into();
        self
    }
    pub fn build(self) -> SecurityEvent {
        self.ev
    }
}
