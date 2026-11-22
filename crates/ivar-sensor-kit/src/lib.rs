//! Shared sensor runtime.
//!
//! Every sensor emits the same event format and behaves the same way when
//! things fail (section 11.2): it keeps enforcing its last signed policy and
//! buffers events while the core is unreachable, sends a heartbeat so silence
//! raises a tamper alert, verifies every policy update before applying it, and
//! decides known attacks locally with no round trip.

pub mod adapters;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use ivar_contracts::sign::{verify_policy, Keyring};
use ivar_contracts::{PolicyBundle, PolicyContent, SecurityEvent, Verdict};
use ivar_core::detect::vocabulary as v;
use ivar_core::failure::EventBuffer;
use ivar_core::redact::Redactor;
use ivar_core::sensor::{EventBuilder, LocalDecision, SensorPolicy};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SensorConfig {
    pub sensor_id: String,
    pub sensor_type: String,
    /// observe or enforce.
    pub mode: String,
    pub core_url: String,
    /// A file holding the sensor token the core issued for sensor_id.
    pub core_token_file: String,
    pub control_url: String,
    pub keyring_file: String,
    pub redaction_key_hex: String,
    /// Where the last verified policy bundle is kept on local disk.
    pub state_dir: String,
    pub buffer_capacity: usize,
    pub flush_ms: u64,
    pub heartbeat_ms: u64,
}

impl Default for SensorConfig {
    fn default() -> Self {
        SensorConfig {
            sensor_id: "sensor-1".into(),
            sensor_type: "host".into(),
            mode: "observe".into(),
            core_url: "http://ivar-core:8080".into(),
            core_token_file: String::new(),
            control_url: "http://ivar-control:8090".into(),
            keyring_file: "/etc/ivar/keyring.json".into(),
            redaction_key_hex: String::new(),
            state_dir: "/var/lib/ivar-sensor".into(),
            buffer_capacity: 50_000,
            flush_ms: 500,
            heartbeat_ms: 20_000,
        }
    }
}

impl SensorConfig {
    /// YAML or JSON.
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let mut cfg: Self = serde_yaml::from_str(&std::fs::read_to_string(path)?)?;
        cfg.apply_env(|k| std::env::var(k).ok());
        Ok(cfg)
    }

    /// Environment overrides, so secrets stay out of the config file and one
    /// file serves a whole DaemonSet: IVAR_REDACTION_KEY_HEX, or
    /// IVAR_REDACTION_KEY_FILE naming a mounted secret, and IVAR_SENSOR_ID
    /// (the node name).
    pub fn apply_env(&mut self, env: impl Fn(&str) -> Option<String>) {
        if let Some(k) = env("IVAR_REDACTION_KEY_HEX") {
            self.redaction_key_hex = k.trim().to_string();
        } else if let Some(f) = env("IVAR_REDACTION_KEY_FILE") {
            if let Ok(k) = std::fs::read_to_string(f) {
                self.redaction_key_hex = k.trim().to_string();
            }
        }
        if let Some(id) = env("IVAR_SENSOR_ID") {
            self.sensor_id = id;
        }
    }
}

/// Delivery to the core.
pub trait Uplink: Send {
    fn send(&mut self, sensor_id: &str, events: &[SecurityEvent]) -> Result<Vec<Verdict>, String>;
    fn fetch_policy(&mut self, have: u64) -> Result<Option<String>, String>;
}

pub struct HttpUplink {
    core_url: String,
    control_url: String,
    agent: ureq::Agent,
    /// Position in the core's verdict feed, so verdicts other sensors caused
    /// reach this one with its next batch or heartbeat.
    verdict_cursor: u64,
    token: Option<String>,
}

impl HttpUplink {
    pub fn new(core_url: &str, control_url: &str) -> Self {
        HttpUplink { core_url: core_url.trim_end_matches('/').into(), control_url: control_url.trim_end_matches('/').into(), agent: ureq::AgentBuilder::new().timeout(Duration::from_secs(3)).build(), verdict_cursor: 0, token: None }
    }

    /// The uplink for a sensor config, with its token when one is configured.
    pub fn for_sensor(cfg: &SensorConfig) -> Self {
        let mut up = Self::new(&cfg.core_url, &cfg.control_url);
        if !cfg.core_token_file.is_empty() {
            match std::fs::read_to_string(&cfg.core_token_file) {
                Ok(t) => up.token = Some(format!("Bearer {}", t.trim())),
                Err(e) => eprintln!("ivar: sensor token {} unreadable ({e}); the core will refuse this sensor's events", cfg.core_token_file),
            }
        }
        up
    }
}

impl Uplink for HttpUplink {
    fn send(&mut self, sensor_id: &str, events: &[SecurityEvent]) -> Result<Vec<Verdict>, String> {
        let mut req = self.agent.post(&format!("{}/v1/events", self.core_url));
        if let Some(t) = &self.token {
            req = req.set("authorization", t);
        }
        let r = req
            .send_json(serde_json::json!({ "sensor_id": sensor_id, "events": events, "verdict_cursor": self.verdict_cursor }))
            .map_err(|e| e.to_string())?;
        let v: serde_json::Value = r.into_json().map_err(|e| e.to_string())?;
        if let Some(c) = v.get("verdict_cursor").and_then(|c| c.as_u64()) {
            self.verdict_cursor = self.verdict_cursor.max(c);
        }
        Ok(v.get("verdicts").and_then(|x| serde_json::from_value(x.clone()).ok()).unwrap_or_default())
    }
    fn fetch_policy(&mut self, have: u64) -> Result<Option<String>, String> {
        match self.agent.get(&format!("{}/v1/policy/bundle?have={have}", self.control_url)).call() {
            Ok(r) if r.status() == 204 => Ok(None),
            Ok(r) => r.into_string().map(Some).map_err(|e| e.to_string()),
            Err(ureq::Error::Status(204, _)) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }
}

struct Shared {
    sensor: Option<SensorPolicy>,
    policy: Option<PolicyContent>,
    buffer: EventBuffer<SecurityEvent>,
    seq: u64,
    last_flush_ok: bool,
}

/// The sensor runtime shared by all Rust sensors.
pub struct Sensor {
    pub cfg: SensorConfig,
    keyring: Keyring,
    redactor: Redactor,
    shared: Arc<Mutex<Shared>>,
}

#[derive(Debug, PartialEq)]
pub enum PolicyUpdate {
    Applied(u64),
    Unchanged,
    Rejected(String),
}

impl Sensor {
    pub fn new(cfg: SensorConfig, keyring: Keyring) -> Self {
        let redactor = Redactor::new(&hex::decode(&cfg.redaction_key_hex).unwrap_or_default());
        let s = Sensor {
            shared: Arc::new(Mutex::new(Shared { sensor: None, policy: None, buffer: EventBuffer::new(cfg.buffer_capacity), seq: 0, last_flush_ok: true })),
            redactor,
            keyring,
            cfg,
        };
        // Start from the last verified policy on local disk, if any.
        if let Ok(b) = std::fs::read_to_string(s.policy_path()) {
            let _ = s.apply_bundle(&b);
        }
        s
    }

    fn policy_path(&self) -> PathBuf {
        PathBuf::from(&self.cfg.state_dir).join("policy.bundle")
    }

    /// Blocks only when the local mode and the signed DETECTION_MODE both
    /// say enforce; without a verified policy the sensor only records.
    pub fn enforce(&self) -> bool {
        self.cfg.mode == "enforce" && self.shared.lock().expect("sensor").sensor.as_ref().map(|s| s.enforce).unwrap_or(false)
    }

    pub fn next_seq(&self) -> u64 {
        let mut g = self.shared.lock().expect("sensor");
        g.seq += 1;
        g.seq
    }

    /// A builder with this sensor's identity and next sequence number.
    pub fn event(&self, class: u32, activity: &str) -> EventBuilder {
        EventBuilder::new(class, activity, now_ms(), &self.cfg.sensor_id, &self.cfg.sensor_type, self.next_seq()).observation_point(&self.cfg.sensor_type)
    }

    pub fn policy(&self) -> Option<PolicyContent> {
        self.shared.lock().expect("sensor").policy.clone()
    }

    /// Verify and apply a signed bundle; invalid, older or expired bundles are
    /// rejected and the current policy kept.
    pub fn apply_bundle(&self, archive_b64: &str) -> PolicyUpdate {
        let Ok(bytes) = B64.decode(archive_b64.trim()) else { return PolicyUpdate::Rejected("not base64".into()) };
        let b = match PolicyBundle::from_archive(&bytes) {
            Ok(b) => b,
            Err(e) => return PolicyUpdate::Rejected(e.to_string()),
        };
        if let Err(e) = verify_policy(&self.keyring, &b) {
            return PolicyUpdate::Rejected(e.to_string());
        }
        let mut g = self.shared.lock().expect("sensor");
        let current = g.policy.as_ref().map(|p| p.version).unwrap_or(0);
        if b.content.version < current {
            return PolicyUpdate::Rejected(format!("rollback from {current} refused"));
        }
        if b.content.version == current && g.policy.is_some() {
            return PolicyUpdate::Unchanged;
        }
        if b.content.expires_at < now_ms() {
            return PolicyUpdate::Rejected("expired bundle refused".into());
        }
        let mut sp = match SensorPolicy::try_from_policy(&b.content) {
            Ok(sp) => sp,
            Err(e) => return PolicyUpdate::Rejected(e),
        };
        // DETECTION_MODE comes from the signed policy; the local mode is a
        // ceiling, so a sensor installed in observe never blocks.
        sp.enforce = sp.enforce && self.cfg.mode == "enforce";
        g.sensor = Some(sp);
        g.policy = Some(b.content.clone());
        drop(g);
        let _ = std::fs::create_dir_all(&self.cfg.state_dir);
        let tmp = self.policy_path().with_extension("tmp");
        if std::fs::write(&tmp, archive_b64.trim()).is_ok() {
            let _ = std::fs::rename(&tmp, self.policy_path());
        }
        PolicyUpdate::Applied(b.content.version)
    }

    /// The local decision for one event: block, cached verdict, or forward.
    pub fn decide(&self, ev: &SecurityEvent) -> LocalDecision {
        let g = self.shared.lock().expect("sensor");
        match &g.sensor {
            Some(s) => s.decide(ev, now_ms()),
            None => LocalDecision::Forward,
        }
    }

    /// Whether the decision should be enforced here.
    pub fn should_block(&self, d: &LocalDecision) -> Option<Verdict> {
        if !self.enforce() {
            return None;
        }
        match d {
            LocalDecision::Block(v) | LocalDecision::Cached(v) if v.mode == "enforce" && matches!(v.decision.as_str(), "block" | "contain" | "refuse") => Some(v.clone()),
            _ => None,
        }
    }

    /// Redact and queue an event for the core.
    pub fn emit(&self, mut ev: SecurityEvent) {
        self.redactor.apply(&mut ev, None, now_ms());
        self.shared.lock().expect("sensor").buffer.push(ev);
    }

    pub fn push_verdict(&self, v: Verdict) {
        if let Some(s) = self.shared.lock().expect("sensor").sensor.as_mut() {
            s.push_verdict(v);
        }
    }

    /// Deliver buffered events. On failure they stay buffered.
    pub fn flush(&self, up: &mut dyn Uplink) -> Result<usize, String> {
        let batch = {
            let mut g = self.shared.lock().expect("sensor");
            g.buffer.drain()
        };
        if batch.is_empty() {
            return Ok(0);
        }
        match up.send(&self.cfg.sensor_id, &batch) {
            Ok(verdicts) => {
                for v in verdicts {
                    self.push_verdict(v);
                }
                self.shared.lock().expect("sensor").last_flush_ok = true;
                Ok(batch.len())
            }
            Err(e) => {
                let mut g = self.shared.lock().expect("sensor");
                g.last_flush_ok = false;
                for ev in batch {
                    g.buffer.push(ev);
                }
                Err(e)
            }
        }
    }

    pub fn buffered(&self) -> (usize, u64) {
        let g = self.shared.lock().expect("sensor");
        (g.buffer.len(), g.buffer.dropped)
    }

    pub fn heartbeat(&self) {
        let ev = self.event(0, v::SENSOR_HEARTBEAT).build();
        self.shared.lock().expect("sensor").buffer.push(ev);
    }

    /// The background loop: flush, heartbeat and policy refresh. Runs until
    /// `stop` returns true.
    pub fn run(&self, up: &mut dyn Uplink, stop: &dyn Fn() -> bool) {
        let mut last_hb = Instant::now() - Duration::from_millis(self.cfg.heartbeat_ms);
        let mut last_policy = Instant::now() - Duration::from_secs(3600);
        while !stop() {
            if last_hb.elapsed() >= Duration::from_millis(self.cfg.heartbeat_ms) {
                self.heartbeat();
                last_hb = Instant::now();
            }
            let _ = self.flush(up);
            if last_policy.elapsed() >= Duration::from_secs(30) {
                let have = self.policy().map(|p| p.version).unwrap_or(0);
                if let Ok(Some(b)) = up.fetch_policy(have) {
                    if let PolicyUpdate::Rejected(r) = self.apply_bundle(&b) {
                        eprintln!("ivar sensor: policy update rejected, current policy kept: {r}");
                    }
                }
                last_policy = Instant::now();
            }
            std::thread::sleep(Duration::from_millis(self.cfg.flush_ms));
        }
        let _ = self.flush(up);
    }
}

#[cfg(test)]
pub mod testing {
    use super::*;

    /// An uplink that can be switched off to simulate a core outage.
    pub struct FakeUplink {
        pub up: bool,
        pub sent: Vec<SecurityEvent>,
        pub verdicts: Vec<Verdict>,
        pub bundle: Option<String>,
    }

    impl Uplink for FakeUplink {
        fn send(&mut self, _id: &str, events: &[SecurityEvent]) -> Result<Vec<Verdict>, String> {
            if !self.up {
                return Err("core unreachable".into());
            }
            self.sent.extend_from_slice(events);
            Ok(std::mem::take(&mut self.verdicts))
        }
        fn fetch_policy(&mut self, _have: u64) -> Result<Option<String>, String> {
            Ok(self.bundle.clone())
        }
    }
}

/// Test support for sensor crates: a sensor holding a signed policy, as a
/// deployed sensor would after its first refresh. Only with the testing
/// feature, never in a production build.
#[cfg(any(test, feature = "testing"))]
pub mod test_support {
    use super::{PolicyUpdate, Sensor, SensorConfig};
    use base64::Engine as _;
    use ivar_contracts::sign::{sign_policy, KeyPair, Keyring};
    use ivar_contracts::PolicyContent;

    /// A sensor with a verified policy. `detection_mode` is the signed
    /// DETECTION_MODE; `edit` adjusts the policy before it is signed.
    pub fn sensor_with_policy(cfg: SensorConfig, detection_mode: &str, edit: impl FnOnce(&mut PolicyContent)) -> Sensor {
        let key = KeyPair::ed25519_from_seed("policy-test", [9; 32]);
        let mut ring = Keyring::default();
        ring.add(key.public(), &["policy"]);
        let mut p = ivar_core::policy::spec_default_policy(0);
        p.settings.insert("detection_mode".into(), serde_json::json!(detection_mode));
        p.version = 1;
        p.expires_at = i64::MAX / 2;
        edit(&mut p);
        let archive = sign_policy(&p, &[&key]).expect("sign").to_archive().expect("archive");
        let s = Sensor::new(cfg, ring);
        assert_eq!(s.apply_bundle(&base64::engine::general_purpose::STANDARD.encode(archive)), PolicyUpdate::Applied(1));
        s
    }
}

#[cfg(test)]
mod tests {
    use super::testing::FakeUplink;
    use super::*;
    use ivar_contracts::sign::{sign_policy, KeyPair};
    use ivar_core::policy::spec_default_policy;
    use ivar_core::sensor::ocsf_class;

    fn setup(dir: &std::path::Path) -> (Sensor, KeyPair) {
        let k = KeyPair::ed25519_from_seed("policy-1", [1; 32]);
        let mut ring = Keyring::default();
        ring.add(k.public(), &["policy"]);
        let cfg = SensorConfig { mode: "enforce".into(), state_dir: dir.display().to_string(), ..Default::default() };
        (Sensor::new(cfg, ring), k)
    }

    fn bundle(k: &KeyPair, version: u64) -> String {
        let mut p = spec_default_policy(0);
        p.settings.insert("detection_mode".into(), serde_json::json!("enforce"));
        p.version = version;
        p.expires_at = i64::MAX / 2;
        B64.encode(sign_policy(&p, &[k]).unwrap().to_archive().unwrap())
    }

    #[test]
    fn outage_buffers_and_keeps_policy_across_restart() {
        let dir = std::env::temp_dir().join(format!("ivar-kit-{}", std::process::id()));
        let (s, k) = setup(&dir);
        assert_eq!(s.apply_bundle(&bundle(&k, 3)), PolicyUpdate::Applied(3));
        assert!(matches!(s.apply_bundle(&bundle(&k, 2)), PolicyUpdate::Rejected(_)));
        let mut up = FakeUplink { up: false, sent: vec![], verdicts: vec![], bundle: None };
        s.emit(s.event(ocsf_class::HTTP_ACTIVITY, "http.request").http("GET", "/.env.backup", &[], 404).build());
        assert!(s.flush(&mut up).is_err());
        assert_eq!(s.buffered().0, 1, "kept while the core is down");
        up.up = true;
        assert_eq!(s.flush(&mut up).unwrap(), 1);
        let (restarted, _) = setup(&dir);
        assert_eq!(restarted.policy().map(|p| p.version), Some(3), "last verified policy survives a restart");
        let ev = restarted.event(ocsf_class::HTTP_ACTIVITY, "http.request").src_ip("203.0.113.1").http("GET", "/.env.backup", &[], 0).build();
        assert!(restarted.should_block(&restarted.decide(&ev)).is_some(), "decoy route blocked locally from the stored policy");
        let _ = std::fs::remove_dir_all(dir);
    }
}
