//! Native collector: new processes and connections from /proc, with the
//! sensor fast path deciding locally (web process starting a shell,
//! unexpected binaries, cloud metadata access). In enforce mode a blocked
//! process is killed after its volatile evidence is captured.

use crate::{evidence, procfs};
use ivar_core::detect::vocabulary as v;
use ivar_core::sensor::ocsf_class;
use ivar_sensor_kit::Sensor;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

pub struct Scanner {
    sensor: Arc<Sensor>,
    root: PathBuf,
    seen_pids: BTreeSet<u32>,
    seen_conns: BTreeSet<(String, u16, u64)>,
    hostname: String,
}

impl Scanner {
    pub fn new(sensor: Arc<Sensor>, root: &str) -> Self {
        let hostname = std::fs::read_to_string("/etc/hostname").unwrap_or_default().trim().to_string();
        let root = PathBuf::from(root);
        let seen_pids = procfs::pids(&root).into_iter().collect();
        Scanner { sensor, root, seen_pids, seen_conns: BTreeSet::new(), hostname }
    }

    /// One scan; returns the pids killed.
    pub fn scan_once(&mut self) -> Vec<u32> {
        let mut killed = Vec::new();
        let now: BTreeSet<u32> = procfs::pids(&self.root).into_iter().collect();
        for pid in now.difference(&self.seen_pids).copied().collect::<Vec<_>>() {
            let Some(p) = procfs::read(&self.root, pid) else { continue };
            let parent = procfs::read(&self.root, p.ppid).map(|x| x.comm).unwrap_or_default();
            let mut ev = self
                .sensor
                .event(ocsf_class::PROCESS_ACTIVITY, v::PROCESS_START)
                .device(&self.hostname, &self.hostname, "server")
                .process(pid, &p.comm, &parent, &p.exe)
                .build();
            if let Some(pr) = ev.process.as_mut() {
                pr.cmd_line = p.cmdline.chars().take(512).collect();
                pr.user = p.uid.to_string();
            }
            let d = self.sensor.decide(&ev);
            if let Some(verdict) = self.sensor.should_block(&d) {
                let ev_capture = evidence::capture(&self.root, pid);
                if let Some(x) = ev.ivar.as_mut() {
                    x.attributes.insert("volatile_evidence".into(), ev_capture.to_string());
                    x.attributes.insert("enforced".into(), format!("killed by verdict {}", verdict.verdict_id));
                }
                if self.root == PathBuf::from("/proc") {
                    unsafe {
                        libc::kill(pid as i32, libc::SIGKILL);
                    }
                }
                killed.push(pid);
            }
            self.sensor.emit(ev);
        }
        self.seen_pids = now;
        if let Ok(text) = std::fs::read_to_string(self.root.join("net/tcp")) {
            let conns = procfs::tcp(&text);
            let owners = if conns.is_empty() { Default::default() } else { procfs::socket_owners(&self.root) };
            for c in conns {
                let key = (c.remote.clone(), c.remote_port, c.inode);
                if !self.seen_conns.insert(key) {
                    continue;
                }
                let pid = owners.get(&c.inode).copied().unwrap_or(0);
                let proc = procfs::read(&self.root, pid);
                let ev = self
                    .sensor
                    .event(ocsf_class::NETWORK_ACTIVITY, v::NET_CONNECT)
                    .device(&self.hostname, &self.hostname, "server")
                    .process(pid, proc.as_ref().map(|p| p.comm.as_str()).unwrap_or(""), "", "")
                    .dst(&c.remote, c.remote_port as u32, "")
                    .egress(&c.remote)
                    .build();
                self.sensor.emit(ev);
            }
        }
        killed
    }

    pub fn run(&mut self, stop: &AtomicBool) {
        while !stop.load(Ordering::Relaxed) {
            self.scan_once();
            std::thread::sleep(Duration::from_millis(250));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ivar_contracts::sign::Keyring;
    use ivar_sensor_kit::SensorConfig;

    fn fake_proc(root: &std::path::Path, pid: u32, ppid: u32, name: &str) {
        let d = root.join(pid.to_string());
        std::fs::create_dir_all(d.join("fd")).unwrap();
        std::fs::write(d.join("status"), format!("Name:\t{name}\nPPid:\t{ppid}\nUid:\t33\t33\t33\t33\n")).unwrap();
        std::fs::write(d.join("cmdline"), format!("{name}\0-c\0id\0")).unwrap();
    }

    #[test]
    fn web_shell_is_captured_then_blocked() {
        let root = std::env::temp_dir().join(format!("ivar-proc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        fake_proc(&root, 100, 1, "php-fpm");
        let cfg = SensorConfig { mode: "enforce".into(), state_dir: root.join("state").display().to_string(), ..Default::default() };
        let sensor = Arc::new(Sensor::new(cfg, Keyring::default()));
        // No signed policy yet: the sensor forwards everything.
        let mut s = Scanner::new(sensor.clone(), root.to_str().unwrap());
        fake_proc(&root, 101, 100, "sh");
        assert!(s.scan_once().is_empty(), "without a verified policy nothing is enforced locally");
        assert_eq!(sensor.buffered().0, 1);

        use base64::Engine;
        let k = ivar_contracts::sign::KeyPair::ed25519_from_seed("policy-1", [1; 32]);
        let mut ring = Keyring::default();
        ring.add(k.public(), &["policy"]);
        let cfg = SensorConfig { mode: "enforce".into(), state_dir: root.join("state2").display().to_string(), ..Default::default() };
        let sensor = Arc::new(Sensor::new(cfg, ring));
        let mut p = ivar_core::policy::spec_default_policy(0);
        p.settings.insert("detection_mode".into(), serde_json::json!("enforce"));
        p.expires_at = i64::MAX / 2;
        let b = base64::engine::general_purpose::STANDARD.encode(ivar_contracts::sign::sign_policy(&p, &[&k]).unwrap().to_archive().unwrap());
        assert!(matches!(sensor.apply_bundle(&b), ivar_sensor_kit::PolicyUpdate::Applied(_)));
        let mut s = Scanner::new(sensor.clone(), root.to_str().unwrap());
        fake_proc(&root, 102, 100, "bash");
        assert_eq!(s.scan_once(), vec![102], "web process starting a shell is blocked");
        let _ = std::fs::remove_dir_all(&root);
    }
}
