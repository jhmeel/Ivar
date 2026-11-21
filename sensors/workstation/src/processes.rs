//! Repositories run locally: package manager lifecycle scripts and build
//! tools started from a repository checkout, and shells started by
//! editors or browsers. Blocked processes are killed in enforce mode.

use ivar_contracts::SecurityEvent;
use ivar_core::detect::vocabulary as v;
use ivar_core::sensor::ocsf_class;
use ivar_sensor_kit::Sensor;
use std::collections::BTreeSet;
use sysinfo::{Pid, ProcessRefreshKind, RefreshKind, System, UpdateKind};

pub struct Watcher {
    sys: System,
    seen: BTreeSet<Pid>,
}

const LIFECYCLE: &[&str] = &["postinstall", "preinstall", "install.js", "setup.py", "node-gyp"];

impl Watcher {
    pub fn new() -> Self {
        let sys = System::new_with_specifics(RefreshKind::new().with_processes(ProcessRefreshKind::new().with_cmd(UpdateKind::Always).with_cwd(UpdateKind::Always)));
        let seen = sys.processes().keys().copied().collect();
        Watcher { sys, seen }
    }

    pub fn scan(&mut self, s: &Sensor) -> Vec<SecurityEvent> {
        self.sys.refresh_processes_specifics(ProcessRefreshKind::new().with_cmd(UpdateKind::Always).with_cwd(UpdateKind::Always));
        let mut out = Vec::new();
        let mut now = BTreeSet::new();
        for (pid, p) in self.sys.processes() {
            now.insert(*pid);
            if self.seen.contains(pid) {
                continue;
            }
            let parent = p.parent().and_then(|pp| self.sys.process(pp)).map(|pp| pp.name().to_string()).unwrap_or_default();
            let cmd = p.cmd().join(" ");
            let cwd = p.cwd().map(|c| c.display().to_string()).unwrap_or_default();
            let in_repo = p.cwd().map(|c| c.ancestors().any(|a| a.join(".git").exists())).unwrap_or(false);
            let lifecycle = LIFECYCLE.iter().any(|l| cmd.contains(l));
            let mut ev = s
                .event(ocsf_class::PROCESS_ACTIVITY, v::PROCESS_START)
                .device(&crate::hostname(), &crate::hostname(), "laptop")
                .process(pid.as_u32(), p.name(), &parent, &p.exe().map(|e| e.display().to_string()).unwrap_or_default())
                .attr("in_repository", if in_repo { "true" } else { "false" })
                .attr("lifecycle_script", if lifecycle { "true" } else { "false" })
                .attr("cwd", &cwd)
                .build();
            if let Some(pr) = ev.process.as_mut() {
                pr.cmd_line = cmd.chars().take(512).collect();
            }
            if s.should_block(&s.decide(&ev)).is_some() && p.kill() {
                if let Some(x) = ev.ivar.as_mut() {
                    x.attributes.insert("enforced".into(), "killed".into());
                }
            }
            out.push(ev);
        }
        self.seen = now;
        out
    }
}
