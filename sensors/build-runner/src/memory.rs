//! Runner memory access: any process other than the runner itself holding
//! /proc/<runner>/mem open is stealing secrets from runner memory (the
//! technique of the 2025 and 2026 Actions supply chain worms).

use ivar_core::detect::vocabulary as v;
use ivar_core::sensor::ocsf_class;
use ivar_sensor_kit::Sensor;
use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

const RUNNER_NAMES: &[&str] = &["Runner.Worker", "Runner.Listener", "gitlab-runner", "jenkins-agent", "circleci-agent"];

pub fn runner_pids(root: &Path) -> Vec<u32> {
    std::fs::read_dir(root)
        .map(|d| {
            d.flatten()
                .filter_map(|e| {
                    let pid: u32 = e.file_name().to_string_lossy().parse().ok()?;
                    let comm = std::fs::read_to_string(e.path().join("comm")).ok()?;
                    let cmd = std::fs::read_to_string(e.path().join("cmdline")).unwrap_or_default();
                    RUNNER_NAMES.iter().any(|r| comm.trim().starts_with(&r[..r.len().min(15)]) || cmd.contains(r)).then_some(pid)
                })
                .collect()
        })
        .unwrap_or_default()
}

/// (reader pid, reader comm, runner pid) for every open handle on a runner's memory.
pub fn readers(root: &Path, runners: &[u32]) -> Vec<(u32, String, u32)> {
    let targets: Vec<String> = runners.iter().map(|p| format!("{}/{p}/mem", root.display())).collect();
    let mut out = Vec::new();
    for e in std::fs::read_dir(root).into_iter().flatten().flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() else { continue };
        for fd in std::fs::read_dir(e.path().join("fd")).into_iter().flatten().flatten() {
            if let Ok(t) = std::fs::read_link(fd.path()) {
                let t = t.display().to_string();
                if let Some(i) = targets.iter().position(|x| *x == t) {
                    if runners[i] != pid {
                        out.push((pid, std::fs::read_to_string(e.path().join("comm")).unwrap_or_default().trim().to_string(), runners[i]));
                    }
                }
            }
        }
    }
    out
}

pub fn watch(sensor: &Sensor) {
    let root = Path::new("/proc");
    let mut seen = BTreeSet::new();
    loop {
        let runners = runner_pids(root);
        for (pid, comm, runner) in readers(root, &runners) {
            if seen.insert((pid, runner)) {
                let ev = sensor.event(ocsf_class::PROCESS_ACTIVITY, v::RUNNER_MEMORY_READ).process(pid, &comm, "", &format!("/proc/{runner}/mem")).build();
                if sensor.enforce() {
                    unsafe_kill(pid);
                }
                sensor.emit(ev);
            }
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn unsafe_kill(pid: u32) {
    let _ = std::process::Command::new("kill").args(["-9", &pid.to_string()]).status();
}
