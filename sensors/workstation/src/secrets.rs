//! Secret access on the laptop, and the decoy deploy token.
//!
//! The decoy is a fake deploy token written where real tokens live, bound to
//! this laptop's context; only an intruder or malware reaches for it. Access
//! to real secret files is reported with the process holding them open.

use ivar_contracts::{DecoySpec, SecurityEvent};
use ivar_core::detect::vocabulary as v;
use ivar_core::sensor::ocsf_class;
use ivar_sensor_kit::Sensor;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub fn secret_files(home: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = [".aws/credentials", ".npmrc", ".docker/config.json", ".kube/config", ".config/gh/hosts.yml", ".git-credentials", ".netrc"].iter().map(|p| home.join(p)).collect();
    if let Ok(d) = std::fs::read_dir(home.join(".ssh")) {
        v.extend(d.flatten().map(|e| e.path()).filter(|p| p.file_name().map(|n| n.to_string_lossy().starts_with("id_") && !n.to_string_lossy().ends_with(".pub")).unwrap_or(false)));
    }
    v
}

/// Write each fake deploy token decoy issued for this laptop.
pub fn plant_decoys(home: &Path, host: &str, decoys: &[DecoySpec]) -> std::io::Result<Vec<PathBuf>> {
    let ctx = format!("laptop:{host}");
    let mut out = Vec::new();
    for d in decoys.iter().filter(|d| d.kind == "fake_deploy_token" && (d.issued_context == ctx || d.issued_context == "*")) {
        let p = home.join(".config/deploy/credentials");
        std::fs::create_dir_all(p.parent().unwrap_or(home))?;
        if !p.exists() {
            std::fs::write(&p, format!("[default]\ndeploy_token = ivar_{}_{}\n", d.marker, d.decoy_id))?;
        }
        out.push(p);
    }
    Ok(out)
}

pub struct Watcher {
    files: Vec<PathBuf>,
    seen: BTreeSet<(u32, PathBuf)>,
}

impl Watcher {
    pub fn new(home: &Path) -> Self {
        let mut files = secret_files(home);
        files.push(home.join(".config/deploy/credentials"));
        Watcher { files, seen: BTreeSet::new() }
    }

    /// Processes holding a secret file open (Linux /proc; elsewhere lsof).
    fn holders(&self) -> Vec<(u32, String, PathBuf)> {
        let mut out = Vec::new();
        if Path::new("/proc/self/fd").exists() {
            if let Ok(d) = std::fs::read_dir("/proc") {
                for e in d.flatten() {
                    let Ok(pid) = e.file_name().to_string_lossy().parse::<u32>() else { continue };
                    let Ok(fds) = std::fs::read_dir(e.path().join("fd")) else { continue };
                    for fd in fds.flatten() {
                        if let Ok(t) = std::fs::read_link(fd.path()) {
                            if self.files.contains(&t) {
                                let comm = std::fs::read_to_string(e.path().join("comm")).unwrap_or_default().trim().to_string();
                                out.push((pid, comm, t));
                            }
                        }
                    }
                }
            }
        } else {
            let existing: Vec<String> = self.files.iter().filter(|f| f.exists()).map(|f| f.display().to_string()).collect();
            if let Ok(o) = std::process::Command::new("lsof").arg("-Fpcn").args(&existing).output() {
                let (mut pid, mut comm) = (0u32, String::new());
                for l in String::from_utf8_lossy(&o.stdout).lines() {
                    match l.split_at(1) {
                        ("p", p) => pid = p.parse().unwrap_or(0),
                        ("c", c) => comm = c.into(),
                        ("n", n) => out.push((pid, comm.clone(), PathBuf::from(n))),
                        _ => {}
                    }
                }
            }
        }
        out
    }

    pub fn scan(&mut self, s: &Sensor) -> Vec<SecurityEvent> {
        let mut out = Vec::new();
        for (pid, comm, path) in self.holders() {
            if !self.seen.insert((pid, path.clone())) {
                continue;
            }
            let decoy = path.ends_with(".config/deploy/credentials");
            let mut b = s.event(ocsf_class::FILE_ACTIVITY, v::SECRET_READ).process(pid, &comm, "", &path.display().to_string()).attr("secret", &path.file_name().unwrap_or_default().to_string_lossy()).attr("context", &format!("laptop:{}", crate::hostname()));
            if decoy {
                if let Some(p) = s.policy() {
                    if let Some(d) = p.decoys.iter().find(|d| d.kind == "fake_deploy_token") {
                        b = b.attr("token_fp", &d.marker);
                    }
                }
            }
            out.push(b.build());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plants_laptop_bound_decoy() {
        let home = std::env::temp_dir().join(format!("ivar-sec-{}", std::process::id()));
        let d = DecoySpec { decoy_id: "dcy_1".into(), kind: "fake_deploy_token".into(), marker: "fp_8a1c".into(), issued_context: "laptop:dev-17".into(), protects: "deploy".into() };
        assert_eq!(plant_decoys(&home, "dev-17", std::slice::from_ref(&d)).unwrap().len(), 1);
        assert!(std::fs::read_to_string(home.join(".config/deploy/credentials")).unwrap().contains("fp_8a1c"));
        assert!(plant_decoys(&home, "other", &[d]).unwrap().is_empty(), "issued to one laptop only");
        let _ = std::fs::remove_dir_all(home);
    }
}
