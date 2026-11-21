//! Installers that land in Downloads (.pkg, .dmg, .msi, .exe, .deb, .rpm,
//! .appimage, install scripts), reported with their digest.

use ivar_contracts::SecurityEvent;
use ivar_core::detect::vocabulary as v;
use ivar_core::sensor::ocsf_class;
use ivar_sensor_kit::Sensor;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const KINDS: &[&str] = &["pkg", "dmg", "msi", "exe", "deb", "rpm", "appimage", "sh", "ps1"];

pub struct Watcher {
    dir: PathBuf,
    seen: BTreeSet<PathBuf>,
}

impl Watcher {
    pub fn new(dir: &Path) -> Self {
        let seen = std::fs::read_dir(dir).map(|d| d.flatten().map(|e| e.path()).collect()).unwrap_or_default();
        Watcher { dir: dir.to_path_buf(), seen }
    }

    pub fn scan(&mut self, s: &Sensor) -> Vec<SecurityEvent> {
        let mut out = Vec::new();
        let Ok(d) = std::fs::read_dir(&self.dir) else { return out };
        for e in d.flatten() {
            let p = e.path();
            let ext = p.extension().map(|x| x.to_string_lossy().to_lowercase()).unwrap_or_default();
            if !KINDS.contains(&ext.as_str()) || !self.seen.insert(p.clone()) {
                continue;
            }
            let digest = std::fs::read(&p).map(|b| hex::encode(Sha256::digest(&b))).unwrap_or_default();
            out.push(s.event(ocsf_class::FILE_ACTIVITY, v::PACKAGE_INSTALL).attr("installer", &p.file_name().unwrap_or_default().to_string_lossy()).attr("sha256", &digest).attr("package", &p.file_stem().unwrap_or_default().to_string_lossy()).build());
        }
        out
    }
}
