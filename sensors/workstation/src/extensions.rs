//! IDE and browser extensions: VS Code, Cursor, VSCodium, JetBrains plugins,
//! Chrome, Edge and Brave. New extensions are reported; in enforce mode one
//! that is not on the allowlist is moved to a quarantine folder (reversible).

use ivar_contracts::SecurityEvent;
use ivar_core::detect::vocabulary as v;
use ivar_core::sensor::ocsf_class;
use ivar_sensor_kit::Sensor;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub fn roots(home: &Path) -> Vec<(String, PathBuf)> {
    let mut r = vec![
        ("vscode".to_string(), home.join(".vscode/extensions")),
        ("cursor".to_string(), home.join(".cursor/extensions")),
        ("vscodium".to_string(), home.join(".vscode-oss/extensions")),
        ("chrome".to_string(), home.join(".config/google-chrome/Default/Extensions")),
        ("chrome".to_string(), home.join("Library/Application Support/Google/Chrome/Default/Extensions")),
        ("edge".to_string(), home.join("Library/Application Support/Microsoft Edge/Default/Extensions")),
        ("brave".to_string(), home.join(".config/BraveSoftware/Brave-Browser/Default/Extensions")),
        ("chrome".to_string(), home.join("AppData/Local/Google/Chrome/User Data/Default/Extensions")),
    ];
    for base in [home.join(".local/share/JetBrains"), home.join("Library/Application Support/JetBrains"), home.join("AppData/Roaming/JetBrains")] {
        if let Ok(d) = std::fs::read_dir(&base) {
            for e in d.flatten() {
                r.push(("jetbrains".into(), e.path().join("plugins")));
            }
        }
    }
    r
}

/// VS Code folders are "publisher.name-1.2.3"; the id drops the version.
pub fn extension_id(folder: &str) -> String {
    let lower = folder.to_lowercase();
    match lower.rfind('-') {
        Some(i) if lower[i + 1..].chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false) => lower[..i].to_string(),
        _ => lower,
    }
}

pub struct Inventory {
    home: PathBuf,
    allow: Vec<String>,
    seen: BTreeSet<PathBuf>,
    first: bool,
}

impl Inventory {
    pub fn new(home: &Path, allow: Vec<String>) -> Self {
        Inventory { home: home.to_path_buf(), allow, seen: BTreeSet::new(), first: true }
    }

    pub fn scan(&mut self, s: &Sensor) -> Vec<SecurityEvent> {
        let mut out = Vec::new();
        for (app, root) in roots(&self.home) {
            let Ok(d) = std::fs::read_dir(&root) else { continue };
            for e in d.flatten() {
                let path = e.path();
                if !path.is_dir() || !self.seen.insert(path.clone()) {
                    continue;
                }
                let id = extension_id(&e.file_name().to_string_lossy());
                if self.first && self.allow.is_empty() {
                    continue;
                }
                let allowed = self.allow.is_empty() || self.allow.contains(&id);
                let mut b = s.event(ocsf_class::APPLICATION_LIFECYCLE, v::EXTENSION_INSTALL).attr("extension", &id).attr("app", &app).attr("allowlisted", if allowed { "true" } else { "false" });
                if s.enforce() && !allowed {
                    let q = self.home.join(".ivar-quarantine").join(&app);
                    let _ = std::fs::create_dir_all(&q);
                    let dest = q.join(e.file_name());
                    if std::fs::rename(&path, &dest).is_ok() {
                        b = b.attr("enforced", "quarantined").attr("reversal", &format!("move {} back to {}", dest.display(), path.display()));
                    }
                }
                out.push(b.build());
            }
        }
        self.first = false;
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ivar_sensor_kit::SensorConfig;

    #[test]
    fn new_unlisted_extension_is_quarantined() {
        let home = std::env::temp_dir().join(format!("ivar-ws-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(home.join(".vscode/extensions/ms-python.python-2026.1.0")).unwrap();
        let s = ivar_sensor_kit::test_support::sensor_with_policy(SensorConfig { mode: "enforce".into(), state_dir: home.join("state").display().to_string(), ..Default::default() }, "enforce", |_| {});
        let mut inv = Inventory::new(&home, vec!["ms-python.python".into()]);
        assert_eq!(inv.scan(&s).len(), 1);
        std::fs::create_dir_all(home.join(".vscode/extensions/shady.helper-0.0.1")).unwrap();
        let evs = inv.scan(&s);
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].ext().attributes["enforced"], "quarantined");
        assert!(home.join(".ivar-quarantine/vscode/shady.helper-0.0.1").exists());
        let _ = std::fs::remove_dir_all(&home);
        assert_eq!(extension_id("Publisher.Name-1.2.3"), "publisher.name");
    }
}
