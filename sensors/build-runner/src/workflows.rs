//! Workflow changes in a pull request (.github/workflows, .gitlab-ci.yml,
//! Jenkinsfile, .circleci/config.yml).

use ivar_contracts::SecurityEvent;
use ivar_core::detect::vocabulary as v;
use ivar_core::sensor::ocsf_class;
use ivar_sensor_kit::Sensor;
use std::path::Path;

fn files(root: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for f in [".gitlab-ci.yml", "Jenkinsfile", ".circleci/config.yml"] {
        if let Ok(t) = std::fs::read_to_string(root.join(f)) {
            out.push((f.to_string(), t));
        }
    }
    if let Ok(d) = std::fs::read_dir(root.join(".github/workflows")) {
        for e in d.flatten() {
            if let Ok(t) = std::fs::read_to_string(e.path()) {
                out.push((format!(".github/workflows/{}", e.file_name().to_string_lossy()), t));
            }
        }
    }
    out.sort();
    out
}

pub fn diff(base: &Path, head: &Path) -> anyhow::Result<Vec<String>> {
    let b = files(base);
    let h = files(head);
    let mut changed: Vec<String> = h.iter().filter(|x| !b.contains(x)).map(|x| x.0.clone()).collect();
    changed.extend(b.iter().filter(|x| !h.iter().any(|y| y.0 == x.0)).map(|x| format!("{} (removed)", x.0)));
    Ok(changed)
}

pub fn event(s: &Sensor, job: &str, file: &str) -> SecurityEvent {
    let actor = std::env::var("GITHUB_ACTOR").or_else(|_| std::env::var("GITLAB_USER_LOGIN")).unwrap_or_default();
    let mut b = s.event(ocsf_class::APPLICATION_LIFECYCLE, v::WORKFLOW_CHANGE).app(job).attr("file", file);
    if !actor.is_empty() {
        b = b.user(&actor, "human");
    }
    b.build()
}
