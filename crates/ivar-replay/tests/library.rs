//! Runs the whole attack replay library against the spec default policy.

use ivar_core::policy::spec_default_policy;
use ivar_replay::library::{parse_scenario, run_library};
use std::path::Path;

fn load(dir: &Path, out: &mut Vec<ivar_replay::library::Scenario>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            load(&p, out);
        } else if p.extension().map(|x| x == "yaml").unwrap_or(false) {
            out.push(parse_scenario(&std::fs::read_to_string(&p).unwrap()).unwrap_or_else(|e| panic!("{}: {e}", p.display())));
        }
    }
}

#[test]
fn library_passes() {
    let mut scenarios = Vec::new();
    load(&Path::new(env!("CARGO_MANIFEST_DIR")).join("../../replay-library"), &mut scenarios);
    assert!(scenarios.len() >= 14, "found {}", scenarios.len());
    let (ok, reports) = run_library(&scenarios, &spec_default_policy(0));
    for r in &reports {
        for s in &r.steps {
            println!("{} {} :: {} => {} ({:.2}) {:?}", if s.passed { "PASS" } else { "FAIL" }, r.scenario, s.step, s.decision, s.risk, s.failures);
        }
    }
    assert!(ok);
}
