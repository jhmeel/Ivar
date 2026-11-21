//! Runs the attack replay library against a policy. Exit status is non zero
//! when any scenario fails, so CI can gate a rule, plugin or model on it.
//!
//! Usage: ivar-replay-library <library dir> [policy.json]

use ivar_replay::library::{parse_scenario, run_library, Scenario};
use std::path::Path;

fn load(dir: &Path, out: &mut Vec<Scenario>) -> anyhow::Result<()> {
    for e in std::fs::read_dir(dir)? {
        let p = e?.path();
        if p.is_dir() {
            load(&p, out)?;
        } else if p.extension().map(|x| x == "yaml" || x == "yml").unwrap_or(false) {
            out.push(parse_scenario(&std::fs::read_to_string(&p)?).map_err(|e| anyhow::anyhow!("{}: {e}", p.display()))?);
        }
    }
    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let dir = args.get(1).cloned().unwrap_or_else(|| "replay-library".into());
    let policy = match args.get(2) {
        Some(p) => serde_json::from_str(&std::fs::read_to_string(p)?)?,
        None => ivar_core::policy::spec_default_policy(0),
    };
    let mut scenarios = Vec::new();
    load(Path::new(&dir), &mut scenarios)?;
    let (ok, reports) = run_library(&scenarios, &policy);
    for r in &reports {
        for s in &r.steps {
            println!("{} {} :: {} => {} ({:.2}){}", if s.passed { "PASS" } else { "FAIL" }, r.scenario, s.step, s.decision, s.risk, if s.failures.is_empty() { String::new() } else { format!(" {:?}", s.failures) });
        }
    }
    println!("{} scenarios, {}", reports.len(), if ok { "all passed" } else { "FAILED" });
    std::process::exit(if ok { 0 } else { 1 });
}
