//! ivar-build-runner.
//!
//!   ivar-build-runner start   --config c.yaml --allow registry.npmjs.org,github.com
//!       DNS allowlist proxy, egress rules and the runner memory watch for the job.
//!   ivar-build-runner verify-packages --lockfile package-lock.json --installed node_modules/.package-lock.json
//!       Fails the build when an installed package differs from its pin.
//!   ivar-build-runner check-workflows --base <dir> --head <dir>
//!       Reports workflow changes in a pull request.

mod dns_proxy;
mod egress;
mod memory;
mod packages;
mod workflows;

use ivar_contracts::sign::Keyring;
use ivar_sensor_kit::{HttpUplink, Sensor, SensorConfig};
use std::sync::Arc;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let get = |n: &str| args.iter().position(|a| a == n).and_then(|i| args.get(i + 1)).cloned();
    let mut cfg = get("--config").map(|p| SensorConfig::from_file(&p)).transpose()?.unwrap_or_default();
    cfg.sensor_type = "build_runner".into();
    let keyring: Keyring = std::fs::read_to_string(&cfg.keyring_file).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
    let sensor = Arc::new(Sensor::new(cfg.clone(), keyring));
    let job = std::env::var("GITHUB_WORKFLOW").map(|w| format!("{w}/{}", std::env::var("GITHUB_JOB").unwrap_or_default())).or_else(|_| std::env::var("CI_JOB_NAME")).unwrap_or_else(|_| "ci-job".into());
    let mut up = HttpUplink::for_sensor(&cfg);
    match args.get(1).map(String::as_str) {
        Some("start") => {
            let allow: Vec<String> = get("--allow").map(|s| s.split(',').map(|x| x.trim().to_string()).collect()).unwrap_or_default();
            let mut policy = egress::EgressPolicy::new(allow, sensor.enforce());
            if let Some(p) = sensor.policy() {
                policy.extend_from_declarations(&p, &format!("ci_job:{job}"));
            }
            egress::install_rules(&policy)?;
            let s2 = sensor.clone();
            std::thread::spawn(move || memory::watch(&s2));
            let s3 = sensor.clone();
            std::thread::spawn(move || {
                let mut up = HttpUplink::for_sensor(&cfg);
                s3.run(&mut up, &|| false);
            });
            dns_proxy::serve(&sensor, &policy, &job, "127.0.0.53:53", "1.1.1.1:53")
        }
        Some("verify-packages") => {
            let lock = std::fs::read_to_string(get("--lockfile").unwrap_or_else(|| "package-lock.json".into()))?;
            let inst = std::fs::read_to_string(get("--installed").unwrap_or_else(|| "node_modules/.package-lock.json".into()))?;
            let bad = packages::verify(&sensor, &job, &lock, &inst)?;
            let _ = sensor.flush(&mut up);
            if !bad.is_empty() && sensor.enforce() {
                eprintln!("ivar: installed packages differ from their pins: {}", bad.join(", "));
                std::process::exit(1);
            }
            Ok(())
        }
        Some("check-workflows") => {
            let changed = workflows::diff(std::path::Path::new(&get("--base").unwrap_or_default()), std::path::Path::new(&get("--head").unwrap_or_else(|| ".".into())))?;
            for c in &changed {
                sensor.emit(workflows::event(&sensor, &job, c));
            }
            let _ = sensor.flush(&mut up);
            println!("{} workflow file(s) changed", changed.len());
            Ok(())
        }
        _ => {
            eprintln!("usage: ivar-build-runner start | verify-packages | check-workflows");
            std::process::exit(2);
        }
    }
}
