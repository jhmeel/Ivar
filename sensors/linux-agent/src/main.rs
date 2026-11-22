//! ivar-linux-agent: the Linux host sensor.
//!
//! Modes:
//!   tetragon  apply generated TracingPolicies and forward Tetragon's JSON export
//!   native    scan /proc for new processes and connections and enforce locally
//!
//! Usage: ivar-linux-agent --config /etc/ivar/agent.yaml [--mode tetragon|native]
//!        ivar-linux-agent tracing-policies > policies.yaml

mod evidence;
mod procfs;
mod scanner;
mod tetragon;

use ivar_contracts::sign::Keyring;
use ivar_sensor_kit::{HttpUplink, Sensor, SensorConfig};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn arg(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mut cfg = arg(&args, "--config").map(|p| SensorConfig::from_file(&p)).transpose()?.unwrap_or_default();
    cfg.sensor_type = "host".into();
    let keyring: Keyring = std::fs::read_to_string(&cfg.keyring_file).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
    let sensor = Arc::new(Sensor::new(cfg.clone(), keyring));

    if args.get(1).map(String::as_str) == Some("tracing-policies") {
        let policy = sensor.policy().unwrap_or_else(|| ivar_core::policy::spec_default_policy(0));
        print!("{}", tetragon::tracing_policies(&policy, sensor.enforce()));
        return Ok(());
    }

    let stop = Arc::new(AtomicBool::new(false));
    let bg = {
        let s = sensor.clone();
        let stop = stop.clone();
        let cfg = cfg.clone();
        std::thread::spawn(move || {
            let mut up = HttpUplink::for_sensor(&cfg);
            s.run(&mut up, &|| stop.load(Ordering::Relaxed));
        })
    };
    match arg(&args, "--mode").as_deref().unwrap_or("native") {
        "tetragon" => {
            let path = arg(&args, "--tetragon-export").unwrap_or_else(|| "/var/run/cilium/tetragon/tetragon.log".into());
            tetragon::follow(&sensor, &path, &stop)?;
        }
        _ => scanner::Scanner::new(sensor.clone(), "/proc").run(&stop),
    }
    stop.store(true, Ordering::Relaxed);
    let _ = bg.join();
    Ok(())
}
