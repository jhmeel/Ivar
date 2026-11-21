//! ivar-workstation-sensor.
//!
//! Usage: ivar-workstation-sensor --config c.yaml [--allow-extensions publisher.name,...]

mod extensions;
mod installers;
mod processes;
mod secrets;

use ivar_contracts::sign::Keyring;
use ivar_sensor_kit::{HttpUplink, Sensor, SensorConfig};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

pub fn home() -> PathBuf {
    std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")).map(PathBuf::from).unwrap_or_else(|| PathBuf::from("."))
}

pub fn hostname() -> String {
    sysinfo::System::host_name().unwrap_or_else(|| "laptop".into())
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let get = |n: &str| args.iter().position(|a| a == n).and_then(|i| args.get(i + 1)).cloned();
    let mut cfg = get("--config").map(|p| SensorConfig::from_file(&p)).transpose()?.unwrap_or_default();
    cfg.sensor_type = "workstation".into();
    let keyring: Keyring = std::fs::read_to_string(&cfg.keyring_file).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
    let sensor = Arc::new(Sensor::new(cfg.clone(), keyring));
    {
        let s = sensor.clone();
        let cfg = cfg.clone();
        std::thread::spawn(move || {
            let mut up = HttpUplink::new(&cfg.core_url, &cfg.control_url);
            s.run(&mut up, &|| false);
        });
    }
    let allow: Vec<String> = get("--allow-extensions").map(|s| s.split(',').map(|x| x.trim().to_lowercase()).collect()).unwrap_or_default();
    let home = home();
    if let Some(p) = sensor.policy() {
        secrets::plant_decoys(&home, &hostname(), &p.decoys)?;
    }
    let mut ext = extensions::Inventory::new(&home, allow);
    let mut inst = installers::Watcher::new(&home.join("Downloads"));
    let mut procs = processes::Watcher::new();
    let mut sec = secrets::Watcher::new(&home);
    loop {
        for ev in ext.scan(&sensor) {
            sensor.emit(ev);
        }
        for ev in inst.scan(&sensor) {
            sensor.emit(ev);
        }
        for ev in procs.scan(&sensor) {
            sensor.emit(ev);
        }
        for ev in sec.scan(&sensor) {
            sensor.emit(ev);
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}
