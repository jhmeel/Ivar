//! ivar-database-sensor.
//!
//! Audit log reader:  ivar-database-sensor --config c.yaml audit <pgaudit|mysql|mongodb|mssql> <file>
//! PostgreSQL proxy:  ivar-database-sensor --config c.yaml proxy <listen addr> <upstream addr>

mod audit;
mod pgproxy;
mod sql;

use ivar_contracts::sign::Keyring;
use ivar_sensor_kit::{HttpUplink, Sensor, SensorConfig};
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let cfg_path = args.iter().position(|a| a == "--config").and_then(|i| args.get(i + 1)).cloned();
    let mut cfg = cfg_path.map(|p| SensorConfig::from_file(&p)).transpose()?.unwrap_or_default();
    cfg.sensor_type = "database".into();
    let keyring: Keyring = std::fs::read_to_string(&cfg.keyring_file).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
    let sensor = Arc::new(Sensor::new(cfg.clone(), keyring));
    let stop = Arc::new(AtomicBool::new(false));
    {
        let s = sensor.clone();
        let stop = stop.clone();
        std::thread::spawn(move || {
            let mut up = HttpUplink::new(&cfg.core_url, &cfg.control_url);
            s.run(&mut up, &|| stop.load(Ordering::Relaxed));
        });
    }
    let pos = args.iter().position(|a| a == "audit" || a == "proxy").ok_or_else(|| anyhow::anyhow!("usage: audit <kind> <file> | proxy <listen> <upstream>"))?;
    match args[pos].as_str() {
        "audit" => {
            let kind = args.get(pos + 1).cloned().unwrap_or_default();
            let mut f = std::fs::File::open(args.get(pos + 2).ok_or_else(|| anyhow::anyhow!("audit file"))?)?;
            f.seek(SeekFrom::End(0))?;
            let mut r = BufReader::new(f);
            let mut line = String::new();
            loop {
                line.clear();
                if r.read_line(&mut line)? == 0 {
                    std::thread::sleep(std::time::Duration::from_millis(200));
                    continue;
                }
                if let Some(ev) = audit::parse(&sensor, &kind, &line) {
                    sensor.emit(ev);
                }
            }
        }
        _ => pgproxy::serve(sensor, &args[pos + 1], &args[pos + 2]),
    }
}
