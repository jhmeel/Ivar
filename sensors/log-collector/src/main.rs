//! ivar-log-collector.
//!
//! Usage: ivar-log-collector --config c.yaml [--syslog 0.0.0.0:514] [--netflow 0.0.0.0:2055]

mod device;
mod netflow;
mod syslog;

use ivar_contracts::sign::Keyring;
use ivar_sensor_kit::{HttpUplink, Sensor, SensorConfig};
use std::io::{BufRead, BufReader};
use std::net::{TcpListener, UdpSocket};
use std::sync::{Arc, Mutex};

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let get = |n: &str| args.iter().position(|a| a == n).and_then(|i| args.get(i + 1)).cloned();
    let mut cfg = get("--config").map(|p| SensorConfig::from_file(&p)).transpose()?.unwrap_or_default();
    cfg.sensor_type = "log".into();
    let keyring: Keyring = std::fs::read_to_string(&cfg.keyring_file).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
    let sensor = Arc::new(Sensor::new(cfg.clone(), keyring));
    {
        let s = sensor.clone();
        let cfg = cfg.clone();
        std::thread::spawn(move || {
            let mut up = HttpUplink::for_sensor(&cfg);
            s.run(&mut up, &|| false);
        });
    }
    let devices = Arc::new(Mutex::new(device::DeviceState::default()));
    let syslog_addr = get("--syslog").unwrap_or_else(|| "0.0.0.0:5514".into());
    {
        let (s, d) = (sensor.clone(), devices.clone());
        let udp = UdpSocket::bind(&syslog_addr)?;
        std::thread::spawn(move || {
            let mut buf = [0u8; 65_535];
            while let Ok((n, peer)) = udp.recv_from(&mut buf) {
                let line = String::from_utf8_lossy(&buf[..n]).to_string();
                handle(&s, &d, &line, &peer.ip().to_string());
            }
        });
    }
    {
        let (s, d) = (sensor.clone(), devices.clone());
        let tcp = TcpListener::bind(&syslog_addr)?;
        std::thread::spawn(move || {
            for c in tcp.incoming().flatten() {
                let (s, d) = (s.clone(), d.clone());
                std::thread::spawn(move || {
                    let peer = c.peer_addr().map(|p| p.ip().to_string()).unwrap_or_default();
                    for line in BufReader::new(c).lines().map_while(Result::ok) {
                        handle(&s, &d, &line, &peer);
                    }
                });
            }
        });
    }
    let nf = UdpSocket::bind(get("--netflow").unwrap_or_else(|| "0.0.0.0:2055".into()))?;
    let mut templates = netflow::Templates::default();
    let mut buf = [0u8; 65_535];
    loop {
        let (n, peer) = nf.recv_from(&mut buf)?;
        for r in netflow::parse(&buf[..n], &peer.ip().to_string(), &mut templates) {
            sensor.emit(netflow::to_event(&sensor, &r));
        }
    }
}

fn handle(s: &Sensor, d: &Mutex<device::DeviceState>, line: &str, peer: &str) {
    let msg = syslog::parse(line);
    let host = if msg.hostname.is_empty() { peer.to_string() } else { msg.hostname.clone() };
    let ev = d.lock().expect("devices").map(s, &host, &msg.message);
    s.emit(ev);
}
