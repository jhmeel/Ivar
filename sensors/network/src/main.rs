//! ivar-network-sensor.
//!
//! Usage: ivar-network-sensor --config sensor.yaml --interface eth1 [--inline] [--eve /var/log/suricata/eve.json]
//!
//! In mirror mode the sensor only observes. With --inline it runs on the
//! gateway and cuts blocked connections through an nftables set.

mod block;
mod capture;
mod dns;
mod flows;
mod packet;
mod tls;

use ivar_contracts::sign::Keyring;
use ivar_core::detect::vocabulary as v;
use ivar_core::sensor::ocsf_class;
use ivar_sensor_kit::{adapters, now_ms, HttpUplink, Sensor, SensorConfig};
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

fn arg(a: &[String], n: &str) -> Option<String> {
    a.iter().position(|x| x == n).and_then(|i| a.get(i + 1)).cloned()
}

/// Turn one parsed packet into events.
pub fn observe(sensor: &Sensor, flows: &mut flows::FlowTable, pkt: &packet::Packet, now: i64) -> Vec<ivar_contracts::SecurityEvent> {
    let mut out = Vec::new();
    let new_flow = flows.record(pkt, now);
    if let (Some(q), true) = (dns::query_name(&pkt.payload), pkt.dst_port == 53 && pkt.proto == 17) {
        out.push(sensor.event(ocsf_class::DNS_ACTIVITY, v::DNS_QUERY).src_ip(&pkt.src).dst(&pkt.dst, 53, "").attr("query", &q).build());
    }
    if pkt.proto == 6 {
        if let Some(sni) = tls::client_hello_sni(&pkt.payload) {
            out.push(sensor.event(ocsf_class::NETWORK_ACTIVITY, v::NET_CONNECT).src_ip(&pkt.src).dst(&pkt.dst, pkt.dst_port as u32, &sni).attr("sni", &sni).egress(&sni).build());
        } else if new_flow {
            out.push(sensor.event(ocsf_class::NETWORK_ACTIVITY, v::NET_CONNECT).src_ip(&pkt.src).dst(&pkt.dst, pkt.dst_port as u32, "").build());
        }
    }
    out
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mut cfg = arg(&args, "--config").map(|p| SensorConfig::from_file(&p)).transpose()?.unwrap_or_default();
    cfg.sensor_type = "network".into();
    let keyring: Keyring = std::fs::read_to_string(&cfg.keyring_file).ok().and_then(|t| serde_json::from_str(&t).ok()).unwrap_or_default();
    let sensor = Arc::new(Sensor::new(cfg.clone(), keyring));
    let inline = args.iter().any(|a| a == "--inline");
    let stop = Arc::new(AtomicBool::new(false));
    {
        let s = sensor.clone();
        let stop = stop.clone();
        let cfg = cfg.clone();
        std::thread::spawn(move || {
            let mut up = HttpUplink::for_sensor(&cfg);
            s.run(&mut up, &|| stop.load(Ordering::Relaxed));
        });
    }
    if let Some(eve) = arg(&args, "--eve") {
        let s = sensor.clone();
        let stop = stop.clone();
        std::thread::spawn(move || -> anyhow::Result<()> {
            let mut f = std::fs::File::open(&eve)?;
            f.seek(SeekFrom::End(0))?;
            let mut r = BufReader::new(f);
            let mut line = String::new();
            while !stop.load(Ordering::Relaxed) {
                line.clear();
                if r.read_line(&mut line)? == 0 {
                    std::thread::sleep(std::time::Duration::from_millis(100));
                    continue;
                }
                if let Some(ev) = adapters::parse("suricata", &line, s.next_seq(), now_ms()) {
                    s.emit(ev);
                }
            }
            Ok(())
        });
    }
    let iface = arg(&args, "--interface").unwrap_or_else(|| "eth0".into());
    let blocker = block::Blocker::new(inline);
    if inline {
        blocker.ensure_table()?;
    }
    let mut flows = flows::FlowTable::new(100_000);
    capture::run(&iface, &stop, |frame| {
        let Some(pkt) = packet::parse_ethernet(frame) else { return };
        for ev in observe(&sensor, &mut flows, &pkt, now_ms()) {
            if let Some(verdict) = sensor.should_block(&sensor.decide(&ev)) {
                if let Some(ip) = verdict.entity.as_ref().filter(|e| e.r#type == "ip").map(|e| e.id.clone()) {
                    let _ = blocker.block(&ip);
                }
            }
            sensor.emit(ev);
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_and_tls_become_events_and_feed_detection() {
        let s = Sensor::new(SensorConfig { state_dir: std::env::temp_dir().join("ivar-net-test").display().to_string(), ..Default::default() }, Keyring::default());
        let mut flows = flows::FlowTable::new(10);
        let q = packet::parse_ethernet(&packet::build_udp_v4([10, 0, 0, 5], [10, 0, 0, 2], 4000, 53, &dns::build_query("aGVsbG8gd29ybGQgdGhpcyBpcyBleGZpbHRyYXRpb24gZGF0YQ.t.example.net"))).unwrap();
        let evs = observe(&s, &mut flows, &q, 1);
        assert_eq!(evs[0].activity_name, "dns.query");
        let mut core = ivar_core::DecisionCore::new(ivar_core::policy::spec_default_policy(0), Default::default()).unwrap();
        assert!(core.process(evs[0].clone(), 1).findings.iter().any(|f| f.rule == "dns_tunnelling"));
        let t = packet::parse_ethernet(&packet::build_tcp_v4([10, 0, 0, 5], [192, 0, 2, 9], 5000, 443, 0x18, &tls::build_client_hello("exfil.example.net"))).unwrap();
        let evs = observe(&s, &mut flows, &t, 2);
        assert_eq!(evs[0].ext().egress_destination, "exfil.example.net");
    }
}
