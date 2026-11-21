//! The DNS allowlist proxy: allowed names are forwarded upstream and their
//! answers added to the egress set; other names get NXDOMAIN and an event.

use crate::egress::{allow_ip, EgressPolicy};
use ivar_core::detect::vocabulary as v;
use ivar_core::sensor::ocsf_class;
use ivar_sensor_kit::Sensor;
use std::net::UdpSocket;
use std::time::Duration;

pub fn qname(p: &[u8]) -> Option<(String, usize)> {
    let mut i = 12;
    let mut labels = Vec::new();
    loop {
        let l = *p.get(i)? as usize;
        if l == 0 {
            return Some((labels.join("."), i + 1));
        }
        if l & 0xC0 != 0 {
            return None;
        }
        labels.push(String::from_utf8_lossy(p.get(i + 1..i + 1 + l)?).to_string());
        i += 1 + l;
    }
}

pub fn nxdomain(q: &[u8]) -> Vec<u8> {
    let mut r = q.to_vec();
    if r.len() >= 4 {
        r[2] = 0x81;
        r[3] = 0x83;
    }
    r
}

/// A records in an answer.
pub fn answers(resp: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let Some((_, mut i)) = qname(resp) else { return out };
    i += 4;
    let an = u16::from_be_bytes([resp[6], resp[7]]) as usize;
    for _ in 0..an {
        if i >= resp.len() {
            break;
        }
        if resp[i] & 0xC0 == 0xC0 {
            i += 2;
        } else {
            while i < resp.len() && resp[i] != 0 {
                i += resp[i] as usize + 1;
            }
            i += 1;
        }
        if i + 10 > resp.len() {
            break;
        }
        let t = u16::from_be_bytes([resp[i], resp[i + 1]]);
        let rdlen = u16::from_be_bytes([resp[i + 8], resp[i + 9]]) as usize;
        i += 10;
        if t == 1 && rdlen == 4 && i + 4 <= resp.len() {
            out.push(format!("{}.{}.{}.{}", resp[i], resp[i + 1], resp[i + 2], resp[i + 3]));
        }
        i += rdlen;
    }
    out
}

pub fn serve(sensor: &Sensor, policy: &EgressPolicy, job: &str, listen: &str, upstream: &str) -> anyhow::Result<()> {
    let sock = UdpSocket::bind(listen)?;
    let up = UdpSocket::bind("0.0.0.0:0")?;
    up.set_read_timeout(Some(Duration::from_secs(3)))?;
    let mut buf = [0u8; 4096];
    loop {
        let (n, peer) = sock.recv_from(&mut buf)?;
        let q = &buf[..n];
        let Some((name, _)) = qname(q) else { continue };
        if policy.allows(&name) {
            up.send_to(q, upstream)?;
            let mut rb = [0u8; 4096];
            if let Ok((m, _)) = up.recv_from(&mut rb) {
                for ip in answers(&rb[..m]) {
                    allow_ip(&ip);
                }
                sock.send_to(&rb[..m], peer)?;
            }
        } else {
            let ev = sensor
                .event(ocsf_class::DNS_ACTIVITY, v::DNS_QUERY)
                .app(job)
                .attr("query", &name)
                .attr("holder", &format!("ci_job:{job}"))
                .egress(&name)
                .attr("enforced", if policy.enforce { "nxdomain" } else { "observed" })
                .build();
            sensor.emit(ev);
            if policy.enforce {
                sock.send_to(&nxdomain(q), peer)?;
            } else {
                up.send_to(q, upstream)?;
                let mut rb = [0u8; 4096];
                if let Ok((m, _)) = up.recv_from(&mut rb) {
                    for ip in answers(&rb[..m]) {
                        allow_ip(&ip);
                    }
                    sock.send_to(&rb[..m], peer)?;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_names_and_answers() {
        let mut q = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        for l in ["exfil", "example", "net"] {
            q.push(l.len() as u8);
            q.extend_from_slice(l.as_bytes());
        }
        q.extend_from_slice(&[0, 0, 1, 0, 1]);
        assert_eq!(super::qname(&q).unwrap().0, "exfil.example.net");
        assert_eq!(super::nxdomain(&q)[3] & 0x0f, 3);
        let mut r = q.clone();
        r[2] = 0x81;
        r[7] = 1;
        r.extend_from_slice(&[0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 7]);
        assert_eq!(super::answers(&r), vec!["192.0.2.7"]);
    }
}
