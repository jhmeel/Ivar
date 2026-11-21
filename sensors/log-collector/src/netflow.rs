//! NetFlow v5 and v9 records.

use ivar_contracts::SecurityEvent;
use ivar_core::detect::vocabulary as v;
use ivar_core::sensor::ocsf_class;
use ivar_sensor_kit::Sensor;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct FlowRecord {
    pub exporter: String,
    pub src: String,
    pub dst: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub bytes: u64,
    pub packets: u64,
}

#[derive(Default)]
pub struct Templates {
    /// (exporter, template id) to field (type, length) list.
    t: BTreeMap<(String, u16), Vec<(u16, u16)>>,
}

fn be16(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

fn be_n(b: &[u8]) -> u64 {
    b.iter().fold(0u64, |a, x| (a << 8) | *x as u64)
}

fn ip4(b: &[u8]) -> String {
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

pub fn parse(d: &[u8], exporter: &str, templates: &mut Templates) -> Vec<FlowRecord> {
    match be16(d, 0) {
        Some(5) => {
            let count = be16(d, 2).unwrap_or(0) as usize;
            (0..count)
                .filter_map(|i| {
                    let r = d.get(24 + i * 48..24 + (i + 1) * 48)?;
                    Some(FlowRecord {
                        exporter: exporter.into(),
                        src: ip4(&r[0..4]),
                        dst: ip4(&r[4..8]),
                        packets: be_n(&r[16..20]),
                        bytes: be_n(&r[20..24]),
                        src_port: be16(r, 32)?,
                        dst_port: be16(r, 34)?,
                        proto: r[38],
                    })
                })
                .collect()
        }
        Some(9) => {
            let mut out = Vec::new();
            let mut i = 20;
            while i + 4 <= d.len() {
                let (set_id, len) = (be16(d, i).unwrap_or(0), be16(d, i + 2).unwrap_or(0) as usize);
                if len < 4 || i + len > d.len() {
                    break;
                }
                let set = &d[i + 4..i + len];
                if set_id == 0 {
                    let mut j = 0;
                    while j + 4 <= set.len() {
                        let (tid, fc) = (be16(set, j).unwrap_or(0), be16(set, j + 2).unwrap_or(0) as usize);
                        let fields: Vec<(u16, u16)> = (0..fc).filter_map(|k| Some((be16(set, j + 4 + k * 4)?, be16(set, j + 6 + k * 4)?))).collect();
                        templates.t.insert((exporter.to_string(), tid), fields);
                        j += 4 + fc * 4;
                    }
                } else if set_id >= 256 {
                    if let Some(fields) = templates.t.get(&(exporter.to_string(), set_id)) {
                        let rec_len: usize = fields.iter().map(|f| f.1 as usize).sum();
                        let mut j = 0;
                        while rec_len > 0 && j + rec_len <= set.len() {
                            let mut r = FlowRecord { exporter: exporter.into(), ..Default::default() };
                            let mut off = j;
                            for (t, l) in fields {
                                let v = &set[off..off + *l as usize];
                                match t {
                                    1 => r.bytes = be_n(v),
                                    2 => r.packets = be_n(v),
                                    4 => r.proto = v[0],
                                    7 => r.src_port = be_n(v) as u16,
                                    8 if v.len() == 4 => r.src = ip4(v),
                                    11 => r.dst_port = be_n(v) as u16,
                                    12 if v.len() == 4 => r.dst = ip4(v),
                                    _ => {}
                                }
                                off += *l as usize;
                            }
                            out.push(r);
                            j += rec_len;
                        }
                    }
                }
                i += len;
            }
            out
        }
        _ => vec![],
    }
}

pub fn to_event(s: &Sensor, r: &FlowRecord) -> SecurityEvent {
    s.event(ocsf_class::NETWORK_ACTIVITY, v::NET_CONNECT).src_ip(&r.src).dst(&r.dst, r.dst_port as u32, "").records(r.bytes).attr("exporter", &r.exporter).attr("packets", &r.packets.to_string()).attr("proto", &r.proto.to_string()).build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v5_and_v9() {
        let mut v5 = vec![0, 5, 0, 1];
        v5.extend([0u8; 20]);
        let mut rec = vec![0u8; 48];
        rec[0..4].copy_from_slice(&[10, 0, 0, 1]);
        rec[4..8].copy_from_slice(&[203, 0, 113, 9]);
        rec[20..24].copy_from_slice(&5000u32.to_be_bytes());
        rec[34..36].copy_from_slice(&443u16.to_be_bytes());
        rec[38] = 6;
        v5.extend(rec);
        let mut t = Templates::default();
        let r = parse(&v5, "rtr", &mut t);
        assert_eq!((r[0].dst.as_str(), r[0].dst_port, r[0].bytes), ("203.0.113.9", 443, 5000));

        let mut v9 = vec![0, 9, 0, 2];
        v9.extend([0u8; 16]);
        let fields: [(u16, u16); 4] = [(8, 4), (12, 4), (11, 2), (1, 4)];
        let mut tmpl = vec![0, 0];
        let tlen = 4 + 4 + fields.len() * 4;
        tmpl.extend((tlen as u16).to_be_bytes());
        tmpl.extend(256u16.to_be_bytes());
        tmpl.extend((fields.len() as u16).to_be_bytes());
        for (a, b) in fields {
            tmpl.extend(a.to_be_bytes());
            tmpl.extend(b.to_be_bytes());
        }
        v9.extend(tmpl);
        let mut data = vec![1, 0];
        data.extend(((4 + 14) as u16).to_be_bytes());
        data.extend([10, 0, 0, 2, 198, 51, 100, 7]);
        data.extend(22u16.to_be_bytes());
        data.extend(777u32.to_be_bytes());
        v9.extend(data);
        let r = parse(&v9, "rtr", &mut t);
        assert_eq!((r[0].src.as_str(), r[0].dst_port, r[0].bytes), ("10.0.0.2", 22, 777));
    }
}
