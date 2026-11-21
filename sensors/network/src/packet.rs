//! Ethernet, IPv4, IPv6, TCP and UDP header parsing.

#[derive(Debug, Clone, PartialEq)]
pub struct Packet {
    pub src: String,
    pub dst: String,
    pub proto: u8,
    pub src_port: u16,
    pub dst_port: u16,
    pub tcp_flags: u8,
    pub len: usize,
    pub payload: Vec<u8>,
}

fn be16(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i + 1)?]))
}

pub fn parse_ethernet(f: &[u8]) -> Option<Packet> {
    let mut ethertype = be16(f, 12)?;
    let mut off = 14;
    if ethertype == 0x8100 {
        ethertype = be16(f, 16)?;
        off = 18;
    }
    match ethertype {
        0x0800 => parse_ipv4(f.get(off..)?),
        0x86DD => parse_ipv6(f.get(off..)?),
        _ => None,
    }
}

pub fn parse_ipv4(p: &[u8]) -> Option<Packet> {
    let ihl = ((*p.first()? & 0x0f) as usize) * 4;
    let proto = *p.get(9)?;
    let src = format!("{}.{}.{}.{}", p.get(12)?, p.get(13)?, p.get(14)?, p.get(15)?);
    let dst = format!("{}.{}.{}.{}", p.get(16)?, p.get(17)?, p.get(18)?, p.get(19)?);
    let total = be16(p, 2)? as usize;
    l4(src, dst, proto, p.get(ihl..total.min(p.len()))?, total)
}

pub fn parse_ipv6(p: &[u8]) -> Option<Packet> {
    let proto = *p.get(6)?;
    let addr = |o: usize| -> Option<String> {
        let b = p.get(o..o + 16)?;
        Some(std::net::Ipv6Addr::from(<[u8; 16]>::try_from(b).ok()?).to_string())
    };
    l4(addr(8)?, addr(24)?, proto, p.get(40..)?, p.len())
}

fn l4(src: String, dst: String, proto: u8, seg: &[u8], len: usize) -> Option<Packet> {
    let (sp, dp, flags, payload) = match proto {
        6 => {
            let doff = ((*seg.get(12)? >> 4) as usize) * 4;
            (be16(seg, 0)?, be16(seg, 2)?, *seg.get(13)?, seg.get(doff..).unwrap_or(&[]).to_vec())
        }
        17 => (be16(seg, 0)?, be16(seg, 2)?, 0, seg.get(8..).unwrap_or(&[]).to_vec()),
        _ => (0, 0, 0, vec![]),
    };
    Some(Packet { src, dst, proto, src_port: sp, dst_port: dp, tcp_flags: flags, len, payload })
}

#[cfg(test)]
pub fn build_udp_v4(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![0u8; 14];
    f[12] = 0x08;
    let total = 20 + 8 + payload.len();
    let mut ip = vec![0x45, 0, (total >> 8) as u8, total as u8, 0, 0, 0, 0, 64, 17, 0, 0];
    ip.extend_from_slice(&src);
    ip.extend_from_slice(&dst);
    f.extend(ip);
    f.extend_from_slice(&sport.to_be_bytes());
    f.extend_from_slice(&dport.to_be_bytes());
    f.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    f.extend_from_slice(&[0, 0]);
    f.extend_from_slice(payload);
    f
}

#[cfg(test)]
pub fn build_tcp_v4(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![0u8; 14];
    f[12] = 0x08;
    let total = 20 + 20 + payload.len();
    let mut ip = vec![0x45, 0, (total >> 8) as u8, total as u8, 0, 0, 0, 0, 64, 6, 0, 0];
    ip.extend_from_slice(&src);
    ip.extend_from_slice(&dst);
    f.extend(ip);
    let mut tcp = vec![0u8; 20];
    tcp[0..2].copy_from_slice(&sport.to_be_bytes());
    tcp[2..4].copy_from_slice(&dport.to_be_bytes());
    tcp[12] = 5 << 4;
    tcp[13] = flags;
    f.extend(tcp);
    f.extend_from_slice(payload);
    f
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_udp() {
        let f = super::build_udp_v4([10, 0, 0, 1], [8, 8, 8, 8], 5353, 53, b"x");
        let p = super::parse_ethernet(&f).unwrap();
        assert_eq!((p.src.as_str(), p.dst.as_str(), p.dst_port, p.payload.as_slice()), ("10.0.0.1", "8.8.8.8", 53, &b"x"[..]));
    }
}
