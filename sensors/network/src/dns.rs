//! DNS query names from UDP payloads.

pub fn query_name(p: &[u8]) -> Option<String> {
    if p.len() < 12 || p[2] & 0x80 != 0 {
        return None;
    }
    let qd = u16::from_be_bytes([p[4], p[5]]);
    if qd == 0 {
        return None;
    }
    let mut i = 12;
    let mut labels = Vec::new();
    loop {
        let len = *p.get(i)? as usize;
        if len == 0 {
            break;
        }
        if len & 0xC0 != 0 || labels.len() > 64 {
            return None;
        }
        labels.push(String::from_utf8_lossy(p.get(i + 1..i + 1 + len)?).to_string());
        i += 1 + len;
    }
    Some(labels.join("."))
}

#[cfg(test)]
pub fn build_query(name: &str) -> Vec<u8> {
    let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for l in name.split('.') {
        q.push(l.len() as u8);
        q.extend_from_slice(l.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]);
    q
}

#[cfg(test)]
mod tests {
    #[test]
    fn reads_query() {
        assert_eq!(super::query_name(&super::build_query("exfil.example.net")).unwrap(), "exfil.example.net");
    }
}
