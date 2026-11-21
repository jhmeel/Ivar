//! TLS ClientHello server name (SNI).

pub fn client_hello_sni(p: &[u8]) -> Option<String> {
    // Record header: handshake (22), version, length; then ClientHello (1).
    if *p.first()? != 22 || *p.get(5)? != 1 {
        return None;
    }
    let mut i = 5 + 4 + 2 + 32; // handshake header, client version, random
    let sid = *p.get(i)? as usize;
    i += 1 + sid;
    let cs = u16::from_be_bytes([*p.get(i)?, *p.get(i + 1)?]) as usize;
    i += 2 + cs;
    let comp = *p.get(i)? as usize;
    i += 1 + comp;
    let ext_total = u16::from_be_bytes([*p.get(i)?, *p.get(i + 1)?]) as usize;
    i += 2;
    let end = (i + ext_total).min(p.len());
    while i + 4 <= end {
        let t = u16::from_be_bytes([p[i], p[i + 1]]);
        let l = u16::from_be_bytes([p[i + 2], p[i + 3]]) as usize;
        if t == 0 {
            let name_len = u16::from_be_bytes([*p.get(i + 7)?, *p.get(i + 8)?]) as usize;
            return Some(String::from_utf8_lossy(p.get(i + 9..i + 9 + name_len)?).to_string());
        }
        i += 4 + l;
    }
    None
}

#[cfg(test)]
pub fn build_client_hello(host: &str) -> Vec<u8> {
    let name = host.as_bytes();
    let mut sni = vec![0, 0];
    let list_len = 3 + name.len();
    sni.extend_from_slice(&((list_len + 2) as u16).to_be_bytes());
    sni.extend_from_slice(&(list_len as u16).to_be_bytes());
    sni.push(0);
    sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sni.extend_from_slice(name);
    let mut body = vec![3, 3];
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
    body.extend_from_slice(&[0, 2, 0x13, 0x01]);
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    body.extend(sni);
    let mut hs = vec![1, 0, (body.len() >> 8) as u8, body.len() as u8];
    hs.extend(body);
    let mut rec = vec![22, 3, 1, (hs.len() >> 8) as u8, hs.len() as u8];
    rec.extend(hs);
    rec
}

#[cfg(test)]
mod tests {
    #[test]
    fn reads_sni() {
        assert_eq!(super::client_hello_sni(&super::build_client_hello("api.stripe.com")).unwrap(), "api.stripe.com");
    }
}
