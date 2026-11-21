//! Deterministic identifiers. Ids are derived from content, so a replay of the
//! same evidence produces the same ids.

use sha2::{Digest, Sha256};

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// `prefix_` + 10 Crockford base32 chars from SHA 256 of the parts
/// (e.g. `vrd_01JD8W3K7Q`).
pub fn derive(prefix: &str, parts: &[&str]) -> String {
    let mut h = Sha256::new();
    for p in parts {
        h.update((p.len() as u64).to_be_bytes());
        h.update(p.as_bytes());
    }
    let d = h.finalize();
    let mut bits: u64 = u64::from_be_bytes(d[0..8].try_into().unwrap());
    let mut out = [0u8; 10];
    for i in (0..10).rev() {
        out[i] = CROCKFORD[(bits & 31) as usize];
        bits >>= 5;
    }
    format!("{prefix}_{}", std::str::from_utf8(&out).unwrap())
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

#[cfg(test)]
mod t {
    #[test]
    fn stable() {
        let a = super::derive("vrd", &["x", "y"]);
        assert_eq!(a, super::derive("vrd", &["x", "y"]));
        assert_ne!(a, super::derive("vrd", &["xy"]));
        assert_eq!(a.len(), 14);
    }
}
