//! Shared networks: Carrier NAT ranges are throttled and never banned, as the
//! hardening guide already requires.

use ipnet::IpNet;
use std::net::IpAddr;

#[derive(Debug, Clone, Default)]
pub struct SharedNetworks {
    nets: Vec<IpNet>,
}

impl SharedNetworks {
    pub fn new(cidrs: &[String]) -> Self {
        let mut nets: Vec<IpNet> = cidrs.iter().filter_map(|c| c.parse().ok()).collect();
        if nets.is_empty() {
            nets.push("100.64.0.0/10".parse().expect("CGNAT range"));
        }
        SharedNetworks { nets }
    }

    pub fn contains(&self, ip: &str) -> bool {
        ip.parse::<IpAddr>().map(|a| self.nets.iter().any(|n| n.contains(&a))).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn cgnat_is_shared() {
        let s = super::SharedNetworks::new(&[]);
        assert!(s.contains("100.64.12.1"));
        assert!(!s.contains("203.0.113.5"));
    }
}
