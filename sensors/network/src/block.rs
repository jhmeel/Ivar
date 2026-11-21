//! Inline blocking through an nftables set: `inet ivar blocklist`.

use std::process::Command;

pub struct Blocker {
    inline: bool,
}

impl Blocker {
    pub fn new(inline: bool) -> Self {
        Blocker { inline }
    }

    /// The commands that create the table, set and drop rule.
    pub fn setup_commands() -> Vec<Vec<&'static str>> {
        vec![
            vec!["add", "table", "inet", "ivar"],
            vec!["add", "set", "inet", "ivar", "blocklist", "{", "type", "ipv4_addr;", "flags", "timeout;", "}"],
            vec!["add", "chain", "inet", "ivar", "forward", "{", "type", "filter", "hook", "forward", "priority", "-10;", "}"],
            vec!["add", "rule", "inet", "ivar", "forward", "ip", "saddr", "@blocklist", "drop"],
            vec!["add", "rule", "inet", "ivar", "forward", "ip", "daddr", "@blocklist", "drop"],
        ]
    }

    pub fn ensure_table(&self) -> anyhow::Result<()> {
        for c in Self::setup_commands() {
            let _ = Command::new("nft").args(&c).status();
        }
        Ok(())
    }

    /// Block an address for an hour (the level 4 expiry); never blocks in mirror mode.
    pub fn block(&self, ip: &str) -> anyhow::Result<bool> {
        if !self.inline || ip.parse::<std::net::Ipv4Addr>().is_err() {
            return Ok(false);
        }
        let element = format!("{{ {ip} timeout 1h }}");
        let s = Command::new("nft").args(["add", "element", "inet", "ivar", "blocklist", &element]).status()?;
        Ok(s.success())
    }
}
