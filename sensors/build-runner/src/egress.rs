//! Default deny build egress (the approach proven by Harden-Runner): only
//! names on the job's allowlist resolve, only addresses they resolved to are
//! reachable. In observe mode undeclared egress is recorded, not dropped.

use ivar_contracts::PolicyContent;
use std::collections::BTreeSet;
use std::process::Command;

pub struct EgressPolicy {
    pub allowed: BTreeSet<String>,
    pub enforce: bool,
}

/// Always needed for the runner to talk to its own service.
const RUNNER_BASE: &[&str] = &["github.com", "*.github.com", "*.githubusercontent.com", "*.actions.githubusercontent.com", "*.blob.core.windows.net", "gitlab.com"];

impl EgressPolicy {
    pub fn new(extra: Vec<String>, enforce: bool) -> Self {
        let mut allowed: BTreeSet<String> = RUNNER_BASE.iter().map(|s| s.to_string()).collect();
        allowed.extend(extra);
        EgressPolicy { allowed, enforce }
    }

    /// Add the egress the workflow declared for this job (x-ivar-egress).
    pub fn extend_from_declarations(&mut self, p: &PolicyContent, holder: &str) {
        let d = ivar_core::declare::Declarations::from_value(&p.declared);
        for e in d.egress.iter().filter(|e| e.holder == holder || e.holder == "*") {
            self.allowed.insert(e.destination.clone());
        }
    }

    pub fn allows(&self, name: &str) -> bool {
        let name = name.trim_end_matches('.').to_lowercase();
        self.allowed.iter().any(|a| match a.strip_prefix("*.") {
            Some(suffix) => name.ends_with(&format!(".{suffix}")) || name == suffix,
            None => &name == a,
        })
    }
}

pub fn rules(enforce: bool) -> Vec<Vec<String>> {
    let verdict = if enforce { "drop" } else { "log prefix \"ivar-undeclared-egress \" accept" };
    let s = |x: &str| x.split(' ').map(String::from).collect::<Vec<_>>();
    vec![
        s("add table inet ivar_ci"),
        s("add set inet ivar_ci allowed { type ipv4_addr; flags timeout; }"),
        s("add chain inet ivar_ci output { type filter hook output priority 0; }"),
        s("add rule inet ivar_ci output oif lo accept"),
        s("add rule inet ivar_ci output ip daddr @allowed accept"),
        s("add rule inet ivar_ci output udp dport 53 ip daddr 127.0.0.53 accept"),
        s("add rule inet ivar_ci output ct state established,related accept"),
        format!("add rule inet ivar_ci output {verdict}").split(' ').map(String::from).collect(),
    ]
}

pub fn install_rules(p: &EgressPolicy) -> anyhow::Result<()> {
    for r in rules(p.enforce) {
        let _ = Command::new("sudo").arg("-n").arg("nft").args(&r).status();
    }
    let _ = std::fs::write("/etc/resolv.conf", "nameserver 127.0.0.53\n");
    Ok(())
}

pub fn allow_ip(ip: &str) {
    let el = format!("{{ {ip} timeout 6h }}");
    let _ = Command::new("sudo").args(["-n", "nft", "add", "element", "inet", "ivar_ci", "allowed", &el]).status();
}

#[cfg(test)]
mod tests {
    #[test]
    fn allowlist_matching() {
        let p = super::EgressPolicy::new(vec!["registry.npmjs.org".into()], true);
        assert!(p.allows("registry.npmjs.org."));
        assert!(p.allows("objects.githubusercontent.com"));
        assert!(!p.allows("exfil.example.net"));
        assert!(super::rules(true).last().unwrap().contains(&"drop".to_string()));
    }
}
