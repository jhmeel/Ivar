//! Signed runtime flags (section 15, defects F1 and F3).
//!
//! Runtime flags are signed and versioned, so a direct write to the store
//! cannot flip a kill switch. The last known flag state is kept on local
//! disk, and the safest value is held when it is missing, so a restart during
//! an outage cannot reopen what an operator closed.

use ivar_contracts::sign::{sign_bytes, verify_bytes, KeyPair, Keyring};
use ivar_contracts::BundleSignature;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Kill switches and their safest value.
pub const KILL_SWITCHES: &[(&str, &str)] = &[
    ("PAYOUTS_ENABLED", "false"),
    ("REGISTRATION_MODE", "closed"),
    ("SIGNING_ENABLED", "false"),
    ("EXPORTS_ENABLED", "false"),
];

/// Safest value for runtime settings that are not kill switches.
const SAFEST_RUNTIME: &[(&str, &str)] = &[("DETECTION_MODE", "enforce"), ("RUNTIME_POSTURE", "lockdown")];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignedFlag {
    pub name: String,
    pub value: String,
    pub version: u64,
    pub issued_at: i64,
    pub signature: Option<BundleSignature>,
}

impl SignedFlag {
    fn signed_bytes(&self) -> Vec<u8> {
        format!("ivar.flag.v1\n{}\n{}\n{}\n{}", self.name, self.value, self.version, self.issued_at).into_bytes()
    }

    pub fn sign(mut self, key: &KeyPair) -> Self {
        self.signature = Some(sign_bytes(key, &self.signed_bytes()));
        self
    }

    pub fn verify(&self, ring: &Keyring) -> bool {
        match &self.signature {
            Some(sig) => verify_bytes(ring, "flags", sig, &self.signed_bytes()).is_ok(),
            None => false,
        }
    }
}

/// Where the last known signed state is kept (a file on local disk in the
/// server and agents, memory in tests and the browser).
pub trait FlagPersistence {
    fn load(&self) -> BTreeMap<String, SignedFlag>;
    fn save(&mut self, flags: &BTreeMap<String, SignedFlag>);
}

#[derive(Default)]
pub struct MemoryFlagPersistence(pub BTreeMap<String, SignedFlag>);

impl FlagPersistence for MemoryFlagPersistence {
    fn load(&self) -> BTreeMap<String, SignedFlag> {
        self.0.clone()
    }
    fn save(&mut self, flags: &BTreeMap<String, SignedFlag>) {
        self.0 = flags.clone();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FlagSource {
    /// From the flag store, signature verified.
    Store,
    /// The store was unavailable: last signed state saved on disk.
    LocalDisk,
    /// Nothing verifiable: the safest value is held and an alert raised.
    SafestDefault,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlagResolution {
    pub name: String,
    pub value: String,
    pub version: u64,
    pub source: FlagSource,
    /// Unsigned or badly signed writes that were refused.
    pub rejected: Vec<String>,
}

pub struct FlagResolver<P: FlagPersistence> {
    ring: Keyring,
    persistence: P,
}

pub fn safest_value(name: &str) -> Option<&'static str> {
    KILL_SWITCHES.iter().chain(SAFEST_RUNTIME.iter()).find(|(n, _)| *n == name).map(|(_, v)| *v)
}

impl<P: FlagPersistence> FlagResolver<P> {
    pub fn new(ring: Keyring, persistence: P) -> Self {
        FlagResolver { ring, persistence }
    }

    pub fn persistence(&self) -> &P {
        &self.persistence
    }

    /// Resolve every named flag from the store snapshot. `store` is None when
    /// the flag store is unavailable.
    pub fn resolve(&mut self, names: &[&str], store: Option<&BTreeMap<String, SignedFlag>>) -> Vec<FlagResolution> {
        let mut disk = self.persistence.load();
        disk.retain(|_, f| f.verify(&self.ring));
        let mut out = Vec::new();
        let mut changed = false;
        for name in names {
            let mut rejected = Vec::new();
            let from_store = store.and_then(|s| s.get(*name)).and_then(|f| {
                if f.verify(&self.ring) {
                    Some(f.clone())
                } else {
                    rejected.push(format!("{name}={} (unsigned or invalid signature)", f.value));
                    None
                }
            });
            let on_disk = disk.get(*name).cloned();
            // Never roll back to an older signed version than the one on disk.
            let chosen = match (from_store, on_disk) {
                (Some(s), Some(d)) if d.version > s.version => {
                    rejected.push(format!("{name} version {} is older than local version {}", s.version, d.version));
                    Some((d, FlagSource::LocalDisk))
                }
                (Some(s), _) => Some((s, FlagSource::Store)),
                (None, Some(d)) => Some((d, FlagSource::LocalDisk)),
                (None, None) => None,
            };
            match chosen {
                Some((f, source)) => {
                    if source == FlagSource::Store && disk.get(*name) != Some(&f) {
                        disk.insert(name.to_string(), f.clone());
                        changed = true;
                    }
                    out.push(FlagResolution { name: name.to_string(), value: f.value, version: f.version, source, rejected });
                }
                None => out.push(FlagResolution {
                    name: name.to_string(),
                    value: safest_value(name).unwrap_or("").to_string(),
                    version: 0,
                    source: FlagSource::SafestDefault,
                    rejected,
                }),
            }
        }
        if changed {
            self.persistence.save(&disk);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (KeyPair, Keyring) {
        let k = KeyPair::ed25519_from_seed("flags-1", [7; 32]);
        let mut ring = Keyring::default();
        ring.add(k.public(), &["flags"]);
        (k, ring)
    }

    fn flag(name: &str, value: &str, version: u64) -> SignedFlag {
        SignedFlag { name: name.into(), value: value.into(), version, issued_at: 0, signature: None }
    }

    /// Defect F1: payouts off and registration closed, then restart while the
    /// store is down. The closed state must hold.
    #[test]
    fn f1_restart_while_store_down_keeps_closed_state() {
        let (k, ring) = setup();
        let mut r = FlagResolver::new(ring.clone(), MemoryFlagPersistence::default());
        let mut store = BTreeMap::new();
        store.insert("PAYOUTS_ENABLED".into(), flag("PAYOUTS_ENABLED", "false", 5).sign(&k));
        store.insert("REGISTRATION_MODE".into(), flag("REGISTRATION_MODE", "closed", 5).sign(&k));
        r.resolve(&["PAYOUTS_ENABLED", "REGISTRATION_MODE"], Some(&store));
        let disk = r.persistence().0.clone();
        let mut restarted = FlagResolver::new(ring, MemoryFlagPersistence(disk));
        let res = restarted.resolve(&["PAYOUTS_ENABLED", "REGISTRATION_MODE"], None);
        assert_eq!(res[0].value, "false");
        assert_eq!(res[1].value, "closed");
        assert!(res.iter().all(|x| x.source == FlagSource::LocalDisk));
    }

    #[test]
    fn missing_state_holds_safest_value() {
        let (_, ring) = setup();
        let mut r = FlagResolver::new(ring, MemoryFlagPersistence::default());
        let res = r.resolve(&["PAYOUTS_ENABLED", "REGISTRATION_MODE"], None);
        assert_eq!((res[0].value.as_str(), res[1].value.as_str()), ("false", "closed"));
        assert_eq!(res[0].source, FlagSource::SafestDefault);
    }

    /// Defect F3: a value written directly to the flag key is refused.
    #[test]
    fn f3_unsigned_write_is_refused() {
        let (k, ring) = setup();
        let mut r = FlagResolver::new(ring, MemoryFlagPersistence::default());
        let mut store = BTreeMap::new();
        store.insert("PAYOUTS_ENABLED".into(), flag("PAYOUTS_ENABLED", "false", 3).sign(&k));
        r.resolve(&["PAYOUTS_ENABLED"], Some(&store));
        store.insert("PAYOUTS_ENABLED".into(), flag("PAYOUTS_ENABLED", "true", 9));
        let res = r.resolve(&["PAYOUTS_ENABLED"], Some(&store));
        assert_eq!(res[0].value, "false");
        assert_eq!(res[0].rejected.len(), 1);
    }

    #[test]
    fn signed_rollback_is_refused() {
        let (k, ring) = setup();
        let mut r = FlagResolver::new(ring, MemoryFlagPersistence::default());
        let mut store = BTreeMap::new();
        store.insert("PAYOUTS_ENABLED".into(), flag("PAYOUTS_ENABLED", "false", 8).sign(&k));
        r.resolve(&["PAYOUTS_ENABLED"], Some(&store));
        store.insert("PAYOUTS_ENABLED".into(), flag("PAYOUTS_ENABLED", "true", 2).sign(&k));
        assert_eq!(r.resolve(&["PAYOUTS_ENABLED"], Some(&store))[0].value, "false");
    }
}
