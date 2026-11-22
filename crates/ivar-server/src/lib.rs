//! The IVAR core service.
//!
//! The core is a horizontally scaled stream processor: each instance owns a
//! shard of entities (`shard_of`), so throughput grows with instances. Heavy
//! correlation runs here, off the request path; sensors decide locally from
//! their last signed policy and keep protecting while the core is unreachable.

pub use ivar_sensor_kit::adapters;
pub mod access;
pub mod config;
pub mod feed;
pub mod grpc;
pub mod http;
pub mod offline;
pub mod responders;
pub mod sinks;
pub mod state;
pub mod store;

/// Stable shard for an event: the source or acting identity, so every event
/// about one attacker lands on the same instance.
pub fn shard_of(ev: &ivar_contracts::SecurityEvent, shards: u32) -> u32 {
    use sha2::{Digest, Sha256};
    if shards <= 1 {
        return 0;
    }
    let key = ev
        .src_endpoint
        .as_ref()
        .map(|s| s.ip.clone())
        .filter(|s| !s.is_empty())
        .or_else(|| ev.actor.as_ref().and_then(|a| a.user.as_ref()).map(|u| u.uid.clone()))
        .unwrap_or_else(|| ev.ext().sensor_id);
    let d = Sha256::digest(key.as_bytes());
    u32::from_be_bytes([d[0], d[1], d[2], d[3]]) % shards
}
