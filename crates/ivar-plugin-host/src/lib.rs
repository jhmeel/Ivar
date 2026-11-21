//! Plugin system (section 14).
//!
//! Every capability beyond the core is a signed plugin with declared
//! permissions. Plugins run in a sandbox and receive only the access their
//! manifest grants. Lifecycle: verify the signature, check permissions, run
//! in shadow mode, release to a small canary group, then activate. A plugin
//! that crashes, exceeds its limits or requests undeclared access is disabled
//! automatically and raises an alert; one whose verdicts drift returns to
//! shadow mode until it passes again. Rule packs and policy bundles go
//! through the same shadow and canary stages.

pub mod adapter;
pub mod drift;
pub mod lifecycle;
pub mod netpolicy;
pub mod permissions;
pub mod process;
pub mod registry;
pub mod sandbox;
pub mod signature;

pub use lifecycle::{Stage, Transition};
pub use registry::{ArtifactKind, PluginRecord, PluginRegistry, RegistryEvent};
