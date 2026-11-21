//! Policy and configuration (section 15).
//!
//! Every setting keeps the resolve order of the existing configuration model:
//! profile default, environment override, hard limits and cross checks, then
//! signed runtime flags.

mod flags;
mod settings;

pub use flags::{FlagPersistence, FlagResolution, FlagResolver, FlagSource, MemoryFlagPersistence, SignedFlag, KILL_SWITCHES};
pub use settings::{
    AiAutonomy, ConfigError, DetectionMode, IntentBindingMode, Profile, RuntimePosture, Settings, SettingsWarning,
};
