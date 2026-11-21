//! IVAR data contracts (spec section 9).
//!
//! Every component exchanges versioned objects, so any sensor or engine can be
//! replaced without changing its neighbours. Protobuf objects are generated
//! from proto/ivar/v1; JSON, YAML and signed archive objects live in their own
//! module here.

pub mod error;
pub mod incident;
pub mod intent;
pub mod invariant;
pub mod plugin;
pub mod policy;
pub mod proto;
pub mod replay;
pub mod sign;

pub use error::ContractError;
pub use incident::*;
pub use intent::*;
pub use invariant::*;
pub use plugin::*;
pub use policy::*;
pub use proto::*;
pub use replay::*;

/// Contract version carried by every non protobuf object.
pub const CONTRACT_VERSION: &str = "ivar.v1";
/// OCSF schema version targeted by sensors.
pub const OCSF_VERSION: &str = "1.3.0";
/// Name of the OCSF extension that holds the IVAR fields.
pub const OCSF_EXTENSION_NAME: &str = "ivar";
pub const OCSF_EXTENSION_UID: &str = "999";
pub const OCSF_EXTENSION_VERSION: &str = "1.0.0";
