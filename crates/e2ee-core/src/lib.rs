#![forbid(unsafe_code)]

//! Shared security runtime contracts for End-To-End Everywhere Suite.
//!
//! Applications consume profile-bound operations through this crate instead of
//! selecting cryptographic primitives directly.

mod identity;
mod profile;
mod runtime;

pub use identity::{
    AccountId, DeviceId, DeviceRecord, EndpointId, IdentityError, RecipientAddress, UserId,
};
pub use profile::{BoundProfile, ProfileId, ProfileParseError, ProfileSet};
pub use runtime::{
    OperationContext, PlaintextBoundary, ProtectionLayer, RuntimePolicy, SecurityDecision,
};

/// Version of the suite architecture contract implemented by this crate.
pub const SUITE_ARCHITECTURE_VERSION: &str = "0.1";
