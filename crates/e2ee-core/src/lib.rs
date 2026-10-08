#![forbid(unsafe_code)]

//! Shared security runtime contracts for End-To-End Everywhere Suite.
//!
//! PR 1 intentionally establishes boundaries rather than inventing cryptography.
//! Concrete cryptographic mechanisms are added only through versioned E2EESA-bound
//! profiles and independently testable runtime components.

/// Version of the suite architecture contract implemented by this crate.
pub const SUITE_ARCHITECTURE_VERSION: &str = "0.1";

/// Prevents accidental treatment of transport security as application E2EE.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionLayer {
    Transport,
    EndToEnd,
}

/// Describes where protected plaintext is permitted to exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaintextBoundary {
    AuthorizedEndpointOnly,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn application_e2ee_is_distinct_from_transport() {
        assert_ne!(ProtectionLayer::Transport, ProtectionLayer::EndToEnd);
    }

    #[test]
    fn plaintext_boundary_is_endpoint_only() {
        assert_eq!(
            PlaintextBoundary::AuthorizedEndpointOnly,
            PlaintextBoundary::AuthorizedEndpointOnly
        );
    }
}
