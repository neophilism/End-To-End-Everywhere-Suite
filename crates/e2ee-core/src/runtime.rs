use crate::ProfileSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtectionLayer {
    Transport,
    EndToEnd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlaintextBoundary {
    AuthorizedEndpointOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityDecision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationContext {
    pub protection_layer: ProtectionLayer,
    pub plaintext_boundary: PlaintextBoundary,
    pub requires_application_e2ee: bool,
}

#[derive(Debug, Clone, Default)]
pub struct RuntimePolicy {
    profiles: ProfileSet,
}

impl RuntimePolicy {
    pub fn new(profiles: ProfileSet) -> Self {
        Self { profiles }
    }

    pub fn profiles(&self) -> &ProfileSet {
        &self.profiles
    }

    /// Fail closed if an operation that requires application E2EE is only
    /// protected at the transport layer.
    pub fn authorize(&self, context: &OperationContext) -> SecurityDecision {
        if context.requires_application_e2ee
            && context.protection_layer != ProtectionLayer::EndToEnd
        {
            return SecurityDecision::Deny;
        }

        if context.plaintext_boundary != PlaintextBoundary::AuthorizedEndpointOnly {
            return SecurityDecision::Deny;
        }

        SecurityDecision::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_only_does_not_satisfy_e2ee_requirement() {
        let policy = RuntimePolicy::default();
        let context = OperationContext {
            protection_layer: ProtectionLayer::Transport,
            plaintext_boundary: PlaintextBoundary::AuthorizedEndpointOnly,
            requires_application_e2ee: true,
        };
        assert_eq!(policy.authorize(&context), SecurityDecision::Deny);
    }

    #[test]
    fn endpoint_e2ee_is_allowed() {
        let policy = RuntimePolicy::default();
        let context = OperationContext {
            protection_layer: ProtectionLayer::EndToEnd,
            plaintext_boundary: PlaintextBoundary::AuthorizedEndpointOnly,
            requires_application_e2ee: true,
        };
        assert_eq!(policy.authorize(&context), SecurityDecision::Allow);
    }
}
