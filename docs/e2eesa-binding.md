# E2EESA profile binding

Every security-sensitive suite feature must declare the exact E2EESA version and profile set it implements.

## Rules

- Profile identifiers are exact-version references, not floating labels.
- A component must not claim properties stronger than its bound profiles.
- Unsupported or prohibited profile combinations fail closed.
- A runtime downgrade must be explicit to the caller and user when relevant.
- Transport encryption must never be reported as application E2EE.
- Metadata protection claims are independent from protected-content claims.
- Test fixtures and conformance evidence must identify the exact implementation revision they exercise.

The suite will eventually consume machine-readable E2EESA profile catalogs directly. Until that integration lands, new implementation PRs must preserve these invariants structurally.
