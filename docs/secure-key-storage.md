# Secure local key storage

PR 4 defines the fail-closed key-storage boundary used by every later client.

## E2EESA-bound storage profiles

The suite recognizes the exact profile identifiers established by E2EESA:

- `secret-platform-keystore@0.1.0`
- `secret-hardware-isolated@0.1.0`
- `secret-external-token@0.1.0`
- `secret-software-vault@0.1.0`

A requested hardware-backed profile never silently falls back to a software vault. If the required backend is unavailable, the operation fails.

## Opaque roots

Durable root/wrapping keys are represented by opaque `SecretHandle` values. The shared API does not expose a method for exporting raw root-key bytes.

Fast-changing E2EE protocol state may later be stored in an authenticated encrypted vault protected by those roots, consistent with the selected E2EESA secret-storage profile.

## Rollback resistance

Secret metadata carries a monotonic generation. Callers supply a minimum acceptable generation and storage providers must reject older state.

## Platform adapters

This PR establishes the provider contract and profile/backend matching rules. OS-specific adapters (Secure Enclave, Android hardware-backed Keystore/StrongBox, TPM/HSM/PKCS#11, and software-vault fallback when explicitly selected) plug into this boundary without changing application APIs.
