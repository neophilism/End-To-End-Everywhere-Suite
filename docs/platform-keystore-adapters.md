# Platform key-store adapter boundary

E2ES-047 begins with a portable contract for reviewed host integrations. The
Rust process receives only an opaque key handle, metadata, and attestation
evidence. It never receives raw platform-root bytes through this API.

## Fail-closed selection

The exact requested storage profile determines the backend. If a platform or
hardware backend is unavailable, selection fails with `BackendUnavailable`.
It does not silently create a software-vault key. The existing software vault
is selected only when the caller explicitly requests
`secret-software-vault@0.1.0`.

Every accepted platform record must:

- match the requested profile, backend, handle, and generation;
- be reported non-exportable by both metadata and attestation;
- identify a bounded ASCII provider name;
- meet the caller's trusted generation floor; and
- for the hardware-isolated profile, report hardware-backed and
  rollback-resistant evidence.

Attestation is evidence supplied by a platform bridge, not proof created by the
portable Rust tests. A real bridge must translate and verify the native
platform result without exposing key bytes.

## Remaining E2ES-047 work

This slice does not claim a working Apple Keychain/Secure Enclave, Android
Keystore/StrongBox, Windows CNG/TPM, Linux secret service/TPM, or external
token integration. Each adapter still needs platform-specific implementation,
device tests, lifecycle/revocation behavior, error translation, and independent
security review. Until then, hardware-backed capability remains unavailable.
