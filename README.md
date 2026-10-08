# End-To-End Everywhere Suite

End-To-End Everywhere Suite is the implementation layer for making end-to-end encryption usable by individuals, organizations, IT teams, and application developers.

The suite is intentionally separate from the [End-To-End Everywhere Security Architecture Standard](https://github.com/neophilism/End-To-End-Everywhere-Security-Architecture-Standard). E2EESA defines security properties, profiles, and conformance rules; this repository implements products and reusable components against those profiles.

## Design principles

- **Endpoints decrypt; services coordinate, store, and transport ciphertext.**
- **One cryptographic core, many user experiences.**
- **Secure defaults with explicit downgrade behavior.**
- **No green-lock overclaims:** metadata and trust limitations remain visible.
- **Portable encrypted envelopes:** applications can carry protected data without understanding its plaintext.
- **Usable by everyone:** desktop, mobile, browser, CLI, SDK, and enterprise administration are first-class surfaces.

## Roadmap

The implementation roadmap begins with the shared runtime, identity/device model, secure local key storage, device verification, transparency, and recovery. It then adds the E2E Capsule envelope, consumer apps, browser overlays, email, messaging/calls, SDKs, enterprise controls, infrastructure, CLI automation, and conformance/release work.

## Status

Pre-alpha. Interfaces and cryptographic profiles are not yet stable.

The Rust workspace now includes text and chunked-file encryption, authenticated
multi-recipient envelopes, optional signer verification, and portable signed or
unsigned deliveries. See [multi-recipient Capsules](docs/multi-recipient-capsules.md),
[signatures](docs/capsule-signatures.md), and [transport](docs/capsule-transport.md).
Consumer applications and platform keystore adapters are subsequent milestones.
The explicit [software-vault fallback](docs/software-vault.md) now encrypts
durable roots and local protocol state with local password-based unlocking.
Recipient and signing keys support [encrypted endpoint persistence](docs/persistent-endpoint-keys.md)
bound to their endpoint, algorithm and expected public key.
The [shared client session](docs/client-sessions.md) now composes verified
contacts, sender-checked text delivery, encrypted key persistence and auto-lock.
The same controller supports [files and portable contact/state records](docs/client-files-and-portability.md).
An [encrypted contact book](docs/contact-lifecycle.md) now blocks unverified,
changed and revoked contacts and requires explicit fingerprint re-verification.
The vault supports [passphrase changes and permanent root-handle retirement](docs/vault-credential-lifecycle.md).
A [private durable file adapter](docs/private-state-storage.md) now supports whole-record
atomic commits, exclusive writer locks and stale-write detection on Unix hosts.
The [persistent client archive](docs/client-archives.md) now restores vault,
endpoint keys and contact trust together, with explicit anchored or password-only policies.
