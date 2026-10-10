# End-To-End Everywhere Suite — original 72-milestone product plan and full handoff

**Historical source:** October 7–8, 2026 conversations. The **72-slot original product roadmap** is distinct from the later **40-unit implementation/Engine Room mapping** in [`.exechub/project.yml`](../.exechub/project.yml). Do not silently overwrite either denominator. Original stage names #8–46 are directly recoverable; #1–7 and #47–72 have their original ordered *phase/category and count* recovered, but the detailed headings shown for those slots are **explicit reconstruction for implementation, not verified verbatim titles**.

## Purpose and security contract

Build a consumer-friendly and organizationally usable end-to-end encrypted product suite implementing the separate [E2EESA standard](https://github.com/neophilism/End-To-End-Everywhere-Security-Architecture-Standard). Shared endpoints perform encryption/decryption; servers coordinate/store/transport ciphertext. A portable encrypted **Capsule** is used for messages, files, notes, email, web forms, backups and APIs, without requiring every third-party app to natively implement E2EE. One shared cryptographic core, clear trust/device verification, named/versioned crypto profiles, reliable offline delivery, usable recovery, strong privacy and honest metadata limitations. Avoid green-lock claims beyond actual protection; no server-only account credential should authorize endpoint keys.

User-requested surfaces include secure personal vault/notes/contacts, encrypted messaging/calls, email/browser wrapper, QR pairing, file exchange, portable keys, desktop/mobile apps, developer SDKs, IT/enterprise tools and safe device recovery. These are future product milestones unless code and real acceptance demonstrate otherwise.

## Original ordered 72 product slots

### Runtime, identity and recovery — 1–7

#### EEES-01 — Foundation and threat boundaries

- **Title provenance:** Stage title reconstructed from original phase boundaries; original exact wording unavailable.
- **Scope:** Keep repo separated from E2EESA standard; threat model endpoint compromise, cloud admins, malware, metadata and provider/relay exposure.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-02 — Reusable E2EE runtime core

- **Title provenance:** Stage title reconstructed from original phase boundaries; original exact wording unavailable.
- **Scope:** Implement platform-independent cryptography and portable serialized envelope contracts with fail-closed version handling.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-03 — User identity and device registry

- **Title provenance:** Stage title reconstructed from original phase boundaries; original exact wording unavailable.
- **Scope:** Separate user, device, recipient enrollment and trust; compromised login must not itself authorize decrypting devices.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-04 — Endpoint key generation and secure persistence

- **Title provenance:** Stage title reconstructed from original phase boundaries; original exact wording unavailable.
- **Scope:** Use OS secure keystores when available; explicit software-vault fallback with password protection, durable nonce/state and secure deletion limits.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-05 — Device verification and authorization

- **Title provenance:** Stage title reconstructed from original phase boundaries; original exact wording unavailable.
- **Scope:** Verification, fingerprints, authorization, revoked/changed-key interlocks, QR/contact pairing and transparency checks.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-06 — Recovery and revocation model

- **Title provenance:** Stage title reconstructed from original phase boundaries; original exact wording unavailable.
- **Scope:** Backup of recovery material with explicit authorization separation, local-only unlock and careful retained-copy semantics.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-07 — Profile resolution and interoperability pinning

- **Title provenance:** Stage title reconstructed from original phase boundaries; original exact wording unavailable.
- **Scope:** Select approved E2EESA named/versioned profiles, reject downgrade and unknown/experimental unsupported suites.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

### Portable encrypted Capsules — 8–13

#### EEES-08 — Universal encrypted Capsule envelope

- **Title provenance:** Original stage title recovered.
- **Scope:** Encode authenticated context, recipient bindings and file/message metadata into portable encrypted Capsules; untrusted services cannot decrypt.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-09 — Encrypted text and messages

- **Title provenance:** Original stage title recovered.
- **Scope:** Encrypt/decrypt selected text or messages to verified endpoints, with replay/freshness and sender verification where supported.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-10 — Encrypted files and attachments

- **Title provenance:** Original stage title recovered.
- **Scope:** Encrypt large and chunked files; resumable transport, authenticated chunks, metadata protection and verified downloads.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-11 — Multi-recipient and group Capsules

- **Title provenance:** Original stage title recovered.
- **Scope:** Multiple separately authorized recipients or devices share ciphertext safely without conflating group and multi-recipient security guarantees.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-12 — Signer verification and provenance

- **Title provenance:** Original stage title recovered.
- **Scope:** Bind author/signer identity to exact content/context, manage changed identities and verify signatures before trust claims.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-13 — Portable Capsule viewer and decryptor

- **Title provenance:** Original stage title recovered.
- **Scope:** Portable open/view/save software for recipients with understandable trust state, no silent legacy fallback.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

### Desktop and mobile personal tools — 14–20

#### EEES-14 — Desktop client foundation

- **Title provenance:** Original stage title recovered.
- **Scope:** Local desktop vault, file workflow, recipients, account recovery and understandable security indicators on supported OSes.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-15 — Encrypted clipboard workflow

- **Title provenance:** Original stage title recovered.
- **Scope:** Encrypt/copied selected text and decrypt via explicit user intent, minimize clipboard persistence, never misrepresent global protections.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-16 — Drag-and-drop encryption and decryption

- **Title provenance:** Original stage title recovered.
- **Scope:** Import/export files and folders with private source retention and clear local/external destinations.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-17 — Secure Send for generic applications

- **Title provenance:** Original stage title recovered.
- **Scope:** Securely package files/text so other apps can relay ciphertext without seeing plaintext; explicit recipient consent.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-18 — Encrypted virtual drive and local vault

- **Title provenance:** Original stage title recovered.
- **Scope:** Virtual drive/folder navigation, secured notes, private local metadata, rekey, storage integrity and backup UX.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-19 — Mobile client foundation

- **Title provenance:** Original stage title recovered.
- **Scope:** Mobile account/device enrollment, secure local storage, screen lock, notices and workspaces.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-20 — Mobile share-sheet integration

- **Title provenance:** Original stage title recovered.
- **Scope:** Share-sheet import/export for text/files/media with OS permission and unavailable-target handling.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

### Browser protections — 21–26

#### EEES-21 — Browser extension foundation

- **Title provenance:** Original stage title recovered.
- **Scope:** Browser extension permissions, origin isolation, secure storage, versioned web/API boundary.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-22 — Automatic Capsule recognition and rendering

- **Title provenance:** Original stage title recovered.
- **Scope:** Detect supported Capsules and show verification/trust states; do not interpret arbitrary embedded attacker HTML.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-23 — Encrypt selected text and editable fields

- **Title provenance:** Original stage title recovered.
- **Scope:** User-initiated encryption of highlighted text, selected form fields, and controlled paste/decrypt actions.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-24 — Encrypted browser upload/download

- **Title provenance:** Original stage title recovered.
- **Scope:** Capture/swap uploaded/downloaded files with encrypted payload only under informed user control.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-25 — Encrypted web form framework

- **Title provenance:** Original stage title recovered.
- **Scope:** Reusable encrypted form widgets and server relay interactions; avoid browser giving server plaintext.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-26 — Cross-site compatibility and fallback UX

- **Title provenance:** Original stage title recovered.
- **Scope:** Robust fallback for unsupported websites, frames, CSPs and broken browser APIs; clear diagnostics.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

### Encrypted email workflows — 27–31

#### EEES-27 — Generic email E2EE envelope

- **Title provenance:** Original stage title recovered.
- **Scope:** Wrap existing mail in recipient-protected Capsule; disclose headers, addressing, server-visible metadata and recovery limits.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-28 — Gmail workflow integration

- **Title provenance:** Original stage title recovered.
- **Scope:** Compose/read workflow with Gmail while storing only ciphertext attachments/body when protected; account access alone is not E2E authorization.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-29 — Microsoft Outlook integration

- **Title provenance:** Original stage title recovered.
- **Scope:** Outlook-specific UI/email handoff with explicit credential, device and plugin isolation.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-30 — Thunderbird and standards-based mail integration

- **Title provenance:** Original stage title recovered.
- **Scope:** Standards-compatible mail path with Thunderbird integration where possible; test real clients.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-31 — Mail attachments, subject handling and interoperability

- **Title provenance:** Original stage title recovered.
- **Scope:** Encrypt attachments and protected metadata as supported; do not claim hidden SMTP envelope recipients or necessarily hidden subjects.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

### Messaging, calls and collaboration — 32–38

#### EEES-32 — One-to-one secure messaging

- **Title provenance:** Original stage title recovered.
- **Scope:** Durable verified one-to-one sessions, asynchronous delivery and forward secrecy/PCS where claimed.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-33 — Group messaging

- **Title provenance:** Original stage title recovered.
- **Scope:** Authenticated group membership, key epochs, removals, delivery failures and group history.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-34 — Messaging attachments, replies and reactions

- **Title provenance:** Original stage title recovered.
- **Scope:** Encrypted attachments, durable replies/reactions and safe notifications.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-35 — Encrypted voice calls

- **Title provenance:** Original stage title recovered.
- **Scope:** Actual voice media E2EE endpoint processing with signaling/control trust boundaries.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-36 — Encrypted video calls

- **Title provenance:** Original stage title recovered.
- **Scope:** Video encryption and understandable consent/recording limits.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-37 — Multiparty SFrame conferencing

- **Title provenance:** Original stage title recovered.
- **Scope:** Multiparty SFrame-compatible meeting and room state; group key control and join/leave handling.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-38 — Screen sharing and encrypted collaboration

- **Title provenance:** Original stage title recovered.
- **Scope:** Screen share/collaboration that encrypts content end-to-end with on-screen sharing/privacy warnings.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

### SDKs and integrations — 39–46

#### EEES-39 — Rust SDK

- **Title provenance:** Original stage title recovered.
- **Scope:** Reviewed Rust FFI/API with safe key ownership, error handling and sample integrations.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-40 — TypeScript and WebAssembly SDK

- **Title provenance:** Original stage title recovered.
- **Scope:** Browser/Node TypeScript SDK with WASM packaging, integrity and stable input types.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-41 — Swift SDK

- **Title provenance:** Original stage title recovered.
- **Scope:** Swift frameworks integrating native platform secure storage, lifecycle and app hooks.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-42 — Android and Kotlin SDK

- **Title provenance:** Original stage title recovered.
- **Scope:** Kotlin Android SDK and keystore integration, modern foreground/background delivery.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-43 — Java/.NET/server bindings

- **Title provenance:** Original stage title recovered.
- **Scope:** Java/.NET bindings, server-side ciphertext transform limitations and developer templates.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-44 — Encrypted database-field toolkit

- **Title provenance:** Original stage title recovered.
- **Scope:** Field-by-field application encryption components with authorized endpoint keys, versioning and search limitations.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-45 — Drop-in E2EE web components

- **Title provenance:** Original stage title recovered.
- **Scope:** Reusable consented UI components for encryption/verification/invitation/import that do not expose plaintext to services.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-46 — Secure encrypted forms and anonymous submissions

- **Title provenance:** Original stage title recovered.
- **Scope:** Protected forms/intake with anonymous/pseudonymous flows, authorization and prohibited security claims.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

### Enterprise and administrative controls — 47–54

#### EEES-47 — Enterprise identity and SSO integration

- **Title provenance:** Stage title reconstructed from original phase boundaries; original exact wording unavailable.
- **Scope:** Versioned enterprise authorization, tenant policy and auditable administrative decisions must not give operators undeclared content-decryption power.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-48 — Enterprise organization and member management

- **Title provenance:** Stage title reconstructed from original phase boundaries; original exact wording unavailable.
- **Scope:** Versioned enterprise authorization, tenant policy and auditable administrative decisions must not give operators undeclared content-decryption power.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-49 — Managed but endpoint-controlled device enrollment

- **Title provenance:** Stage title reconstructed from original phase boundaries; original exact wording unavailable.
- **Scope:** Versioned enterprise authorization, tenant policy and auditable administrative decisions must not give operators undeclared content-decryption power.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-50 — Enterprise policy and approval workflows

- **Title provenance:** Stage title reconstructed from original phase boundaries; original exact wording unavailable.
- **Scope:** Versioned enterprise authorization, tenant policy and auditable administrative decisions must not give operators undeclared content-decryption power.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-51 — Organization key-recovery governance

- **Title provenance:** Stage title reconstructed from original phase boundaries; original exact wording unavailable.
- **Scope:** Versioned enterprise authorization, tenant policy and auditable administrative decisions must not give operators undeclared content-decryption power.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-52 — Enterprise audit/assurance reporting

- **Title provenance:** Stage title reconstructed from original phase boundaries; original exact wording unavailable.
- **Scope:** Versioned enterprise authorization, tenant policy and auditable administrative decisions must not give operators undeclared content-decryption power.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-53 — Compliance and DLP boundary disclosure

- **Title provenance:** Stage title reconstructed from original phase boundaries; original exact wording unavailable.
- **Scope:** Versioned enterprise authorization, tenant policy and auditable administrative decisions must not give operators undeclared content-decryption power.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-54 — Admin dashboard and lifecycle operations

- **Title provenance:** Stage title reconstructed from original phase boundaries; original exact wording unavailable.
- **Scope:** Versioned enterprise authorization, tenant policy and auditable administrative decisions must not give operators undeclared content-decryption power.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

### Infrastructure and relay deployment — 55–61

#### EEES-55 — Ciphertext relay and transport service

- **Title provenance:** Stage title reconstructed from original phase boundaries; original exact wording unavailable.
- **Scope:** Ciphertext-only services, replay-resistant messaging, endpoint-exclusive keys, monitoring and reliable recovery without violating E2EE claims.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-56 — Offline delivery and resumable queue

- **Title provenance:** Stage title reconstructed from original phase boundaries; original exact wording unavailable.
- **Scope:** Ciphertext-only services, replay-resistant messaging, endpoint-exclusive keys, monitoring and reliable recovery without violating E2EE claims.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-57 — Directory/key-transparency interface

- **Title provenance:** Stage title reconstructed from original phase boundaries; original exact wording unavailable.
- **Scope:** Ciphertext-only services, replay-resistant messaging, endpoint-exclusive keys, monitoring and reliable recovery without violating E2EE claims.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-58 — Encrypted backup and sync transport

- **Title provenance:** Stage title reconstructed from original phase boundaries; original exact wording unavailable.
- **Scope:** Ciphertext-only services, replay-resistant messaging, endpoint-exclusive keys, monitoring and reliable recovery without violating E2EE claims.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-59 — Multi-region service/deployment options

- **Title provenance:** Stage title reconstructed from original phase boundaries; original exact wording unavailable.
- **Scope:** Ciphertext-only services, replay-resistant messaging, endpoint-exclusive keys, monitoring and reliable recovery without violating E2EE claims.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-60 — Observability without plaintext leaks

- **Title provenance:** Stage title reconstructed from original phase boundaries; original exact wording unavailable.
- **Scope:** Ciphertext-only services, replay-resistant messaging, endpoint-exclusive keys, monitoring and reliable recovery without violating E2EE claims.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-61 — Operations and disaster recovery

- **Title provenance:** Stage title reconstructed from original phase boundaries; original exact wording unavailable.
- **Scope:** Ciphertext-only services, replay-resistant messaging, endpoint-exclusive keys, monitoring and reliable recovery without violating E2EE claims.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

### CLI and scripting — 62–65

#### EEES-62 — CLI encryption and delivery automation

- **Title provenance:** Stage title reconstructed from original phase boundaries; original exact wording unavailable.
- **Scope:** Script-friendly local tooling with deterministic errors, non-interactive safety, verified device trust and key isolation.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-63 — CLI identity, trust and contact operations

- **Title provenance:** Stage title reconstructed from original phase boundaries; original exact wording unavailable.
- **Scope:** Script-friendly local tooling with deterministic errors, non-interactive safety, verified device trust and key isolation.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-64 — CLI file, batch and scripted integrations

- **Title provenance:** Stage title reconstructed from original phase boundaries; original exact wording unavailable.
- **Scope:** Script-friendly local tooling with deterministic errors, non-interactive safety, verified device trust and key isolation.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-65 — CLI diagnostics and packaging

- **Title provenance:** Stage title reconstructed from original phase boundaries; original exact wording unavailable.
- **Scope:** Script-friendly local tooling with deterministic errors, non-interactive safety, verified device trust and key isolation.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

### Assurance, interoperability and release — 66–72

#### EEES-66 — Cross-client cryptographic test vectors

- **Title provenance:** Stage title reconstructed from original phase boundaries; original exact wording unavailable.
- **Scope:** Security assurance requires real cross-client fixtures, audited integrations, compatibility, accessibility, reproducible releases and independent review.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-67 — E2EESA profile and conformance evidence

- **Title provenance:** Stage title reconstructed from original phase boundaries; original exact wording unavailable.
- **Scope:** Security assurance requires real cross-client fixtures, audited integrations, compatibility, accessibility, reproducible releases and independent review.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-68 — Independent interoperability tests

- **Title provenance:** Stage title reconstructed from original phase boundaries; original exact wording unavailable.
- **Scope:** Security assurance requires real cross-client fixtures, audited integrations, compatibility, accessibility, reproducible releases and independent review.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-69 — Threat-model and security red-team review

- **Title provenance:** Stage title reconstructed from original phase boundaries; original exact wording unavailable.
- **Scope:** Security assurance requires real cross-client fixtures, audited integrations, compatibility, accessibility, reproducible releases and independent review.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-70 — Accessible user-experience validation

- **Title provenance:** Stage title reconstructed from original phase boundaries; original exact wording unavailable.
- **Scope:** Security assurance requires real cross-client fixtures, audited integrations, compatibility, accessibility, reproducible releases and independent review.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-71 — Reproducible cross-platform packaging

- **Title provenance:** Stage title reconstructed from original phase boundaries; original exact wording unavailable.
- **Scope:** Security assurance requires real cross-client fixtures, audited integrations, compatibility, accessibility, reproducible releases and independent review.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

#### EEES-72 — Production acceptance and public release

- **Title provenance:** Stage title reconstructed from original phase boundaries; original exact wording unavailable.
- **Scope:** Security assurance requires real cross-client fixtures, audited integrations, compatibility, accessibility, reproducible releases and independent review.
- **Acceptance:** Include relevant deterministic crypto fixtures, negative trust/replay/rollback tests, unauthorized role/device access denial, portability and interruption/recovery tests, accessible user flow, explicit limits and versioned conformance evidence. Only claim real interoperability after device/client integration tests.

## Relation to repository's later 40-unit plan

The GitHub code focused early on reusable Rust Capsule/CLI/key/contact/archives. A later **40-unit implementation roadmap** exists in `.exechub/project.yml` with foundation, capsules, persistent client state, CLI delivery and personal vault tests. It **does not cancel** the previously approved 72-slot full product scope. Engineering PRs, especially original GitHub PR #21–40, refer to the later **code implementation sequence**, NOT EEES-21–40 browser/email/product stages. Preserve both namespaces explicitly:

- `EEES-01..EEES-72`: historical complete product-capability roadmap.
- `implementation-01..implementation-40`: existing Engine Room historical PR accounting on the actual codebase.
- Subsequent GitHub PR #41 onward: later code and release work; may implement parts of one or multiple EEES slots and must be mapped by evidence.

Do not mark browser, mail, calling, white-label admin or mobile stages done simply because Rust unit tests and CLI pass. Future approved scope changes require a new immutable manifest version and denominator explanation.

## Current code and supporting technical sources

Review [architecture](architecture.md), [runtime contract](runtime-contract.md), [capsule format](e2e-capsule-format.md), [client session](client-sessions.md), [device enrollment](device-enrollment.md), [contact trust](contact-lifecycle.md), [software vault](software-vault.md), [recovery](recovery-backup.md), [CLI](cli.md), [E2EESA binding](e2eesa-binding.md), and [Engine Room monitoring](engine-room-monitoring.md) for current constraints before designing new providers/UI.

## Cross-account release and execution

1. Fetch latest GitHub `main`, open PRs, CI, compatibility pins, release tags and known security risks. Use current-source tests rather than assumed completion from prior conversations.
2. Maintain a project-wide evidence matrix: `EEES-ID → full product capability → implementation/GitHub PRs → tests and device/browser/provider evidence → actual deployed availability`. Use the 72-stage plan for remaining product scope and the 40-item original code manifest for historical implementation progress, not conflated totals.
3. Continue reusable core first, then usable desktop/mobile vault and endpoint trust, then protected app/browser/email/messaging, with dependency parallelism only where contracts are stable. Do not hardcode provider, OS or tenant assumptions in the crypto core.
4. Require E2EESA contract/conformance evidence, manual security review, key compromise/recovery and revocation tests, cross-device interop and real user/product usability testing before release. Signatures, encryption and delivery promises must be demonstrated, not inferred from schemas.
5. Never commit credentials/keys; defer only access/permissions, material cryptographic/profile decisions or failed gates. Chain routine PRs and keep a live work-status page with completed/remaining, CI, deploy/monitor checks.

## Recovery confidence

**All 72 slots and the original phase allocation recovered; 39 exact numbered titles (EEES-08 to EEES-46) recovered.** The other 33 slot headings are labeled as reconstructed; claiming they were exact original titles would be inaccurate. Further original conversation access could be used to upgrade these to verified verbatim titles without changing required capabilities.
