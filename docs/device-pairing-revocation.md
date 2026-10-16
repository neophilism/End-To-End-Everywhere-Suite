# Device pairing and revocation boundary

E2ES-048 builds on the existing two-sided pairing ceremony. A pairing offer
still authorizes nothing until both clients submit the same verification digest
and the session is finalized before expiry. Finalization can now issue a device
authorization receipt bound to:

- the user, new device, and new endpoint;
- the existing endpoint that authorized the pairing;
- the enrollment identifier and matched verification digest; and
- the finalization time.

A `DeviceRoster` begins from one explicitly trusted bootstrap endpoint. Hosts
must obtain and restore that bootstrap through a separately protected account
setup path. The portable code does not turn an unverified endpoint into a trust
anchor.

## Fail-closed lifecycle

A paired authorization is accepted only when its user matches the roster and
its authorizing endpoint is still active. Endpoint identifiers are single-use:
an authorization cannot replace an existing endpoint or reactivate a revoked
one. Roster revisions advance monotonically for every accepted authorization
or revocation.

Revocation requires a distinct active endpoint and a timestamp no older than
either participating authorization. Once accepted, the target immediately
fails authorization checks and cannot authorize another device. Replaying its
old pairing receipt is rejected.

## Remaining E2ES-048 work

This is a portable state-machine boundary, not a deployed cross-client product.
It does not yet provide signed or encrypted pairing transport, durable
rollback-protected roster storage, QR rendering/scanning, synchronization,
multi-administrator policy, recovery authorization, user interface acceptance,
or real desktop/mobile interoperability tests. Those integrations, substantive AI source/security review and applicable passing tests
remain necessary before claiming E2ES-048 complete. Independent human review is
deferred under [the owner policy](../AGENTS.md); its absence does not block implementation,
merge or deployment, and AI review does not establish independent certification.
