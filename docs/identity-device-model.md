# Identity and device model

The suite keeps account identity, user identity, physical/logical device identity, and cryptographic endpoint identity separate.

A login account is not automatically a cryptographic identity. A device is not automatically an authorized endpoint.

## Core entities

- **User** — a human or explicitly modeled non-human principal.
- **Account** — a service/account namespace used for authentication and administration.
- **Device** — an enrolled device record.
- **Endpoint** — a cryptographic endpoint authorized to hold/use E2EE state.
- **Recipient address** — a portable discovery address that resolves to cryptographic recipient material through later directory/transparency components.

## Invariants

- IDs are typed so code cannot casually interchange accounts, devices, endpoints, and users.
- Recipient addresses are syntax-validated before discovery.
- Device records carry explicit enabled state; revocation is not inferred from deletion.
- Authorization to decrypt is established by cryptographic recipient state, not merely by account membership.
- Multi-device users are expected, not treated as an exception.
- Directory/discovery results will later be authenticated and transparency-checked before being trusted.

This model deliberately avoids putting server-controlled authorization directly in the plaintext trust boundary.
