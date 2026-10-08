# Encrypted software vault

`e2ee_keystore::software::SoftwareVault` implements the explicitly selected
`secret-software-vault@0.1.0` fallback. Requests for other profiles fail closed.
It provides opaque generated roots, password-encrypted snapshots, and
authenticated encryption of local endpoint protocol state.

The default unlock KDF is Argon2id v1.3 with 64 MiB, three passes, four lanes and
a random 16-byte salt, matching RFC 9106's second recommended configuration.
The first configuration (2 GiB, one pass, four lanes) is also accepted when the
caller explicitly raises the memory budget. Untrusted snapshot parameters must
meet the floor and fit the local budget before any KDF allocation. A 12-byte
minimum is an input requirement, not a claim of password entropy.

ChaCha20-Poly1305 protects both snapshots and state. Domain-separated associated
data authenticates versions, parameters, vault identity, revision, nonces,
lengths, root handles/classes/generations, application contexts and state
sequences. Random nonces are fresh for each operation. Parsers reject trailing
bytes, truncation, duplicate or unsorted roots and oversized records.

Root and derived keys, decrypted records and the Argon2 memory matrix are
zeroized when released. Applications must drop the unlocked vault on lock,
suspend, inactivity timeout or logout. Software protection does not prevent a
compromised unlocked process from obtaining secrets; metadata reports
`SoftwareProtected`, never hardware non-exportability.

Persist ciphertext snapshots atomically and keep the expected vault ID and
minimum revision in an independently trusted anchor. For each state record,
keep an independently trusted minimum sequence. Raising a floor before its
corresponding ciphertext is durable can cause data loss. Reading the floor
from the same replayable file does not provide rollback resistance. Platform
keystore, hardware-counter, independent-witness and durable file adapters are
separate integration work.

Provisioning never replaces an existing root. Passphrases and plaintext are
not logged, exported by the root API, or sent to any service. The encrypted
snapshot contains root material and requires the user's unlock secret.
