# Persistent endpoint protocol keys

HPKE recipient keys and Ed25519 Capsule signing keys now offer `seal_local` and
`open_local`. These operations use the `LocalStateCipher` provider boundary;
the software vault is the first concrete implementation. No raw root or
private-key export operation is added.

Each encrypted key record binds its algorithm, endpoint ID and expected public
key in authenticated context. Opening requires these values from trusted client
state, together with the wrapping-root handle and minimum state sequence. The
decrypted private key must derive the expected public key. Recipient and signer
records cannot be interchanged, even when using the same wrapping root.

Only roots classified as `ProtocolStateWrappingRoot` can persist protocol keys.
Provider/backend matching is checked against the selected exact storage profile.
Record creation and restore do not authorize a device, verify a recipient, or
change a public-key pin. Client enrollment and contact verification remain
responsible for those decisions. In particular, importing an encrypted key
record must not silently replace an existing identity.

Applications persist ciphertext only, clear unlocked key objects on lock, and
advance independently trusted sequence floors after successful durable writes.
Persisting ciphertext and its sequence together in replayable storage does not
create rollback protection.
