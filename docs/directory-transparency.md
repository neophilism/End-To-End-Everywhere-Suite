# Recipient directory and key transparency

Directory infrastructure is treated as untrusted coordination infrastructure, not as authority to silently replace recipient keys.

PR 6 introduces a client-side verification boundary. A recipient lookup is usable only after:

1. the returned address matches the requested recipient;
2. the directory record is structurally valid and contains no duplicate endpoint or key bindings;
3. the transparency checkpoint is authenticated by the selected verifier;
4. the record has a valid inclusion proof;
5. the checkpoint is not older than the locally pinned checkpoint;
6. a same-size checkpoint has the same root; and
7. an advancing checkpoint has a valid consistency proof.

A different root at the same tree size is treated as equivocation. A smaller tree is treated as rollback.

The verifier is an injected cryptographic component. This crate does not claim that a proof is valid merely because a server supplied proof-shaped bytes. Production proof/signature verification is implemented behind that interface and bound to the selected E2EESA profile.
