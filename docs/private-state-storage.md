# Private durable local state

`e2ee-storage::PrivateStateStore` supplies the file adapter for a complete
ciphertext client record. It creates one private 0700 directory with 0600 files,
takes a nonblocking exclusive file lock for the entire transaction, bounds reads
and writes to 4 MiB, and rejects symlinks, hard links and non-regular records.
Creation refuses an existing directory. Opening never repairs unsafe permissions.

Keep the store guard alive while loading, unlocking, changing and saving state.
`commit(None, bytes)` initializes an empty store. Subsequent commits require the
SHA-256 digest of the record loaded by this transaction. A stale digest fails
without replacing the current record. This digest is an optimistic concurrency
token; it is **not** an independent rollback anchor or authenticity proof.

Commit writes a randomly named, exclusively created private temporary file,
flushes its contents with `sync_all`, renames it over the fixed record name, and
syncs the directory. All client state belongs in one complete encrypted record
so multiple logical components cannot be partially committed. Advance a trusted
revision/sequence floor only after successful durable commit. A failed directory
sync after rename returns `DurabilityUnknown`; reload before retrying or claiming
success. Crash-abandoned temporary files contain only the caller's ciphertext.
They are not used for recovery automatically.

This adapter accepts opaque bytes and does not encrypt them itself. Hosts must
supply an encrypted archive and keep secrets out of filenames. The implementation
currently supports Unix local filesystems, including Linux and macOS. Windows
fails explicitly until a private ACL adapter is supplied. Filesystem permissions,
advisory locking, rename and sync guarantees depend on the host/filesystem; this
does not claim network-filesystem or hardware rollback protection. A user must
control the selected directory and trust its ancestors. Concurrent malicious
processes running as that same user, directory relocation, OS compromise and
privileged readers are outside this file adapter's protection.

The lock file must never be removed or replaced while a process uses the store.
This API provides no automatic plaintext output, backup erasure or secure delete.
