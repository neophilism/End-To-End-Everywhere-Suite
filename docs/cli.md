# Local command-line client

Build/install the pre-alpha `e2ee` binary with `cargo install --path crates/e2ee-cli
--locked`. Linux/macOS private local state uses the Unix adapter; Windows state
storage fails explicitly. This client performs local operations and makes no
network service calls. Each invocation unlocks for one operation and drops keys
when complete.

Choose the software profile and restore policy explicitly. For basic local use:

```sh
e2ee --state ./alice-private --software-vault --password-only init alice
e2ee --state ./alice-private --software-vault --password-only identity
e2ee --state ./alice-private --software-vault --password-only card
```

The normal flow prompts on the controlling terminal with password echo disabled.
Creation and password changes require confirmation. Passphrases are never
displayed; Ctrl-C cancels a prompt, restores terminal echo and exits with status
130. Interruptions during password derivation are observed after that bounded
operation returns, before publishing a new identity or saving a mutation.
Passphrases are never accepted as command arguments or environment variables.
For automation, explicitly
add `--password-stdin` and supply a private, non-terminal credential stream ending
at EOF. It contains one passphrase line for normal commands; `passwd` consumes
the old and new passphrases on separate lines. Input is bounded, preserves spaces,
and accepts LF or CRLF. Protect the stream at its source; shell history and
unencrypted password files are not secret stores.

Importing a public `e2ec:v1:` card never verifies it. Compare its complete
fingerprint with the other person through an independent channel, then run the
separate verification command:

```sh
e2ee --state ./alice-private --software-vault --password-only import CONTACT_URI
e2ee --state ./alice-private --software-vault --password-only contacts
e2ee --state ./alice-private --software-vault --password-only verify bob FULL_FINGERPRINT
e2ee --state ./alice-private --software-vault --password-only revoke bob
e2ee --state ./alice-private --software-vault --password-only reactivate bob FULL_FINGERPRINT
e2ee --state ./alice-private --software-vault --password-only passwd
```

The basic password-only policy has no independent identity pin or rollback
protection, and says so on stderr. An older authenticated backup can restore old
contact decisions or an old unlock password. To enforce independent pins and
floors, retain the public `ANCHOR` token printed after a durable save in a
separately trusted system, then use `--anchor TOKEN` instead of `--password-only`.
The token is 140 hex characters encoding the versioned 70-byte archive anchor.
State mutation prints a new token only after successful durable commit. Update
the trusted system after that point. The CLI does not turn an adjacent anchor
file into trusted hardware or a monotonic witness, and cannot update your
independent trusted system automatically.

Existing directories are never reinitialized, permissions are never silently
repaired, and contact revocation cannot be cleared by import or ordinary verify.
Signed text delivery is available once both sides have imported and independently
verified one another's complete contact fingerprints. The comma-separated
recipient list has no whitespace. Text input must be UTF-8 and at most 4 MiB.
The destination must not already exist, including a symlink.

```sh
e2ee --state ./alice-private --software-vault --password-only seal-text bob mail-v1 ./draft.txt ./message.e2ed
e2ee --state ./bob-private --software-vault --password-only open-text alice mail-v1 ./message.e2ed ./opened.txt
```

Deliver the encrypted `.e2ed` file through any transport; the sender must be
verified in the receiver's contact book. Signed context is an exact, shared
application identifier (1-256 printable ASCII bytes); a missing signature,
unexpected signer, changed or revoked key, or wrong context fails closed.
No plaintext or passphrase is printed to stdout. The opened output is created
as a new private (0600) file on Unix and never silently overwrites files.
Protect plaintext source and output files, disk snapshots, and filesystem backups
yourself. This workflow does not provide forward secrecy after long-term key
compromise, message replay prevention, or network delivery. The output directory
should be private and trusted.

See `e2ee --help` for commands. File-attachment CLI follows this milestone.

## Signed attachments

Once both peers have independently verified the other's full contact fingerprint,
run:

```sh
e2ee --state ./alice-private --software-vault --password-only seal-file bob file-share-v1 ./report.pdf ./report.e2ed
e2ee --state ./bob-private --software-vault --password-only open-file alice file-share-v1 ./report.e2ed ./received.pdf
```

The local CLI supports inline attachments up to 32 MiB, and signs encrypted
multi-recipient Capsules. The sender-provided filename is authenticated inside
the encrypted payload but is **never** interpreted as an output path. The user
must explicitly select an output path that does not exist. The output is written
privately (0600 on Unix); contents are not automatically opened or executed.
Changed, unverified, or revoked sender/recipient contacts fail closed.
This is not a streaming API for larger files. The source filename, explicit
output paths, filesystem snapshots, and file lengths may remain visible to local
systems. E2EE does not protect plaintext files at rest outside the vault.
