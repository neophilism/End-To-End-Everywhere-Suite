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

## Email-friendly ASCII-armored deliveries

Add `--armor` **before** a seal/open command to select a strictly parsed,
copyable text representation of the same authenticated encrypted Capsule.
Both endpoints must explicitly select armor; binary `.e2ed` remains the
default. For example:

```sh
e2ee --state ./alice-private --software-vault --password-only --armor seal-text bob mail-v1 ./draft.txt ./encrypted.asc
e2ee --state ./bob-private --software-vault --password-only --armor open-text alice mail-v1 ./encrypted.asc ./opened.txt
e2ee --state ./alice-private --software-vault --password-only --armor seal-file bob file-share-v1 ./report.pdf ./report.asc
e2ee --state ./bob-private --software-vault --password-only --armor open-file alice file-share-v1 ./report.asc ./received.pdf
```

The armor is framed as `-----BEGIN E2E DELIVERY-----` and
`-----END E2E DELIVERY-----`; it represents **ciphertext**, not plaintext.
It can be placed in an email body or other text channel, provided that the
entire envelope remains intact. Sending platforms may expose the contact
roster, lengths, subjects, timestamps or other routing metadata outside
the payload. Do not include the plaintext draft in the email and never
interpret the armor's presence alone as proof of sender authenticity:
`open-*` still requires an independently verified sender and exact context.

The `--armor` option is rejected on identity, contact and password commands;
it never silently guesses formats. Input size is bounded, output files must
not already exist, and decoded ciphertext is not published before signature
verification and authenticated opening. Encrypted output remains 0600 on Unix.

## Small local URI handoff (not HTTP)

The `--uri` selector exports an encrypted Capsule as a compact
`e2ed:v1:` local-handoff representation. Its maximum encoded size is
8,192 bytes, so it is intended for short signed notes rather than
attachments. An oversized delivery fails without creating an output file.
Use this mode when handing ciphertext to a trusted QR renderer or another
local application that accepts this envelope type.

```sh
e2ee --state ./alice-private --software-vault --password-only --uri seal-text bob note-v1 ./note.txt ./encrypted-uri.txt
e2ee --state ./bob-private --software-vault --password-only --uri open-text alice note-v1 ./encrypted-uri.txt ./decrypted-note.txt
```

The `--uri` format is **not a browser URL** and must not be inserted into
HTTP query strings, analytics, server logs, or third-party URL shorteners.
Like binary and armored deliveries, a valid prefix does not establish
authenticity: opening still requires a separately verified sender, an exact
signature context and authenticated decryption for the local recipient.
Only one explicit delivery encoding may be selected (`--armor` and `--uri`
are mutually exclusive), and neither is accepted for identity/password
commands. QR pairing and safe display surfaces require separate work.

## Local self-encrypted notes

Protect a short note using your own local endpoint without creating,
importing, or verifying a separate contact. The `seal-note` command encrypts
to the local endpoint and signs with the same unlocked identity. The
`open-note` command refuses any delivery whose signature does not match that
authenticated local endpoint card and the exact context supplied by the user.

```sh
e2ee --state ./my-private --software-vault --password-only seal-note personal-note-v1 ./scratch.txt ./note.e2ed
e2ee --state ./my-private --software-vault --password-only open-note personal-note-v1 ./note.e2ed ./opened.txt
```

Both commands support the same explicit `--armor` and size-limited `--uri`
formats as regular deliveries. Output files are always newly created and 0600
on Unix; the CLI never prints note contents by default.

This is an encrypted **note file**, not yet a notes-management application,
encrypted editor, secure clipboard, or automatically synchronized vault.
The plaintext input and any decrypted output remain on disk. Users should
protect and clear those files as appropriate; snapshots, filesystem backups
and indexing may retain copies. Losing the identity's encrypted archive or
its unlock secret may make notes unrecoverable. Password-only restores do not
provide independent rollback or identity pinning.
