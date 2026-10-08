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
See `e2ee --help` for commands. Text/file delivery commands follow this identity
and lifecycle layer.
