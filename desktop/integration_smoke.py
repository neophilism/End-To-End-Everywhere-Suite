"""Real CLI smoke for the headless desktop controller on package hosts."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

from vault_core import VaultError, command, execute, verify_cli


def main(binary: str) -> None:
    executable = str(Path(binary).resolve(strict=True))
    verify_cli(executable)
    password = "throwaway-test-passphrase"
    with tempfile.TemporaryDirectory(prefix="e2ee-desktop-smoke-") as directory:
        root = Path(directory)
        state = root / "new-state"
        anchor = execute(command(executable, str(state), "init",
                                 endpoint="desktop-smoke"), password)
        if not anchor or len(anchor) != 140:
            raise AssertionError("identity creation did not return an independent anchor")
        source = root / "selected.txt"
        plaintext = b"local encrypted file vault integration sample"
        source.write_bytes(plaintext)
        sealed = root / "selected.e2ed"
        execute(command(executable, str(state), "seal-self-file",
                        "personal-file", str(source), str(sealed), anchor=anchor),
                password)
        if not sealed.is_file() or plaintext in sealed.read_bytes():
            raise AssertionError("encryption did not create an opaque delivery")
        exported = root / "exported.txt"
        execute(command(executable, str(state), "open-self-file",
                        "personal-file", str(sealed), str(exported), anchor=anchor),
                password)
        if exported.read_bytes() != plaintext:
            raise AssertionError("verified desktop export does not match input")
        if os.name == "posix" and exported.stat().st_mode & 0o077:
            raise AssertionError("exported plaintext is accessible to other users")

        def denied(input_file: Path, context: str, output: Path, passphrase: str) -> None:
            try:
                execute(command(executable, str(state), "open-self-file", context,
                                str(input_file), str(output), anchor=anchor), passphrase)
            except VaultError:
                pass
            else:
                raise AssertionError("invalid delivery was accepted")
            if output.exists():
                raise AssertionError("invalid delivery published plaintext")

        denied(sealed, "wrong-context", root / "wrong-context.txt", password)
        denied(sealed, "personal-file", root / "wrong-password.txt", "incorrect-test-passphrase")
        damaged = root / "damaged.e2ed"
        payload = bytearray(sealed.read_bytes())
        payload[len(payload) // 2] ^= 1
        damaged.write_bytes(payload)
        denied(damaged, "personal-file", root / "tampered.txt", password)
    print("Desktop vault real-CLI smoke passed (throwaway local state).")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: integration_smoke.py ABSOLUTE_CLI_BINARY")
    main(sys.argv[1])
