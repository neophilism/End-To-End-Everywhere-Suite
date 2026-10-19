"""Exercise the desktop controller against a built Unix CLI in disposable state."""
from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from notes_core import ClientError, build_command, run_cli, verify_cli


def raw(binary: str, state: Path, *args: str) -> str:
    result = subprocess.run([binary, "--state", str(state), "--software-vault",
                             "--password-only", "--password-stdin", *args],
                            input="integration passphrase\n", text=True, capture_output=True,
                            timeout=180, check=False)
    if result.returncode:
        raise AssertionError(f"CLI {args[0]} failed: {result.stderr}")
    return result.stdout


def call(binary: str, state: Path, action: str, *args: str) -> str:
    argv = build_command(binary, str(state), action, list(args), password_only=True)
    output, _anchor = run_cli(argv, "integration passphrase")
    return output


def main(binary: str) -> None:
    verify_cli(binary)
    with tempfile.TemporaryDirectory(prefix="e2ee-desktop-notes-") as name:
        root = Path(name)
        os.chmod(root, 0o700)
        alice, bob = root / "alice", root / "bob"
        raw(binary, alice, "init", "alice")
        raw(binary, bob, "init", "bob")
        source = root / "draft.txt"
        source.write_text("private desktop note\n")
        sealed = root / "note.e2ed"
        opened = root / "opened.txt"
        call(binary, alice, "seal-note", "desktop-notes-v1", str(source), str(sealed))
        assert sealed.exists() and sealed.stat().st_mode & 0o777 == 0o600
        try:
            call(binary, alice, "open-note", "wrong-context", str(sealed), str(opened))
        except ClientError:
            pass
        else:
            raise AssertionError("Wrong note context was accepted")
        assert not opened.exists()
        try:
            call(binary, bob, "open-note", "desktop-notes-v1", str(sealed), str(opened))
        except ClientError:
            pass
        else:
            raise AssertionError("Wrong note identity was accepted")
        assert not opened.exists()
        call(binary, alice, "open-note", "desktop-notes-v1", str(sealed), str(opened))
        assert opened.read_text() == source.read_text()
        assert opened.stat().st_mode & 0o777 == 0o600
        try:
            build_command(binary, str(alice), "open-note",
                          ["desktop-notes-v1", str(sealed), str(opened)], password_only=True)
        except ClientError:
            pass
        else:
            raise AssertionError("Existing note output was accepted")
        card = root / "alice.card"
        raw(binary, alice, "card-save", str(card))
        call(binary, bob, "import-card", str(card))
        assert "alice\tunverified\t" in call(binary, bob, "contacts")
        identity = call(binary, alice, "identity")
        fingerprint = re.search(r"^Fingerprint: ([0-9a-f]{64})$", identity, re.MULTILINE)
        assert fingerprint, "CLI did not return a complete fingerprint"
        call(binary, bob, "verify", "alice", fingerprint.group(1))
        assert "alice\tverified\t" in call(binary, bob, "contacts")
    print("Desktop notes/contact native CLI integration passed.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: integration_notes.py /absolute/path/to/e2ee")
    main(str(Path(sys.argv[1]).absolute()))
