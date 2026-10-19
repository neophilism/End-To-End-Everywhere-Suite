"""Pre-alpha local file vault controller, independent of the display toolkit."""
from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_DELIVERY_BYTES = 40 * 1024 * 1024


class VaultError(Exception):
    def __init__(self, message: str, anchor: str | None = None) -> None:
        super().__init__(message)
        self.anchor = anchor


def command(binary: str, state: str, action: str, context: str = "",
            source: str = "", destination: str = "", endpoint: str = "",
            anchor: str = "", password_only: bool = False) -> list[str]:
    if not binary or not state:
        raise VaultError("Select the e2ee program and a local state directory.")
    if not Path(state).is_absolute():
        raise VaultError("Choose an absolute state directory path.")
    executable = Path(binary)
    if (not executable.is_absolute() or executable.is_symlink()
            or not executable.is_file() or not os.access(executable, os.X_OK)):
        raise VaultError("Select an absolute path to a regular executable e2ee program.")
    prefix = [binary, "--state", state, "--software-vault"]
    if action == "init":
        if anchor:
            raise VaultError("Creation does not use a previous anchor.")
        prefix += ["--password-only"]
    elif anchor and not password_only and re.fullmatch(r"[0-9a-fA-F]{140}", anchor):
        prefix += ["--anchor", anchor]
    elif password_only and not anchor:
        prefix += ["--password-only"]
    else:
        raise VaultError("Enter a 140-character independent anchor, or explicitly accept password-only mode.")
    prefix += ["--password-stdin"]
    if action == "init":
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", endpoint):
            raise VaultError("Enter a simple endpoint ID (letters, digits, dot, dash or underscore).")
        if os.path.lexists(state):
            raise VaultError("Identity creation requires a new state directory.")
        return prefix + ["init", endpoint]
    if action not in {"seal-self-file", "open-self-file"}:
        raise VaultError("Unsupported vault action.")
    if not (1 <= len(context.encode("utf-8")) <= 256) or not all(
        33 <= ord(c) <= 126 for c in context
    ):
        raise VaultError("Context must be 1–256 printable ASCII characters without spaces.")
    if not Path(source).is_absolute() or not Path(destination).is_absolute():
        raise VaultError("Select absolute input and output paths.")
    try:
        if not Path(source).is_file():
            raise VaultError("Select a regular input file.")
        limit = MAX_FILE_BYTES if action == "seal-self-file" else MAX_DELIVERY_BYTES
        if Path(source).stat().st_size > limit:
            raise VaultError("Input exceeds the selected file operation limit.")
        if not destination or os.path.lexists(destination):
            raise VaultError("Choose a new destination; existing files are never overwritten.")
        if Path(source).resolve() == Path(destination).resolve():
            raise VaultError("Input and destination must differ.")
    except OSError as exc:
        raise VaultError("Could not inspect the selected file paths; choose them again.") from exc
    return prefix + [action, context, source, destination]


def verify_cli(binary: str) -> None:
    """Reject incompatible executables before giving a process a passphrase."""
    try:
        result = subprocess.run([binary, "--capabilities-json"], text=True,
                                capture_output=True, timeout=10, check=False)
        document = json.loads(result.stdout)
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        raise VaultError("Could not verify the selected e2ee program capabilities.") from exc
    if not isinstance(document, dict):
        raise VaultError("Selected program returned an invalid capability inventory.")
    features = document.get("features", {})
    if (result.returncode != 0 or document.get("schema_version") != 1
            or document.get("component") != "local-cli"
            or not isinstance(features, dict)
            or not all(features.get(name) is True for name in (
                "self_encrypted_files", "software_password_vault",
                "private_atomic_file_publication"))):
        raise VaultError("Selected program does not advertise the required local vault capabilities.")


def execute(argv: list[str], password: str) -> str | None:
    if not 12 <= len(password.encode("utf-8")) <= 1024 or "\n" in password or "\r" in password:
        raise VaultError("Passphrase must be 12–1024 bytes without a line break.")
    # CLI confirms interactively only; stdin mode consumes exactly one line.
    credential = password + "\n"
    try:
        result = subprocess.run(argv, input=credential, text=True,
                                capture_output=True, timeout=180, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise VaultError(
            "Operation did not complete normally. Inspect the selected destination "
            "and state before retrying."
        ) from exc
    anchors = re.findall(r"^ANCHOR ([0-9a-f]{140})$", result.stderr, re.MULTILINE)
    new_anchor = anchors[-1] if anchors else None
    if result.returncode:
        if new_anchor:
            raise VaultError("The operation reported an error after emitting a new anchor. "
                             "Inspect the state and destination before retrying.", new_anchor)
        raise VaultError("The e2ee operation failed. Inspect the destination and state "
                         "before retrying; run the CLI for detailed diagnostics.")
    if "init" in argv[-2:] and not new_anchor:
        raise VaultError("Creation may have committed but no new anchor was returned. "
                         "Inspect local state before retrying.")
    return new_anchor


