"""Desktop notes/contact controller using the Suite CLI as the security boundary."""
from __future__ import annotations

import json
import os
import re
import subprocess
import stat
from dataclasses import dataclass
from pathlib import Path

MAX_NOTE_BYTES = 4 * 1024 * 1024
MAX_DELIVERY_BYTES = 40 * 1024 * 1024
QR_PREFIX = "e2ee-verify-v1:"
TOKEN = r"[A-Za-z0-9._:-]+"
HEX64 = r"[0-9a-f]{64}"


class ClientError(Exception):
    def __init__(self, message: str, anchor: str | None = None) -> None:
        super().__init__(message)
        self.anchor = anchor


@dataclass(frozen=True)
class QrCandidate:
    enrollment_id: str
    digest: str


def parse_qr(payload: str) -> QrCandidate:
    """Parse non-secret QR text. Parsing never authorizes a device."""
    if len(payload.encode("utf-8")) > 256 or payload.strip() != payload:
        raise ClientError("Invalid or oversized QR payload.")
    match = re.fullmatch(QR_PREFIX + f"({TOKEN}):({HEX64})", payload)
    if not match:
        raise ClientError("Invalid or noncanonical QR payload.")
    return QrCandidate(*match.groups())


def compare_qr(payload: str, local_enrollment_id: str, local_digest: str) -> bool:
    candidate = parse_qr(payload)
    if not re.fullmatch(TOKEN, local_enrollment_id):
        raise ClientError("Local enrollment ID is invalid.")
    if not re.fullmatch(HEX64, local_digest):
        raise ClientError("Local transcript digest must be 64 lowercase hex characters.")
    return (candidate.enrollment_id == local_enrollment_id
            and candidate.digest == local_digest)


def build_command(binary: str, state: str, action: str, arguments: list[str],
                  anchor: str = "", password_only: bool = False) -> list[str]:
    program = Path(binary)
    if (not program.is_absolute() or program.is_symlink() or not program.is_file()
            or not os.access(program, os.X_OK) or not Path(state).is_absolute()):
        raise ClientError("Select an absolute regular e2ee program and state directory.")
    if anchor and not password_only and re.fullmatch(r"[0-9a-fA-F]{140}", anchor):
        mode = ["--anchor", anchor]
    elif password_only and not anchor:
        mode = ["--password-only"]
    else:
        raise ClientError("Provide the independent anchor or explicitly accept password-only mode.")
    if action in {"identity", "contacts"}:
        if arguments:
            raise ClientError("Unexpected command arguments.")
    elif action == "import-card":
        if len(arguments) != 1 or not Path(arguments[0]).is_absolute():
            raise ClientError("Choose an absolute public contact card file.")
        if not is_regular_file(Path(arguments[0]), 4096):
            raise ClientError("Contact card must be a regular file within the CLI limit.")
    elif action == "verify":
        if (len(arguments) != 2 or not re.fullmatch(TOKEN, arguments[0])
                or not re.fullmatch(r"[0-9a-fA-F]{64}", arguments[1])):
            raise ClientError("Supply an endpoint and its complete independent fingerprint.")
    elif action in {"seal-note", "open-note"}:
        if len(arguments) != 3:
            raise ClientError("Select note context, input and new output.")
        context, source, destination = arguments
        if not 1 <= len(context) <= 256 or not context.isascii() or not context.isprintable() or " " in context:
            raise ClientError("Note context must be printable ASCII without spaces.")
        if not Path(source).is_absolute() or not Path(destination).is_absolute():
            raise ClientError("Use absolute note input and output paths.")
        limit = MAX_NOTE_BYTES if action == "seal-note" else MAX_DELIVERY_BYTES
        if not is_regular_file(Path(source), limit):
            raise ClientError("Note input is missing or exceeds the supported limit.")
        if os.path.lexists(destination) or Path(source).resolve() == Path(destination).resolve():
            raise ClientError("Choose a new output path; existing files are never overwritten.")
    else:
        raise ClientError("Unsupported notes/contact command.")
    return [binary, "--state", state, "--software-vault", *mode,
            "--password-stdin", action, *arguments]


def run_cli(argv: list[str], password: str) -> tuple[str, str | None]:
    if not 12 <= len(password.encode("utf-8")) <= 1024 or "\r" in password or "\n" in password:
        raise ClientError("Passphrase must be 12–1024 bytes without line breaks.")
    try:
        result = subprocess.run(argv, input=password + "\n", text=True,
                                capture_output=True, timeout=180, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ClientError("Operation may be incomplete; inspect local state and files before retrying.") from exc
    anchors = re.findall(r"^ANCHOR ([0-9a-f]{140})$", result.stderr, re.MULTILINE)
    latest = anchors[-1] if anchors else None
    if result.returncode:
        raise ClientError("CLI operation failed; inspect state before retrying.", latest)
    if argv[argv.index("--password-stdin") + 1] in {"verify", "import-card"}:
        if not latest:
            raise ClientError("State may have changed without returning an anchor; inspect before retrying.")
    elif latest:
        raise ClientError("Read-only operation unexpectedly changed the anchor; inspect state.", latest)
    return result.stdout, latest


def is_regular_file(path: Path, limit: int) -> bool:
    try:
        mode = path.lstat().st_mode
        return stat.S_ISREG(mode) and path.stat().st_size <= limit
    except OSError:
        return False


def verify_cli(binary: str) -> None:
    program = Path(binary)
    if not program.is_absolute() or program.is_symlink() or not program.is_file() or not os.access(program, os.X_OK):
        raise ClientError("Choose an executable absolute e2ee CLI path.")
    try:
        result = subprocess.run([binary, "--capabilities-json"], capture_output=True,
                                text=True, timeout=10, check=False)
        data = json.loads(result.stdout)
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        raise ClientError("Could not inspect CLI capabilities.") from exc
    features = data.get("features", {})
    if result.returncode or data.get("component") != "local-cli" or any(
        features.get(feature) is not True for feature in
        ("encrypted_personal_notes", "verified_contact_pinning", "private_atomic_file_publication")
    ):
        raise ClientError("CLI lacks required notes and contact capabilities.")
