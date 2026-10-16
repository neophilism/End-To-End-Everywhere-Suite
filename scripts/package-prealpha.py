#!/usr/bin/env python3
"""Deterministic packaging and unsigned build records, not source attestations."""
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import zlib

MAX_BINARY = 128 * 1024 * 1024
NOTICE = b"""END-TO-END EVERYWHERE SUITE - UNSIGNED PRE-ALPHA TEST BUILD
Use disposable test data. This is not a production messenger or installer.
No network delivery, forward-secret messaging or post-compromise security.
Anchored receive-once replay rejection is local and requires an independently
retained trusted floor. Archival opens remain repeatable; there is no global
cross-device replay guarantee. Protect plaintext and encrypted backups.
The checksum and build record detect changes but do not authenticate origin.
No signing, independent human audit or certification is claimed.
"""


class PackageError(Exception):
    pass


def command(root, *args):
    try:
        result = subprocess.run(args, cwd=root, check=True, capture_output=True,
                                text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        raise PackageError("build_metadata_unavailable") from None
    if len(result.stdout) > 65536:
        raise PackageError("invalid_build_metadata")
    return result.stdout.strip()


def binary_bytes(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    except OSError:
        raise PackageError("regular_binary_required") from None
    try:
        with os.fdopen(fd, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or not 1 <= info.st_size <= MAX_BINARY:
                raise PackageError("regular_bounded_binary_required")
            content = source.read(MAX_BINARY + 1)
            after = os.fstat(source.fileno())
            if (len(content) != info.st_size or info.st_size != after.st_size
                    or info.st_mtime_ns != after.st_mtime_ns):
                raise PackageError("binary_changed")
            return content
    except OSError:
        raise PackageError("binary_read_failed") from None


def publish(path, data):
    """Publish a complete staging inode without replacing an existing artifact."""
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".package-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
        temporary.unlink()
        temporary = None
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError:
        raise PackageError("artifact_publication_failed_or_uncertain") from None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def package(binary, platform, out, root):
    if not re.fullmatch(r"[a-z0-9_-]{1,64}", platform):
        raise PackageError("invalid_platform")
    content = binary_bytes(binary)
    if command(root, "git", "status", "--porcelain", "--untracked-files=no"):
        raise PackageError("tracked_source_not_clean")
    commit = command(root, "git", "rev-parse", "HEAD")
    tree = command(root, "git", "rev-parse", "HEAD^{tree}")
    epoch_text = command(root, "git", "show", "-s", "--format=%ct", "HEAD")
    if not re.fullmatch(r"[0-9a-f]{40}", commit) or not re.fullmatch(r"[0-9a-f]{40}", tree):
        raise PackageError("invalid_source_identity")
    if not re.fullmatch(r"[0-9]{1,12}", epoch_text) or int(epoch_text) > 8589934591:
        raise PackageError("invalid_source_epoch")
    epoch = int(epoch_text)
    record = {
        "schema": "e2ee-unsigned-build-record-v1",
        "source_commit": commit,
        "source_tree": tree,
        "source_date_epoch": epoch,
        "tracked_sources_clean": True,
        "cargo_lock_sha256": hashlib.sha256((root / "Cargo.lock").read_bytes()).hexdigest(),
        "binary_sha256": hashlib.sha256(content).hexdigest(),
        "platform": platform,
        "rustc_verbose_version": command(root, "rustc", "-Vv"),
        "cargo_verbose_version": command(root, "cargo", "-Vv"),
        "packaging_python_version": ".".join(map(str, sys.version_info[:3])),
        "packaging_zlib_version": zlib.ZLIB_RUNTIME_VERSION,
        "signed": False,
        "build_origin_attested": False,
        "rust_build_reproducibility_verified": False,
    }
    manifest = (json.dumps(record, sort_keys=True, indent=2) + "\n").encode("utf-8")
    folder = "e2ee-prealpha-" + platform
    files = {"BUILD-MANIFEST.json": manifest, "SECURITY-NOTICE.txt": NOTICE, "e2ee": content}
    buffer = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buffer, compresslevel=9, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            directory = tarfile.TarInfo(folder)
            directory.type = tarfile.DIRTYPE
            directory.mode, directory.mtime = 0o755, epoch
            archive.addfile(directory)
            for name, value in sorted(files.items()):
                info = tarfile.TarInfo(folder + "/" + name)
                info.mode, info.mtime = (0o755 if name == "e2ee" else 0o644), epoch
                info.size = len(value)
                archive.addfile(info, io.BytesIO(value))
    payload = buffer.getvalue()
    out.mkdir(parents=True, exist_ok=True)
    archive_path = out / (folder + ".tar.gz")
    manifest_path = out / (folder + ".build.json")
    checksum_path = out / (folder + ".tar.gz.sha256")
    if any(os.path.lexists(path) for path in (archive_path, manifest_path, checksum_path)):
        raise PackageError("artifact_already_exists")
    publish(archive_path, payload)
    publish(manifest_path, manifest)
    checksum = hashlib.sha256(payload).hexdigest() + "  " + archive_path.name + "\n"
    publish(checksum_path, checksum.encode("ascii"))
    return archive_path


def main():
    if len(sys.argv) != 4:
        raise PackageError("usage_binary_platform_output_directory")
    path = package(Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3]),
                   Path(__file__).resolve().parent.parent)
    print("Created unsigned pre-alpha test artifact: " + str(path))


if __name__ == "__main__":
    try:
        main()
    except (PackageError, OSError) as error:
        code = str(error) if isinstance(error, PackageError) else "packaging_io_failed"
        print("Packaging stopped: " + code, file=sys.stderr)
        sys.exit(1)
