#!/bin/sh
# Package a local CLI test build without implying it is a signed release.
set -eu
if [ "$#" -ne 3 ]; then
  echo "usage: package-prealpha.sh BINARY PLATFORM OUT_DIR" >&2
  exit 2
fi
binary="$1"
platform="$2"
out="$3"
case "$platform" in
  ""|*[!a-z0-9_-]*) echo "invalid platform identifier" >&2; exit 2 ;;
esac
if [ ! -f "$binary" ] || [ -L "$binary" ]; then
  echo "expected a regular, non-symlink CLI binary" >&2
  exit 2
fi
mkdir -p "$out"
out="$(cd "$out" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
folder="e2ee-prealpha-$platform"
mkdir "$tmp/$folder"
cp "$binary" "$tmp/$folder/e2ee"
chmod 755 "$tmp/$folder/e2ee"
cat > "$tmp/$folder/SECURITY-NOTICE.txt" <<'NOTE'
END-TO-END EVERYWHERE SUITE - UNSIGNED PRE-ALPHA TEST BUILD
Not an audited secure messenger, production service, or installer.
No network delivery, forward-secret messaging, post-compromise security,
or replay prevention. Protect source/output plaintext and all backups.
A same-source SHA-256 checksum detects corruption, not authentic provenance.
Use only test data. Read the repository's security limitations before use.
NOTE
archive="$out/$folder.tar.gz"
tar -czf "$archive" -C "$tmp" "$folder"
python3 - "$archive" <<'PY'
import hashlib
import pathlib
import sys
archive = pathlib.Path(sys.argv[1])
digest = hashlib.sha256(archive.read_bytes()).hexdigest()
archive.with_name(archive.name + ".sha256").write_text(
    f"{digest}  {archive.name}\n", encoding="ascii"
)
PY
echo "Created unsigned pre-alpha test artifact: $archive"
