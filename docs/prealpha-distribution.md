# CI test builds for macOS and Linux

The `Pre-alpha CLI packages` workflow tests the Rust workspace and builds `e2ee` in release mode on GitHub-hosted Ubuntu and macOS. It packages the executable with an explicit security notice in a `.tar.gz` and writes a SHA-256 checksum. Artifacts are uploaded to the CI run for 14 days; they are not releases or installed services.

**Security status:** These are unsigned pre-alpha engineering builds. The checksum is distributed together with the archive and cannot authenticate its origin. They must not be promoted as safe for sensitive production communication without independent review, signed release provenance, proven device-key storage, rollback-resistant recovery and completed conformance evidence. The existing local CLI lacks message forward secrecy, replay protection and network delivery. Windows is not currently supported for local-state persistence.

For a source install on Unix, use `cargo install --path crates/e2ee-cli --locked`. See [CLI usage](cli.md). If the macOS workflow fails, fix the platform issue rather than suppressing the test.
