# Continuous integration performance and trust boundaries

Suite Rust CI and pre-alpha packaging continue to run their existing mandatory
format, Clippy, unit/integration, build and host-OS package validations. The
optimization changes **when they run and whether compiled dependencies can be
reused**, not which security gates are required for merging or releasing.

- GitHub-owned checkout, cache and artifact-upload actions are pinned to exact
  inspected commits rather than mutable major-version tags. Pins must be
  explicitly reviewed before upgrades.
- A per-OS/architecture, lockfile-associated Rust cache stores fetched
  dependencies and Cargo's local `target` build outputs. Fresh or changed
  sources still undergo all test/build jobs and must satisfy Cargo fingerprints.
  Cache hits are **not** evidence of source security, cryptographic compliance,
  signed/reproducible output or successful tests.
- A new push to the **same open PR** cancels superseded jobs so only its latest
  candidate consumes long-running macOS/Linux runners. Pushes to `main` are
  never cancelled by this rule; different PRs remain independently validated.
- PR caches and permissions remain governed by GitHub Actions' normal scoped
  cache access. Do not put secrets, private keys or sensitive plaintext in
  build outputs, build scripts or logs. Release-signing credentials are not
  used by these workflows.
- The unsigned pre-alpha CLI packages remain engineering artifacts, **not**
  signed production releases. They still require clean accepted exact-head
  checks and the separate production release gates.

This does not accelerate a presently running job retroactively. Future
pipelines may save compilation/download work, subject to GitHub cache
availability and eviction. Never merge a code change based only on cached
artifacts or cancelled/superseded checks.
