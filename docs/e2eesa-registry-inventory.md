# Machine-checked standards registry inventory

This repository binds to an **exact E2EESA source commit**, recorded in `.e2eesa/binding-pin.json`. CI checks that its implemented secret-store profile identifiers and message HPKE suite still exist in that revision's authoritative catalogs and are allowed or recommended.

The workflow checks out the public standard at an immutable commit SHA and verifies that the source actually resolves to the pinned SHA. Python's standard library checks constant names, exact profile versions, family identity, and registry status. A mismatch fails closed.

**Scope limits:** This is only a compatibility inventory. It does not run the E2EESA conformance framework, prove semantics, validate side-channel resistance, audit key handling, establish forward secrecy, or certify a product. The standard is at a development revision and its catalog's `standard_version` field is independent of its top-level `VERSION` file. Do not infer conformance or certification from a passing CI gate.

**Updating the pin:** Review the standards repository's new SHA and registry diffs, confirm that every changed profile/suite is accepted for this implementation, then update the source SHA **both** in `.e2eesa/binding-pin.json` and in the GitHub Actions checkout ref. Any security-property or API change requires independent implementation review. Avoid floating branch references.
