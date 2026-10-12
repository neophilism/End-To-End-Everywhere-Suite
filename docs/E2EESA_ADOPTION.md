# End-to-End Everywhere adoption and independent review

The owner requested three separate stages on October 11, 2026: implementation,
complete testing, and later independent expert review. The canonical record is
`security/e2eesa-status.json`; its schema is `security/e2eesa-status.schema.json`.
Engine Room reads the default branch through GitHub on manual and background
refresh. The repository owns its status; no Engine Room snapshot edit is needed.

The initial record leaves all three stages pending. Existing security locks,
source evidence and approved decisions remain authoritative in their cited files.
The tracking baseline pin does not upgrade a product's cryptographic profiles.

## Scope and prerequisite work

`security/e2eesa-inventory.json` starts as an unverified discovery record. Empty
components/flows mean discovery is incomplete, never that protected flows are
absent or requirements are exempt. Inspect source, runtime and build outputs;
enumerate public disclosures, protected content, authorization metadata, keys,
business processing, endpoints, relays, storage and third-party services.
Apply the pinned upstream component-inventory and scoped-assessment contracts,
classify components and exact flows, record applicable profiles and reviewed
non-applicability rationales, and preserve existing approved decisions.
Declarations require trusted completeness evidence before conformance claims.

Public data and intentionally authorized server processing remain explicit.
TLS and server-held keys cannot support private E2EE-content claims. Use reviewed
protocols and retain gated activation for unverified protected flows/releases.

## Three stages

| Record | Completion rule |
| --- | --- |
| `implementation.complete` | Reviewed complete component/flow scope, actual applicable controls implemented, evidence for all 19 secure-development practices, and exact assessed source binding. |
| `testing.complete` | All six required gates passed, plus applicable real integration/runtime/platform checks; immutable tools/configuration/reports bind the same source. |
| `independentReview.complete` | Qualified independent experts reviewed that same source and scope, real authenticated review evidence is retained, and the owner accepted it. |

The expert-review stage is intentionally initialized unchecked. Author self-review,
synthetic fixtures, AI self-assessment and CI success cannot complete this stage.
Recover existing evidence only after verifying its provenance and scope; PR counts
do not establish approvals or security properties.

Each stage carries evidence repository paths and explicit pending work.
Implementation controls list `id`, `state: "implemented"`, and evidence paths.
Every test records kind, status, sourceDigest, completedAt, toolDigest,
configurationDigest and report. Tool/configuration digests are SHA-256.
Required gates: unit, adversarial, fuzz, secret-scan, dependency-scan and
static-analysis. Gates older than seven days, future-dated, skipped, failed or
bound to changed source cannot check testing. Also retain applicable real device,
provider, recovery, permission and end-to-end acceptance evidence.

## Source binding and commands

Run `python3 scripts/validate_e2eesa_status.py` to validate the record and refuse
unsupported checked stages. Use `--fingerprint` to compute the current Git source
fingerprint before an evidence-only update.

`git-blob-manifest-sha256-v1` hashes UTF-8 lines
`<mode> <type> <git-object-id>\t<path>\n`, ordered by UTF-8 path bytes.
It covers blobs and submodule commits, excluding only the status file and
`security/e2eesa-evidence/**`. Changes to code, configuration, tests, dependencies,
the inventory or normative documentation invalidate old claims. Require a clean
source checkout; a status/evidence-only commit preserves its own source binding.

This tracking fingerprint supplements the upstream source/build/artifact digests,
authenticated assessor adapters, signatures, runtime evidence, profile checks
and conformance verdict. Engine Room checks structure, source drift, evidence
paths, stage dependencies and freshness. Review identity/authentication and
cryptographic quality require independent assessment. All three boxes record
development progress; production certification remains a separate gate. The
current upstream development basis cannot pass final Candidate or production
certification.

## Independent-account continuation

1. Read README, AGENTS, product plan, actual source/PR state and existing security
   evidence. Read the exact standard commit in the record; preserve earlier
   locks/profile decisions unless a reviewed upgrade is authorized.
2. Complete the source/build/runtime inventory and threat/requirements review.
   Record unresolved coverage and activation prerequisites explicitly.
3. Implement dependency-ready controls and negative permission/recovery tests.
   Continue work around unavailable providers/hardware/review while keeping the
   affected activation paths closed.
4. Run all required checks on the exact source and applicable platforms/providers.
   Retain reports, minimized fuzz failures, tool/configuration hashes, source/build/
   artifact identity and timestamps.
5. Populate implementation/testing from verified evidence. Validate and commit
   through a reviewed PR; confirm automatic default-branch import in Engine Room.
6. Leave expert review unchecked until the owner arranges actual qualified review.
   Release also needs the upstream assessment, protected source, authenticated
   release authorizers, artifact/deployment evidence and platform/hardware gates.

High/critical findings require fixes and source-bound retests. Lower-severity
acceptance follows the standard's independent, scoped, time-limited process.
Metadata cannot waive an invariant or approval requirement.
