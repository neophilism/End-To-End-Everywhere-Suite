# Development handoff — 2026-10-16

The owner requests continuous work, frequent durable repository checkpoints and integration of passing changes. GitHub, Render and Neon are authorized for this conversation. Do not wait for an external human auditor; follow AGENTS.md, preserve actual security controls and require applicable automated checks before merge.

## Integrated Suite work

PRs 53–59 are merged. They add persisted bounded receive-once receipts, anchored CLI text/file receive, an application SDK preview, same-endpoint encrypted checkpoint backup/recovery, safer atomic plaintext exports and corrected review/progress documentation. Main was `79f02ec50efe206f49c6fefddd9a4a6c1e4dc07c` at this checkpoint. The approved roadmap remains 61 units; partial work belongs in `contributingPrs`, not completed `prs`.

PR 60 (`work/sdk-floor-freshness`, head `042906f11aca89b94c96b048b237aaaeb4d4425e`) invalidates unlocked SDK controllers when the independent trusted floor changes or cannot be read. Main CI, static checks and Linux packaging passed. macOS packaging is still running as of this checkpoint (run 38939471711, job 117103170565). Check live GitHub state before merging. Preserve ancestry with a merge commit when integrating stacked work.

## Current checkpoint

`work/unsigned-build-records` starts at PR 60. The new Python packaging helper is being saved before wiring it into the shell wrapper/workflow. Its purpose is deterministic archive packaging plus an explicitly unsigned source/compiler/lockfile/binary build record. It must not claim a signed attestation or independently reproducible Rust compilation. Finish the wrapper, regression tests, workflow integration and distribution documentation before treating it as complete. Run the packaging tests against actual filesystem operations and verify real Linux/macOS artifacts. Existing output names must never be overwritten.

The next intended changes are: normalized archive ownership/order/permissions/timestamps; no gzip wall-clock timestamp; an embedded and standalone build manifest; bounded regular-file inputs; clean tracked-source checks; pinned packaging checkout/upload actions; compiled SDK documentation; and correction of the old package notice that claimed no local replay rejection at all. The rolling Rust toolchain must be recorded honestly rather than called reproducibly pinned.

The local workspace can be transient. Remote branch commits are authoritative; fetch and inspect before editing. Never rely on conversation-tool memory as the only copy of source.

## Related NFT project

NFT-Minting-Console PRs 43–51 are merged. Latest main is `6ec36eddb468689594ed862b064f8d780b8458d5`; the preview is https://nft-minting-console-preview.onrender.com/#/launch . Latest deployment is `dep-db9663ivcj2c73ahjitg` on Render service `srv-db7gket9fdbs73e6a0d0` in Phillip's workspace `tea-db23jkks728c73av263g`. Deployment was verified live. Exact-head CI passed all four workflows/seven jobs, including native PostgreSQL, actual Safe/validator tests, 94 browser cases and pinned private Geth simulation.

The public flow supports direct EOA deployment/mint signing, exact public IPFS file readback, durable transaction history, finalized self-cancellation recovery without hash replacement or automatic resend, and funding estimates for all supplied works up to 500. Estimates explicitly distinguish supplied works from the full collection supply. It still requires actual RPC/Pinata credentials, public role addresses, approved final assets/rights and funded wallet signatures. Never request wallet seeds/private keys. No public-chain ETH has been spent.

Neon project `dark-math-52213387`: isolated branch `br-misty-band-b4052asu` has baseline and authorization migrations 001–005. Migration 005 checksum is `e46355bca3fd6118df3b6e66511c4c2d5688eb784c5e3cace048e64f9ee5708a`; its forced RLS, immutable proof permissions and zero unbound visibility were checked. The restricted SQL runtime role is `nft_console_app_runtime` (not the unused provider-created role with broad default membership). Temporary local credentials were deleted; do not expose secrets in logs or commits.

Automatic approval review rejected migration of the default production branch `br-late-forest-b4z0hjsa`, requiring approval of that exact target. It remains unchanged. Do not bypass that rejection. The owner forbids additional permission prompts; continue independent work instead.

Render rejected creation of the Suite information site because the Hobby workspace is limited to 25 services. No Suite site was created, no paid upgrade was selected and no other service was deleted. Keep improving the application code while infrastructure or credentials are unavailable. No native desktop/mobile GUI, production protected anchor adapter, ratchet/forward secrecy, network delivery, signed release or certification should be claimed complete.
