# Round 3 batch workflow

Effective 2026-11-15, Leo's directive supersedes all older lane briefs, source-only holds, frozen-candidate restrictions and evidence requirements. Current counts are in [status.md](../../status.md); immutable original ownership is in [ownership.json](ownership.json).

## Acceptance gate

A batch is accepted when it is based on current main, `tools/cargo-locked.sh test --workspace` has zero failures, clippy and formatting are clean, and applicable ported originals have a differential check against pyHanko 0.38.1 in `/tmp/pyhanko-oracle/venv`.

```sh
tools/cargo-locked.sh test --workspace
tools/cargo-locked.sh clippy --workspace --all-targets -- -D warnings
tools/cargo-locked.sh fmt --all -- --check
```

That is the whole gate. Standalone build/docs/layering stages, source-file hashes, BLAKE3, ELF captures, fingerprint/dep-info audits, transport dispositions, frozen-source evidence pipelines and independent final reviews are not acceptance requirements. Do not generate JSON evidence artifacts. Keep normal test output and a short human-readable batch report. Existing evidence can remain historical; do not regenerate it.

## Parallel ownership

| Lane/session | Remaining scope | Main implementation boundary |
| --- | --- | --- |
| P / sigis-r3-p | Two CLI signing-PIN originals plus fixture/hardware exclusions | PKCS#11 implementation and dedicated tests; coordinate runtime/shared CLI edits with L |
| C / sigis-r3-c | Current 34-original batch accepted; help remaining CLI work | CLI commands/configuration and tests; coordinate helper boundaries |
| V / sigis-r3-v | Later-revoked leaf original | Necessary CV/CMS/PAdES completion implementation and tests |
| S / sigis-r3-s | Two CLI historical-validation cases plus five registry/PDF exclusions | CLI validation/reporting cases and registry/PDF equivalents; coordinate lower completion with V |
| L / sigis-cx | Integration and status | Shared API coordination, rebases/merges, simple gate and ledger/status updates |

These scopes use the current accepted counts, not the directive's older 46-pending/7-skipped snapshot: USER-PIN prompt and Boolean have already been accepted once. Operational assignments do not transfer original ownership.

Each lane works in its own worktree, tests originals before implementation, commits locally in English and submits one short ready-batch report containing commit, original IDs/tests added, Cargo summary and applicable differential result. Aim for a whole useful batch of 5–15 originals rather than one original per packet. No per-step reports or permission loop for work already assigned. Report a concrete blocker only when another lane must resolve an interface or genuine external availability issue; otherwise continue independent work.

Use the normal repository wrapper, canonical target, system slots and existing cache/flags. Independent lane work proceeds concurrently with placement delegated to system slots; do not create a repository lock or manually interfere with builds. No raw/manual remote Cargo, target cleanup, speed flag/profile/feature change, push, process kill or service restart. Preserve real semantic/security assertions; simplify the process rather than weakening tests. The lead alone rebases/merges ready batches and changes accepted counts.

The lead removes clean merged/obsolete review worktrees without force; keep active lane worktrees and dirty work. Historical branches/commits remain recoverable. [Previous workflow](../../history/round3-lane-process-before-batching.md).
