# Round 3 current source473 acceptance and next scopes

Accepted compiled source: `473b7cbddef5df4aaaefef5a0f7075953927d0b3`.

The source473 cohort completes exactly eleven unique upstream functions: ten C-owned CLI originals and one S-owned fetch original. No P-owned or V original is added. Accepted inventory is **1431 total /1374 passed /10 skipped /47 pending**; library scope is **1168/1157/10/1**. Immutable ownership remains unchanged. The Root ledger postimage preserves all346old raw overrides in order and appends eleven passed rows, yielding357; prior dispositions remain intact.

**57 functions remain unfinished:47 Pending (46 CLI plus1 V) and10 skipped (9 S plus1 P SafeNet).** Function IDs, parameters, Rust wrappers, callbacks, API calls and executable captures are separate counts.

The complete [per-crate inventory](../../status.md) and [L acceptance proof](l-cli-policy-acceptance.md) record the returned gate and exact eleven IDs. Immutable ownership and the launch baseline remain preserved below.

## Remaining completion scope and immediate assignments

| CLI upstream module | Pending |
| --- | ---: |
| validation/test_cli_qualified_validation.py |22|
| test_cli_signing_pkcs11.py |10|
| test_cli_signing.py |7|
| test_cli_decode_limits.py |4|
| test_cli_ltv.py |3|
| Total |46|

Full work ownership is P's temporary10C-owned provider originals plus its own1SafeNet skip; C's other36CLI originals; V's1Pending original; S's9skips (3fetch+2deprecated CV+4PDF type/language); L's integration/gates/acceptance. That partition is broader than immediate implementation authority:

- S: [three remaining lifecycle originals](s-remaining-fetch-three-source.md), TESTS ONLY with the explicit limited empty-capability fixture mapping; no production/API or general source-graph parity.
- P: [one Env PIN token-signing original](p-cli-signing-env-pin.md), bounded tests-first implementation/allfiveeffectiveEd25519rows/new private store. Other nine signing originals remain source-only. Whole CLIlib is P-exclusive until freeze/L handoff.
- C: [one qualified-required original](c-qualified-one-tests-first.md), TESTS/FIXTURE PREPARATION ONLY, with qualified+required VALID and nonqualified+not-required VALID controls before same-byte mandatory negative credit. The [eight-original source inventory](c-qualified-current-source.md) is retained, within22remaining qualified-module functions. No production/lib/lower/manifest edits.
- V: [one later-revoked leaf original](v-leaf-revoked-completion.md), bounded tests-first implementation with status5314/owned-facts5444guards. Its current Pending annotation/count remains until a later accepted proof.
- L: all shared coordination, exact source integration, metadata/ledger, final gates and local main transactions. No lane merges or expands shared APIs independently.

Future packets receive no credit from this cohort. All Cargo uses tools/cargo-locked.sh/canonical rust-target-env/system slots/preserved sccache. Keep exclusive ownership, local English commits, old proofs and dirty independent work; no target cleaning, speed flags/features/profiles, manual remote Cargo, pushes, kills, service restarts or interference.

## Historical pre-source473 document retained verbatim

The complete preceding document below retains its original acceptance numbers and source-stage statements as historical evidence. Current accepted scope and next authority are defined above.

# Round 3 port lanes

The lead remains `sigis-cx` and owns L. Four independent Codex aoa sessions
run P/V/S/C from branches created after the launch commit. The immutable
[ownership.json](ownership.json) enumerates all 1,431 upstream functions;
parameters count once. [p.md](p.md), [v.md](v.md), [s.md](s.md), [c.md](c.md)
and [l.md](l.md) are the execution briefs and ownership contracts.

The table below is the immutable launch baseline. Current accepted counts are
in [status.md](../../status.md) and [acceptance.json](acceptance.json); lane
proposals do not update those counts before the lead gate.

| Lane | Session | Branch | Assigned | Passed | Skipped | Pending |
| --- | --- | --- | ---: | ---: | ---: | ---: |
| P | sigis-r3-p | hanko/r3-p | 297 | 271 | 13 | 13 |
| V | sigis-r3-v | hanko/r3-v | 47 | 12 | 0 | 35 |
| S | sigis-r3-s | hanko/r3-s | 824 | 738 | 80 | 6 |
| C | sigis-r3-c | hanko/r3-c | 252 | 0 | 0 | 252 |
| L | sigis-cx | main | 11 | 0 | 0 | 11 |
| Total | | | 1431 | 1021 | 93 | 317 |

S centrally reviews all 93 skips, but changes to the 13 signing skips stay
P-owned. Existing API/fixture coverage remains regression scope, not new
passes. No cross-lane file edits or count double-booking. Reports are
`<lane>-report.md`, API requests go to L, and only L updates consolidated
status/manifests/lockfile. Root's existing live integration tests remain L-owned.

All Cargo commands from all five lanes must use `tools/cargo-locked.sh`.
It injects `rust-target-env`, then delegates concurrency and placement to
system rust-slots, including its per-host worktree locks. There is no
repository-wide flock, forced local placement or repository job cap.
Check/test/clippy can use vm2064/vm2065 through automatic rust-remote.
Keep canonical targets and existing flags/profiles/features. Do not kill
old slot jobs; new invocations use the corrected wrapper. Configured
sccache is retained; [cargo-scheduling.md](cargo-scheduling.md) explains
the nested workspace-wrapper probe repair and validation evidence.
L runs merge gates sequentially; independent lane jobs use system slots.

Each lane ports exact upstream tests before implementation, uses the
shared pinned oracle venv, requires fail-closed trust decisions and reports
per-crate total/passed/skipped/pending plus parameter/runtime exclusions and
differential evidence. Local English commits only; no push, service restart,
`pkill` or interference with other sessions. Old sessions stay unchanged.

Expected dependency merge order is S primitives -> P signing -> V LTA and
reports -> C complete commands, with independent ready increments accepted
sooner. L runs build, test, clippy -D warnings, strict docs, layering and fmt
after each integration and updates docs/status.md. Completion requires the
full pending set, honest skip dispositions and live L acceptance; a launch
or a recording-only replay is not full-port completion.
