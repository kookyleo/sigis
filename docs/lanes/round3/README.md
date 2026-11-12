# Round 3 port lanes

The lead remains `sigis-cx` and owns L. Four independent Codex aoa sessions
run P/V/S/C from branches created after the launch commit. The immutable
[ownership.json](ownership.json) enumerates all 1,431 upstream functions;
parameters count once. [p.md](p.md), [v.md](v.md), [s.md](s.md), [c.md](c.md)
and [l.md](l.md) are the execution briefs and ownership contracts.

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
Its shared `.git/round3-cargo.lock` is outside tracked files and independent
of worktree paths. The lock covers the entire command, including tests and
document generation; ordinary Cargo build locks alone do not cover runtime
tests. The wrapper selects `/build/sigis/target` through `rust-target-env`,
keeps the system local slot queue, caps compilation at two jobs (docs one),
and bypasses the proven broken sccache compiler probe consistently. Never
create per-lane targets on the nearly full root disk or change profiles,
features or Rust flags for speed. L uses this same wrapper for every merge
gate. Internal metadata children inherit the parent lock; no recursive lock.

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
