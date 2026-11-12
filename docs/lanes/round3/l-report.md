# Round 3 lane L progress

Status: active; lead sigis-cx. Launch commit b5bb72f.

## Counts

| Crate / assigned suite | Total | Passed | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| root live integrations | 11 | 0 | 0 | 11 |

The four Codex aoa sessions were created in dedicated worktrees and all
reported busy at launch. Their scope and exact ownership are in the briefs.
At launch the repository flock was tested for blocking and release; the
subsequent FD audit found it unsuitable across the scheduler boundary. Main
now delegates to the absolute system rust-slots Cargo entry point, without
that repository lock or forced local/job settings. CLI skeleton, metadata,
formatting and dependency layering passed at launch. Logs and session
snapshots: ~/.codex/artifacts/sigis/round3-launch/.

## Current work

Port the two live HTTP timestamp functions first, with Rust CMS integrity
and empty-trust-root assertions plus live oracle comparisons. Build a
loopback-only Certomancer sidecar and a repeatable collected-case inventory.
The six live PAdES/backend flows depend on P/V accepted signing/LTA APIs;
the CLI live LTA case also depends on C. CSC batching is next independent
integration work. No live function is newly counted passed yet.

## Integration contract

Accept S primitive increments, then P signer hooks, V LTA/report consumers,
and complete C commands. Independent increments may merge sooner. Rebase
and fast-forward only; run the full locked workspace gate after each merge
and reconcile unique-function status centrally. Keep old sessions and
services unchanged. No push or service restart.

## Shared historical validation API

ValidationContext::with_timing and with_fetchers clone the complete context
and replace only the requested field. L integrated S's initial design and
strengthened its native regressions to use non-default security state.
Both context tests, crate all-target clippy -D warnings, strict crate docs
and package formatting passed. No upstream function count is added.

The old wrapper's FD 9 could be replaced by rust-slots slot acquisition.
Other bypass paths could retain it; a lane PATH putting rustup Cargo first
was found. The launcher now uses the absolute system scheduler entry point.
See cargo-lock-audit.md and context-clone-api artifacts. No build was killed.
The live integration baseline remains 11/0/0/11; earlier queued runs and
unvalidated drafts are not accepted passing ports.
