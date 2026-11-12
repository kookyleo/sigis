# Round 3 lane L progress

Status: active; lead sigis-cx. Launch commit b5bb72f.

## Counts

| Crate / assigned suite | Total | Passed | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| root live integrations | 11 | 2 | 0 | 9 |

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
integration work. The two live timestamp functions are now accepted after the complete main gate.

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
The immutable live baseline was 11/0/0/11; accepted main is now 11/2/0/9.
Earlier queued runs and unvalidated drafts were not used as passing evidence.

## Live TSA acceptance

Main0823cef passes the full serial build/test/clippy/strict-doc/layer/fmt gate.
The exact upstream default-session and explicit-session functions exercise
actual loopback HTTP and compare correct/wrong imprint verdicts against the
pinned oracle. Accepted2, pending9; four Python validation calls are not four
functions. Worker oracle replicas passed real loopback smoke checks.

The accepted ledger also downgrades two historically partial CMS passes;
overall counts therefore remain1431/1021/93/317 until further lane acceptance.
The immutable ownership baseline is unchanged. See acceptance.json and
python3 tools/port-status.py for reproducible counts.

## S primitive acceptance

Main6dc97bb integrates only the reviewed fetch/name-policy/PDF subset and
passes the complete serial workspace gate. Accepted13 formerly skipped
functions, no CMS source known-red suite. Policy graph8 adapters remain
partial and count0; stronger main context tests remain intact. Accepted
S824/749/67/8, overall1431/1034/80/317. See acceptance.json for exact IDs.
