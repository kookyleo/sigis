# Source freshness repair and renewed main acceptance

Accepted source: `45a8b44262dac39e7a13942beeb1eba50a922585`.
No unique function is added by this infrastructure repair.

## Counterexample and bounded remedy

The earlier mtime-based target reused a foreign-worktree library whose public
API was absent in the selected source tree. Byte-identical source with a newer
mtime correctly failed compilation. The installed Cargo's documented two-key
content configuration is now fixed in the repository, with a wrapper guard
against an environment downgrade. An equal-length source mutation with the
original older mtime is detected by its BLAKE3 mismatch. sccache, scheduler,
canonical target, profiles and feature settings remain intact.

The first full retry passed1754 native tests and then failed a doctest because
core/ades-model referenced a different const-oid crate hash from the actual
same-path metadata. The failure and24 artifact snapshots remain saved. An
unchanged focused doctest rebuilt the stale graph; a subsequent unchanged
workspace-build/doctest reuse cycle stayed content-based and passed. No source
waiver, test exclusion, cache clean or proposed environment cache salt was used.
The precise original overwrite/replay event remains unproven; do not attribute
it to a particular cache component or assert universal race prevention.

## Complete repeated gate

All six stages passed on clean main45: build19.89s, complete workspace tests
471.99s, strict all-target Clippy59.82s, strict docs204.96s, layer/cycle check
26.22s, formatting2.61s. Actual results remain1764 discovered/1760 passed/
4 ignored/0 failed across163 reports. This includes1754 native passes and6
Rustdoc passes; earlier failed logs are not relabelled green.

For every selected local Cargo compiler-artifact message, the verifier freezes
its content fingerprint and emitted dependency info, then checks actual source
bytes and lengths. The successful run contains391 phase observations over368
unit paths,2411 emitted input records and381 unique actual source files.
Both local vendor packages are included. Every selected input matches main45;
no vendor exception is silently filtered. This binds the selected libraries
as well as test source, beyond the earlier native-only snapshot.

The source45 private CLI SHA-256 is
`36dec5650c89dae0ce1432e70f682776551db06ec01ecc0be122429fb4d9c946`,
96308328bytes. The repeated producer independently audits7 local library
units and133 input records; its binary matches the earlier source45 producer.
Both workers have exact copied executables. All four actual subprocess
selections match it. Selected source correctness does not prove every future
concurrent cache/artifact race, and Cargo build-script file watching remains
an explicitly documented mtime limitation.

## Runtime and existing function inventory

The successful gate also verifies actual V213/S69 input reads, L18 live outputs,
eight shared/distinct registry profiles, six fresh S output verdicts, encrypted
state continuation and six resource-operation denials. Nine P AC outputs and
two Adobe outputs/public DER identities match fresh same-output Python; the
independent complete original Python9+2 runs remain separately identified.
Native Adobe finalNO_POE versus PythonOK remains a bounded stricter status gap.

Renewed counts are unchanged:1431 total/1259 passed/29 skipped/143 pending;
P294/3/0, V47/0/0, S798/26/0, C110/0/142 and L10/0/1. The immutable assignment
and accepted IDs stay unchanged. This source-correct gate renews the existing
inventory; it does not complete the port or prove all divergences fail closed.

Evidence: `/home/l/.codex/artifacts/sigis/round3-launch/source-freshness-rerun/`.
The original failed run, mode/mtime controls, metadata mismatch snapshots and
independent audits remain under source-freshness-integration, cargo-freshness-audit
and cargo-doctest-audit directories. Next RIA/HTTP/PDF/CLI increments remain
isolated until their own exact-source acceptance.

Independent final review: final-main-review.md/json reparses every selected
Cargo event/frozen fingerprint/dep-info tuple, rehashes all381 source files and
compares them byte-for-byte with main45 Git blobs. All391 observations and2411
records match. One interleaved nonacceptance CLI fixture-snapshot log line is
retained; all four executable records are complete and do not depend on that line.
