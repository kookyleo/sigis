# V: contain incomplete MAIN trust promotion

Accepted baseline ab08d1c6/source14d6c6a3 retains V47/47/0/0. Diagnostic d56ba126
has genuine signed expired-MAIN/proper-TST counterexamples and an actual retained
hardening RED: public native WithTime accepts invalid path length and certificate
signature where pinned Python refuses. Name/critical/usage omissions shared
with Python are unsafe too. Final LTA refusal does not repair public WithTime.

## Exact scope and ownership

This is zero-new-original hardening. Audit all47 V IDs in immutable ownership.json
against exact original assertions; in particular inspect
pyhanko/test_ades_validation.py::test_embedded_cades_pre_revoke_with_poe.
Report exact affected IDs/parameters and any proposed pending downgrade to L;
never silently retain a broken original as passed. Ownership does not change.

Only ades/with_time.rs, its actual unit assertions and V adversarial tests/fixtures/
oracles may change. Keep the tests-first diagnostic source and ELF frozen. No
CV/CMS, policy.rs, other LTA production, public API, dependency or clock change.
The pure transformer cannot promote failed MAIN to trusted/OK merely from a
candidate path and trusted timestamp. Retain typed original failure, diagnostic
path/API status and timing bounds. Already fully checked valid MAIN still
processes timestamps/qualification normally. Preserve mandatory TSA/MAIN checks,
imprint/order and denied-token handling.

Explicitly disclose stricter refusal of incomplete expired/revoked recovery
positives. Do not invent historical completion, relax revocation/time, use a
KU-only check, copy preliminary API status or waive the final CLI AND. Existing
genuine full LTA must recover only through its actual final complete historical
operation; failed-past conservative results remain. No shared-role timing or
POE/source framework is authorized.

Retain actual signature/path-length/name/critical/purpose adversarial cases,
current+best clones, no roots/mutations, denied TSA purpose/imprint/clock, complete
current positive and genuine LTA positives. Changed old expectations require
explicit contract/ID impact review. L has reviewed the actual0acc3eee regression:
156native tests passed and2failed, one original plus one supplemental assertion.
A bounded exception is now approved: retain the complete unchanged assertion body
of test_embedded_cades_pre_revoke_with_poe with one explicit pending ignore
annotation naming incomplete same-policy MAIN validation. It must be reported as
pending, never passed or a provider skip. Root will change its existing accepted
ledger entry only after the hardening source and full gate pass. No other
original may be ignored or removed. Replace/rename the old supplemental
pre_revocation_poe_restores_api_trust expectation with the intentional fail-closed
contract, preserving the actual before/after proof; it earns no original ID.
This temporary pending status does not complete historical recovery. Implementing
safe positive completion remains required future work. If genuine full LTA
positives fail, report raw outcomes instead of broadening the repair.

Artifacts: round3/v/withtime-containment/. L approves shared architecture,
integrates the minimal packet and makes any central count decision.

## Execution and reporting

Use tools/cargo-locked.sh for every Cargo call, one at a time per lane. It
injects canonical rust-target-env and delegates placement/concurrency to system
rust-slots; automatic VM dispatch is allowed. Preserve sccache, targets, flags,
profiles and features. Do not introduce a repository lock, local pin or job cap.
Keep proof snapshots lean; compressed ELF archives require distinct raw/archive
SHA256 and length checks. Do not clean shared targets or old evidence.

Port complete exact upstream assertions before implementation. Use the pinned
pyHanko0.38.1/CV0.33.0 oracle at /tmp/pyhanko-oracle/venv, assertions enabled.
Fresh original bodies, same-output comparisons, replay and native executions
remain distinct. Trust decisions fail closed; mandatory unsupported conditions
refuse. Report exact IDs and parameters, source/ELF/runtime/input receipts,
per-crate total/passed/skipped/pending and divergences. Root owns acceptance
counts and full build/test/clippy -D warnings/strict doc/layer/fmt gates.

English local commits only; no push, pkill, service restarts, target cleanup or
interference with other sessions. Preserve frozen branches, proof artifacts and
dirty lockfiles. Save progress and handoffs under the assigned artifact path.
