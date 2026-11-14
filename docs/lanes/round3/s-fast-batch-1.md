# S final six-function batch

Base: main cc1f4fb3. The lane supplies the existing-API language adaptation for
`pyhanko/test_internal_utils.py::test_bool_dunders`, preserving all nine
statements and both comparisons in each final chain. The local simplified gate results are recorded below. During this run Root accepted
the identical Boolean test in main0492678c; it must not receive another credit.

The other five originals remain skipped for these exact reasons:

- `pyhanko-certvalidator/test_registry.py::test_system_trust_fallback_deprecated`: Python's deprecated implicit OS-trust constructor/runtime warning has no native counterpart; Rust keeps explicit roots and no OS fallback.
- `pyhanko-certvalidator/test_registry.py::test_extra_trust_roots_deprecated`: Python's deprecated extra-roots keyword/runtime warning has no native alias; native explicit trust anchors are supported separately.
- `pyhanko/test_internal_utils.py::test_name_encode_fail`: native names store normalized bytes and discard an optional leading slash; they cannot retain the Python invalid-prefix state until writing.
- `pyhanko/test_internal_utils.py::test_text_string_no_bytes_available`: native strings always contain materialized bytes; Python's unknown-original-encoding accessor state is absent.
- `pyhanko/test_internal_utils.py::test_dictionary_setvalue_guard`: native Dictionary.set intentionally accepts integer-to-Object conversion and has no dynamic setdefault; Python's raw-value runtime rejection is not its contract.

No missing-method compile failures, empty passing wrappers, fabricated warnings,
OS trust fallback, representation replacement or weakened negative tests are
introduced. No additional original is credited from setup controls.


## Validation and delivery

- Rebased the minimal lane projection onto maincc1f4fb3 before execution; preserved the original lane and its dirty lock.
- `tools/cargo-locked.sh test -p sigis-pdf --test boolean_dunders`: 1 passed,0failed.
- Fresh unchanged upstream originals via `/tmp/pyhanko-oracle/venv/bin/python -B -m pytest`: PDF4+CV2,6passed.
- `tools/cargo-locked.sh test --workspace --no-fail-fast` with existing integration resource selectors: **2226passed,0failed,4pre-existingignored; exit0** (229reports,vm2064slot0).
- `tools/cargo-locked.sh clippy --workspace --all-targets -- -D warnings`: exit0.
- `tools/cargo-locked.sh fmt --all -- --check`: exit0.

The local execution base was cc1f4fb3 plus the identical Boolean test, not the
later P prompt implementation. Main advanced to5a7a2720 during the run and already
contains the Boolean port/credit. This documentation-only projection preserves
that accepted Rust source and does not relabel the earlier execution as a rerun
of the new P implementation. Current accepted S remains824/819/5/0 (PDF406/403/3/0,
CV133/131/2/0); all other assigned crates retain their main counts.

Plain logs and the integration command configuration are under
`~/.codex/artifacts/sigis/round3/s/fast-batch-1/`. Earlier failed attempts remain:
missing legacy CLI/scratch selectors, missing worker upstream inputs and one
nonreproducing CLI snapshot-path failure. The final full rerun passed after
supplying existing fixture resources. Missing upstream inputs were copied to
workers without replacing existing files or changing providers/venv/services.

The current Boolean fixture support is simplified to three byte inputs and a
short source-to-native table/direct pytest command. No new SHA/BLAKE3 evidence,
ELF capture, JSON evidence pipeline or independent review was added for this
batch; old sealed history/artifacts remain intact. The five exclusions above
remain skipped, without synthetic wrappers, absent-method compile failures or
new runtime/API behavior.
