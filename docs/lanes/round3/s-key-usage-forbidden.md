# Forbidden-only key usage policies

L requested this independent repair after C reported that a forbidden-only KU
policy was silently accepted. This increment changes only
`crates/pki-core/src/key_usage.rs` and S reports. It has no dependency or shared
API change and does not include the known-red CMS signing suites.

## Confirmed behavior and repair

At the original lane verification checkpoint, before the repair, `validate()` delegates through `validate_with_extra()` and
`validate_key_usage_extension()` to `validate_asserted_key_usage()`. That method
returns success when positive `key_usage` is `None` or empty, before checking
`key_usage_forbidden`. The same behavior exists on current main and pinned
pyHanko 0.38.1, `pkgs/pyhanko/src/pyhanko/sign/validation/settings.py:124-137`.

The repair checks forbidden asserted usages before the positive-policy early
return. Certificate extensions and extra asserted usages both participate.
Forbidden usages retain precedence over missing positive requirements. A
forbidden usage that is not asserted does not cause rejection.

Default KU remains `None`, and `with_key_usage([], [])` retains explicit
`Some(empty)` for positive KU. Both mean no positive usage requirement;
`match_all_key_usages` has no effect for either. Empty or absent forbidden sets
remain unrestricted. EKU semantics are unchanged: `None` accepts any EKU;
explicit empty rejects a concrete asserted purpose. Missing EKU and
anyExtendedKeyUsage retain the existing explicitness-policy exceptions.

## Tests and oracle evidence

Five native regressions in `key_usage::tests` were added before implementation:

| Rust test | Coverage |
| --- | --- |
| `forbidden_key_usages_reject_without_positive_requirements` | Real Ed25519 signer certificate, exact asserted KU, positive None/empty x match-all false/true; asserted banned usage rejects with exact error, absent banned usage accepts |
| `forbidden_key_usages_include_extra_assertions` | None/empty positive KU; real certificate and absent extension; extra forbidden usage rejects, no forbidden assertion accepts |
| `forbidden_key_usages_precede_positive_requirements` | Exact forbidden error wins when positive requirement is also missing; positive requirement still rejects when no forbidden usage is asserted |
| `unrestricted_key_usages_preserve_none_and_empty` | Default fields versus explicit empty constructor, real certificate, absent extension, empty forbidden set |
| `extended_key_usages_preserve_none_and_empty` | None/empty EKU x explicitness false/true; concrete, missing and anyExtendedKeyUsage assertions |

The certificate is the existing public test fixture
`pyhanko-certvalidator/testing-ca-ed25519/signer.cert.pem`, SHA-256
`5152cc703f1b65bde1a99a6dfd7ab6508da41a9dac13295dfdf666536fd2b4bd`.
There are no provider/runtime exclusions or new fixtures.

Fresh live Python 0.38.1 / certvalidator 0.33.0 performed 26 validation calls on
those same certificate bytes. Six forbidden-only cases intentionally differ:
Python accepts, repaired Rust rejects (four certificate-asserted combinations
and two extra-assertion combinations). The other 20 controls agree. This is a
specified stricter rejection difference, not universal oracle parity. These are
fresh calls, not committed-verdict replay. No encoding difference is involved.

The tests-first run had 5 passes and 2 failures, both caused by erroneous
success on forbidden-only policies. After repair:

| Command suffix (all use the wrapper below) | Result |
| --- | --- |
| `check -p sigis-pki-core` | Pass, before and after repair |
| `test -p sigis-pki-core --lib` | 27 passed, zero failed/ignored |
| `test -p sigis-cms --test test_key_usage_constraints` | All four existing upstream functions pass, preserving all 22 original parameter cases |
| `clippy -p sigis-pki-core --all-targets -- -D warnings` | Pass |
| `fmt -p sigis-pki-core -- --check` | Pass after formatting only new assertions |

Reproduce from the S worktree with
`/home/l/D/kooky/sigis/tools/cargo-locked.sh` until L synchronizes this branch;
after synchronization use `tools/cargo-locked.sh`. Test invocations set
`HANKO_ORACLE=/tmp/pyhanko-oracle/venv/bin/python`. Every compiling invocation
reported **vm2065 slot0**. Normal configured sccache, flags, features and target
policy were preserved; no local mode or job flags were added.

Detailed red/green/check/clippy/fmt logs, the tests-first patch and fresh oracle
script/results are under
`/home/l/.codex/artifacts/sigis/round3/s/key-usage-forbidden/`.
Run the oracle with:

```sh
/tmp/pyhanko-oracle/venv/bin/python \
  /home/l/.codex/artifacts/sigis/round3/s/key-usage-forbidden/oracle.py
```

## Accounting and safe handoff

This repair earns zero new unique upstream functions. At the original
verification checkpoint, accepted main62a72a2
remains S **824/753/63/8**, overall **1431/1038/76/317**; CMS remains
**78/73/2/3**, including both historical partial downgrades. The helper tests and
26 oracle calls do not change those counts.

Only this independent ready increment is offered for integration. Full S branch
still contains preserved known-red CMS/coverage/decode-limit work. L-reserved
reader.rs, MAC getter, context files and shared algorithm types are untouched.
The pre-existing dirty Cargo.lock and L-owned tools/cargo-locked.sh are excluded
from the commit and must be preserved during L's eventual main sync/rebase.


L curated this source with the certificate-position fix after main6ec3816.
Mainb81c254 passed the complete integration gate; accepted counts remain
S824/754/63/7, overall1431/1052/66/313 (no new upstream functions). The older counts above are historical
verification context, not a current ledger replacement.
