# Portable AC assertion oracle

`ac_assertions.py` contains all post-signing statements from seven pinned
pyHanko 0.38.1 AC tests, with their 59 assertions unchanged. It executes these
assertions against a newly generated Rust PDF. It needs the pinned Python
packages and common test data, but does not load an upstream source checkout.

The assertion tails and `live_ac_vcs` helper are derived from pyHanko under the
MIT license. Copyright (c) 2020-2026 Matthias Valvekens. The complete upstream
license is included in `LICENSE-pyHanko`.

`ac-assertions-source.json` records the pinned commit, original source SHA-256,
helper source SHA-256, exact line ranges, source-tail hashes, assertion counts
and generated fixture hash. The test source SHA-256 is
`286358234dda7b42f59da61b8b845deac383a1f7fb08ee7cdf202f263c409d69`.

Regenerate using a local pinned checkout:

```sh
python3 crates/testdata/data/lanes/r3-p/ac/extract_ac_assertions.py \
  --source /tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko/tests/test_pades.py \
  --helper-source /tmp/pyhanko-oracle/src/v0.38.1/internal/common-test-utils/src/pyhanko_testing_commons/test_utils/signing_commons.py \
  --output-dir crates/testdata/data/lanes/r3-p/ac
```

The extractor selects the first assignment to `r` through the end of each
function. For the LTA case it selects the body after the first signing-time
`with` block, retaining the complete 2028 validation-time block. It copies the
helper as written. Before writing output, it checks AST equality for every
selected statement and the complete helper. Dedenting into parameter-free
async functions is the only transformation to the selected bodies. The runner
supplies the same `out`, PKI architecture, live services and fetcher-backend
namespace used by the previous source-driven harness.

Portable import smoke:

```sh
/tmp/pyhanko-oracle/venv/bin/python -I \
  crates/testdata/data/lanes/r3-p/ac/ac_assertions.py --list
```

Run one assertion tail against actual newly signed output:

```sh
/tmp/pyhanko-oracle/venv/bin/python -I \
  crates/testdata/data/lanes/r3-p/ac/ac_assertions.py \
  test_pades_live_ac_presign_validation output.pdf requests
```

The two live functions retain `requests` and `aiohttp` runner cases. These
parameter wrappers do not increase unique upstream-function counts. Python
validation status is differential evidence; it does not implement or establish
Rust AC status/LTA parity. Rust still supplies AC OCSP evidence explicitly
because automatic AC fetching and V-owned status integration remain incomplete.

The pre-existing DER AC, claimed-group attribute and OCSP fixtures are unchanged.
