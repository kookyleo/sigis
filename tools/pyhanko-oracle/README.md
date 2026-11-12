# pyHanko oracle

pyHanko itself, run from a Python venv outside the repository, is the
reference implementation for the Rust port. It serves two purposes:

1. **Fixture generation.** Scripts produce inputs (PKI material, signed CMS
   and PDF files) together with pyHanko's verdicts as JSON. The outputs are
   committed under `crates/testdata/data/`, so the Rust tests run
   without Python.
2. **Differential tests.** Rust tests run pyHanko on the same inputs and
   compare verdicts. They skip themselves (with a message) when the oracle is
   not installed; see `sigis_testdata::oracle`.

Baseline: pyHanko **0.38.1** and pyhanko-certvalidator **0.33.0** (tags
`v0.38.1` and `pyhanko-certvalidator/v0.33.0`).

```sh
tools/pyhanko-oracle/setup.sh            # creates /tmp/pyhanko-oracle
export HANKO_ORACLE=/tmp/pyhanko-oracle/venv/bin/python
```

Layout of scripts:

- `tools/pyhanko-oracle/*.py` — shared helpers, owned by the lead.
- `crates/<crate>/oracle/*.py` — generators and verdict scripts owned by the
  lane that owns the crate. Each script writes JSON to stdout.

Scripts must pin the validation time and never contact external hosts.
The round-3 live integration sidecar binds only `127.0.0.1:0` and serves
Certomancer over actual loopback HTTP; its parent test owns its lifetime.
Other verdict scripts remain offline and disable fetching.
