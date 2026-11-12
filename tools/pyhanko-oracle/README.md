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


The accepted live integration suites require the pinned oracle explicitly;
missing dependencies fail instead of turning into a successful early return.
`tests/live_csc.rs` additionally needs certomancer-csc-dummy0.4.2 and
python-pae0.1.0. They may be installed separately without changing the shared
reference venv:

```sh
/tmp/pyhanko-oracle/venv/bin/python -m pip install --no-deps \
  --target /path/to/csc-oracle-deps certomancer-csc-dummy==0.4.2 python-pae==0.1.0
export HANKO_CSC_ORACLE_DEPS=/path/to/csc-oracle-deps
HANKO_ORACLE=/tmp/pyhanko-oracle/venv/bin/python tools/cargo-locked.sh test --test live_csc
```

The acceptance hosts use an isolated artifact directory replicated identically
on s7/vm2064/vm2065; the helper also supports correctly pinned normal installs.
Each test owns its ephemeral loopback service child. Real Rust/Python PDF
outputs are validated in both implementations with the actual generated root
and fixed time, then checked again with empty roots. The CSC suite preserves
the original automatic-batch and authorization-count parameters.
