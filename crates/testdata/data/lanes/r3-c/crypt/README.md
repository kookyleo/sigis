# CLI encryption fixtures

`generate.py` exports the exact `minimal_with_oversized_objstm` fixture used
by pyHanko 0.38.1 `test_cli_decode_limits.py`, encrypted with the same password
and recipient. Run it with `/tmp/pyhanko-oracle/venv/bin/python`.
The generator and derived fixtures use pyHanko's MIT license; see
`LICENSE-pyHanko` at the repository root.

These committed inputs support native Rust assertions. Their generation
does not establish a passing port or count as a live differential comparison.
