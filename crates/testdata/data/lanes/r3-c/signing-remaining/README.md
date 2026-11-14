# Remaining field, hybrid and dictionary signing originals

Seven exact pyHanko0.38.1 originals,16parameter cases: four algorithms for
PKCS12 visible creation, field-then-sign and implied selection; fixed RSA for
missing field, strict/nonstrict hybrid and dictionary entries. Existing pinned
fixtures are reused. Native top-level runtime uses the original2020 fixture
clock and supplied password prompter. verify.py validates the same output bytes
with explicit roots and fresh original PKI services; empty roots refuse.
These tests add no provider substitutions or product clock option.
