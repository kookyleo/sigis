# Native boundary reference checks

Run the five unchanged pyHanko/CV originals and same-input public PKI peers:

```sh
/tmp/pyhanko-oracle/venv/bin/python -B \
  crates/testdata/data/lanes/r3-s/five-native-boundaries/reference.py \
  --native-data crates/testdata/data
```

Native controls:

```sh
tools/cargo-locked.sh test -p sigis-pki-certvalidator --test registry_language_boundaries
tools/cargo-locked.sh test -p sigis-pdf --test object_model_boundaries
```

These preserve explicit trust requirements and real crypto/path checks. PDF
name normalization, materialized string bytes and integer conversion are
native contracts, not equivalent Python runtime errors. All five original
exclusions remain; these controls earn no passing-function credit.
