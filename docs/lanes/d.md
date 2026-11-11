# Lane D — Signing

Owner: lane D (branch `hanko/d-sign`). See `docs/hanko-lanes.md`.

## Status

Not started (skeleton only).

## Per-suite counts

| Suite | Total | Ported-pass | Skipped | Pending |
| --- | ---: | ---: | ---: | ---: |
| `test_signing.py` | 78 | 0 | 0 | 78 |
| `test_pades.py` | 48 | 0 | 0 | 48 |
| `test_fields.py` | 27 | 0 | 0 | 27 |
| `test_seed_values.py` | 36 | 0 | 0 | 36 |
| `test_pkcs11.py` | 36 | 0 | 0 | 36 |
| `test_csc.py` | 17 | 0 | 0 | 17 |
| `test_sign_encrypted.py` | 11 | 0 | 0 | 11 |
| `test_stamp.py` | 25 | 0 | 0 | 25 |
| `test_text.py` | 15 | 0 | 0 | 15 |
| `test_images.py` | 2 | 0 | 0 | 2 |
| `test_barcode.py` | 2 | 0 | 0 | 2 |

## Known divergences

None yet.

## Requests to the lead

None yet.

## Requests from other lanes (relayed by the lead, 2026-11-12)

When rebasing onto `main`, keep this section in your version of this file.

- **D-1 (from lane E).** Seed value validation in `hanko-validate` is pending
  on `SigSeedValueSpec` (pyHanko `sign/fields.py`). Please expose the seed
  value model with parsing from a PDF dictionary
  (`SigSeedValueSpec::from_pdf_object`, including `/MDP`, `/LockDocument`,
  `/Cert` constraints, `/Reasons`, `/SubFilter`, `/DigestMethod`, `/TimeStamp`,
  `/AppearanceFilter`, `/Ff`) as public API of `hanko-sign`. `hanko-validate`
  may depend on `hanko-sign` (no cycle: `hanko-sign` must not depend on
  `hanko-validate`; dev-dependencies may).
- **D-2 (from the lead).** `crates/hanko-sign/tests/support/mod.rs` uses
  `env!("CARGO_MANIFEST_DIR")`; switch to `hanko_testdata::manifest_dir()` /
  `hanko_testdata::data_dir()` (run-time paths, see `docs/hanko-lanes.md`
  §5.2).
- **Lead answers to your requests:** 1 approved (recorded in
  `docs/hanko-lanes.md` §8). 2 done on `main` (run-time fixture paths).
  3 and 4 relayed to lane A (A-5, A-6). 5 relayed to lane B (B-4). The
  standard oracle venv is `/tmp/pyhanko-oracle/venv`.
