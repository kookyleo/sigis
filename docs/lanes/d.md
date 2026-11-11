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

- **D-1 (from lane E).** Seed value validation in `sigis-pades` is pending
  on `SigSeedValueSpec` (pyHanko `sign/fields.py`). Please expose the seed
  value model with parsing from a PDF dictionary
  (`SigSeedValueSpec::from_pdf_object`, including `/MDP`, `/LockDocument`,
  `/Cert` constraints, `/Reasons`, `/SubFilter`, `/DigestMethod`, `/TimeStamp`,
  `/AppearanceFilter`, `/Ff`) as public API of `sigis-pades-sign`. `sigis-pades`
  may depend on `sigis-pades-sign` (no cycle: `sigis-pades-sign` must not depend on
  `sigis-pades`; dev-dependencies may).
- **D-2 (from the lead).** `crates/pades-sign/tests/support/mod.rs` uses
  `env!("CARGO_MANIFEST_DIR")`; switch to `sigis_testdata::manifest_dir()` /
  `sigis_testdata::data_dir()` (run-time paths, see `docs/hanko-lanes.md`
  §5.2).
- **Lead answers to your requests:** 1 approved (recorded in
  `docs/hanko-lanes.md` §8). 2 done on `main` (run-time fixture paths).
  3 and 4 relayed to lane A (A-5, A-6). 5 relayed to lane B (B-4). The
  standard oracle venv is `/tmp/pyhanko-oracle/venv`.

## Lead round 2 (2026-11-12)

- **Not merged yet.** Your committed head `a9d07e0` does not compile on
  `main`: 13 non-exhaustive `match`es on `DigestAlgorithm` in
  `src/signer.rs` and `src/pkcs11.rs` (lane A added `Md5`, `Sha3_*`,
  `Shake256`). Your session was still running with uncommitted edits in
  those files, so the lead did not touch them.
- D-2 decided: reading the run-time `CARGO_MANIFEST_DIR` first is fine;
  prefer `sigis_testdata::manifest_dir()` for uniformity.
- D-6 done: `HankoError::{Layout, Configuration, FormFilling}(String)`.
- The layout was renamed (`docs/crates.md`): your crate is now
  `crates/pades-sign` (`sigis-pades-sign`). To catch up: commit your work,
  run `tools/migrate-crate-names.sh` on your branch, commit, then
  `git rebase main` (keep both sides in `docs/lanes/d.md`; take `main`'s
  `Cargo.lock` and run `cargo check --workspace`). Then the lead merges.
- Divergence to review: images "1-bit and 16-bit accepted where Pillow
  rejects" accepts input pyHanko rejects. It concerns appearance images, not
  signature validation, but please either reject them as Pillow does or list
  it explicitly as an accepted divergence with a reason.
