# Fresh PDF seed-value validation corpus

Generated with pyHanko 0.38.1 and pyhanko-certvalidator 0.33.0 from the pinned
`tests/test_seed_values.py` helper and assertions. There are 75 signed PDFs,
75 oracle validation calls and seven Rust test groups. These are supplementary
validation regressions, not new upstream-function passes for lanes V or P.

The `manifest.json` records the source function, actual digest/SubFilter/reason/
DocMDP values, seed constraint error class/message and meaningful status flags.
It separates status results from oracle exceptions and identifies deliberate
stricter Rust rejection explicitly.

| Group | Cases |
| --- | ---: |
| Digest requirement and hints | 7 |
| Required reasons and all three prohibition parameters | 12 |
| Trusted, missing, untrusted and optional timestamps | 4 |
| Required, hinted and partially unsupported SubFilter lists | 5 |
| Certification/approval, DocMDP and field/document locks | 17 |
| Certificate subject DN, exact certificate, issuer, KU and composite constraints | 20 |
| Unsupported mandatory constraints and Adobe revinfo guards | 10 |

The signer is `FROM_CA` from the `testing-ca` architecture. The usual timestamp
provider is `DUMMY_TS`; the untrusted-token case uses `unrelated-tsa`. Signing
and validation are frozen at 2020-11-01T00:00:00Z. PDF negatives use `_ignore_sv`
while signing, then validate the actual signed PDF against the original seed.
The corpus embeds no private keys. No HTTP server or external service is used.

The oracle validation context is upstream `dummy_ocsp_vc()` with a single
`testing-ca` root, no fetching, soft-fail revocation and no weak-hash deny list.
Its unrelated fixed OCSP object does not determine any exercised result; the
Rust context supplies the root, same time, soft-fail and empty weak-hash deny
list. `cert_issuer_path_missing` sets `trust_signer: false` and supplies no root
on either side, preserving the upstream missing-validation-path rejection.
No signature modification review is requested (`skip_diff=True` / Rust None).

Regenerate from the repository root:

```sh
/tmp/pyhanko-oracle/venv/bin/python crates/pades/oracle/seed_oracle.py \
  --output crates/testdata/data/lanes/r3-v/seed
```

For an interrupted export, add `--resume`; completed inputs and outcomes remain
on disk. For a fresh differential run, choose a new output directory and set
`HANKO_SEED_FIXTURE_DIR` to it when running the Rust suite:

```sh
HANKO_ORACLE=/tmp/pyhanko-oracle/venv/bin/python \
  tools/cargo-locked.sh test -p sigis-pades --test ades_seed
```

There are 68 oracle status results (41 seed-valid / 27 seed-invalid) and seven
explicit oracle exceptions: mandatory legal attestations, certificate RESERVED
and OID flags, unknown SubFilter, unknown handler, future version and unknown
mandatory flags. Rust must reject each unsupported mandatory guard explicitly.

`mandatory_appearance_unverifiable` is the one deliberate stricter trust-policy
case: the oracle logs a warning and accepts the mandatory named appearance;
Rust rejects the unsupported mandatory requirement. This is listed separately,
not described as encoding parity. The fixture has a cryptographically valid,
trusted CMS and timestamp; Rust guard tests verify those positive controls
before checking the rejection, so unrelated signature failures cannot satisfy
the mandatory-constraint assertion.

Diagnostic strings are recorded for review. Rust checks the seed-error subclass
and a nonempty diagnostic; strings are not required to match byte for byte.

An additional `optional_filter_dangling.pdf` mutation has a valid trusted CMS
and timestamp but `/SV/Ff 0` with `/Filter 999999 0 R`. The pinned oracle raises
PdfStrictReadError despite the optional flag. The Rust regression requires an
explicit malformed-input rejection and preserves the independent CMS trust
control. Regenerate this extra input with `--dangling-filter-only`; the original
75-case manifest and parameter counts are unchanged.
