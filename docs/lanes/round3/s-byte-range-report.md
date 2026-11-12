# Verified bounded variable ByteRange increment

Base: accepted main8fb499c. L approved only the S-owned interface below in
interfaces-l.md; V owns coverage/status behavior and P owns signer consumers:

```rust
// sigis_pdf::signatures::EmbeddedSignature
pub byte_range: Vec<u64>;
// sigis_pdf::signatures
pub fn byte_range_data(bytes: &[u8], br: &[u64]) -> PdfResult<Vec<u8>>;
```

Seven meaningful native tests were added before production changes. The first
run failed compilation at six slice calls because the old helper accepted only
&[u64;4]. After a type-only migration retaining old behavior, runtime tests ran
2 passed/5 failed: cardinality, invalid-entry stage, odd truncation, allocation
amplification and the real single-range PDF. Only then was bounded behavior
implemented. All seven regressions now pass. The only source migration beyond
signatures.rs is S-owned tests/interface.rs borrowing the Vec instead of moving
it. No new upstream-function credit follows from this interface increment.

The tests cover exact empty/two/four/six-entry pairs; preservation of order,
overlap and zero-length ranges; odd/incomplete rejection; 28 combinations of
negative/noninteger entry and position; every pair's bounds and checked overflow;
bounded total repeated-range output; and actual one-byterange/weird-byterange
fixtures (two and four entries respectively). They do not claim standard
coverage or a trusting final verdict for either anomalous fixture.

The Vec-return API validates every pair and cumulative length before output
allocation, with total concatenated bytes capped by input file length. This
prevents repeated-range output amplification while preserving complete pairs
within the bound. It is an explicit stricter resource difference from Python's
streaming digest helper. No new dependency, decoder default or layer exemption
is requested. No reader/getter/MAC/context/shared-core file is edited.

Fresh pinned oracle completed 32 helper calls plus two real reader and two
coverage calls; both fixtures remain UNCLEAR. Python accepts some negative
length, beyond-EOF and output-amplification inputs that the bounded Rust helper
explicitly rejects. These semantics/resource differences are recorded, not
labelled universal parity. Tests do not weaken rejection assertions or invent
trust from successful byte extraction.

Evidence: /home/l/.codex/artifacts/sigis/round3/s/variable-byte-range/.
The exact two S-owned diff upstream functions remain unaccepted skipped IDs
until complete V validator assertions are integrated centrally. Root caller
patches stay with L, and no upward cyclic dev-dependency is reintroduced.
Current accepted S824/754/63/7 and CMS78/74/2/2 remain unchanged.

## Exact native regression mapping and verification

All seven live under signatures::byte_range_regressions:

| Rust test | Parameters / assertions |
| --- | --- |
| variable_byte_range_parser_retains_every_complete_pair | Empty/2/4/6 entries and i64::MAX boundary; retain full order/cardinality |
| variable_byte_range_data_preserves_pair_order_overlap_and_zero_lengths | Seven cases: complete arbitrary pairs, overlap, empty and EOF zero lengths |
| variable_byte_range_rejects_incomplete_pairs_before_returning_data | Three odd cardinalities through both parser and data API; no partial return |
| variable_byte_range_parser_rejects_noninteger_and_negative_entries | Non-array plus seven invalid types x four positions, including later pairs |
| variable_byte_range_checks_all_bounds_and_integer_overflow | Six EOF/bounds cases and three checked-add overflow cases |
| variable_byte_range_bounds_total_allocation_for_repeated_ranges | Exact input-size boundary succeeds; two repeated-range amplification cases reject |
| variable_byte_range_preserves_real_nonstandard_fixture_cardinality | Exact one/weird fixture ranges, copied bytes, native input/output SHA-256 and lengths |

Final native fixture receipts match both fresh oracle input hashes, full ranges,
extracted lengths (690 and40), and SHA-256 outputs. Unit discovery/extraction
proves structural data behavior, not a native final coverage/trust verdict.
The oracle reports UNCLEAR for both fixtures. The complete S-owned diff callers
still require V's status/modification/summary assertions and L-owned root
integration; no empty wrapper was re-enabled or counted.

Commands from the S worktree, all using tools/cargo-locked.sh:

| Command suffix | Result / recorded scope |
| --- | --- |
| check -p sigis-pdf | Passed; s7 slot0 |
| test -p sigis-pdf | 435 passed,2 existing ignored MAC pending tests,0 failed; s7 slot1 |
| test -p sigis-pdf --lib byte_range_regressions -- --nocapture | Final7 passed; machine-checked same-input/output oracle receipts |
| test -p sigis-pades --lib coverage::tests | 3 existing coverage unit controls passed; not new anomalous validator assertions |
| test --test pdf_diff_signing | 4 existing actual signing/diff callers passed |
| clippy -p sigis-pdf -p sigis-cms --all-targets -- -D warnings | Passed after correcting a test-only constant-chunk iterator lint; no lint suppression |
| RUSTDOCFLAGS='-D warnings' doc -p sigis-pdf --no-deps | Passed; s7 slot0 |
| fmt -p sigis-pdf -p sigis-cms -- --check | Passed |
| test --test layering | Passed, including dev-cycle enforcement |

The final seven-case rerun also covers the test-only iterator correction and
native hash receipts. The two unchanged runtime ignores are exactly
pyhanko/test_pdfmac.py::test_pdf_mac_pades and
pyhanko/test_pdfmac.py::test_sign_cannot_reuse_pdf_signer_with_macs_in_parallel,
which still need real P/V MAC session/LTA interfaces. No new provider or runtime
exclusion was added. All production P/V consumers on the accepted base compiled;
future V draft consumers remain their owner's responsibility.

No manifest/dependency/lockfile/root file is included. The generated lockfile
remains uncommitted, all prior source/history is archived, and reserved shared
context/core-schema/reader/getter/wrapper files match accepted main. No flag,
feature, profile, cache wrapper or placement override was used. Concrete patch
and commit heads are recorded in the ready receipt for L's independent gate.


L integration note: only this source/test/report delta is selected over
accepted main9c4436c. Ancestor known-red caller suites are not imported.
Complete S anomaly/tamper assertions stay pending; root gate and next
validator candidate run remain required.
