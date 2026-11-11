# hanko-pdf fuzz targets

cargo-fuzz layout (libFuzzer via `libfuzzer-sys`). Not a member of the main
workspace. Targets:

| Target | What it exercises |
| --- | --- |
| `parse_pdf` | whole-file reader (strict and lenient): xref chains, revisions, objects of every revision, stream decoding, signatures, DSS, metadata, reverse path index |
| `parse_object` | object parser (regular and content-stream modes), serialise/reparse, content stream operator parser |
| `xref_stream` | xref table parser and xref stream entry decoding with fuzzed `/W` and `/Index` |
| `object_stream` | object stream headers and members, through the writer and through a hand-made xref stream |
| `incremental_roundtrip` | incremental writer: strict-readable input + update must reparse in strict mode with one more revision |
| `xmp` | XMP parser and serialise/reparse |

Invariant for all targets: no panic on any input.

## Running

With cargo-fuzz: `cargo +nightly fuzz run <target> -- -max_total_time=600`.

Without cargo-fuzz (as done for the lane B budget), build with the same
flags cargo-fuzz uses, in a target directory outside the shared one (the
flags differ, so sharing it would invalidate the main build cache):

```sh
cd crates/hanko-pdf/fuzz
CARGO_TARGET_DIR=/tmp/hanko-b/fuzz-target \
RUSTFLAGS="-Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4 \
  -Cllvm-args=-sanitizer-coverage-inline-8bit-counters \
  -Cllvm-args=-sanitizer-coverage-pc-table \
  -Cllvm-args=-sanitizer-coverage-trace-compares --cfg fuzzing \
  -Cdebug-assertions -Coverflow-checks" \
cargo build --release --bins --target x86_64-unknown-linux-gnu
/tmp/hanko-b/fuzz-target/x86_64-unknown-linux-gnu/release/parse_pdf \
  -max_total_time=600 -rss_limit_mb=4096 /tmp/hanko-b/corpus/parse_pdf
```

Seed corpora are not committed; seed `parse_pdf` and
`incremental_roundtrip` with the PDFs in
`crates/hanko-testdata/data/pyhanko/pdf/` and `xmp` with
`crates/hanko-testdata/data/pyhanko/xml/`.

## Budget and results

See `docs/lanes/b.md` ("Fuzzing").
