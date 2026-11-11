#!/bin/sh
# Rewrite references to the pre-2026-11-12 crate names (hanko-*) to the
# layered layout described in docs/crates.md.
#
# Run from the repository root on a branch based on the old layout, after
# `git mv`-ing nothing: the script only rewrites file contents. It touches
# tracked *.rs, *.toml, *.md, *.py, *.sh and *.txt files outside vendor/ and
# outside fixture data (README.md files in crates/*/data are rewritten).
#
#   tools/migrate-crate-names.sh            # rewrite in place
#   tools/migrate-crate-names.sh --check    # list files that still mention old names
set -eu
mode=${1:-rewrite}
files=$(git ls-files -- '*.rs' '*.toml' '*.md' '*.py' '*.sh' '*.txt' |
  grep -v '^vendor/' |
  grep -v -E '^crates/(hanko-)?testdata/data/.*' ; git ls-files -- 'crates/*testdata/data/**/README.md')
# Order matters: longer and more specific names first.
script='
s/hanko_ades::/sigis_pades::ades::/g
s/use hanko_ades;/use sigis_pades::ades;/g
s/\bhanko_ades\b/sigis_pades::ades/g
s/\bhanko_validate\b/sigis_pades/g
s/\bhanko_certvalidator\b/sigis_pki_certvalidator/g
s/\bhanko_core\b/sigis_pki_core/g
s/\bhanko_fetch\b/sigis_pki_fetch/g
s/\bhanko_cms\b/sigis_cms/g
s/\bhanko_pdf\b/sigis_pdf/g
s/\bhanko_diff\b/sigis_pdf_diff/g
s/\bhanko_eutl\b/sigis_eutl/g
s/\bhanko_sign\b/sigis_pades_sign/g
s/\bhanko_testdata\b/sigis_testdata/g
s#crates/hanko-ades/#crates/pades/#g
s#crates/hanko-validate/#crates/pades/#g
s#crates/hanko-certvalidator#crates/pki-certvalidator#g
s#crates/hanko-core#crates/pki-core#g
s#crates/hanko-fetch#crates/pki-fetch#g
s#crates/hanko-cms#crates/cms#g
s#crates/hanko-pdf#crates/pdf#g
s#crates/hanko-diff#crates/pdf-diff#g
s#crates/hanko-eutl#crates/eutl#g
s#crates/hanko-sign#crates/pades-sign#g
s#crates/hanko-testdata#crates/testdata#g
s#\.\./hanko-testdata/#../testdata/#g
s/`hanko-certvalidator`/`sigis-pki-certvalidator`/g
s/`hanko-core`/`sigis-pki-core`/g
s/`hanko-fetch`/`sigis-pki-fetch`/g
s/`hanko-cms`/`sigis-cms`/g
s/`hanko-pdf`/`sigis-pdf`/g
s/`hanko-diff`/`sigis-pdf-diff`/g
s/`hanko-eutl`/`sigis-eutl`/g
s/`hanko-validate`/`sigis-pades`/g
s/`hanko-ades`/`sigis-pades`/g
s/`hanko-sign`/`sigis-pades-sign`/g
s/`hanko-testdata`/`sigis-testdata`/g
s/^hanko-ades = /sigis-pades = /
s/^hanko-validate = /sigis-pades = /
s/^hanko-certvalidator = /sigis-pki-certvalidator = /
s/^hanko-core = /sigis-pki-core = /
s/^hanko-fetch = /sigis-pki-fetch = /
s/^hanko-cms = /sigis-cms = /
s/^hanko-pdf = /sigis-pdf = /
s/^hanko-diff = /sigis-pdf-diff = /
s/^hanko-eutl = /sigis-eutl = /
s/^hanko-sign = /sigis-pades-sign = /
s/^hanko-testdata = /sigis-testdata = /
'
if [ "$mode" = "--check" ]; then
  # shellcheck disable=SC2086
  grep -l -E '\bhanko_(core|certvalidator|fetch|cms|pdf|diff|eutl|validate|ades|sign|testdata)\b|crates/hanko-[a-z]|`hanko-(core|certvalidator|fetch|cms|pdf|diff|eutl|validate|ades|sign|testdata)`' $files || true
  exit 0
fi
# shellcheck disable=SC2086
for f in $files; do
  [ -f "$f" ] && sed -i -E "$script" "$f"
done
