#!/bin/sh
# Regenerate the lane C fixtures (crates/testdata/data/lanes/c/) by
# running pyHanko's own test_diff_analysis.py (tag v0.38.1) with
# capture_plugin.py, which records every difference analysis.
#
# Usage: capture.sh [PYTHON] [PYHANKO_SRC]
#   PYTHON       python of a venv with pyHanko 0.38.1 + test dependencies
#                (default: $HANKO_ORACLE or /tmp/pyhanko-oracle/venv/bin/python)
#   PYHANKO_SRC  checkout of pyHanko at tag v0.38.1
#                (default: /tmp/pyhanko-oracle/src/v0.38.1)
#
# The test suite freezes time (freezegun), and its signatures use the
# Certomancer test PKI with fixed keys; the recorded verdicts depend only on
# the PDF structure, so reruns reproduce the same cases.json. Signed PDFs
# embed signing times and random CMS content, so their bytes (and hashes)
# change between runs.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
python=${1:-${HANKO_ORACLE:-/tmp/pyhanko-oracle/venv/bin/python}}
src=${2:-/tmp/pyhanko-oracle/src/v0.38.1}
out="$repo/crates/testdata/data/lanes/c"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

"$python" -c 'from importlib.metadata import version as v; assert v("pyhanko") == "0.38.1" and v("pyhanko-certvalidator") == "0.33.0"'
"$python" -m pip install -q -e "$src/internal/common-test-utils" \
    pytest pytest-asyncio freezegun requests-mock pytest-aiohttp >/dev/null

mkdir -p "$tmp/out"
cp "$here/capture_plugin.py" "$tmp/"
(
  cd "$src/pkgs/pyhanko"
  HANKO_CAPTURE_OUT="$tmp/out" PYTHONPATH="$tmp" "$python" -m pytest -q \
      -p capture_plugin -p no:cacheprovider tests/test_diff_analysis.py
) || echo "pytest reported failures; see cases.json outcomes" >&2

rm -rf "$out/pdf" "$out/model" "$out/cases.json"
mkdir -p "$out"
cp -r "$tmp/out/pdf" "$tmp/out/model" "$tmp/out/cases.json" "$out/"
echo "wrote $(ls "$out/pdf" | wc -l) PDFs and cases.json to $out"
