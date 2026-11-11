#!/bin/sh
# Record pyHanko's AdES validation verdicts for lane E fixtures.
#
# Usage: run_oracle.sh <python> <pyhanko-v0.38.1-checkout> <repo-root>
# Runs the upstream test modules with record_plugin.py and writes one JSON
# file per module to crates/hanko-testdata/data/lanes/e/ades/.
set -eu
py=$1
src=$2
repo=$3
here=$(cd "$(dirname "$0")" && pwd)
out=$repo/crates/hanko-testdata/data/lanes/e/ades
mkdir -p "$out"
cd "$src/pkgs/pyhanko"
for mod in test_ades_validation test_ades_validation_report test_ades_validation_requests; do
  HANKO_RECORD_OUT=$out/$mod.json \
  PYTHONPATH=$here:$src/pkgs/pyhanko/src:$src/internal/common-test-utils/src${HANKO_EXTRA_PYTHONPATH:+:$HANKO_EXTRA_PYTHONPATH} \
  PYTHONDONTWRITEBYTECODE=1 \
    "$py" -m pytest -q -p record_plugin -p no:cacheprovider -o log_cli=false \
      "tests/$mod.py" || true
done
