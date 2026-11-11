#!/bin/sh
# Re-generate the lane A oracle fixtures from the upstream pyHanko tests.
#
# Requires a pyHanko 0.38.1 / pyhanko-certvalidator 0.33.0 oracle venv
# (tools/pyhanko-oracle/setup.sh, or $HANKO_ORACLE pointing at its python)
# and the upstream source tree at $HANKO_SRC (tag v0.38.1).
#
#   HANKO_SRC=/tmp/pyhanko-oracle/src/v0.38.1 crates/hanko-cms/oracle/harvest.sh test_cms
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
py=${HANKO_ORACLE:-/tmp/pyhanko-oracle/venv/bin/python}
src=${HANKO_SRC:-/tmp/pyhanko-oracle/src/v0.38.1}
out_dir="$repo/crates/hanko-testdata/data/lanes/a/harvest"
mkdir -p "$out_dir"
for module in "$@"; do
  tests="$src/pkgs/pyhanko/tests/$module.py"
  [ -f "$tests" ] || tests="$src/pkgs/pyhanko-certvalidator/tests/$module.py"
  (cd "$(dirname "$tests")" && PYTHONDONTWRITEBYTECODE=1 TZ=UTC PYTHONPATH="$here" HARVEST_OUT="$out_dir/$module.json" \
    "$py" -m pytest -q -p harvest_plugin -p no:cacheprovider "$tests") || true
done
