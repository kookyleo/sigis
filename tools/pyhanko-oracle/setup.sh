#!/bin/sh
# Create the pyHanko oracle used by differential tests and fixture generators.
#
# The venv lives outside the repository (default /tmp/pyhanko-oracle/venv).
# It pins the parity baseline (pyHanko 0.38.1, pyhanko-certvalidator 0.33.0,
# requirements.txt) and checks out the matching source tags, whose
# internal/common-test-utils is installed into the venv.
#
#   HANKO_ORACLE_DIR  venv parent directory (default /tmp/pyhanko-oracle)
#   PYHANKO_SRC       directory with a pyHanko clone, or where to make one
#                     (default $HANKO_ORACLE_DIR/src)
#
# PyPI and GitHub are reachable only intermittently from some networks; the
# script retries.
set -eu
root=${HANKO_ORACLE_DIR:-/tmp/pyhanko-oracle}
src=${PYHANKO_SRC:-$root/src}
here=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$root" "$src"

# Source tags (tests, test data, test utilities).
if [ ! -d "$src/pyHanko" ]; then
  git clone -q --filter=blob:none https://github.com/MatthiasValvekens/pyHanko "$src/pyHanko"
fi
git -C "$src/pyHanko" rev-parse -q --verify "refs/tags/v0.38.1" >/dev/null ||
  git -C "$src/pyHanko" fetch -q origin tag v0.38.1
git -C "$src/pyHanko" rev-parse -q --verify "refs/tags/pyhanko-certvalidator/v0.33.0" >/dev/null ||
  git -C "$src/pyHanko" fetch -q origin tag pyhanko-certvalidator/v0.33.0
[ -d "$src/v0.38.1" ] || git -C "$src/pyHanko" worktree add -q "$src/v0.38.1" v0.38.1
[ -d "$src/cv-0.33.0" ] || git -C "$src/pyHanko" worktree add -q "$src/cv-0.33.0" pyhanko-certvalidator/v0.33.0

# Python packages.
[ -x "$root/venv/bin/python" ] || python3 -m venv "$root/venv"
pip="$root/venv/bin/pip"
n=0
until "$pip" install --retries 30 --timeout 60 -q -r "$here/requirements.txt"; do
  n=$((n + 1)); [ "$n" -ge 6 ] && { echo "failed to install requirements" >&2; exit 1; }
  sleep 5
done
"$pip" install -q --no-deps -e "$src/v0.38.1/internal/common-test-utils"

"$root/venv/bin/python" -c "
import importlib.metadata as m
import pyhanko, pyhanko_certvalidator, certomancer, pyhanko_testing_commons
print('pyHanko', m.version('pyHanko'), 'certvalidator', m.version('pyhanko-certvalidator'), 'certomancer', m.version('certomancer'))"
