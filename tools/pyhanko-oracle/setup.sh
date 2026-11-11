#!/bin/sh
# Create the pyHanko oracle used by differential tests and fixture generators.
#
# The venv lives outside the repository (default /tmp/pyhanko-oracle). It pins
# the parity baseline: pyHanko 0.38.1 and pyhanko-certvalidator 0.33.0, and
# checks out the matching source tags (tests and test data) next to it.
#
# PyPI is reachable only intermittently from some networks; the script retries.
set -eu
root=${HANKO_ORACLE_DIR:-/tmp/pyhanko-oracle}
mkdir -p "$root"
[ -x "$root/venv/bin/python" ] || python3 -m venv "$root/venv"
pip="$root/venv/bin/pip"
req="$(cd "$(dirname "$0")" && pwd)/requirements.txt"
n=0
until "$pip" install --retries 30 --timeout 60 -q -r "$req"; do
  n=$((n + 1)); [ "$n" -ge 6 ] && { echo "failed to install $req" >&2; exit 1; }
  sleep 5
done
src="$root/src"
if [ ! -d "$src/pyHanko" ]; then
  git clone -q --filter=blob:none https://github.com/MatthiasValvekens/pyHanko "$src/pyHanko"
fi
git -C "$src/pyHanko" fetch -q origin tag v0.38.1 tag pyhanko-certvalidator/v0.33.0
[ -d "$src/v0.38.1" ] || git -C "$src/pyHanko" worktree add -q "$src/v0.38.1" v0.38.1
[ -d "$src/cv-0.33.0" ] || git -C "$src/pyHanko" worktree add -q "$src/cv-0.33.0" pyhanko-certvalidator/v0.33.0
"$root/venv/bin/python" -c "import pyhanko, pyhanko_certvalidator; print('pyHanko', pyhanko.__version__, 'certvalidator', pyhanko_certvalidator.__version__)"
