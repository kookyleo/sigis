#!/usr/bin/env bash
# New private store; never mutate the already-frozen original-reference store.
set -euo pipefail
if (($# != 1)); then echo 'Usage: run_adverse_reference.sh ABSOLUTE_NEW_RECORD_DIRECTORY' >&2; exit 2; fi
case "$1" in /*) ;; *) echo 'Record directory must be absolute.' >&2; exit 2;; esac
record_root=$1
plugin_dir=$(cd -- "$(dirname -- "$0")" && pwd)
overlay=/home/l/.codex/artifacts/sigis/round3/p/raw-dsa-overlay/overlay-0.9.5
mkdir -p -- "$record_root"
export SIGIS_PKCS11_ORACLE_OVERLAY=$overlay
export PYTHONPATH="/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli/src:$overlay:$plugin_dir"
export PYTHONDONTWRITEBYTECODE=1 PYTHONNOUSERSITE=1
unset PYTHONHOME PKCS11_CONFIG PKCS11_TEST_MODULE PKCS11_PLATFORMS SOFTHSM2_CONF PYHANKO_PKCS11_PIN PYHANKO_PKCS11_SIGNING_PIN
python=/tmp/pyhanko-oracle/venv/bin/python
"$python" -B -s -P "$plugin_dir/provision_signing.py" "$record_root/provider" > "$record_root/provision.stdout" 2> "$record_root/provision.stderr"
export SOFTHSM2_CONF="$record_root/provider/softhsm2.conf"
export PKCS11_TEST_MODULE=${SIGIS_PKCS11_SIGNING_MODULE:-/tmp/sigis-p-softhsm-8453e1bde7da/libsofthsm2.so}
export PKCS11_PLATFORMS=softhsm
exec "$python" -B -s -P "$plugin_dir/adverse_reference.py" "$record_root"
