#!/usr/bin/env bash
# Execute exactly the unchanged no-provider original using an isolated overlay.
set -euo pipefail
if (($# != 1)); then
    echo 'Usage: run_original_reference.sh ABSOLUTE_RECORD_DIRECTORY' >&2
    exit 2
fi
case "$1" in /*) ;; *) echo 'The record directory must be absolute.' >&2; exit 2;; esac
plugin_dir=$(cd -- "$(dirname -- "$0")" && pwd)
overlay=/home/l/.codex/artifacts/sigis/round3/p/raw-dsa-overlay/overlay-0.9.5
export SIGIS_PKCS11_ORACLE_RECORD_DIR=$1
export SIGIS_PKCS11_ORACLE_OVERLAY=$overlay
export PYTHONPATH="$overlay:$plugin_dir"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONNOUSERSITE=1
export PYTEST_ADDOPTS=
unset PYTHONHOME PKCS11_CONFIG PKCS11_TEST_MODULE PKCS11_PLATFORMS
cd /tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli
exec /tmp/pyhanko-oracle/venv/bin/python -B -s -P -m pytest -q \
    -p no:cacheprovider -p original_oracle_plugin --setup-show \
    tests/test_cli_signing_pkcs11.py::test_cli_pkcs11_setup_config_unreadable
