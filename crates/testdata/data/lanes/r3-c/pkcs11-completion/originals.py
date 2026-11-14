"""Run unchanged PKCS11 originals against a new private software token store.

No bodies or fixtures are patched. The real upstream fixture chooses algorithms
and applies its existing hardware/mechanism availability skips. Text pytest
output distinguishes actual bodies from exclusions; no provenance pipeline is
created.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys


FUNCTIONS = [
    "test_cli_addsig_pkcs11_pull_interm",
    "test_cli_addsig_pkcs11_read_interm_from_file",
    "test_cli_addsig_raw_ecdsa",
    "test_cli_addsig_pkcs11_with_setup_pull_certs",
    "test_cli_addsig_pkcs11_with_setup_read_certs_from_file",
    "test_cli_addsig_pkcs11_with_setup_raw_ecdsa",
    "test_cli_addsig_pkcs11_with_setup_and_pin_prompt",
]


def main():
    if len(sys.argv) < 2:
        raise SystemExit("Usage: originals.py ABSOLUTE_NEW_DIRECTORY [EXACT_FUNCTION ...]")
    root = Path(sys.argv[1])
    assert root.is_absolute() and not root.exists()
    names = sys.argv[2:] or FUNCTIONS
    assert set(names).issubset(FUNCTIONS)
    python = os.environ.get("HANKO_ORACLE", "/tmp/pyhanko-oracle/venv/bin/python")
    overlay = os.environ.get("SIGIS_PKCS11_ORACLE_OVERLAY", "/home/l/.codex/artifacts/sigis/round3/p/raw-dsa-overlay/overlay-0.9.5")
    env = os.environ.copy()
    for key in ["PKCS11_CONFIG", "SOFTHSM2_CONF", "PYHANKO_PKCS11_PIN", "PYHANKO_PKCS11_SIGNING_PIN", "PYTHONHOME", "PYTHONOPTIMIZE"]:
        env.pop(key, None)
    env.update(PYTHONPATH=overlay, PYTHONDONTWRITEBYTECODE="1", PYTHONNOUSERSITE="1", PYTEST_ADDOPTS="")
    subprocess.run([python, "-B", "-s", "-P", str(Path(__file__).with_name("prepare.py")), str(root)], env=env, check=True)
    env.update(SOFTHSM2_CONF=str(root / "provider/softhsm2.conf"), PKCS11_PLATFORMS="softhsm",
               PKCS11_TEST_MODULE=env.get("SIGIS_PKCS11_SIGNING_MODULE", "/tmp/sigis-p-softhsm-8453e1bde7da/libsofthsm2.so"))
    cwd = "/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli"
    # A fresh process for each exact original retains its own real fixture
    # scope and cache semantics. The separate completed provisioner authenticates
    # no body process. All five root-cert labels are collected by pytest.
    for name in names:
        print(f"\n=== Unchanged original: {name} ===", flush=True)
        result = subprocess.run([python, "-B", "-s", "-P", "-m", "pytest", "-q", "-ra", "-p", "no:cacheprovider",
                                 f"tests/test_cli_signing_pkcs11.py::{name}"], cwd=cwd, env=env)
        if result.returncode:
            raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
