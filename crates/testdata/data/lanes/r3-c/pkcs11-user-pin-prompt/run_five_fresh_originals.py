"""Run five unchanged original items, each in a new pytest process/token store.

The controller imports no provider/upstream module. Provisioning and readback
finish in a separate process before each fresh original process is launched.
Historical single-process evidence is never overwritten or relabelled.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time


LABELS = ["rsa", "ecdsa", "ed25519", "ed448", "mldsa"]
ORIGINAL = "tests/test_cli_signing_pkcs11.py::test_cli_addsig_pkcs11_with_setup_and_pin_prompt"
PIN_NAMES = ["PYHANKO_PKCS11_PIN", "PYHANKO_PKCS11_SIGNING_PIN"]
UPSTREAM = Path("/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli")


def identity(path):
    path = Path(path).resolve()
    raw = path.read_bytes()
    return {"path": str(path), "length": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def save(path, record):
    path.write_text(json.dumps(record, indent=2) + "\n")


def execute(argv, env, cwd, directory, prefix):
    command = {"argv": [str(value) for value in argv], "cwd": str(cwd),
               "host": platform.node(), "controller_pid": os.getpid(),
               "production_PIN_environment_presence": {name: name in env for name in PIN_NAMES},
               "start_unix": time.time()}
    assert not any(command["production_PIN_environment_presence"].values())
    save(directory / f"{prefix}-command.json", command)
    start = time.monotonic()
    with (directory / f"{prefix}.stdout.bin").open("xb") as stdout, (directory / f"{prefix}.stderr.bin").open("xb") as stderr:
        process = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                   stdout=stdout, stderr=stderr)
        process.wait()
    record = {"pid": process.pid, "exit_code": process.returncode,
              "wall_seconds": time.monotonic() - start, "completed_unix": time.time(),
              "stdout": identity(directory / f"{prefix}.stdout.bin"),
              "stderr": identity(directory / f"{prefix}.stderr.bin")}
    save(directory / f"{prefix}-process.json", record)
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("record_directory", type=Path)
    parser.add_argument("--python", type=Path, default=Path("/tmp/pyhanko-oracle/venv/bin/python"))
    parser.add_argument("--overlay", type=Path, default=Path("/home/l/.codex/artifacts/sigis/round3/p/raw-dsa-overlay/overlay-0.9.5"))
    parser.add_argument("--module", type=Path, default=Path("/home/l/.codex/artifacts/sigis/round3/p/cli-user-pin-prompt/runtime/libsofthsm2.so"))
    parser.add_argument("--utility", type=Path, default=Path("/home/l/.codex/artifacts/sigis/round3/p/cli-user-pin-prompt/runtime/softhsm2-util"))
    args = parser.parse_args()
    assert __debug__ and sys.flags.optimize == 0
    root = args.record_directory
    assert root.is_absolute() and not root.exists(), "Each verification needs a new record directory"
    root.mkdir(mode=0o700, parents=True)
    fixture = Path(__file__).resolve().parent
    repo = fixture.parents[5]
    assert (repo / ".git").exists()
    source = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
    shared_source = identity(fixture / "original_oracle_plugin.py")
    original_before = identity(UPSTREAM / "tests/test_cli_signing_pkcs11.py")
    original_body = json.loads((fixture / "upstream-source-pins.json").read_text())["original"]
    env = os.environ.copy()
    cleared = ["PYTHONHOME", "PYTHONOPTIMIZE", "PKCS11_CONFIG", "PKCS11_TEST_MODULE",
               "PKCS11_PLATFORMS", "SOFTHSM2_CONF", *PIN_NAMES]
    for name in cleared:
        env.pop(name, None)
    assert not env.get("LD_PRELOAD") and not env.get("LD_AUDIT")
    env.update(PYTHONPATH=f"{args.overlay}:{fixture}", PYTHONDONTWRITEBYTECODE="1",
               PYTHONNOUSERSITE="1", PYTEST_ADDOPTS="",
               SIGIS_PKCS11_ORACLE_OVERLAY=str(args.overlay),
               SIGIS_PKCS11_SIGNING_MODULE=str(args.module),
               SIGIS_PKCS11_SIGNING_UTILITY=str(args.utility))
    summary = {"kind": "Five fresh original processes/stores, not a native rerun or new original count",
               "source_commit": source, "controller": identity(__file__),
               "controller_runtime": {"pid": os.getpid(), "host": platform.node(), "python": sys.version,
                                      "interpreter": identity(sys.executable), "assertions_enabled": __debug__},
               "fresh_observer": identity(fixture / "fresh_original_oracle_plugin.py"),
               "frozen_shared_observer": shared_source, "original_file_before": original_before,
               "original_source_assertions": original_body["assertions"],
               "isolation_cache_assertions_are_observer_supplements": True,
               "expected_original_items": 5, "unique_original_functions": 1,
               "new_accepted_originals": 0, "native_C_Sign_call_count": None, "runs": []}
    save(root / "summary.json", summary)
    for label in LABELS:
        directory = root / label
        directory.mkdir(mode=0o700)
        (directory / "tmp").mkdir(mode=0o700)
        child_env = dict(env, TMPDIR=str(directory / "tmp"),
                         SIGIS_PKCS11_ORACLE_RECORD_DIR=str(directory),
                         SIGIS_PKCS11_ORACLE_SINGLE_LABEL=label)
        provider = directory / "provider"
        provision = execute([str(args.python), "-B", "-s", "-P", str(fixture / "provision_signing.py"), str(provider)],
                            child_env, UPSTREAM, directory, "provision")
        assert provision["exit_code"] == 0, f"Real {label} provisioning failed; retained logs are mandatory"
        readback = json.loads((provider / "receipt.json").read_text())
        assert readback["pid"] == provision["pid"] and readback["actual_EDDSA_available"]
        assert not any(readback["production_PIN_environment_at_entry"].values())
        body_env = dict(child_env, SOFTHSM2_CONF=str(provider / "softhsm2.conf"),
                        PKCS11_TEST_MODULE=str(args.module), PKCS11_PLATFORMS="softhsm")
        nodeid = f"{ORIGINAL}[softhsm-{label}]"
        result = execute([str(args.python), "-B", "-s", "-P", "-m", "pytest", "-q", "-p", "no:cacheprovider",
                          "-p", "fresh_original_oracle_plugin", "--setup-show", nodeid],
                         body_env, UPSTREAM, directory, "original")
        assert result["exit_code"] == 0, f"Actual original {label} failed; do not overwrite or relabel its logs"
        record = json.loads((directory / "record.json").read_text())
        assert record["process"]["pid"] == result["pid"] != provision["pid"]
        assert record["process"]["parent_pid"] == os.getpid()
        assert record["observer_postconditions_passed"] and record["session_exitstatus"] == 0
        assert record["selected_original_items"] == len(record["calls"]) == len(record["bodies"]) == 1
        assert record["collection"][0]["nodeid"] == nodeid
        assert record["collection"][0]["parameters"] == {"platform": "softhsm", "root_cert_data": label}
        config = [row for row in record["fixtures"] if row["name"] == "p11_config"]
        assert len(config) == 1 and config[0]["algo"] == "ed25519"
        assert record["bodies"][0]["source_sha256_before"] == record["bodies"][0]["source_sha256_after"] == original_body["decorated_sha256"]
        events = Counter(row["entry"] for row in record["provider_calls"])
        assert events["credential_prompt"] == events["DummyPrompter.prompt_for_password"] == events["DummyPrompter.prompt_for_password.return"] == 1
        assert len(record["validation_statuses"]) == 1
        status = record["validation_statuses"][0]
        assert all(status[key] for key in ["intact", "valid", "trusted", "bottom_line"])
        assert len(status["path_sha256"]) == 3 and status["coverage"] == "ENTIRE_FILE"
        assert record["original_module_before"] == record["original_module_after"] == original_before
        assert not any(record["process"]["PIN_environment_at_plugin_import"].values())
        assert not any(record["runtime"]["production_PIN_environment_presence"].values())
        observed_conf = record["runtime"]["configuration"]
        assert observed_conf == readback["configuration"] == identity(provider / "softhsm2.conf")
        summary["runs"].append({"label": label, "effective_algorithm": config[0]["algo"],
            "nodeid": nodeid, "provision_process": provision, "original_process": result,
            "readback": identity(provider / "receipt.json"), "record": identity(directory / "record.json"),
            "configuration": observed_conf, "provider_calls": dict(events),
            "actual_config_DER_parse_counts": [config[0]["actual_certificate_DER_parses"]],
            "returned_config_identity_process_local_only": config[0]["returned_config_identity"],
            "fixture_setup_count": len(record["fixtures"]), "fixture_finalizer_count": len(record["fixture_finalizers"]),
            "reports": record["reports"], "full_teardown_status": status,
            "actual_body_output": record["calls"][0]["after"]["output.pdf"],
            "actual_runtime": record["runtime"], "production_PIN_environment_presence": record["process"]["PIN_environment_at_plugin_import"]})
        save(root / "summary.json", summary)
    assert len({row["original_process"]["pid"] for row in summary["runs"]}) == 5
    assert len({row["provision_process"]["pid"] for row in summary["runs"]}) == 5
    assert len({row["configuration"]["path"] for row in summary["runs"]}) == 5
    assert len({row["configuration"]["sha256"] for row in summary["runs"]}) == 5
    assert identity(fixture / "original_oracle_plugin.py") == shared_source
    assert identity(UPSTREAM / "tests/test_cli_signing_pkcs11.py") == original_before
    summary.update(complete=True, actual_passed_items=5, actual_original_processes=5,
                   actual_provisioning_processes=5, actual_private_stores=5,
                   actual_prompt_consumptions=5, original_file_after=identity(UPSTREAM / "tests/test_cli_signing_pkcs11.py"),
                   config_DER_parse_counts=[row["actual_config_DER_parse_counts"] for row in summary["runs"]])
    save(root / "summary.json", summary)
    print(json.dumps({"summary": identity(root / "summary.json"), "actual_passed_items": 5,
                      "actual_fresh_original_processes": 5, "new_accepted_originals": 0}))


if __name__ == "__main__":
    main()
