"""Observe ONE selected unchanged original item in ONE fresh pytest process.

Reuse the frozen transparent provider/body/fixture observers without changing
upstream code. Collection cardinality and fresh-cache checks below are observer
supplements, not assertions added to the upstream original. The historical
five-item shared-process observer remains unchanged and separately recorded.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import sys

import original_oracle_plugin as observed

# These functions delegate real fixture/body/teardown behavior unchanged. They
# retain the original observer's hookwrapper metadata and its shared state.
pytest_fixture_setup = observed.pytest_fixture_setup
pytest_fixture_post_finalizer = observed.pytest_fixture_post_finalizer
pytest_runtest_call = observed.pytest_runtest_call
pytest_runtest_teardown = observed.pytest_runtest_teardown
pytest_runtest_logreport = observed.pytest_runtest_logreport


def pytest_sessionstart(session):
    selected = os.environ["SIGIS_PKCS11_ORACLE_SINGLE_LABEL"]
    assert selected in observed._LABELS
    module = Path(os.environ["PKCS11_TEST_MODULE"]).resolve()
    initial_maps = Path("/proc/self/maps").read_text()
    assert str(module) not in initial_maps, "Fresh original process must not inherit a provider session"
    (observed._root() / "initial-maps.txt").write_text(initial_maps)
    observed.pytest_sessionstart(session)
    observed._STATE["kind"] = "one unchanged original item with full real fixtures in a fresh pytest/provider process"
    observed._STATE["fresh_process_observation"] = {
        "selected_label": selected,
        "expected_nodeid": f"tests/test_cli_signing_pkcs11.py::{observed._TARGET}[softhsm-{selected}]",
        "initial_provider_mapped": False,
        "initial_maps": observed._file(observed._root() / "initial-maps.txt"),
        "observer_source": observed._file(Path(__file__)),
        "shared_observer_source": observed._file(Path(observed.__file__)),
        "expectation_scope": "Supplemental isolation/identity checks, not upstream body assertions",
    }


def pytest_collection_modifyitems(session, config, items):
    selected = os.environ["SIGIS_PKCS11_ORACLE_SINGLE_LABEL"]
    assert len(items) == 1, "Each subprocess must collect its one actual original item"
    item = items[0]
    assert item.originalname == observed._TARGET
    assert Path(item.path).resolve() == observed._ORIGINAL.resolve()
    assert item.nodeid == observed._STATE["fresh_process_observation"]["expected_nodeid"]
    assert item.callspec.params == {"platform": "softhsm", "root_cert_data": selected}
    required = {
        "event_loop_policy", "cli_runner", "p11_config", "p11_global_test_config",
        "declared_algo", "platform", "required_mechanism", "post_validate",
        "root_cert_data", "pinentry_context",
    }
    assert required.issubset(item.fixturenames)
    marks = [{"name": mark.name, "args": [str(x) for x in mark.args], "kwargs": mark.kwargs} for mark in item.iter_markers()]
    assert any(mark["name"] == "hsm" and mark["kwargs"] == {"platform": "softhsm"} for mark in marks)
    assert next(item.iter_markers("algo")).kwargs["algo"] == "ed25519"
    observed._STATE["collection"] = [{
        "nodeid": item.nodeid, "originalname": item.originalname,
        "parameters": item.callspec.params, "fixture_names": item.fixturenames,
        "markers": marks,
    }]

    # Identical transparent DummyPrompter/teardown observations to the frozen
    # shared-process observer. Never substitute a fixture or call a body here.
    conftest = sys.modules[item.module.__package__ + ".conftest"]
    actual_dummy_prompt = conftest.DummyPrompter.prompt_for_password

    def observed_dummy_prompt(prompter, prompt):
        observed._record("DummyPrompter.prompt_for_password", label=prompt, object_identity=id(prompter))
        result = actual_dummy_prompt(prompter, prompt)
        observed._record("DummyPrompter.prompt_for_password.return", object_identity=id(prompter),
                         result_present=result is not None, result_length=len(result),
                         result_sha256=observed._sha(result.encode()))
        return result

    observed._PATCH.setattr(conftest.DummyPrompter, "prompt_for_password", observed_dummy_prompt)
    actual_validate = conftest.validate_pdf_signature

    def observed_validate(*args, **kwargs):
        status = actual_validate(*args, **kwargs)
        observed._STATE["validation_statuses"].append({
            "nodeid": observed._NODE, "phase": observed._PHASE,
            "intact": status.intact, "valid": status.valid, "trusted": status.trusted,
            "bottom_line": status.bottom_line, "coverage": status.coverage.name,
            "signer_sha256": observed._sha(status.signing_cert.dump()),
            "path_sha256": None if status.validation_path is None else [observed._sha(c.dump()) for c in status.validation_path],
        })
        return status

    observed._PATCH.setattr(conftest, "validate_pdf_signature", observed_validate)


def pytest_sessionfinish(session, exitstatus):
    state = observed._STATE
    state["session_exitstatus"] = int(exitstatus)
    state["selected_original_items"] = session.testscollected
    state["immutable_original_functions"] = 1
    state["new_upstream_credit"] = 0
    state["runtime"] = observed._runtime()
    state["original_module_after"] = observed._file(observed._ORIGINAL)
    state["observer_postconditions_passed"] = False
    try:
        if exitstatus == 0:
            assert session.testscollected == len(state["calls"]) == len(state["bodies"]) == 1
            assert state["original_module_before"] == state["original_module_after"]
            assert "pkcs11._pkcs11" in state["runtime"]["modules"]
            assert any(row["sha256"] == "8453e1bde7dac7a24ed1bab11786fa8641a0ff2b4093c5f027ceaf368a7a438d" for row in state["runtime"]["loaded_dso_files"])
            configs = [row for row in state["fixtures"] if row["name"] == "p11_config"]
            assert len(configs) == 1 and configs[0]["algo"] == "ed25519"
            parses = [row["actual_certificate_DER_parses"] for row in configs]
            state["fresh_process_observation"]["actual_p11_config_DER_parse_counts"] = parses
            state["fresh_process_observation"]["cache_expectation_is_upstream_assertion"] = False
            assert parses == [2], "One genuinely fresh fixture config must read/parse both chain certificates"
            assert all(report["outcome"] == "passed" for report in state["reports"])
            assert {report["when"] for report in state["reports"]} == {"setup", "call", "teardown"}
            assert len(state["validation_statuses"]) == 1
            status = state["validation_statuses"][0]
            assert all(status[key] for key in ["bottom_line", "trusted", "intact", "valid"])
            assert status["coverage"] == "ENTIRE_FILE" and len(status["path_sha256"]) == 3
            assert sum(row["entry"] == "private_key.sign" for row in state["provider_calls"]) >= 1
            state["observer_postconditions_passed"] = True
    finally:
        (observed._root() / "record.json").write_text(json.dumps(state, indent=2) + "\n")
        observed._PATCH.undo()
