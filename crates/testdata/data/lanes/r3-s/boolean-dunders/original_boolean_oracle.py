#!/usr/bin/env python3
"""Run the unchanged pinned original and separately observe real PDF inputs.

Use the pinned interpreter with -B. This is fresh reference execution only;
it does not execute, predict or certify the Rust test or its lowercase profile.
"""
from __future__ import annotations

import sys

# Establish suppression before importing any product, test or pytest module.
if not sys.dont_write_bytecode or not __debug__ or sys.flags.optimize != 0:
    raise RuntimeError("Run with -B and assertions enabled (no -O)")

import argparse
import ast
import datetime
import hashlib
import importlib.metadata
import inspect
import json
import marshal
import os
from pathlib import Path
import platform
import socket
import traceback

NAME = "test_bool_dunders"
EXPECTED_BODY = "3cb06319a4783870a8c847e68a62bf11d65d30f12d2fdd7eeefc684f87accb2c"
SOURCE = Path(
    "/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko/tests/test_internal_utils.py"
)
PINNED_GENERIC = SOURCE.parent.parent / "src/pyhanko/pdf_utils/generic.py"
OPEN_EVENTS = []
EXEC_EVENTS = []
NETWORK_EVENTS = []
IN_AUDIT = False


def record(path):
    path = Path(path)
    data = path.read_bytes()
    return {"path": str(path), "resolved_path": str(path.resolve()),
            "length": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def audit(event, args):
    global IN_AUDIT
    if IN_AUDIT:
        return
    IN_AUDIT = True
    try:
        if event == "open" and isinstance(args[0], (str, bytes)):
            path = Path(os.fsdecode(args[0])).absolute()
            row = {"path": str(path), "mode": args[1], "flags": args[2]}
            if path.is_file():
                row["existing_bytes_at_open"] = record(path)
            OPEN_EVENTS.append(row)
        elif event == "exec":
            code = args[0]
            EXEC_EVENTS.append({
                "filename": code.co_filename, "name": code.co_name,
                "first_line": code.co_firstlineno,
                "marshal_sha256": hashlib.sha256(marshal.dumps(code)).hexdigest(),
            })
        elif event.startswith("socket."):
            NETWORK_EVENTS.append({"event": event, "arguments": repr(args)})
    finally:
        IN_AUDIT = False


def observe(generic, true_value, false_value, empty_value):
    # These are separate actual observations, not a replacement original body.
    rows = [true_value != false_value, true_value != empty_value,
            false_value != empty_value, bool(true_value), not bool(false_value),
            true_value == bool(true_value), false_value == bool(false_value),
            repr(true_value) == str(true_value) == "True",
            repr(false_value) == str(false_value) == "False"]
    assert len(rows) == 9 and all(rows)
    return {
        "statement_results": {f"B{i + 1}": bool(value)
                              for i, value in enumerate(rows)},
        "true": {"type": type(true_value).__qualname__,
                 "bool": bool(true_value), "repr": repr(true_value),
                 "str": str(true_value)},
        "false": {"type": type(false_value).__qualname__,
                  "bool": bool(false_value), "repr": repr(false_value),
                  "str": str(false_value)},
        "empty_type": type(empty_value).__qualname__,
        "boolean_classes_are_real_product_classes":
            type(true_value) is type(false_value) is generic.BooleanObject,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    start = datetime.datetime.now(datetime.timezone.utc).isoformat()
    sys.addaudithook(audit)
    try:
        source_bytes = SOURCE.read_bytes()
        source = source_bytes.decode()
        node = next(n for n in ast.parse(source).body
                    if isinstance(n, ast.FunctionDef) and n.name == NAME)
        body = "".join(source.splitlines(keepends=True)[node.lineno - 1:node.end_lineno])
        assert hashlib.sha256(body.encode()).hexdigest() == EXPECTED_BODY
        assert node.args.args == [] and node.decorator_list == []
        statements = [n for n in node.body if isinstance(n, ast.Assert)]
        assert len(statements) == 9
        assert [len(n.test.ops) for n in statements[-2:]] == [2, 2]
        assert (Path(__file__).parent / "original_test_bool_dunders.py").read_bytes() == body.encode()

        import pytest

        class Reports:
            def __init__(self):
                self.items = []
                self.results = []

            def pytest_collection_modifyitems(self, items):
                for item in items:
                    actual_body = inspect.getsource(item.obj)
                    assert actual_body == body
                    self.items.append({
                        "nodeid": item.nodeid, "fixture_names": item.fixturenames,
                        "function_source": record(Path(inspect.getsourcefile(item.obj))),
                        "function_source_sha256": hashlib.sha256(actual_body.encode()).hexdigest(),
                        "executed_function_code_sha256": hashlib.sha256(
                            marshal.dumps(item.obj.__code__)).hexdigest(),
                        "code_filename": item.obj.__code__.co_filename,
                        "code_first_line": item.obj.__code__.co_firstlineno,
                    })

            def pytest_runtest_logreport(self, report):
                self.results.append({"nodeid": report.nodeid, "when": report.when,
                                     "outcome": report.outcome,
                                     "longrepr": str(report.longrepr) if report.failed else None})

        reports = Reports()
        pytest_args = ["-q", "--strict-markers", "-p", "no:cacheprovider",
                       str(SOURCE) + "::" + NAME]
        pytest_exit = int(pytest.main(pytest_args, plugins=[reports]))
        assert pytest_exit == 0
        assert len(reports.items) == 1
        assert [(r["when"], r["outcome"]) for r in reports.results] == [
            ("setup", "passed"), ("call", "passed"), ("teardown", "passed")]

        from io import BytesIO
        import pyhanko_certvalidator
        from pyhanko import version
        from pyhanko.pdf_utils import generic

        assert Path(inspect.getsourcefile(generic)).read_bytes() == PINNED_GENERIC.read_bytes()
        versions = {name: importlib.metadata.version(name) for name in
                    ("pyHanko", "pyhanko-certvalidator")}
        assert versions == {"pyHanko": "0.38.1", "pyhanko-certvalidator": "0.33.0"}
        constructed = observe(generic, generic.BooleanObject(True),
                              generic.BooleanObject(False), "")
        inputs = []
        values = []
        for name in ("true.pdfobj", "false.pdfobj", "empty-string.pdfobj"):
            path = Path(__file__).parent / name
            raw = path.read_bytes()
            stream = BytesIO(raw)
            values.append(generic.read_object(stream, None))
            assert stream.tell() == len(raw)
            inputs.append({**record(path), "hex": raw.hex(), "consumed": stream.tell()})
        assert isinstance(values[2], generic.TextStringObject) and values[2] == ""
        parsed = observe(generic, *values)
        result = {
            "kind": "fresh unchanged original plus separate constructed/parsed Python probes",
            "started_utc": start,
            "finished_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "host": socket.gethostname(), "platform": platform.platform(),
            "pid": os.getpid(), "cwd": os.getcwd(), "argv": sys.argv,
            "sys_executable": sys.executable,
            "interpreter": record(Path(sys.executable)),
            "proc_self_exe": record(Path("/proc/self/exe")),
            "python_version": sys.version, "implementation": sys.implementation.name,
            "python_flags": repr(sys.flags), "dont_write_bytecode": sys.dont_write_bytecode,
            "assertions_enabled": __debug__, "versions": versions,
            "raw_module_versions": {"pyhanko.version": vars(version).get("__version__"),
                                    "pyhanko_certvalidator": vars(pyhanko_certvalidator).get("__version__")},
            "runner": record(Path(__file__)), "original_source": record(SOURCE),
            "original_body_sha256": EXPECTED_BODY,
            "original_statement_count": len(statements),
            "original_last_two_chain_comparison_counts": [2, 2],
            "generic_imported": record(Path(inspect.getsourcefile(generic))),
            "generic_pinned": record(PINNED_GENERIC),
            "cv_imported": record(Path(pyhanko_certvalidator.__file__)),
            "pytest_arguments": pytest_args, "pytest_exit": pytest_exit,
            "pytest_collection": reports.items, "pytest_results": reports.results,
            "cacheprovider_disabled_only_to_avoid_pytest_cache_writes": True,
            "original_provider_or_parameter_exclusions": [],
            "original_constructed_python_probe": constructed,
            "separate_same_fixture_parsed_python_probe": parsed,
            "actual_opened_profile_inputs": inputs,
            "native_execution": "NOT AUTHORIZED/NOT RUN; no native comparison result",
            "raw_difference_to_approved_native_expectation":
                "Python repr/str remain True/False; native Object Debug/scalar bool Display expected lowercase",
        }
        (args.output / "reference-result.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps({"reference_original_pass": True, "native_run": False,
                          "python_true_repr": constructed["true"]["repr"],
                          "python_false_repr": constructed["false"]["repr"]}))
        return 0
    except BaseException:
        (args.output / "failure.json").write_text(json.dumps({
            "traceback": traceback.format_exc(), "started_utc": start,
            "finished_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }, indent=2) + "\n")
        raise
    finally:
        (args.output / "actual-open-events.json").write_text(json.dumps(OPEN_EVENTS, indent=2) + "\n")
        (args.output / "actual-exec-events.json").write_text(json.dumps(EXEC_EVENTS, indent=2) + "\n")
        (args.output / "actual-socket-events.json").write_text(json.dumps(NETWORK_EVENTS, indent=2) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
