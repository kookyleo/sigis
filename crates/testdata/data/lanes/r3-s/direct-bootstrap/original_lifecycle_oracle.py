#!/usr/bin/env python3
"""Run four unchanged CV 0.33.0 bootstrap originals and separate identity probes.

This runner makes no network requests. It reports Python runtime ownership and
explicit-close semantics; Rust Arc lifetime and synchronous adaptation are
separate native obligations. No other upstream function earns credit here.
"""

from __future__ import annotations

import argparse
import ast
import asyncio
import contextlib
import hashlib
import importlib.metadata
import importlib.util
import inspect
import io
import json
from pathlib import Path
import sys
import traceback

import pytest
import pyhanko_certvalidator
from pyhanko_certvalidator.context import ValidationContext
from pyhanko_certvalidator.fetchers import OwnedFetcherBackend
from pyhanko_certvalidator.fetchers.aiohttp_fetchers import AIOHttpFetcherBackend


FUNCTIONS = (
    "test_bootstrap_owns_the_default_backend",
    "test_bootstrap_owns_the_default_backend_explicitly",
    "test_bootstrap_leaves_a_supplied_backend_alone",
    "test_bootstrap_leaves_supplied_fetchers_alone",
)
DEFAULT_SOURCE = Path(
    "/tmp/pyhanko-oracle/src/cv-0.33.0/pkgs/pyhanko-certvalidator"
    "/tests/test_fetcher_lifecycle.py"
)


def file_record(path: Path) -> dict:
    resolved = path.resolve()
    data = resolved.read_bytes()
    return {
        "path": str(path),
        "resolved_path": str(resolved),
        "length": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not __debug__:
        raise RuntimeError("The oracle must execute Python assertions.")
    assert importlib.metadata.version("pyhanko-certvalidator") == "0.33.0"
    assert importlib.metadata.version("pyHanko") == "0.38.1"

    source_bytes = args.source.read_bytes()
    source_text = source_bytes.decode("utf-8")
    lines = source_text.splitlines(keepends=True)
    tree = ast.parse(source_text)
    originals = []
    for name in FUNCTIONS:
        function = next(
            node for node in tree.body
            if isinstance(node, ast.AsyncFunctionDef) and node.name == name
        )
        body = "".join(lines[function.lineno - 1:function.end_lineno])
        originals.append({
            "name": name,
            "line": function.lineno,
            "end_line": function.end_lineno,
            "body": body,
            "body_sha256": hashlib.sha256(body.encode()).hexdigest(),
            "decorators": [ast.get_source_segment(source_text, item)
                           for item in function.decorator_list],
            "assertions": [ast.get_source_segment(source_text, item)
                           for item in ast.walk(function)
                           if isinstance(item, ast.Assert)],
        })

    network_events = []
    denied_framework_bind_probes = []

    def deny_network(event, arguments):
        if event == "socket.bind":
            # Some pytest plugin imports probe IPv6 support by binding ::1.
            # Deny and disclose that framework probe: no listener is created.
            denied_framework_bind_probes.append({
                "event": event, "arguments": repr(arguments),
                "stack": traceback.format_stack(),
            })
            raise AssertionError("Socket bind is not part of these originals")
        if event in {"socket.connect", "socket.sendto", "socket.getaddrinfo",
                     "socket.gethostbyname"}:
            network_events.append({"event": event, "arguments": repr(arguments)})
            raise AssertionError("Network activity is not part of these originals")

    sys.addaudithook(deny_network)

    class Reports:
        reports = []

        def pytest_runtest_logreport(self, report):
            self.reports.append({
                "nodeid": report.nodeid,
                "when": report.when,
                "outcome": report.outcome,
                "longrepr": str(report.longrepr) if report.failed else None,
            })

    collector = Reports()
    pytest_output = io.StringIO()
    # The originals use RecordingBackend, not requests_mock. Disable only the
    # unrelated plugin whose urllib3 import performs a loopback capability bind.
    # No provider or required original fixture is excluded.
    pytest_args = ["-q", "--strict-markers", "-p", "no:requests_mock", *[
        str(args.source) + "::" + name for name in FUNCTIONS
    ]]
    with contextlib.redirect_stdout(pytest_output), contextlib.redirect_stderr(pytest_output):
        pytest_exit = int(pytest.main(pytest_args, plugins=[collector]))

    # Import the exact unmodified module only for independent observability
    # probes. The pytest executions above are the four original test bodies.
    spec = importlib.util.spec_from_file_location("cv_backend_originals", args.source)
    assert spec is not None and spec.loader is not None
    original_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(original_module)

    async def probe(mode: str) -> dict:
        bootstrap = original_module.bootstrap_validation_data_handlers
        supplied = None
        backend = None
        factory_events = []
        original_factory = AIOHttpFetcherBackend.get_fetchers

        def observed_factory(owner):
            result = original_factory(owner)
            factory_events.append((owner, result))
            return result

        # Separate probes only. The original pytest bodies above ran unchanged.
        from unittest.mock import patch
        with patch.object(AIOHttpFetcherBackend, "get_fetchers", observed_factory):
            if mode == "implicit-default":
                handlers = bootstrap()
            elif mode == "explicit-default":
                handlers = bootstrap(fetchers=original_module.USE_DEFAULT_FETCHERS)
            else:
                backend = original_module.RecordingBackend()
                if mode == "supplied-set":
                    supplied = backend.get_fetchers()
                    factory_events.clear()  # Count bootstrap retrieval separately.
                    handlers = bootstrap(fetchers=supplied)
                else:
                    handlers = bootstrap(fetchers=backend)
        owner = handlers.owned_fetcher_backend
        is_default = mode in {"implicit-default", "explicit-default"}
        assert (isinstance(owner, AIOHttpFetcherBackend)) if is_default else (owner is None)
        assert len(factory_events) == (0 if mode == "supplied-set" else 1)
        issued = supplied if supplied is not None else factory_events[0][1]
        assert handlers.revinfo_manager._fetchers is issued
        assert handlers.cert_registry.fetcher is issued.cert_fetcher
        assert handlers.revinfo_manager._fetchers.ocsp_fetcher is issued.ocsp_fetcher
        assert handlers.revinfo_manager._fetchers.crl_fetcher is issued.crl_fetcher
        close_events = []
        if owner is not None:
            original_close = owner.close

            async def observed_close():
                close_events.append(id(owner))
                await original_close()

            owner.close = observed_close
        await handlers.aclose()
        first_count = len(close_events) if is_default else backend.closed
        assert first_count == (1 if is_default else 0)
        assert handlers.owned_fetcher_backend is owner
        await handlers.aclose()
        repeated_count = len(close_events) if is_default else backend.closed
        assert repeated_count == (2 if is_default else 0)
        return {
            "mode": mode,
            "owner_is_none": owner is None,
            "owner_is_actual_aiohttp_backend": isinstance(owner, AIOHttpFetcherBackend),
            "owner_identity": id(owner) if owner else None,
            "bootstrap_factory_calls": len(factory_events),
            "issued_set_identity": id(issued),
            "exact_component_identity": True,
            "close_count_after_first": first_count,
            "close_count_after_repeat": repeated_count,
            "owner_retained_after_close": handlers.owned_fetcher_backend is owner,
            "caller_backend_survives": backend is not None,
        }

    probes = [asyncio.run(probe(mode)) for mode in (
        "implicit-default", "explicit-default", "borrowed-backend", "supplied-set"
    )]
    imported_context = Path(inspect.getsourcefile(ValidationContext))
    imported_backend = Path(inspect.getsourcefile(AIOHttpFetcherBackend))
    pinned_package = args.source.parent.parent / "src" / "pyhanko_certvalidator"
    source_matches = []
    for actual, relative in [
        (imported_context, "context.py"),
        (imported_backend, "fetchers/aiohttp_fetchers/__init__.py"),
    ]:
        pinned = pinned_package / relative
        same = actual.read_bytes() == pinned.read_bytes()
        assert same, (str(actual), str(pinned))
        source_matches.append({"imported": file_record(actual),
                               "pinned": file_record(pinned), "byte_equal": same})

    result = {
        "schema": 1,
        "kind": "fresh pinned Python execution; no native result claim",
        "runner": file_record(Path(__file__)),
        "interpreter": file_record(Path(sys.executable)),
        "python_version": sys.version,
        "assertions_enabled": __debug__,
        "versions": {"pyhanko-certvalidator": importlib.metadata.version("pyhanko-certvalidator"),
                     "pyHanko": importlib.metadata.version("pyHanko")},
        "imported_package": file_record(Path(pyhanko_certvalidator.__file__)),
        "pinned_test_module": file_record(args.source),
        "original_functions": originals,
        "pytest_arguments": pytest_args,
        "pytest_exit": pytest_exit,
        "pytest_reports": collector.reports,
        "pytest_output": pytest_output.getvalue(),
        "original_test_executions": len(FUNCTIONS),
        "separate_identity_close_probes": probes,
        "imported_sources_match_pinned": source_matches,
        "network_request_attempts": network_events,
        "denied_framework_bind_probes": denied_framework_bind_probes,
        "provider_exclusions": [],
        "factory_source_audit": {
            "method_source": inspect.getsource(AIOHttpFetcherBackend.get_fetchers),
            "close_source": inspect.getsource(AIOHttpFetcherBackend.close),
            "disposition": "Source-only: each get_fetchers constructs a new FetchBudget and component fetchers over the same session; close handles LazySession only. Not extra original executions or runtime network proof.",
        },
        "new_upstream_credit": 0,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.output), "pytest_exit": pytest_exit,
                      "original_test_executions": len(FUNCTIONS),
                      "identity_close_probes": probes,
                      "network_request_attempts": len(network_events),
                      "denied_framework_bind_probes": len(denied_framework_bind_probes)}, indent=2))
    assert source_bytes == args.source.read_bytes(), "The pinned test source changed"
    assert not network_events
    assert pytest_exit == 0, pytest_output.getvalue()
    call_reports = [report for report in collector.reports if report["when"] == "call"]
    assert len(call_reports) == 4 and all(report["outcome"] == "passed" for report in call_reports)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
