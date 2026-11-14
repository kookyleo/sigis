#!/usr/bin/env python3
"""Execute one unchanged default-context original and separate identity probes.

The original is run untouched by pytest. A separate probe instruments factory
and explicit-close calls while still using the real AIOHTTP default backend and
real lazily created sessions, without making network requests. This runner does
not claim native execution, HTTP trust parity or any new accepted function.
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
from unittest.mock import patch

import pytest
import pyhanko_certvalidator
from pyhanko_certvalidator import context
from pyhanko_certvalidator.fetchers.aiohttp_fetchers import AIOHttpFetcherBackend
from pyhanko_certvalidator.revinfo.manager import RevinfoManager
from pyhanko_certvalidator.fetchers.aiohttp_fetchers.util import LazySession

NAME = "test_context_provisions_and_owns_a_backend"
DEFAULT_SOURCE = Path(
    "/tmp/pyhanko-oracle/src/cv-0.33.0/pkgs/pyhanko-certvalidator"
    "/tests/test_fetcher_lifecycle.py"
)


def file_record(path: Path) -> dict:
    resolved = path.resolve()
    data = resolved.read_bytes()
    return {"path": str(path), "resolved_path": str(resolved),
            "length": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not __debug__:
        raise RuntimeError("Python assertions must be enabled")
    versions = {name: importlib.metadata.version(name) for name in
                ("pyHanko", "pyhanko-certvalidator")}
    assert versions == {"pyHanko": "0.38.1", "pyhanko-certvalidator": "0.33.0"}
    source_bytes = args.source.read_bytes()
    source = source_bytes.decode()
    node = next(n for n in ast.parse(source).body
                if isinstance(n, ast.AsyncFunctionDef) and n.name == NAME)
    lines = source.splitlines(keepends=True)
    body = "".join(lines[node.lineno - 1:node.end_lineno])
    original = {
        "name": NAME, "line": node.lineno, "end_line": node.end_lineno,
        "body": body, "body_sha256": hashlib.sha256(body.encode()).hexdigest(),
        "decorators": [ast.get_source_segment(source, n) for n in node.decorator_list],
        "assertions": [ast.get_source_segment(source, n) for n in ast.walk(node)
                       if isinstance(n, ast.Assert)],
    }
    network_events = []
    framework_binds = []

    def deny_network(event, arguments):
        if event == "socket.bind":
            framework_binds.append({"event": event, "arguments": repr(arguments),
                                    "stack": traceback.format_stack()})
            raise AssertionError("No socket listener belongs to this original")
        if event in {"socket.connect", "socket.sendto", "socket.getaddrinfo",
                     "socket.gethostbyname"}:
            network_events.append({"event": event, "arguments": repr(arguments)})
            raise AssertionError("This default-context lifecycle original has no network I/O")

    sys.addaudithook(deny_network)

    class Reports:
        def __init__(self):
            self.rows = []

        def pytest_runtest_logreport(self, report):
            self.rows.append({"nodeid": report.nodeid, "when": report.when,
                              "outcome": report.outcome,
                              "longrepr": str(report.longrepr) if report.failed else None})

    reports = Reports()
    pytest_output = io.StringIO()
    pytest_args = ["-q", "--strict-markers", "-p", "no:requests_mock",
                   str(args.source) + "::" + NAME]
    # requests_mock is unused by this exact original. Its import probes IPv6
    # binding; disabling that plugin is a disclosed framework adaptation, never
    # an original fixture/provider exclusion.
    with contextlib.redirect_stdout(pytest_output), contextlib.redirect_stderr(pytest_output):
        pytest_exit = int(pytest.main(pytest_args, plugins=[reports]))

    async def separate_probe() -> dict:
        factories = []
        closes = []
        default_provisions = []
        actual_factory = AIOHttpFetcherBackend.get_fetchers
        actual_close = AIOHttpFetcherBackend.close
        actual_default = context._default_fetcher_backend

        def observed_factory(owner):
            issued = actual_factory(owner)
            factories.append((owner, issued))
            return issued

        def observed_default():
            backend = actual_default()
            default_provisions.append(backend)
            return backend

        async def observed_close(owner):
            closes.append(owner)
            await actual_close(owner)

        # These observations are separate from the untouched pytest execution.
        with patch.object(AIOHttpFetcherBackend, "get_fetchers", observed_factory), \
             patch.object(AIOHttpFetcherBackend, "close", observed_close), \
             patch.object(context, "_default_fetcher_backend", observed_default):
            vc = context.ValidationContext(trust_roots=[], allow_fetching=True)
            owner = vc._owned_fetcher_backend
            assert isinstance(owner, AIOHttpFetcherBackend)
            assert len(default_provisions) == 1
            assert default_provisions[0] is owner
            assert len(factories) == 1 and factories[0][0] is owner
            issued = factories[0][1]
            manager = vc.revinfo_manager
            registry = vc.certificate_registry
            assert manager._fetchers is issued
            assert manager.fetching_allowed
            assert registry.fetcher is issued.cert_fetcher
            components = (issued.cert_fetcher, issued.crl_fetcher, issued.ocsp_fetcher)
            session = owner.session
            assert isinstance(session, LazySession)
            assert session._session is None
            assert all(component._session is session for component in components)
            assert all(component._budget is components[0]._budget for component in components)
            caches = [component._AIOHttpMixin__results for component in components]

            # Creating actual sessions performs no request. This proves close
            # authority and reuse separately from the original's lazy no-op close.
            first = session.get_session()
            assert not first.closed
            await vc.aclose()
            assert first.closed and session._session is None
            assert len(closes) == 1 and closes[0] is owner
            assert vc._owned_fetcher_backend is owner
            second = session.get_session()
            assert second is not first and not second.closed
            await vc.aclose()
            assert second.closed and session._session is None
            assert closes == [owner, owner]
            assert vc._owned_fetcher_backend is owner
            assert vc.revinfo_manager is manager
            assert vc.certificate_registry is registry
            assert manager._fetchers is issued and registry.fetcher is issued.cert_fetcher
            assert all(component._AIOHttpMixin__results is cache
                       for component, cache in zip(components, caches))
            assert len(default_provisions) == len(factories) == 1
        return {
            "selection": "ValidationContext(empty roots, allow_fetching=True)",
            "owner_is_real_aiohttp_backend": isinstance(owner, AIOHttpFetcherBackend),
            "owner_is_exact_implicit_factory_backend": default_provisions[0] is owner,
            "default_backend_provisions": len(default_provisions),
            "backend_factory_calls": len(factories),
            "backend_close_calls_after_first": 1,
            "backend_close_calls_after_repeat": len(closes),
            "owner_retained_after_both_explicit_closes": vc._owned_fetcher_backend is owner,
            "exact_component_and_manager_registry_identities_retained": True,
            "components_share_real_lazy_session_and_budget": True,
            "component_cache_objects_retained": True,
            "first_real_session_closed": first.closed,
            "second_real_session_is_new_and_closed": second is not first and second.closed,
            "lazy_session_released_after_close": session._session is None,
            "owner_identity": id(owner), "issued_identity": id(issued),
            "manager_identity": id(manager), "registry_identity": id(registry),
            "first_session_identity": id(first), "second_session_identity": id(second),
            "network_requests": 0,
        }

    probe = asyncio.run(separate_probe())
    pinned_package = args.source.parent.parent / "src" / "pyhanko_certvalidator"
    matches = []
    for value, relative in [(context, "context.py"),
                            (RevinfoManager, "revinfo/manager.py"),
                            (AIOHttpFetcherBackend, "fetchers/aiohttp_fetchers/__init__.py"),
                            (LazySession, "fetchers/aiohttp_fetchers/util.py")]:
        imported = Path(inspect.getsourcefile(value))
        pinned = pinned_package / relative
        assert imported.read_bytes() == pinned.read_bytes()
        matches.append({"imported": file_record(imported), "pinned": file_record(pinned),
                        "byte_equal": True})
    result = {
        "schema": 1, "kind": "fresh unchanged pinned original and separate probe",
        "runner": file_record(Path(__file__)),
        "interpreter": file_record(Path(sys.executable)), "python_version": sys.version,
        "assertions_enabled": __debug__, "versions": versions,
        "imported_package": file_record(Path(pyhanko_certvalidator.__file__)),
        "pinned_test_module": file_record(args.source), "original_function": original,
        "pytest_arguments": pytest_args, "pytest_exit": pytest_exit,
        "pytest_reports": reports.rows, "pytest_output": pytest_output.getvalue(),
        "unchanged_original_executions": 1, "separate_default_context_probe": probe,
        "imported_sources_match_pinned": matches,
        "network_request_attempts": network_events,
        "denied_framework_bind_probes": framework_binds,
        "provider_exclusions": [], "original_parameter_exclusions": [],
        "unrelated_pytest_plugin_disabled": "requests_mock (unused; import performs IPv6 bind probe)",
        "boundary": "Only default-context lifecycle original. No source reachability/policy ownership or HTTP trust verdict is claimed.",
        "new_accepted_upstream_credit": 0,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"output": str(args.output), "pytest_exit": pytest_exit,
                      "original_executions": 1, "probe": probe,
                      "network_attempts": len(network_events),
                      "denied_framework_binds": len(framework_binds)}, indent=2))
    assert source_bytes == args.source.read_bytes()
    assert not network_events
    assert pytest_exit == 0, pytest_output.getvalue()
    calls = [row for row in reports.rows if row["when"] == "call"]
    assert len(calls) == 1 and calls[0]["outcome"] == "passed"
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
