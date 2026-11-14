#!/usr/bin/env python3
"""Execute the unchanged policy-owner original and separate alias/error probes.

The original is run untouched by pytest. Separate probes use its actual
RecordingBackend and real policy/context objects, checking shared close authority,
factory suppression and error propagation without making network requests. The
RecordingBackend only increments close counts; no HTTP pool-close proof follows.
This runner does not claim native execution or new accepted function credit.
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

NAME = "test_policy_hands_ownership_to_the_context"
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
    assert not args.output.exists(), "Preserve prior oracle runs"
    assert Path(sys.prefix).resolve() == Path("/tmp/pyhanko-oracle/venv")
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
            raise AssertionError("This policy-owner lifecycle original has no network I/O")

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
        # This import and every observation below are separate from the exact
        # pytest run. The imported source bytes are pinned and recorded.
        spec = importlib.util.spec_from_file_location("policy_owner_probe_source", args.source)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        backend = module.RecordingBackend()
        factory_calls = []
        actual_factory = backend.get_fetchers

        def observed_factory():
            factory_calls.append(backend)
            return actual_factory()

        manager, registry = module._handlers_only()
        handler_poe = module.POEManager()
        handlers = context.ValidationDataHandlers(
            revinfo_manager=manager, poe_manager=handler_poe,
            cert_registry=registry, owned_fetcher_backend=backend,
        )
        policy = context.CertValidationPolicySpec(
            trust_manager=module.SimpleTrustManager.build(trust_roots=[]),
            revinfo_policy=module.CertRevTrustPolicy(
                module.RevocationCheckingPolicy.from_legacy("soft-fail")),
        )
        timing = module.ValidationTimingInfo.now()
        assert manager.poe_manager is not handler_poe
        assert manager.certificate_registry is registry
        assert not manager.fetching_allowed
        assert backend.closed == 0
        with patch.object(backend, "get_fetchers", observed_factory):
            kwargs = policy.build_validation_context_kwargs(timing_info=timing, handlers=handlers)
            wrapped = kwargs["fetcher_backend"]
            assert isinstance(wrapped, module.OwnedFetcherBackend)
            assert wrapped.backend is backend
            assert kwargs["revinfo_manager"] is manager
            assert kwargs["certificate_registry"] is registry
            assert kwargs["poe_manager"] is handler_poe
            assert kwargs["trust_manager"] is policy.trust_manager
            assert kwargs["revinfo_policy"] is policy.revinfo_policy
            assert kwargs["algorithm_usage_policy"] is policy.algorithm_usage_policy
            assert kwargs["signature_validator"] is policy.signature_validator
            assert kwargs["moment"] is timing.validation_time
            assert kwargs["best_signature_time"] is timing.best_signature_time
            assert kwargs["time_tolerance"] is policy.time_tolerance
            assert kwargs["acceptable_ac_targets"] is policy.acceptable_ac_targets
            assert kwargs["allow_fetching"] is False
            vc = context.ValidationContext(trust_roots=[], **kwargs)
            assert vc._owned_fetcher_backend is backend
            assert vc.revinfo_manager is manager
            assert vc.certificate_registry is registry
            assert handlers.owned_fetcher_backend is backend
            assert factory_calls == []
            await vc.aclose()
            after_first = backend.closed
            assert after_first == 1
            await vc.aclose()
            after_repeat = backend.closed
            assert after_repeat == 2
            await handlers.aclose()
            after_handler = backend.closed
            assert after_handler == 3
            assert vc._owned_fetcher_backend is backend
            assert handlers.owned_fetcher_backend is backend
            assert factory_calls == []

        # The sibling ORIGINAL is not executed. This is a separate zero-ID
        # policy-kwargs absence probe; it does not normalize native None rules.
        absent = policy.build_validation_context_kwargs(timing_info=timing, handlers=None)
        assert "fetcher_backend" not in absent
        assert absent["allow_fetching"] is False
        absent_ctx = context.ValidationContext(trust_roots=[], **absent)
        assert absent_ctx._owned_fetcher_backend is None
        await absent_ctx.aclose()
        assert backend.closed == after_handler

        class MarkerError(RuntimeError):
            pass

        marker = MarkerError("policy-owned close failure remains the same exception")

        class FailingBackend(module.RecordingBackend):
            def get_fetchers(self):
                raise AssertionError("No backend factory is reachable in the original manager fixture")

            async def close(self):
                self.closed += 1
                raise marker

        failing = FailingBackend()
        error_handlers = context.ValidationDataHandlers(
            revinfo_manager=manager, poe_manager=handler_poe,
            cert_registry=registry, owned_fetcher_backend=failing,
        )
        error_kwargs = policy.build_validation_context_kwargs(timing_info=timing, handlers=error_handlers)
        error_ctx = context.ValidationContext(trust_roots=[], **error_kwargs)
        exceptions = []
        for closer in (error_ctx.aclose, error_ctx.aclose, error_handlers.aclose):
            try:
                await closer()
            except MarkerError as caught:
                assert caught is marker
                exceptions.append({"class": type(caught).__name__, "message": str(caught),
                                   "same_exception_object": caught is marker,
                                   "close_count": failing.closed})
            else:
                raise AssertionError("Explicit close failure must propagate")
        assert failing.closed == 3
        assert error_ctx._owned_fetcher_backend is failing
        assert error_handlers.owned_fetcher_backend is failing

        # Python refuses naive clocks before unwrapping backend ownership.
        # No mutation or auto-close occurs in the producer or failed consumer.
        naive = dict(error_kwargs)
        naive["moment"] = timing.validation_time.replace(tzinfo=None)
        before_invalid = failing.closed
        try:
            context.ValidationContext(trust_roots=[], **naive)
        except ValueError as error:
            invalid = {"class": type(error).__name__, "message": str(error)}
        else:
            raise AssertionError("Naive validation clock must refuse construction")
        assert failing.closed == before_invalid
        assert error_handlers.owned_fetcher_backend is failing

        return {
            "kind": "separate policy-owner supplemental probes; not unchanged original executions",
            "factory_calls_with_supplied_managers": len(factory_calls),
            "owned_wrapper_exact_backend_identity": wrapped.backend is backend,
            "context_exact_owner_identity": vc._owned_fetcher_backend is backend,
            "handler_alias_retains_exact_backend": handlers.owned_fetcher_backend is backend,
            "close_count_initial": 0, "close_count_after_context": after_first,
            "close_count_after_repeated_context_close": after_repeat,
            "close_count_after_old_handler_alias_close": after_handler,
            "same_C_R_and_distinct_handler_P_identities_retained": True,
            "old_handlers_not_mutated_or_consumed": True,
            "real_delegate_pool_closed_by_RecordingBackend": False,
            "no_handlers_probe": {"backend_key_present": False, "owned_backend": None,
                                  "sibling_original_executed": False},
            "close_errors": exceptions, "same_exception_propagated_each_time": True,
            "invalid_clock_constructor_refusal": invalid,
            "no_close_on_constructor_failure": failing.closed == before_invalid,
            "owner_identity": id(backend), "manager_identity": id(manager),
            "registry_identity": id(registry), "handler_poe_identity": id(handler_poe),
            "R_internal_poe_identity": id(manager.poe_manager), "network_requests": 0,
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
        "unchanged_original_executions": 1, "separate_policy_owner_probe": probe,
        "imported_sources_match_pinned": matches,
        "network_request_attempts": network_events,
        "denied_framework_bind_probes": framework_binds,
        "provider_exclusions": [], "original_parameter_exclusions": [],
        "unrelated_pytest_plugin_disabled": "requests_mock (unused; import performs IPv6 bind probe)",
        "boundary": "Only one policy-owner lifecycle original is executed. Alias/error/None probes add zero IDs. Generic manager identity is Python evidence; no native graph/HTTP trust parity is claimed.",
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
