"""Observe two unchanged preflights with REAL upstream software-token fixtures.

Every provider result is delegated unchanged to the actual module/session/object.
There is no replacement fixture, fake provider or direct original-body call.
"""
from __future__ import annotations

import datetime
import hashlib
import importlib
import importlib.metadata
import inspect
import json
import os
from pathlib import Path
import platform
import sys

import pytest
from click.testing import CliRunner

_TARGETS = ("test_cli_pkcs11_args_required", "test_cli_pkcs11_setup_requires_config")
_ORIGINAL = Path("/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli/tests/test_cli_signing_pkcs11.py")
_STATE = {"kind": "two unchanged original CLI preflights and real p11_config fixtures", "calls": [], "provider_calls": [], "fixtures": [], "fixture_finalizers": [], "reports": [], "bodies": []}
_PATCH = pytest.MonkeyPatch()
_PHASE = "session"
_NODE = None


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _file(path: Path) -> dict:
    path = path.resolve()
    data = path.read_bytes()
    return {"path": str(path), "length": len(data), "sha256": _sha(data)}


def _root() -> Path:
    root = Path(os.environ["SIGIS_PKCS11_ORACLE_RECORD_DIR"]).resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root


def _record(entry: str, **fields) -> None:
    _STATE["provider_calls"].append({"entry": entry, "phase": _PHASE, "nodeid": _NODE, **fields})


def _snapshot(name: str, tag: str) -> dict:
    path = Path(name)
    if not path.exists():
        return {"path": str(path.resolve()), "exists": False}
    data = path.read_bytes()
    archive = _root() / f"{tag}-{path.name}"
    archive.write_bytes(data)
    return {"path": str(path.resolve()), "exists": True, "length": len(data), "sha256": _sha(data), "archive": str(archive)}


class _ObservedSession:
    """Keep the real session lifetime, iterator and attribute values intact."""
    def __init__(self, actual):
        self._actual = actual

    def __enter__(self):
        self._actual.__enter__()
        _record("session.__enter__")
        return self

    def __exit__(self, *args):
        try:
            return self._actual.__exit__(*args)
        finally:
            _record("session.__exit__")

    def get_objects(self, *args, **kwargs):
        from pkcs11 import Attribute
        template = args[0] if args else kwargs.get("attrs", {})
        _record("session.get_objects", label=(template or {}).get(Attribute.LABEL), template={str(k): str(v) for k, v in (template or {}).items()})
        # Preserve the real lazy iterator/errors and yield each actual object
        # unchanged. The pure-Python DER parser is observed separately below.
        for actual in self._actual.get_objects(*args, **kwargs):
            _record("session.get_objects.yield", actual_type=f"{type(actual).__module__}.{type(actual).__qualname__}")
            yield actual

    def __getattr__(self, name):
        if name in {"sign", "generate_key", "generate_keypair", "create_object"}:
            raise AssertionError(f"Unassigned signing/key/object mutation in reference fixture: {name}")
        return getattr(self._actual, name)


def _runtime() -> dict:
    overlay = Path(os.environ["SIGIS_PKCS11_ORACLE_OVERLAY"]).resolve()
    loaded = {}
    for name, module in tuple(sys.modules.items()):
        if (name == "pkcs11" or name.startswith("pkcs11.") or name in {"pyhanko.sign.pkcs11", "pyhanko.cli", "pyhanko.cli.commands.signing.pkcs11_cli", "pyhanko_certvalidator", "pyhanko_testing_commons.test_utils.pkcs11_utils.fixtures", "pyhanko_testing_commons.test_utils.pkcs11_utils.config"}) and getattr(module, "__file__", None):
            loaded[name] = _file(Path(module.__file__))
    maps = Path("/proc/self/maps").read_text()
    (_root() / "loaded-maps.txt").write_text(maps)
    dso = []
    for name in sorted({line.split(maxsplit=5)[-1] for line in maps.splitlines() if len(line.split(maxsplit=5)) == 6 and line.split(maxsplit=5)[-1].startswith("/")}):
        path = Path(name)
        if path.exists() and ".so" in path.name:
            dso.append(_file(path))
    return {"interpreter": _file(Path(sys.executable)), "python_version": sys.version, "hostname": platform.node(), "assertions_enabled": __debug__, "flags": {n: getattr(sys.flags, n) for n in ["optimize", "isolated", "no_user_site", "safe_path", "dont_write_bytecode"]}, "argv": sys.argv, "packages": {n: importlib.metadata.version(n) for n in ["pyhanko", "pyhanko-certvalidator", "python-pkcs11", "pytest", "pytest-asyncio", "click", "cryptography", "PyYAML"]}, "modules": loaded, "loaded_dso_files": dso, "overlay": str(overlay), "overlay_RECORD": _file(overlay / "python_pkcs11-0.9.5.dist-info/RECORD"), "environment": {n: os.environ.get(n) for n in ["PYTHONPATH", "PKCS11_CONFIG", "PKCS11_TEST_MODULE", "PKCS11_PLATFORMS", "SOFTHSM2_CONF"]}, "configuration": _file(Path(os.environ["SOFTHSM2_CONF"]))}


def pytest_sessionstart(session):
    assert __debug__ and sys.flags.optimize == 0
    assert os.environ.get("PKCS11_CONFIG") is None
    assert os.environ.get("PKCS11_PLATFORMS") == "softhsm"
    p11 = importlib.import_module("pkcs11")
    overlay = Path(os.environ["SIGIS_PKCS11_ORACLE_OVERLAY"]).resolve()
    assert Path(p11.__file__).resolve().is_relative_to(overlay)
    assert importlib.metadata.version("python-pkcs11") == "0.9.5"
    assert importlib.metadata.version("pyhanko") == "0.38.1"
    assert importlib.metadata.version("pyhanko-certvalidator") == "0.33.0"
    hp11 = importlib.import_module("pyhanko.sign.pkcs11")
    original_lib = p11.lib
    original_open = hp11.open_pkcs11_session
    from asn1crypto import x509
    original_der_load = x509.Certificate.load

    def observed_der_load(cls, encoded_data, *args, **kwargs):
        result = original_der_load(encoded_data, *args, **kwargs)
        if _PHASE == "fixture:p11_config":
            _record("Certificate.load", input_length=len(encoded_data), input_sha256=_sha(encoded_data), result_der_sha256=_sha(result.dump()), result_type=f"{type(result).__module__}.{type(result).__qualname__}")
        return result

    _PATCH.setattr(x509.Certificate, "load", classmethod(observed_der_load))

    def observed_lib(*args, **kwargs):
        _record("pkcs11.lib", arguments=[str(x) for x in args], keyword_names=sorted(kwargs))
        result = original_lib(*args, **kwargs)
        _record("pkcs11.lib.return", module=_file(Path(args[0])))
        return result

    def observed_open(*args, **kwargs):
        _record("open_pkcs11_session", module=str(args[0]), keyword_names=sorted(kwargs), authenticated=kwargs.get("user_pin") is not None)
        result = original_open(*args, **kwargs)
        _record("open_pkcs11_session.return", actual_type=f"{type(result).__module__}.{type(result).__qualname__}")
        return _ObservedSession(result)

    _PATCH.setattr(p11, "lib", observed_lib)
    _PATCH.setattr(hp11, "p11_lib", observed_lib)
    _PATCH.setattr(hp11, "open_pkcs11_session", observed_open)
    _STATE["original_module_before"] = _file(_ORIGINAL)
    _STATE["unfrozen_session_start_clock"] = datetime.datetime.now(datetime.timezone.utc).isoformat()


def pytest_collection_modifyitems(session, config, items):
    assert len(items) == 2
    assert {item.originalname for item in items} == set(_TARGETS)
    collection = []
    required = {"event_loop_policy", "cli_runner", "p11_config", "p11_global_test_config", "declared_algo", "platform", "required_mechanism"}
    forbidden = {"any_algo", "post_validate", "root_cert_data", "pinentry_context", "p11_session"}
    for item in items:
        assert Path(item.path).resolve() == _ORIGINAL.resolve()
        assert item.callspec.params == {"platform": "softhsm"}, item.callspec.params
        assert required.issubset(item.fixturenames)
        assert forbidden.isdisjoint(item.fixturenames)
        marks = [{"name": mark.name, "args": [str(x) for x in mark.args], "kwargs": mark.kwargs} for mark in item.iter_markers()]
        assert any(mark["name"] == "hsm" and mark["kwargs"] == {"platform": "softhsm"} for mark in marks)
        collection.append({"nodeid": item.nodeid, "originalname": item.originalname, "parameters": item.callspec.params, "fixture_names": item.fixturenames, "markers": marks})
    _STATE["collection"] = collection


@pytest.hookimpl(hookwrapper=True)
def pytest_fixture_setup(fixturedef, request):
    global _PHASE, _NODE
    before_phase, before_node = _PHASE, _NODE
    _PHASE, _NODE = f"fixture:{fixturedef.argname}", request.node.nodeid
    start = len(_STATE["provider_calls"])
    record = {"name": fixturedef.argname, "scope": fixturedef.scope, "nodeid": request.node.nodeid, "source": inspect.getsourcefile(fixturedef.func), "line": inspect.getsourcelines(fixturedef.func)[1], "provider_start_index": start}
    fixture_source = inspect.getsource(fixturedef.func)
    record["function_source_sha256"] = _sha(fixture_source.encode())
    if record["source"]:
        record["source_file"] = _file(Path(record["source"]))
    _STATE["fixtures"].append(record)
    outcome = yield
    try:
        result = outcome.get_result()
        record["setup_success"] = True
        if fixturedef.argname == "p11_config":
            record["returned_config_identity"] = id(result)
            record["module"] = result.module
            record["token_label"] = result.token_label
            record["algo"] = result.algo
            record["freeze_time_spec"] = result.freeze_time_spec
            record["cert_chain"] = [{"length": len(cert.dump()), "sha256": _sha(cert.dump()), "subject": cert.subject.human_friendly} for cert in result.cert_chain]
            assert len(record["cert_chain"]) == 2
        if fixturedef.argname == "required_mechanism":
            record["actual_value"] = str(result)
            assert result is None
    finally:
        record["provider_end_index"] = len(_STATE["provider_calls"])
        record["actual_certificate_DER_parses"] = sum(x["entry"] == "Certificate.load" for x in _STATE["provider_calls"][start:])
        _PHASE, _NODE = before_phase, before_node


def pytest_fixture_post_finalizer(fixturedef, request):
    _STATE["fixture_finalizers"].append({"name": fixturedef.argname, "scope": fixturedef.scope, "nodeid": request.node.nodeid, "source": inspect.getsourcefile(fixturedef.func), "function_source_sha256": _sha(inspect.getsource(fixturedef.func).encode()), "clock_at_finalizer": datetime.datetime.now(datetime.timezone.utc).isoformat()})


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item):
    global _PHASE, _NODE
    original_invoke = CliRunner.invoke
    original_source = inspect.getsource(item.obj)
    row = {"nodeid": item.nodeid, "source_before": original_source, "source_sha256_before": _sha(original_source.encode()), "provider_start_index": len(_STATE["provider_calls"]), "frozen_fixture_clock": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    _STATE["bodies"].append(row)
    before_phase, before_node = _PHASE, _NODE
    _PHASE, _NODE = "body", item.nodeid

    def recorded_invoke(runner, cli, args=None, *positional, **kwargs):
        tag = item.originalname
        before = {name: _snapshot(name, f"{tag}-before") for name in ["input.pdf", "pyhanko.yml", "output.pdf"]}
        entries = sorted(p.name for p in Path.cwd().iterdir())
        provider_start = len(_STATE["provider_calls"])
        result = original_invoke(runner, cli, args, *positional, **kwargs)
        after = {name: _snapshot(name, f"{tag}-after") for name in ["input.pdf", "pyhanko.yml", "output.pdf"]}
        call = {"nodeid": item.nodeid, "arguments": list(args or []), "cwd": str(Path.cwd()), "exit_code": result.exit_code, "stdout": result.stdout, "stderr": result.stderr, "output": result.output, "exception_type": type(result.exception).__name__ if result.exception else None, "before": before, "after": after, "provider_start_index": provider_start, "provider_end_index": len(_STATE["provider_calls"]), "directory_entries_before": entries, "directory_entries_after": sorted(p.name for p in Path.cwd().iterdir())}
        _STATE["calls"].append(call)
        assert before["input.pdf"]["sha256"] == after["input.pdf"]["sha256"]
        assert not before["pyhanko.yml"]["exists"] and not after["pyhanko.yml"]["exists"]
        assert not before["output.pdf"]["exists"] and not after["output.pdf"]["exists"]
        assert call["directory_entries_before"] == call["directory_entries_after"]
        assert call["provider_start_index"] == call["provider_end_index"], "CLI body must add no provider calls"
        return result

    patch = pytest.MonkeyPatch()
    patch.setattr(CliRunner, "invoke", recorded_invoke)
    try:
        yield
    finally:
        patch.undo()
        row["source_sha256_after"] = _sha(inspect.getsource(item.obj).encode())
        row["provider_end_index"] = len(_STATE["provider_calls"])
        assert row["source_sha256_before"] == row["source_sha256_after"]
        assert row["provider_start_index"] == row["provider_end_index"]
        _PHASE, _NODE = before_phase, before_node


def pytest_runtest_logreport(report):
    _STATE["reports"].append({"nodeid": report.nodeid, "when": report.when, "outcome": report.outcome})


def pytest_sessionfinish(session, exitstatus):
    _STATE["session_exitstatus"] = int(exitstatus)
    _STATE["selected_originals"] = session.testscollected
    _STATE["new_upstream_credit"] = 0
    _STATE["runtime"] = _runtime()
    _STATE["original_module_after"] = _file(_ORIGINAL)
    (_root() / "record.json").write_text(json.dumps(_STATE, indent=2) + "\n")
    _PATCH.undo()
    if exitstatus == 0:
        assert session.testscollected == 2
        assert len(_STATE["calls"]) == 2 and len(_STATE["bodies"]) == 2
        assert _STATE["original_module_before"] == _STATE["original_module_after"]
        assert "pkcs11._pkcs11" in _STATE["runtime"]["modules"], "Full fixture must load the actual native binding"
        assert any(row["sha256"] == "8453e1bde7dac7a24ed1bab11786fa8641a0ff2b4093c5f027ceaf368a7a438d" for row in _STATE["runtime"]["loaded_dso_files"]), "Actual module must be mapped"
        assert sum(row["entry"] == "open_pkcs11_session" for row in _STATE["provider_calls"]) == 2
        assert sum(row["entry"] == "session.__exit__" for row in _STATE["provider_calls"]) == 2
        actual_configs = [row for row in _STATE["fixtures"] if row["name"] == "p11_config"]
        assert len(actual_configs) == 2
        assert actual_configs[0]["returned_config_identity"] == actual_configs[1]["returned_config_identity"], "Original session-scoped default config must be shared"
        assert [row["actual_certificate_DER_parses"] for row in actual_configs] == [2, 0], "Retain actual first retrieval and second cached chain behavior"
        expected = {row["der_sha256"] for row in json.loads((Path(__file__).resolve().parent / "certificates.json").read_text())["certificates"]}
        for row in actual_configs:
            assert {cert["sha256"] for cert in row["cert_chain"]} == expected
        assert all(report["outcome"] == "passed" for report in _STATE["reports"])
        assert len([report for report in _STATE["reports"] if report["when"] == "call"]) == 2
