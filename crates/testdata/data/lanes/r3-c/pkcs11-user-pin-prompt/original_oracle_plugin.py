"""Observe ONE unchanged signing original with all FIVE real fixture-label rows.

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

_TARGET = "test_cli_addsig_pkcs11_with_setup_and_pin_prompt"
_LABELS = {"rsa", "ecdsa", "ed25519", "ed448", "mldsa"}
_ORIGINAL = Path("/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli/tests/test_cli_signing_pkcs11.py")
_STATE = {"kind": "five unchanged original Ed25519 injected USER-PIN prompt signing bodies and real fixtures", "calls": [], "provider_calls": [], "fixtures": [], "fixture_finalizers": [], "reports": [], "bodies": [], "validation_statuses": [], "native_C_Sign_call_count": None}
_PATCH = pytest.MonkeyPatch()
_PHASE = "session"
_NODE = None
_PIN_NAMES = ("PYHANKO_PKCS11_PIN", "PYHANKO_PKCS11_SIGNING_PIN")
_INITIAL_PIN_ENVIRONMENT = {name: name in os.environ for name in _PIN_NAMES}


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


class _ObservedKey:
    """Delegate to the actual resident signing key without exporting its VALUE."""
    def __init__(self, actual):
        self._actual = actual

    def sign(self, data, *args, **kwargs):
        _record("private_key.sign", input_length=len(data), input_sha256=_sha(data),
                mechanism=str(kwargs.get("mechanism")), signing_pin_supplied="pin" in kwargs)
        result = self._actual.sign(data, *args, **kwargs)
        _record("private_key.sign.return", length=len(result), sha256=_sha(result))
        return result

    def __getitem__(self, attribute):
        from pkcs11 import Attribute
        assert attribute != Attribute.VALUE, "No private-key export is assigned"
        return self._actual[attribute]

    def __getattr__(self, name):
        return getattr(self._actual, name)


class _ObservedSlot:
    def __init__(self, actual):
        self._actual = actual

    def get_mechanisms(self, *args, **kwargs):
        result = self._actual.get_mechanisms(*args, **kwargs)
        _record("slot.get_mechanisms", actual_ids=sorted(int(x) for x in result))
        return result

    def __getattr__(self, name):
        return getattr(self._actual, name)


class _ObservedToken:
    def __init__(self, actual):
        self._actual = actual

    @property
    def slot(self):
        return _ObservedSlot(self._actual.slot)

    def __getattr__(self, name):
        return getattr(self._actual, name)


class _ObservedSession:
    """Forward real session lifetime/searches; wrap only actual signing handles."""
    def __init__(self, actual):
        self._actual = actual

    @property
    def token(self):
        return _ObservedToken(self._actual.token)

    def __enter__(self):
        self._actual.__enter__()
        _record("session.__enter__")
        return self

    def __exit__(self, *args):
        try:
            return self._actual.__exit__(*args)
        finally:
            _record("session.__exit__")

    def close(self):
        try:
            return self._actual.close()
        finally:
            _record("session.close")

    def get_objects(self, *args, **kwargs):
        from pkcs11 import Attribute, ObjectClass
        template = args[0] if args else kwargs.get("attrs", {})
        _record("session.get_objects", label=(template or {}).get(Attribute.LABEL),
                object_class=str((template or {}).get(Attribute.CLASS)),
                template={str(k): str(v) for k, v in (template or {}).items()})
        for actual in self._actual.get_objects(*args, **kwargs):
            _record("session.get_objects.yield", actual_class=str(actual[Attribute.CLASS]),
                    actual_label=actual[Attribute.LABEL])
            yield _ObservedKey(actual) if (template or {}).get(Attribute.CLASS) == ObjectClass.PRIVATE_KEY else actual

    def __getattr__(self, name):
        if name in {"generate_key", "generate_keypair", "create_object"}:
            raise AssertionError(f"No key generation/object mutation inside original run: {name}")
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
    return {"interpreter": _file(Path(sys.executable)), "python_version": sys.version, "hostname": platform.node(), "assertions_enabled": __debug__, "pid": os.getpid(), "parent_pid": os.getppid(), "production_PIN_environment_presence": {name: name in os.environ for name in _PIN_NAMES}, "flags": {n: getattr(sys.flags, n) for n in ["optimize", "isolated", "no_user_site", "safe_path", "dont_write_bytecode"]}, "argv": sys.argv, "packages": {n: importlib.metadata.version(n) for n in ["pyhanko", "pyhanko-certvalidator", "python-pkcs11", "pytest", "pytest-asyncio", "click", "cryptography", "PyYAML"]}, "modules": loaded, "loaded_dso_files": dso, "overlay": str(overlay), "overlay_RECORD": _file(overlay / "python_pkcs11-0.9.5.dist-info/RECORD"), "environment": {n: os.environ.get(n) for n in ["PYTHONPATH", "PKCS11_CONFIG", "PKCS11_TEST_MODULE", "PKCS11_PLATFORMS", "SOFTHSM2_CONF"]}, "configuration": _file(Path(os.environ["SOFTHSM2_CONF"]))}


def pytest_sessionstart(session):
    assert __debug__ and sys.flags.optimize == 0
    assert not any(_INITIAL_PIN_ENVIRONMENT.values())
    assert not any(name in os.environ for name in _PIN_NAMES)
    _STATE["process"] = {"pid": os.getpid(), "parent_pid": os.getppid(), "PIN_environment_at_plugin_import": _INITIAL_PIN_ENVIRONMENT}
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
        _record("open_pkcs11_session", module=str(args[0]), keyword_names=sorted(kwargs), authenticated=kwargs.get("user_pin") is not None, user_pin_sha256=_sha(kwargs["user_pin"].encode()) if isinstance(kwargs.get("user_pin"), str) else None)
        result = original_open(*args, **kwargs)
        _record("open_pkcs11_session.return", actual_type=f"{type(result).__module__}.{type(result).__qualname__}")
        return _ObservedSession(result)

    _PATCH.setattr(p11, "lib", observed_lib)
    _PATCH.setattr(hp11, "p11_lib", observed_lib)
    _PATCH.setattr(hp11, "open_pkcs11_session", observed_open)
    cfg = importlib.import_module("pyhanko.config.pkcs11")
    actual_load_files = cfg.load_certs_from_pemder
    def observed_load_files(paths):
        names = tuple(paths)
        _record("file_certificate_load", inputs=[_file(Path(name)) if Path(name).exists() else {"path": str(Path(name).resolve()), "exists": False} for name in names])
        for cert in actual_load_files(names):
            _record("file_certificate_load.return", der_sha256=_sha(cert.dump()))
            yield cert
    _PATCH.setattr(cfg, "load_certs_from_pemder", observed_load_files)
    cli_pkcs11 = importlib.import_module("pyhanko.cli.commands.signing.pkcs11_cli")
    actual_prompt = cli_pkcs11.prompt_for_password
    def observed_prompt(*args, **kwargs):
        _record("credential_prompt", prompt=str(kwargs.get("prompt", args[0] if args else "")))
        return actual_prompt(*args, **kwargs)
    _PATCH.setattr(cli_pkcs11, "prompt_for_password", observed_prompt)
    _STATE["original_module_before"] = _file(_ORIGINAL)
    pins = json.loads((Path(__file__).parent / "upstream-source-pins.json").read_text())
    _STATE["source_pins"] = []
    for expected in pins["source_files"]:
        actual = _file(Path(expected["path"]))
        assert actual["sha256"] == expected["sha256"] and actual["length"] == expected["length"]
        _STATE["source_pins"].append(actual)
    provenance = Path("/home/l/.codex/artifacts/sigis/round3/p/raw-dsa-overlay/candidate-refresh")
    _STATE["verified_overlay_provenance_receipts"] = [_file(provenance / name) for name in ["distribution-0.9.5-receipt.json", "binding-0.9.5-receipt.json", "overlay-0.9.5-files.json"]]
    _STATE["unfrozen_session_start_clock"] = datetime.datetime.now(datetime.timezone.utc).isoformat()


def pytest_collection_modifyitems(session, config, items):
    assert len(items) == 5 and {item.originalname for item in items} == {_TARGET}
    collection = []
    required = {"event_loop_policy", "cli_runner", "p11_config", "p11_global_test_config", "declared_algo", "platform", "required_mechanism", "post_validate", "root_cert_data", "pinentry_context"}
    assert {item.callspec.params["root_cert_data"] for item in items} == _LABELS
    for item in items:
        assert Path(item.path).resolve() == _ORIGINAL.resolve()
        assert item.callspec.params["platform"] == "softhsm"
        assert required.issubset(item.fixturenames)
        marks = [{"name": mark.name, "args": [str(x) for x in mark.args], "kwargs": mark.kwargs} for mark in item.iter_markers()]
        assert any(mark["name"] == "hsm" and mark["kwargs"] == {"platform": "softhsm"} for mark in marks)
        assert next(item.iter_markers("algo")).kwargs["algo"] == "ed25519"
        collection.append({"nodeid": item.nodeid, "originalname": item.originalname, "parameters": item.callspec.params, "fixture_names": item.fixturenames, "markers": marks})
    _STATE["collection"] = collection
    conftest = sys.modules[item.module.__package__ + ".conftest"]
    actual_dummy_prompt = conftest.DummyPrompter.prompt_for_password
    def observed_dummy_prompt(prompter, prompt):
        _record("DummyPrompter.prompt_for_password", label=prompt, object_identity=id(prompter))
        result = actual_dummy_prompt(prompter, prompt)
        _record("DummyPrompter.prompt_for_password.return", object_identity=id(prompter),
                result_present=result is not None, result_length=len(result), result_sha256=_sha(result.encode()))
        return result
    _PATCH.setattr(conftest.DummyPrompter, "prompt_for_password", observed_dummy_prompt)
    actual_validate = conftest.validate_pdf_signature
    def observed_validate(*args, **kwargs):
        status = actual_validate(*args, **kwargs)
        _STATE["validation_statuses"].append({"nodeid": _NODE, "phase": _PHASE,
            "intact": status.intact, "valid": status.valid, "trusted": status.trusted,
            "bottom_line": status.bottom_line, "coverage": status.coverage.name,
            "signer_sha256": _sha(status.signing_cert.dump()),
            "path_sha256": None if status.validation_path is None else [_sha(c.dump()) for c in status.validation_path]})
        return status
    _PATCH.setattr(conftest, "validate_pdf_signature", observed_validate)


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
            assert result.algo == "ed25519" and result.token_label == "tested25519"
        if fixturedef.argname == "required_mechanism":
            record["actual_value"] = str(result)
            assert str(result) == "EDDSA" or int(result) == 0x1057
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
        tag = item.nodeid.rsplit("::", 1)[-1].replace("[", "-").replace("]", "")
        before = {name: _snapshot(name, f"{tag}-before") for name in ["input.pdf", "pyhanko.yml", "interm.crt", "output.pdf"]}
        entries = sorted(p.name for p in Path.cwd().iterdir())
        provider_start = len(_STATE["provider_calls"])
        from pyhanko.cli.commands.signing.pkcs11_cli import P11_PIN_ENV_VAR
        import yaml
        expected_pin_hash = _sha(item.funcargs["p11_config"].user_pin.encode())
        assert not any(name in os.environ or name in runner.env for name in _PIN_NAMES)
        context = kwargs["obj"]
        assert context is item.funcargs["pinentry_context"]
        prompter = context.ux.prompter
        assert type(prompter).__name__ == "DummyPrompter"
        assert _sha(prompter.password.encode()) == expected_pin_hash
        configured = yaml.safe_load(Path("pyhanko.yml").read_text())["pkcs11-setups"]["test"]
        assert configured.get("user-pin") is None and configured.get("user_pin") is None
        result = original_invoke(runner, cli, args, *positional, **kwargs)
        after = {name: _snapshot(name, f"{tag}-after") for name in ["input.pdf", "pyhanko.yml", "interm.crt", "output.pdf"]}
        call = {"nodeid": item.nodeid, "arguments": list(args or []), "cwd": str(Path.cwd()), "exit_code": result.exit_code, "stdout": result.stdout, "stderr": result.stderr, "output": result.output, "exception_type": type(result.exception).__name__ if result.exception else None, "before": before, "after": after, "provider_start_index": provider_start, "provider_end_index": len(_STATE["provider_calls"]), "environment_PIN_presence": {name: name in os.environ or name in runner.env for name in _PIN_NAMES}, "injected_prompter_identity": id(prompter), "expected_fixture_user_pin_sha256": expected_pin_hash, "configured_user_pin_absent": True, "directory_entries_before": entries, "directory_entries_after": sorted(p.name for p in Path.cwd().iterdir())}
        _STATE["calls"].append(call)
        assert before["input.pdf"]["sha256"] == after["input.pdf"]["sha256"]
        assert before["pyhanko.yml"]["sha256"] == after["pyhanko.yml"]["sha256"]
        assert before["interm.crt"]["sha256"] == after["interm.crt"]["sha256"]
        assert not before["output.pdf"]["exists"] and after["output.pdf"]["exists"]
        assert result.exit_code == 0 and result.exception is None
        assert set(call["directory_entries_after"]) == set(call["directory_entries_before"]) | {"output.pdf"}
        events = _STATE["provider_calls"][provider_start:]
        assert any(row["entry"] == "private_key.sign" for row in events)
        prompts = [row for row in events if row["entry"] == "credential_prompt"]
        consumed = [row for row in events if row["entry"] == "DummyPrompter.prompt_for_password"]
        returned = [row for row in events if row["entry"] == "DummyPrompter.prompt_for_password.return"]
        assert len(prompts) == len(consumed) == len(returned) == 1
        assert prompts[0]["prompt"] == consumed[0]["label"] == "PKCS#11 user PIN: "
        assert consumed[0]["object_identity"] == id(prompter)
        assert returned[0]["result_sha256"] == expected_pin_hash
        assert item.funcargs["p11_config"].user_pin not in result.output
        assert all(row["user_pin_sha256"] == expected_pin_hash for row in events if row["entry"] == "open_pkcs11_session")
        assert any(row["entry"] == "file_certificate_load.return" for row in events)
        assert any(row["entry"] == "session.get_objects.yield" and row["actual_label"] == "interm" for row in events)
        assert all(not row["signing_pin_supplied"] for row in events if row["entry"] == "private_key.sign")
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
        _PHASE, _NODE = before_phase, before_node


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_teardown(item, nextitem):
    global _PHASE, _NODE
    before_phase, before_node = _PHASE, _NODE
    _PHASE, _NODE = "teardown", item.nodeid
    try:
        yield
    finally:
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
        assert session.testscollected == 5 and len(_STATE["calls"]) == 5 and len(_STATE["bodies"]) == 5
        assert _STATE["original_module_before"] == _STATE["original_module_after"]
        assert "pkcs11._pkcs11" in _STATE["runtime"]["modules"]
        assert any(row["sha256"] == "8453e1bde7dac7a24ed1bab11786fa8641a0ff2b4093c5f027ceaf368a7a438d" for row in _STATE["runtime"]["loaded_dso_files"])
        actual_configs = [row for row in _STATE["fixtures"] if row["name"] == "p11_config"]
        assert len(actual_configs) == 5 and all(row["algo"] == "ed25519" for row in actual_configs)
        assert len({row["returned_config_identity"] for row in actual_configs}) == 1
        assert [row["actual_certificate_DER_parses"] for row in actual_configs] == [2, 0, 0, 0, 0]
        assert all(report["outcome"] == "passed" for report in _STATE["reports"])
        assert len([report for report in _STATE["reports"] if report["when"] == "call"]) == 5
        assert len(_STATE["validation_statuses"]) == 5
        assert all(row["bottom_line"] and row["trusted"] and row["intact"] and row["valid"] for row in _STATE["validation_statuses"])
        assert all(len(row["path_sha256"]) == 3 for row in _STATE["validation_statuses"])
        assert sum(row["entry"] == "private_key.sign" for row in _STATE["provider_calls"]) >= 5
