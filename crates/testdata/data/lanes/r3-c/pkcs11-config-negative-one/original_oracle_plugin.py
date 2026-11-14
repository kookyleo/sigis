"""Record one unchanged upstream no-provider CLI original; never supply a token."""

from __future__ import annotations

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


_TARGET = "test_cli_pkcs11_setup_config_unreadable"
_PINNED = Path("/tmp/pyhanko-oracle/src/v0.38.1")
_ORIGINAL = _PINNED / "pkgs/pyhanko-cli/tests/test_cli_signing_pkcs11.py"
_STATE: dict = {"scope": "unchanged original, actual CliRunner, no signing", "calls": [], "provider_calls": [], "fixtures": [], "reports": []}
_GUARDS = pytest.MonkeyPatch()


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


def _snapshot(name: str, prefix: str) -> dict:
    path = Path(name)
    if not path.exists():
        return {"path": str(path.resolve()), "exists": False}
    data = path.read_bytes()
    target = _root() / f"{prefix}-{path.name}"
    target.write_bytes(data)
    return {"path": str(path.resolve()), "exists": True, "length": len(data), "sha256": _sha(data), "archive": str(target)}


def _deny(label: str):
    def forbidden(*args, **kwargs):
        # A hard failure if a regression tries to load/query/open a provider.
        # No replacement provider, token, mechanism or signing result exists.
        _STATE["provider_calls"].append({"entry": label, "argument_count": len(args), "keyword_names": sorted(kwargs)})
        raise AssertionError(f"Unauthorized provider call in no-provider original: {label}")
    return forbidden


def pytest_sessionstart(session):
    root = _root()
    assert __debug__ and sys.flags.optimize == 0, "Reference assertions must remain enabled"
    expected_overlay = Path(os.environ["SIGIS_PKCS11_ORACLE_OVERLAY"]).resolve()
    p11 = importlib.import_module("pkcs11")
    origin = Path(p11.__file__).resolve()
    assert origin.is_relative_to(expected_overlay), (origin, expected_overlay)
    assert importlib.metadata.version("python-pkcs11") == "0.9.5"
    assert importlib.metadata.version("pyhanko") == "0.38.1"
    assert importlib.metadata.version("pyhanko-certvalidator") == "0.33.0"
    _GUARDS.setattr(p11, "lib", _deny("pkcs11.lib"))
    hp11 = importlib.import_module("pyhanko.sign.pkcs11")
    # This module imports lib by alias: guard that path explicitly as well.
    _GUARDS.setattr(hp11, "p11_lib", _deny("pyhanko.sign.pkcs11.p11_lib"))
    _GUARDS.setattr(hp11, "open_pkcs11_session", _deny("pyhanko.sign.pkcs11.open_pkcs11_session"))
    packages = ["pyhanko", "pyhanko-certvalidator", "python-pkcs11", "click", "pytest", "cryptography", "PyYAML"]
    modules = ["pkcs11", "pkcs11.mechanisms", "pyhanko.sign.pkcs11", "pyhanko.cli", "pyhanko.cli.commands.signing.pkcs11_cli", "pyhanko_certvalidator"]
    _STATE["runtime"] = {
        "interpreter": _file(Path(sys.executable)),
        "python_version": sys.version,
        "platform": platform.platform(),
        "hostname": platform.node(),
        "debug": __debug__,
        "flags": {name: getattr(sys.flags, name) for name in ["optimize", "isolated", "no_user_site", "safe_path", "dont_write_bytecode"]},
        "argv": sys.argv,
        "cwd_at_sessionstart": str(Path.cwd()),
        "pythonpath": os.environ.get("PYTHONPATH"),
        "packages": {name: importlib.metadata.version(name) for name in packages},
        "modules": {name: _file(Path(importlib.import_module(name).__file__)) for name in modules},
        "loaded_binding_modules": {
            name: _file(Path(module.__file__))
            for name, module in tuple(sys.modules.items())
            if (name == "pkcs11" or name.startswith("pkcs11."))
            and getattr(module, "__file__", None)
        },
        "overlay": str(expected_overlay),
        "overlay_RECORD": _file(expected_overlay / "python_pkcs11-0.9.5.dist-info/RECORD"),
        "provider_environment": {name: os.environ.get(name) for name in ["PKCS11_CONFIG", "PKCS11_TEST_MODULE", "PKCS11_PLATFORMS"]},
    }
    _STATE["original_module_before"] = _file(_ORIGINAL)
    (root / "runtime.json").write_text(json.dumps(_STATE["runtime"], indent=2) + "\n")


def pytest_collection_modifyitems(session, config, items):
    assert len(items) == 1 and items[0].name == _TARGET, "Execute exactly the unparameterized original"
    item = items[0]
    assert Path(item.path).resolve() == _ORIGINAL.resolve()
    _STATE["collection"] = {"nodeid": item.nodeid, "fixture_names": item.fixturenames, "markers": [m.name for m in item.iter_markers()]}
    forbidden = {"p11_config", "p11_session", "p11_global_test_config", "platform", "post_validate", "root_cert_data", "pinentry_context"}
    assert forbidden.isdisjoint(item.fixturenames), item.fixturenames


@pytest.hookimpl(hookwrapper=True)
def pytest_fixture_setup(fixturedef, request):
    _STATE["fixtures"].append({"name": fixturedef.argname, "scope": fixturedef.scope, "source": inspect.getsourcefile(fixturedef.func), "line": inspect.getsourcelines(fixturedef.func)[1]})
    yield


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item):
    original_invoke = CliRunner.invoke
    original_source = inspect.getsource(item.obj)
    _STATE["original_body_before"] = {"sha256": _sha(original_source.encode()), "source": original_source, "path": str(Path(inspect.getsourcefile(item.obj)).resolve())}

    def recorded_invoke(runner, cli, args=None, *positional, **kwargs):
        before = {name: _snapshot(name, "before") for name in ["input.pdf", "pyhanko.yml", "output.pdf"]}
        result = original_invoke(runner, cli, args, *positional, **kwargs)
        after = {name: _snapshot(name, "after") for name in ["input.pdf", "pyhanko.yml", "output.pdf"]}
        _STATE["calls"].append({
            "arguments": list(args or []), "cwd": str(Path.cwd()),
            "exit_code": result.exit_code, "output": result.output,
            "stdout": result.stdout, "stderr": result.stderr,
            "exception_type": type(result.exception).__name__ if result.exception else None,
            "exception": str(result.exception) if result.exception else None,
            "before": before, "after": after,
        })
        # Supplemental invariants, independent of the unchanged original's two assertions.
        assert before["input.pdf"]["sha256"] == after["input.pdf"]["sha256"]
        assert before["pyhanko.yml"]["sha256"] == after["pyhanko.yml"]["sha256"]
        assert not before["output.pdf"]["exists"] and not after["output.pdf"]["exists"]
        return result

    patch = pytest.MonkeyPatch()
    patch.setattr(CliRunner, "invoke", recorded_invoke)
    try:
        yield
    finally:
        patch.undo()
        _STATE["original_body_after_sha256"] = _sha(inspect.getsource(item.obj).encode())
        _STATE["original_module_after"] = _file(_ORIGINAL)
        (_root() / "record.json").write_text(json.dumps(_STATE, indent=2) + "\n")
    assert len(_STATE["calls"]) == 1, "The original must execute its actual CLI call exactly once"
    assert _STATE["provider_calls"] == [], "Any provider call is outside this no-provider original"
    assert _STATE["original_body_before"]["sha256"] == _STATE["original_body_after_sha256"]
    assert _STATE["original_module_before"] == _STATE["original_module_after"]


def pytest_runtest_logreport(report):
    _STATE["reports"].append({"nodeid": report.nodeid, "when": report.when, "outcome": report.outcome})


def pytest_sessionfinish(session, exitstatus):
    _STATE["session_exitstatus"] = int(exitstatus)
    _STATE["selected_originals"] = session.testscollected
    _STATE["new_upstream_credit"] = 0
    (_root() / "record.json").write_text(json.dumps(_STATE, indent=2) + "\n")
    _GUARDS.undo()
