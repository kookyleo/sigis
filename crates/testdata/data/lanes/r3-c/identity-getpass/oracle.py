"""Run unmodified pinned original bodies, or validate the same native PDF.

Original fixture clock and root/HTTP fixture services are explicit; native
subprocesses do not receive a clock override. No shared venv is changed.
"""
import argparse
import builtins
import contextlib
import hashlib
import importlib
import importlib.metadata
import importlib.util
import io
import json
import os
import sys
import types
from datetime import datetime
from pathlib import Path

if sys.flags.optimize:
    raise RuntimeError("Original reference assertions must remain enabled")
import pyhanko
pyhanko.__path__.append("/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli/src/pyhanko")
import pytest
import tzlocal
from asn1crypto import pem, x509
from click.testing import CliRunner
from freezegun import freeze_time
from certomancer.registry import CertLabel
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext
from pyhanko_testing_commons.test_data.samples import TESTING_CA, TESTING_CA_ECDSA, TESTING_CA_ED25519, TESTING_CA_ED448
from pyhanko_testing_commons.test_utils.live_http import live_pki_services


def snapshot(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return {"path": str(path), "length": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def load_original():
    directory = Path("/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli/tests")
    package = types.ModuleType("_sigis_original_cli_tests")
    package.__path__ = [str(directory)]
    sys.modules[package.__name__] = package
    name = package.__name__ + ".test_cli_signing"
    spec = importlib.util.spec_from_file_location(name, directory / "test_cli_signing.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module, sys.modules[package.__name__ + ".conftest"]


class RecordingRunner(CliRunner):
    def __init__(self):
        super().__init__()
        self.calls = []

    def invoke(self, cli, args, **kwargs):
        result = super().invoke(cli, args, **kwargs)
        self.calls.append({"argv": args, "code": result.exit_code, "output": result.output,
                           "exception": None if result.exception is None else str(result.exception)})
        return result


class RecordingMonkeyPatch:
    def __init__(self):
        self.patch = pytest.MonkeyPatch()
        self.calls = []

    def setattr(self, target, name, value):
        def record(*args, **kwargs):
            self.calls.append({"args": list(args), "kwargs": kwargs,
                               "callback_file": value.__code__.co_filename,
                               "callback_line": value.__code__.co_firstlineno})
            return value(*args, **kwargs)
        self.patch.setattr(target, name, record)


p = argparse.ArgumentParser()
p.add_argument("--mode", choices=["original", "verify", "revinfo"], required=True)
p.add_argument("--kind", choices=["identity", "programmatic", "getpass"], required=True)
p.add_argument("--architecture", choices=["rsa", "ecdsa", "ed25519", "ed448"], required=True)
p.add_argument("--file", default="output.pdf")
p.add_argument("--export-revinfo", type=Path)
a = p.parse_args()
assert importlib.metadata.version("pyhanko") == "0.38.1"
assert importlib.metadata.version("pyhanko-certvalidator") == "0.33.0"
arch = {"rsa": TESTING_CA, "ecdsa": TESTING_CA_ECDSA, "ed25519": TESTING_CA_ED25519, "ed448": TESTING_CA_ED448}[a.architecture]
moment = datetime(2020, 8, 1, tzinfo=tzlocal.get_localzone())
record = {"mode": a.mode, "kind": a.kind, "architecture": a.architecture,
          "moment": moment.isoformat(), "cwd": str(Path.cwd()), "python": snapshot(sys.executable),
          "driver": snapshot(__file__), "optimize": sys.flags.optimize,
          "PYTHONOPTIMIZE": os.environ.get("PYTHONOPTIMIZE"),
          "pyhanko": importlib.metadata.version("pyhanko"),
          "certvalidator": importlib.metadata.version("pyhanko-certvalidator")}
modules = ["pyhanko.cli.commands.signing.plugin", "pyhanko.cli.commands.signing.simple",
           "pyhanko.sign.validation.generic_cms", "pyhanko.sign.validation.pdf_embedded",
           "pyhanko_certvalidator.validate", "pyhanko_testing_commons.test_data.samples",
           "pyhanko_testing_commons.test_utils.live_http", "certomancer.registry.pki_arch"]
record["modules"] = {name: snapshot(importlib.import_module(name).__file__) for name in modules}
captured = io.StringIO()
record["actual_case_file_reads"] = []
@contextlib.contextmanager
def track_case_reads():
    original_builtin, original_io = builtins.open, io.open
    def inspect_read(file, mode):
        if isinstance(file, (str, bytes, os.PathLike)) and ("r" in mode or "+" in mode):
            path = Path(os.fsdecode(file)).resolve()
            if path.is_relative_to(Path.cwd()) and path.is_file():
                with original_io(path, "rb") as stream:
                    data = stream.read()
                record["actual_case_file_reads"].append({"path":str(path),"length":len(data),"sha256":hashlib.sha256(data).hexdigest()})
    def builtin(file, mode="r", *args, **kwargs):
        inspect_read(file, mode)
        return original_builtin(file, mode, *args, **kwargs)
    def iopen(file, mode="r", *args, **kwargs):
        inspect_read(file, mode)
        return original_io(file, mode, *args, **kwargs)
    builtins.open, io.open = builtin, iopen
    try:
        yield
    finally:
        builtins.open, io.open = original_builtin, original_io
with track_case_reads(), freeze_time(moment), live_pki_services() as services, contextlib.redirect_stdout(captured):
    services.register(arch)
    if a.mode == "original":
        module, conftest = load_original()
        record["original_module"] = snapshot(module.__file__)
        record["original_conftest"] = snapshot(conftest.__file__)
        runner = RecordingRunner()
        chain = ("root.cert.pem", "interm.cert.pem", "signer.crt")
        if a.kind == "identity":
            module.test_cli_addsig_pemder_with_identity_setup(runner, chain, "signer.key.pem")
        elif a.kind == "programmatic":
            module.test_cli_addsig_pemder_with_identity_programmatically(runner, chain, "signer.key.pem")
        else:
            patch = RecordingMonkeyPatch()
            try:
                module.test_cli_sign_getpass(runner, patch, "signer.p12", None)
                assert len(patch.calls) == 1
                record["getpass_calls"] = patch.calls
            finally:
                patch.patch.undo()
        # Exact teardown function inherited through user_key and p12_keys;
        # no fixture-body assertion is replaced with a raw-signing shortcut.
        conftest._validate_last_sig_in(arch.get_cert(CertLabel("root")), "output.pdf", strict=True)
        record.update(code=0, exception=None, calls=runner.calls,
                      original_function_completed=True, original_teardown_completed=True)
    else:
        root_data = Path("root.cert.pem").read_bytes()
        root = x509.Certificate.load(pem.unarmor(root_data)[2])
        if a.mode == "verify":
            with Path(a.file).open("rb") as stream:
                reader = PdfFileReader(stream)
                assert not reader.encrypted
                assert len(reader.embedded_regular_signatures) == 1
                status = validate_pdf_signature(reader.embedded_regular_signatures[0],
                    signer_validation_context=ValidationContext(trust_roots=[root], allow_fetching=True))
                assert status.bottom_line, status.pretty_print_details()
                assert status.intact and status.valid and status.trusted
                record.update(bottom_line=status.bottom_line, intact=status.intact,
                              valid=status.valid, trusted=status.trusted)
        a.export_revinfo.mkdir()
        crls = []
        for index, repo in enumerate(arch.service_registry.list_crl_repos()):
            data = arch.service_registry.get_crl(repo.label, at_time=moment).dump()
            path = a.export_revinfo / f"crl-{index}.der"
            path.write_bytes(data)
            crls.append(snapshot(path))
        assert crls
        record["crls"] = crls
        (a.export_revinfo / "metadata.json").write_text(json.dumps(record, indent=2) + "\n")
record["output"] = snapshot(a.file)
record["captured_output"] = captured.getvalue()
print(json.dumps(record))
