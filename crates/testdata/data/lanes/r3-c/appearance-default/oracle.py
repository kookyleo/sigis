"""Fresh pinned original bodies and validation of the exact native PDF bytes.

The two original function IDs remain separate from supplemental structure and
policy checks. The positive reference alone inherits the fixture clock, live
PKI services and original post_validate generator teardown.
"""
import argparse
import ast
import builtins
import contextlib
import hashlib
import importlib
import importlib.metadata
import importlib.util
import io
import json
import os
import shutil
import sys
import types
from datetime import datetime
from pathlib import Path

if sys.flags.optimize or os.environ.get("PYTHONOPTIMIZE") != "0":
    raise RuntimeError("Original assertions require explicit PYTHONOPTIMIZE=0")

import pyhanko
pyhanko.__path__.append("/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli/src/pyhanko")
import tzlocal
from asn1crypto import pem, x509
from certomancer.registry import CertLabel
from freezegun import freeze_time
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.decode_limits import DecodeLimits
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext
from pyhanko_testing_commons.test_data.samples import (
    TESTING_CA, TESTING_CA_ECDSA, TESTING_CA_ED25519, TESTING_CA_ED448,
)
from pyhanko_testing_commons.test_utils.live_http import live_pki_services

SOURCE = Path("/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli/tests")
SOURCE_HASHES = {
    "test_cli_signing.py": "363e41f063048edd4b922db1d51a3b3713cd017f2ca7b437ff6e671f0ca45877",
    "conftest.py": "6a67cf73ca8f81394e9fd3fa0fec18ad9a0896e70d0f6c90621787062e1612e6",
}
BODY_HASHES = {
    "visible": ("test_cli_sign_visible_no_style", "b52050c44f83530786373a9ae08c809579d7dcc51d116cf15e25a67baa73ee4b"),
    "conflict": ("test_cli_new_field_spec_bars_existing_only", "48dbb31cc480e05aa62b1b280adf04dd7268315809c24bbcf4b0ed4fdab49d48"),
}


def snapshot(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return {"path": str(path), "length": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def load_original(record):
    record["original_sources_before_import"] = {}
    for name, expected in SOURCE_HASHES.items():
        row = snapshot(SOURCE / name)
        assert row["sha256"] == expected, row
        record["original_sources_before_import"][name] = row
    text = (SOURCE / "test_cli_signing.py").read_text()
    lines = text.splitlines(keepends=True)
    record["original_bodies"] = {}
    for kind, (name, expected) in BODY_HASHES.items():
        node = next(node for node in ast.parse(text).body if isinstance(node, ast.FunctionDef) and node.name == name)
        body = "".join(lines[node.lineno - 1:node.end_lineno]).encode()
        digest = hashlib.sha256(body).hexdigest()
        assert digest == expected
        record["original_bodies"][kind] = {"name": name, "line": node.lineno, "sha256": digest}
    package = types.ModuleType("_sigis_appearance_original_cli_tests")
    package.__path__ = [str(SOURCE)]
    sys.modules[package.__name__] = package
    name = package.__name__ + ".test_cli_signing"
    spec = importlib.util.spec_from_file_location(name, SOURCE / "test_cli_signing.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module, sys.modules[package.__name__ + ".conftest"]


parser = argparse.ArgumentParser()
parser.add_argument("--mode", choices=["original", "verify", "revinfo"], required=True)
parser.add_argument("--kind", choices=["visible", "conflict", "supplemental"], required=True)
parser.add_argument("--architecture", choices=["rsa", "ecdsa", "ed25519", "ed448"], required=True)
parser.add_argument("--file", type=Path)
parser.add_argument("--native-fixture-directory", type=Path, required=True)
parser.add_argument("--export-revinfo", type=Path)
args = parser.parse_args()
assert importlib.metadata.version("pyhanko") == "0.38.1"
assert importlib.metadata.version("pyhanko-certvalidator") == "0.33.0"
architecture = {"rsa": TESTING_CA, "ecdsa": TESTING_CA_ECDSA, "ed25519": TESTING_CA_ED25519, "ed448": TESTING_CA_ED448}[args.architecture]
moment = datetime(2020, 8, 1, tzinfo=tzlocal.get_localzone())
record = {
    "kind": args.kind, "mode": args.mode, "architecture": args.architecture,
    "moment": moment.isoformat(), "cwd": str(Path.cwd()),
    "python": snapshot(sys.executable), "driver": snapshot(__file__),
    "optimize": sys.flags.optimize, "PYTHONOPTIMIZE": os.environ.get("PYTHONOPTIMIZE"),
    "pyhanko": importlib.metadata.version("pyhanko"),
    "certvalidator": importlib.metadata.version("pyhanko-certvalidator"),
    "evidence_kind": "fresh Python original" if args.mode == "original" else "same-byte native PDF reference validation",
}
modules = [
    "pyhanko.cli.commands.signing", "pyhanko.cli.commands.signing.simple",
    "pyhanko.cli.commands.signing.plugin", "pyhanko.sign.validation.generic_cms",
    "pyhanko.sign.validation.pdf_embedded", "pyhanko_certvalidator.validate",
    "pyhanko_testing_commons.test_data.samples",
    "pyhanko_testing_commons.test_utils.live_http", "certomancer.registry.pki_arch",
]
record["modules"] = {name: snapshot(importlib.import_module(name).__file__) for name in modules}
record["actual_case_file_reads"] = []


@contextlib.contextmanager
def track_case_reads():
    original_builtin, original_io = builtins.open, io.open
    roots = [Path.cwd().resolve(), args.native_fixture_directory.resolve()]

    def inspect_read(file, mode):
        if isinstance(file, (str, bytes, os.PathLike)) and ("r" in mode or "+" in mode):
            path = Path(os.fsdecode(file)).resolve()
            # Include CliRunner's temporary isolated cwd as well.
            if path.is_file() and any(path.is_relative_to(root) for root in roots + [Path.cwd()]):
                with original_io(path, "rb") as stream:
                    data = stream.read()
                record["actual_case_file_reads"].append({"path": str(path), "length": len(data), "sha256": hashlib.sha256(data).hexdigest()})

    def builtin(file, mode="r", *positional, **kwargs):
        inspect_read(file, mode)
        return original_builtin(file, mode, *positional, **kwargs)

    def iopen(file, mode="r", *positional, **kwargs):
        inspect_read(file, mode)
        return original_io(file, mode, *positional, **kwargs)

    builtins.open, io.open = builtin, iopen
    try:
        yield
    finally:
        builtins.open, io.open = original_builtin, original_io


def original():
    module, conftest = load_original(record)
    record["original_module"] = snapshot(module.__file__)
    record["original_conftest"] = snapshot(conftest.__file__)
    destination = Path.cwd() / "output.pdf"
    fixture = conftest.cli_runner.__wrapped__()
    runner = next(fixture)
    invoke = runner.invoke
    calls = []

    def recording_invoke(cli, argv, **kwargs):
        inputs_before_use = [snapshot(value) for value in argv if isinstance(value, str) and Path(value).is_file()]
        result = invoke(cli, argv, **kwargs)
        calls.append({"argv": argv, "inputs_before_use": inputs_before_use, "code": result.exit_code, "output": result.output,
                      "exception": None if result.exception is None else str(result.exception)})
        return result

    runner.invoke = recording_invoke
    try:
        record["original_isolated_cwd"] = str(Path.cwd())
        assert snapshot("input.pdf")["sha256"] == snapshot(args.native_fixture_directory / "input.pdf")["sha256"]
        if args.kind == "visible":
            # Bind exactly the staged native fixture bytes. ECDSA certificates
            # generated anew by Certomancer have nondeterministic signatures;
            # recreating them here would compare different signed artifacts.
            # The original body and full teardown remain unchanged; this is a
            # manual fixture binding, not a claim of a complete pytest run.
            chain = ("root.cert.pem", "interm.cert.pem", "signer.crt")
            user_key = "signer.key.pem"
            record["fixture_binding"] = "manual staged native bytes in original cli_runner isolated filesystem"
            record["staged_fixture_inputs_before_copy"] = [
                snapshot(args.native_fixture_directory / name)
                for name in [*chain, user_key]
            ]
            for name in [*chain, user_key]:
                shutil.copyfile(args.native_fixture_directory / name, name)
            root_bytes = Path(chain[0]).read_bytes()
            root = x509.Certificate.load(pem.unarmor(root_bytes)[2])
            teardown = conftest.post_validate.__wrapped__(root)
            post_validate = next(teardown)
            record["fixture_arguments"] = {"cert_chain": list(chain), "user_key": user_key, "post_validate": post_validate}
            record["fixture_inputs_before_use"] = [snapshot(name) for name in ["input.pdf", *chain, user_key]]
            for name in ["input.pdf", *chain, user_key]:
                assert snapshot(name)["sha256"] == snapshot(args.native_fixture_directory / name)["sha256"], name
            try:
                module.test_cli_sign_visible_no_style(runner, chain, user_key, post_validate)
                record["original_function_completed"] = True
            finally:
                # Invoke the complete, unchanged original teardown, including
                # strict-input detection and its ordinary bottom_line assertion.
                try:
                    next(teardown)
                except StopIteration:
                    record["original_teardown_completed"] = True
            record["original_teardown_applicable"] = True
            with Path("input.pdf").open("rb") as stream:
                PdfFileReader(stream, decode_limits=DecodeLimits.for_trusted_input())
            record["original_input_strict"] = True
            assert Path("output.pdf").is_file()
        else:
            assert args.kind == "conflict" and args.architecture == "rsa"
            # Original body writes direct TESTING_CA PEM cert/key; no chain,
            # parametrised pki_arch or post_validate fixture is introduced.
            module.test_cli_new_field_spec_bars_existing_only(runner)
            for name in ["cert.pem", "signer.key.pem"]:
                assert snapshot(name)["sha256"] == snapshot(args.native_fixture_directory / name)["sha256"]
            record.update(original_function_completed=True, original_teardown_applicable=False)
        record.update(calls=calls, exception=None)
        record["output"] = snapshot("output.pdf") if Path("output.pdf").exists() else None
        if Path("output.pdf").exists():
            shutil.copyfile("output.pdf", destination)
    finally:
        try:
            next(fixture)
        except StopIteration:
            pass


def verify_or_export():
    if args.mode == "verify":
        assert args.file and args.file.is_file()
        record["input_before_use"] = snapshot(args.file)
        root_path = args.native_fixture_directory / "root.cert.pem"
        record["trust_anchor_before_use"] = snapshot(root_path)
        root_der = pem.unarmor(root_path.read_bytes())[2]
        record["trust_anchor_der_sha256"] = hashlib.sha256(root_der).hexdigest()
        root = x509.Certificate.load(root_der)
        with args.file.open("rb") as stream:
            reader = PdfFileReader(stream)
            assert not reader.encrypted
            assert len(reader.embedded_regular_signatures) == 1
            status = validate_pdf_signature(
                reader.embedded_regular_signatures[0],
                signer_validation_context=ValidationContext(
                    trust_roots=[root], allow_fetching=True,
                ),
            )
            assert status.bottom_line, status.pretty_print_details()
            assert status.intact and status.valid and status.trusted
            record.update(bottom_line=status.bottom_line, intact=status.intact, valid=status.valid, trusted=status.trusted)
        record["output"] = snapshot(args.file)
        assert record["input_before_use"] == record["output"]
    assert args.export_revinfo is not None
    args.export_revinfo.mkdir(parents=True)
    crls = []
    for index, repo in enumerate(architecture.service_registry.list_crl_repos()):
        path = args.export_revinfo / f"crl-{index}.der"
        path.write_bytes(architecture.service_registry.get_crl(repo.label, at_time=moment).dump())
        crls.append(snapshot(path))
    assert crls
    record["crls"] = crls
    (args.export_revinfo / "metadata.json").write_text(json.dumps(record, indent=2) + "\n")


captured = io.StringIO()
with track_case_reads(), contextlib.redirect_stdout(captured), contextlib.ExitStack() as stack:
    if args.mode != "original" or args.kind == "visible":
        stack.enter_context(freeze_time(moment))
        services = stack.enter_context(live_pki_services())
        services.register(architecture)
        record["fixture_clock_applied"] = True
    else:
        record["fixture_clock_applied"] = False
    if args.mode == "original":
        original()
    else:
        verify_or_export()
record["captured_output"] = captured.getvalue()
print(json.dumps(record))
