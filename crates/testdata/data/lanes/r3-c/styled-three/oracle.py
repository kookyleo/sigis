"""Fresh exact named-style originals and signed-PDF vector/QR evidence (MIT).

Originals use actual pinned fixture functions, not a full pytest collection.
Same-native-output trust validation uses the separate accepted appearance driver.
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
import re
import shutil
import sys
import types
from datetime import datetime, timezone, timedelta
from pathlib import Path

assert sys.flags.optimize == 0 and os.environ.get("PYTHONOPTIMIZE") == "0"
import pyhanko
pyhanko.__path__.append("/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli/src/pyhanko")
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.generic import read_object
from pyhanko.pdf_utils.writer import init_xobject_dictionary
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext
from asn1crypto import crl, pem, x509
from pyhanko.sign.fields import enumerate_sig_fields
from pyhanko.stamp.art import STAMP_ART_CONTENT
import qrcode
from qrcode.constants import ERROR_CORRECT_M

SOURCE = Path("/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli/tests")
KINDS = {
    "text": "test_cli_sign_visible_with_style",
    "qr": "test_cli_sign_visible_with_qr_style",
    "missing-url": "test_cli_sign_visible_with_qr_style_omit_stamp_url",
}
SOURCE_SHA = "363e41f063048edd4b922db1d51a3b3713cd017f2ca7b437ff6e671f0ca45877"
CONFT_SHA = "6a67cf73ca8f81394e9fd3fa0fec18ad9a0896e70d0f6c90621787062e1612e6"

def snapshot(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return {"path": str(path), "length": len(data), "sha256": hashlib.sha256(data).hexdigest()}

parser = argparse.ArgumentParser()
parser.add_argument("mode", choices=["original", "inspect"])
parser.add_argument("kind", choices=KINDS)
parser.add_argument("architecture", choices=["rsa", "ecdsa", "ed25519", "ed448"])
parser.add_argument("--native-fixtures", type=Path, required=True)
parser.add_argument("--file", type=Path)
args = parser.parse_args()
assert args.kind != "missing-url" or args.architecture == "ed25519"
record = {"mode": args.mode, "kind": args.kind, "architecture": args.architecture,
          "optimize": sys.flags.optimize, "python": snapshot(sys.executable),
          "driver": snapshot(__file__), "started_now_utc": datetime.now(timezone.utc).isoformat(),
          "versions": {n: importlib.metadata.version(n) for n in ["pyhanko", "pyhanko-certvalidator", "qrcode"]},
          "actual_case_reads": [], "calls": []}
assert record["versions"]["pyhanko"] == "0.38.1"
assert record["versions"]["pyhanko-certvalidator"] == "0.33.0"
record["pinned_sources"] = {n: snapshot(SOURCE / n) for n in ["test_cli_signing.py", "conftest.py"]}
assert record["pinned_sources"]["test_cli_signing.py"]["sha256"] == SOURCE_SHA
assert record["pinned_sources"]["conftest.py"]["sha256"] == CONFT_SHA
for name in ["pyhanko.cli.commands.signing", "pyhanko.cli.commands.signing.simple", "pyhanko.cli.commands.signing.utils", "pyhanko.cli.commands.stamp", "pyhanko.pdf_utils.writer", "pyhanko.stamp.art", "qrcode.main", "pyhanko_certvalidator.validate"]:
    record.setdefault("modules", {})[name] = snapshot(importlib.import_module(name).__file__)

@contextlib.contextmanager
def track_reads():
    old_builtin, old_io = builtins.open, io.open
    def note(path, mode):
        if isinstance(path, (str, os.PathLike)) and ("r" in mode or "+" in mode):
            path = Path(path).resolve()
            if path.is_file() and (path.is_relative_to(Path.cwd()) or path.is_relative_to(args.native_fixtures.resolve())):
                with old_io(path, "rb") as f:
                    data = f.read()
                record["actual_case_reads"].append({"path": str(path), "length": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    def builtin(path, mode="r", *a, **kw):
        note(path, mode)
        return old_builtin(path, mode, *a, **kw)
    def iopen(path, mode="r", *a, **kw):
        note(path, mode)
        return old_io(path, mode, *a, **kw)
    builtins.open, io.open = builtin, iopen
    try:
        yield
    finally:
        builtins.open, io.open = old_builtin, old_io

def load_original():
    package = types.ModuleType("_sigis_styled_originals")
    package.__path__ = [str(SOURCE)]
    sys.modules[package.__name__] = package
    spec = importlib.util.spec_from_file_location(package.__name__ + ".test_cli_signing", SOURCE / "test_cli_signing.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    conftest = sys.modules[package.__name__ + ".conftest"]
    record["original_module"] = snapshot(module.__file__)
    record["original_conftest"] = snapshot(conftest.__file__)
    text = (SOURCE / "test_cli_signing.py").read_text()
    lines = text.splitlines(keepends=True)
    record["bodies"] = []
    for node in ast.parse(text).body:
        if isinstance(node, ast.FunctionDef) and node.name in KINDS.values():
            body = "".join(lines[node.lineno - 1:node.end_lineno]).encode()
            record["bodies"].append({"name": node.name, "line": node.lineno, "sha256": hashlib.sha256(body).hexdigest()})
    return module, conftest

def original():
    module, conf = load_original()
    archive = Path.cwd() / "original-artifacts"
    archive.mkdir()
    cwd_fixture = conf.cli_runner.__wrapped__()
    runner = next(cwd_fixture)
    pki_fixture = conf.pki_arch.__wrapped__(args.architecture, True)
    arch = next(pki_fixture)
    teardown = None
    try:
        record["original_isolated_cwd"] = str(Path.cwd())
        record["clock"] = {"FREEZE_DT": conf.FREEZE_DT.isoformat(), "unix": conf.FREEZE_DT.timestamp(),
                           "observed_fixture_now": datetime.now(timezone.utc).isoformat()}
        assert snapshot("input.pdf")["sha256"] == snapshot(args.native_fixtures / "input.pdf")["sha256"]
        root_data = conf.root_cert_data.__wrapped__(arch)
        root_file = conf.root_cert.__wrapped__(arch)
        chain = conf.cert_chain.__wrapped__(arch, root_file)
        teardown = conf.post_validate.__wrapped__(root_data)
        post = next(teardown)
        key = module.user_key.__wrapped__(arch, post)
        before_inputs = ["input.pdf", *chain, key]
        record["original_fixture_inputs"] = [snapshot(p) for p in before_inputs]
        for name in before_inputs:
            shutil.copyfile(name, archive / Path(name).name)
        invoke = runner.invoke
        def trace(cli, argv, **kw):
            inputs = [snapshot(p) for p in [*before_inputs, "pyhanko.yml"] if Path(p).is_file()]
            result = invoke(cli, argv, **kw)
            record["calls"].append({"argv": argv, "inputs": inputs, "exit_code": result.exit_code,
                                     "exception": None if result.exception is None else repr(result.exception), "output": result.output})
            return result
        runner.invoke = trace
        body = getattr(module, KINDS[args.kind])
        if args.kind == "missing-url":
            body(runner, chain, key, post, args.architecture)
        else:
            body(runner, chain, key, post)
        record["original_body_completed"] = True
        assert len(record["calls"]) == 1
        assert Path("output.pdf").is_file() == (args.kind != "missing-url")
        record["original_output_existed"] = Path("output.pdf").exists()
        try:
            next(teardown)
        except StopIteration:
            record["full_post_validate_teardown_completed"] = True
        teardown = None
        for name in ["pyhanko.yml", "output.pdf"]:
            if Path(name).exists():
                shutil.copyfile(name, archive / name)
        record["original_artifacts"] = [snapshot(p) for p in sorted(archive.iterdir())]
    finally:
        if teardown is not None:
            teardown.close()
        pki_fixture.close()
        cwd_fixture.close()

def appearance():
    assert args.file and args.file.is_file() and args.kind != "missing-url"
    record["same_native_output"] = snapshot(args.file)
    with args.file.open("rb") as stream:
        reader = PdfFileReader(stream)
        sigs = reader.embedded_regular_signatures
        assert len(sigs) == 1 and sigs[-1].field_name == "Sig1"
        root_path = args.native_fixtures / "root.cert.pem"
        record["actual_root"] = snapshot(root_path)
        root = x509.Certificate.load(pem.unarmor(root_path.read_bytes())[2])
        meta_path = args.native_fixtures / "revinfo" / "metadata.json"
        meta = json.loads(meta_path.read_text())
        evidence = []
        for row in meta["crls"]:
            assert snapshot(row["path"])["sha256"] == row["sha256"]
            evidence.append(crl.CertificateList.load(Path(row["path"]).read_bytes()))
        settings = dict(moment=datetime.fromisoformat(meta["moment"]), crls=evidence,
                        time_tolerance=timedelta(seconds=1), revocation_mode="soft-fail", allow_fetching=False)
        positive = validate_pdf_signature(sigs[0], signer_validation_context=ValidationContext(trust_roots=[root], **settings))
        assert positive.intact and positive.valid and positive.trusted and positive.bottom_line
        assert positive.coverage.name == "ENTIRE_FILE" and positive.seed_value_ok and positive.docmdp_ok is not False
        denied = validate_pdf_signature(sigs[0], signer_validation_context=ValidationContext(trust_roots=[], **settings))
        assert not denied.trusted and not denied.bottom_line
        record["same_evidence_full_pdf_status"] = {
            "moment": meta["moment"], "crls": meta["crls"], "allow_fetching": False,
            "root_positive": {"intact": positive.intact,"valid": positive.valid,"trusted": positive.trusted,"bottom_line": positive.bottom_line,
                              "coverage": positive.coverage.name,"docmdp_ok": positive.docmdp_ok,"seed_value_ok":positive.seed_value_ok},
            "empty_roots": {"intact": denied.intact,"valid": denied.valid,"trusted": denied.trusted,"bottom_line": denied.bottom_line}}
        field_ref = list(enumerate_sig_fields(reader, with_name="Sig1"))[0][2]
        field = field_ref.get_object()
        normal = field["/AP"]["/N"]
        data = normal.data
        tokens = b" ".join(data.split())
        background = b" ".join(STAMP_ART_CONTENT.data.split())
        assert background in tokens, "Configured __stamp__ operators missing"
        record["normal_appearance"] = {"length": len(data), "sha256": hashlib.sha256(data).hexdigest(), "background_operator_sha256": hashlib.sha256(background).hexdigest(), "builtin_background_present": True}
        # Require actual text painting and Form resources, not merely a nonempty AP.
        assert b"BT" in tokens and (b"Tj" in tokens or b"TJ" in tokens)
        record["normal_appearance"]["text_paint_operators_present"] = True
        resources = normal["/Resources"]
        forms = resources.get("/XObject", {})
        if args.kind == "qr":
            qr_form = forms["/QR"]
            qr_data = qr_form.data
            points = {(int(row), int(col)) for col, row in re.findall(rb"(?m)^(\d+) (\d+) 1 1 re$", qr_data)}
            expected = qrcode.QRCode(error_correction=ERROR_CORRECT_M)
            expected.add_data("https://example.com")
            expected.make(fit=True)
            wanted = {(r, c) for r, row in enumerate(expected.modules) for c, dark in enumerate(row) if dark}
            assert points == wanted, "Actual QR vector modules do not encode requested URL"
            assert len(points) > 100
            # Decode actual PDF text strings; the writer may use octal escapes.
            literals = re.findall(rb"(\((?:\\.|[^()\\])*\))\s*Tj", data)
            painted_text = "".join(str(read_object(io.BytesIO(token), None)) for token in literals)
            assert "https://example.com" in painted_text
            record["painted_text"] = painted_text
            n = len(expected.modules)
            transform = f"10 0 0 -10 40 {40 + n * 10} cm".encode()
            assert transform in qr_data
            expected_box = [float(value) for value in init_xobject_dictionary(b"", (n + 8) * 10, (n + 8) * 10)["/BBox"]]
            actual_box = [float(value) for value in qr_form["/BBox"]]
            assert actual_box == expected_box
            record["qr_bbox"] = {"actual": actual_box, "pinned_writer": expected_box}
            record["qr"] = {"url": "https://example.com", "version": expected.version,
                            "dark_modules": len(points), "matrix_matches_independent_qrcode": True,
                            "stream_sha256": hashlib.sha256(qr_data).hexdigest(), "render_or_scanner_claim": False}
        else:
            assert "/QR" not in forms and b"https://example.com" not in data
            record["no_qr_in_text_style"] = True
    assert snapshot(args.file) == record["same_native_output"]

capture = io.StringIO()
with track_reads(), contextlib.redirect_stdout(capture):
    if args.mode == "original":
        original()
    else:
        appearance()
record["captured_output"] = capture.getvalue()
record["success"] = True
print(json.dumps(record))
