"""Exact pinned visible-negative originals and same-native-input CLI checks (MIT).

Original bodies and fixture functions are imported unchanged. Preparation and
same-input negative checks are supplemental and do not count as original IDs.
Unsigned fixture structure and rejection do not establish signature trust.
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
import traceback
import types
from datetime import datetime, timezone
from pathlib import Path

if sys.flags.optimize or os.environ.get("PYTHONOPTIMIZE") != "0":
    raise RuntimeError("Original assertions require explicit PYTHONOPTIMIZE=0")

import pyhanko
pyhanko.__path__.append("/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli/src/pyhanko")
from click.testing import CliRunner
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.sign import fields

SOURCE = Path("/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli/tests")
SOURCE_HASHES = {
    "test_cli_signing.py": "363e41f063048edd4b922db1d51a3b3713cd017f2ca7b437ff6e671f0ca45877",
    "conftest.py": "6a67cf73ca8f81394e9fd3fa0fec18ad9a0896e70d0f6c90621787062e1612e6",
}
BODIES = {
    "no-config": ("test_cli_sign_visible_with_style_but_no_config", "92afcc6764f1a82092dc80b2eade000595ab55266be8c5d82924eed8a7fedb72"),
    "missing": ("test_cli_underspecified_visible_new_field", "d4ccf2840b8bbcf6307d9030cd007e2cc9fbbb2b8989f9e2f0878a3d0765a740"),
    "unnamed": ("test_cli_underspecified_visible_new_field_no_name", "6824ff7f2d8893acc83a6e0da5db9c93fa236e1254d290c5bdde0aafe735c50d"),
    "invisible": ("test_cli_explicit_style_but_field_invisible", "efc385473510b006219a97c91838f47bf9fb943da3cbb4570478af7182db0d05"),
}
INVISIBLE_DECORATED_SHA = "3d7e440a6a6253bb154c4ad6f9cad94e72891aa682b2d65f4465bdc1dece15c3"
BOXES = {"none": None, "zero-zero": (0, 0, 0, 0), "zero-height": (0, 0, 1, 0), "zero-width": (0, 0, 0, 1)}
DIAGNOSTICS = {
    "no-config": ["requires a configuration file"],
    "missing": ["'Sig1' does not exist in the PDF file", "you did not specify a bounding box"],
    "unnamed": ["did not contain any signature fields", "you did not specify a bounding box"],
    "invisible": ["the field 'Sig1' in the PDF is not a visible one"],
}


def snapshot(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return {"path": str(path), "length": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def optional_snapshot(path):
    return snapshot(path) if Path(path).is_file() else None


parser = argparse.ArgumentParser()
parser.add_argument("--mode", choices=["original", "prepare", "inspect-negative", "verify-last"], required=True)
parser.add_argument("--kind", choices=BODIES, required=True)
parser.add_argument("--arch", choices=["rsa", "ecdsa", "ed25519", "ed448"], required=True)
parser.add_argument("--named", choices=["true", "false"])
parser.add_argument("--box", choices=BOXES)
parser.add_argument("--native-fixtures", type=Path, required=True)
parser.add_argument("--file", type=Path)
parser.add_argument("--root", type=Path)
parser.add_argument("--revinfo", type=Path)
args = parser.parse_args()
args.native_fixtures = args.native_fixtures.resolve()
if args.kind != "no-config" and args.arch != "rsa":
    parser.error("The three fixed TESTING_CA originals have exactly one RSA architecture")
if args.kind == "invisible":
    if args.named is None or args.box is None:
        parser.error("Invisible cases require explicit --named and --box")
elif args.named is not None or args.box is not None:
    parser.error("--named and --box apply only to invisible cases")

record = {
    "mode": args.mode, "kind": args.kind, "architecture": args.arch,
    "field_name_passed": args.named == "true" if args.kind == "invisible" else None,
    "box_key": args.box, "box": BOXES[args.box] if args.box is not None else None,
    "cwd": str(Path.cwd()), "native_fixtures": str(args.native_fixtures),
    "python": snapshot(sys.executable), "driver": snapshot(__file__),
    "optimize": sys.flags.optimize, "PYTHONOPTIMIZE": os.environ.get("PYTHONOPTIMIZE"),
    "started_now_utc": datetime.now(timezone.utc).isoformat(),
    "versions": {name: importlib.metadata.version(name) for name in ["pyhanko", "pyhanko-certvalidator", "click"]},
    "calls": [], "actual_case_reads": [],
}
assert record["versions"]["pyhanko"] == "0.38.1"
assert record["versions"]["pyhanko-certvalidator"] == "0.33.0"
MODULES = [
    "pyhanko.cli", "pyhanko.cli.commands.signing", "pyhanko.cli.commands.signing.simple",
    "pyhanko.cli.commands.signing.plugin", "pyhanko.cli.commands.signing.utils",
    "pyhanko.cli.commands.stamp", "pyhanko.pdf_utils.incremental_writer",
    "pyhanko.pdf_utils.reader", "pyhanko.sign.fields", "pyhanko.sign.validation.pdf_embedded",
    "pyhanko_certvalidator.validate", "pyhanko_testing_commons.test_data.samples",
    "pyhanko_testing_commons.test_utils.live_http", "certomancer.registry.pki_arch",
]
record["modules"] = {name: snapshot(importlib.import_module(name).__file__) for name in MODULES}


@contextlib.contextmanager
def track_reads():
    old_builtin, old_io = builtins.open, io.open
    initial_cwd = Path.cwd().resolve()

    def note(file, mode):
        if isinstance(file, (str, bytes, os.PathLike)) and ("r" in mode or "+" in mode):
            path = Path(os.fsdecode(file)).resolve()
            roots = [initial_cwd, args.native_fixtures, Path.cwd().resolve()]
            if path.is_file() and any(path.is_relative_to(root) for root in roots):
                with old_io(path, "rb") as stream:
                    data = stream.read()
                record["actual_case_reads"].append({"path": str(path), "length": len(data), "sha256": hashlib.sha256(data).hexdigest()})

    def builtin(file, mode="r", *positional, **kwargs):
        note(file, mode)
        return old_builtin(file, mode, *positional, **kwargs)

    def iopen(file, mode="r", *positional, **kwargs):
        note(file, mode)
        return old_io(file, mode, *positional, **kwargs)

    builtins.open, io.open = builtin, iopen
    try:
        yield
    finally:
        builtins.open, io.open = old_builtin, old_io


def load_original():
    record["pinned_sources"] = {}
    for name, expected in SOURCE_HASHES.items():
        row = snapshot(SOURCE / name)
        assert row["sha256"] == expected, row
        record["pinned_sources"][name] = row
    text = (SOURCE / "test_cli_signing.py").read_text()
    lines = text.splitlines(keepends=True)
    tree = ast.parse(text)
    record["original_bodies"] = {}
    for kind, (name, expected) in BODIES.items():
        node = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name)
        body = "".join(lines[node.lineno - 1:node.end_lineno]).encode()
        first_line = min([node.lineno] + [decorator.lineno for decorator in node.decorator_list])
        decorated = "".join(lines[first_line - 1:node.end_lineno]).encode()
        digest = hashlib.sha256(body).hexdigest()
        assert digest == expected
        decorated_digest = hashlib.sha256(decorated).hexdigest()
        assert decorated_digest == (INVISIBLE_DECORATED_SHA if kind == "invisible" else expected)
        record["original_bodies"][kind] = {
            "name": name, "line": node.lineno, "last_line": node.end_lineno,
            "sha256": digest, "decorated_sha256": decorated_digest,
            "ast_sha256": hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest(),
            "literal_assertions": [ast.get_source_segment(text, item) for item in ast.walk(node) if isinstance(item, ast.Assert)],
            "fixture_arguments": [argument.arg for argument in node.args.args],
        }
    package = types.ModuleType("_sigis_visible_negative_originals")
    package.__path__ = [str(SOURCE)]
    sys.modules[package.__name__] = package
    spec = importlib.util.spec_from_file_location(package.__name__ + ".test_cli_signing", SOURCE / "test_cli_signing.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    conf = sys.modules[package.__name__ + ".conftest"]
    record["original_module"] = snapshot(module.__file__)
    record["original_conftest"] = snapshot(conf.__file__)
    return module, conf


def fixture_names():
    if args.kind == "no-config":
        return ["input.pdf", "root.cert.pem", "interm.cert.pem", "signer.crt", "signer.key.pem"]
    return ["input.pdf", "pyhanko.yml", "cert.pem", "signer.key.pem"]


def native_argv():
    if args.kind == "no-config":
        return ["sign", "addsig", "--style-name", "test", "--field", "1/0,0,100,100/Sig1", "pemder", "--no-pass", "--cert", "signer.crt", "--chain", "interm.cert.pem", "--key", "signer.key.pem", "input.pdf", "output.pdf"]
    field = ["--field", "Sig1"] if args.kind == "missing" or (args.kind == "invisible" and args.named == "true") else []
    return ["sign", "addsig", *field, "--style-name", "test", "pemder", "--no-pass", "--cert", "cert.pem", "--key", "signer.key.pem", "input.pdf", "output.pdf"]


@contextlib.contextmanager
def original_fixture_session(module, conf):
    cwd_fixture = conf.cli_runner.__wrapped__()
    runner = next(cwd_fixture)
    pki_fixture = teardown = None
    chain = key = None
    record["original_teardown_applicable"] = args.kind == "no-config"
    try:
        record["original_isolated_cwd"] = str(Path.cwd())
        record["initial_minimal_input"] = snapshot("input.pdf")
        if args.kind == "no-config":
            pki_fixture = conf.pki_arch.__wrapped__(args.arch, True)
            arch = next(pki_fixture)
            record["clock"] = {"FREEZE_DT": conf.FREEZE_DT.isoformat(), "unix": conf.FREEZE_DT.timestamp(), "observed_fixture_now": datetime.now(timezone.utc).isoformat()}
            record["fixture_clock_applied"] = True
            root_data = conf.root_cert_data.__wrapped__(arch)
            root_file = conf.root_cert.__wrapped__(arch)
            chain = conf.cert_chain.__wrapped__(arch, root_file)
            teardown = conf.post_validate.__wrapped__(root_data)
            post = next(teardown)
            key = module.user_key.__wrapped__(arch, post)
        else:
            record["fixture_clock_applied"] = False
        yield runner, chain, key
    finally:
        try:
            if teardown is not None:
                try:
                    next(teardown)
                except StopIteration:
                    record["full_post_validate_teardown_completed"] = True
                else:
                    raise AssertionError("Unexpected second post_validate yield")
                finally:
                    teardown.close()
        finally:
            if pki_fixture is not None:
                pki_fixture.close()
            cwd_fixture.close()


def trace_runner(runner):
    invoke = runner.invoke

    def traced(cli, argv, **kwargs):
        before = optional_snapshot("input.pdf")
        output_before = optional_snapshot("output.pdf")
        inputs = [snapshot(name) for name in fixture_names() if Path(name).is_file()]
        result = invoke(cli, argv, **kwargs)
        record["calls"].append({
            "argv": list(argv), "inputs": inputs, "exit_code": result.exit_code,
            "exception": None if result.exception is None else repr(result.exception), "output": result.output,
            "input_before": before, "input_after": optional_snapshot("input.pdf"),
            "output_before": output_before, "output_after": optional_snapshot("output.pdf"),
            "config": optional_snapshot("pyhanko.yml"),
        })
        return result

    runner.invoke = traced


def check_negative_call():
    assert len(record["calls"]) == 1
    call = record["calls"][0]
    assert call["argv"] == native_argv()
    assert call["exit_code"] == 1, call
    for text in DIAGNOSTICS[args.kind]:
        assert text in call["output"], call
    # Supplemental side effects, separate from unchanged upstream assertions.
    assert call["input_before"] == call["input_after"]
    assert call["output_before"] is None and call["output_after"] is None
    record["supplemental_input_unchanged"] = True
    record["supplemental_output_absent"] = True


def original(module, conf):
    archive = Path.cwd() / "original-artifacts"
    archive.mkdir()
    with original_fixture_session(module, conf) as (runner, chain, key):
        trace_runner(runner)
        body = getattr(module, BODIES[args.kind][0])
        if args.kind == "no-config":
            body(runner, chain, key)
        elif args.kind == "invisible":
            body(runner, args.named == "true", BOXES[args.box])
        else:
            body(runner)
        record["original_body_completed"] = True
        record["original_output_existed"] = Path("output.pdf").exists()
        check_negative_call()
        for name in fixture_names():
            shutil.copyfile(name, archive / name)
        record["original_artifacts"] = [snapshot(path) for path in sorted(archive.iterdir())]


def prepare(module, conf):
    args.native_fixtures.mkdir(parents=True, exist_ok=True)
    assert not list(args.native_fixtures.iterdir()), "Preparation requires an empty native fixtures directory"
    with original_fixture_session(module, conf):
        if args.kind != "no-config":
            module._write_config({"stamp-styles": {"test": {"type": "text", "background": "__stamp__"}}})
            if args.kind == "invisible":
                # Match the original's pre-CLI mutation, including incremental
                # write_in_place, rather than using a newly serialized PDF.
                with open("input.pdf", "rb+") as stream:
                    writer = IncrementalPdfFileWriter(stream)
                    fields.append_signature_field(writer, sig_field_spec=fields.SigFieldSpec("Sig1", box=BOXES[args.box]))
                    writer.write_in_place()
                record["native_widget_preparation"] = "IncrementalPdfFileWriter + append_signature_field + write_in_place"
            module._write_cert(module.TESTING_CA, module.CertLabel("signer1"), "cert.pem")
            module._write_user_key(module.TESTING_CA)
        for name in fixture_names():
            shutil.copyfile(name, args.native_fixtures / name)
    record["fixture_inputs"] = [snapshot(args.native_fixtures / name) for name in fixture_names()]
    record["native_argv"] = native_argv()
    record["config"] = optional_snapshot(args.native_fixtures / "pyhanko.yml")
    record["original_body_executed"] = False
    manifest = {key: record[key] for key in ["kind", "architecture", "field_name_passed", "box_key", "box", "fixture_inputs", "native_argv", "config"]}
    manifest_path = args.native_fixtures / "fixture-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    record["fixture_manifest"] = snapshot(manifest_path)


def native_state():
    names = [*fixture_names(), "output.pdf", "fixture-manifest.json"]
    return {name: optional_snapshot(args.native_fixtures / name) for name in names}


def inspect_negative(module):
    record["native_state_before"] = native_state()
    assert all(record["native_state_before"][name] is not None for name in fixture_names())
    if args.kind == "no-config":
        assert not (args.native_fixtures / "pyhanko.yml").exists()
    runner = CliRunner()
    with runner.isolated_filesystem():
        record["reference_isolated_cwd"] = str(Path.cwd())
        for name in fixture_names():
            shutil.copyfile(args.native_fixtures / name, name)
            assert snapshot(name)["sha256"] == record["native_state_before"][name]["sha256"]
        trace_runner(runner)
        runner.invoke(module.cli_root, native_argv())
        check_negative_call()
    record["native_state_after"] = native_state()
    assert record["native_state_before"] == record["native_state_after"]
    record["same_native_input_negative_completed"] = True
    record["original_body_executed"] = False
    record["original_teardown_applicable"] = False


def verify_last():
    import math
    from datetime import timedelta
    from asn1crypto import crl, pem, x509
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import validate_pdf_signature
    from pyhanko_certvalidator import ValidationContext

    assert args.file and args.root and args.revinfo
    assert all(path.is_absolute() and path.is_file() for path in [args.file, args.root, args.revinfo])
    record["original_body_executed"] = False
    record["original_teardown_applicable"] = False
    record["fixture_clock_applied"] = False
    record["validation_moment_source"] = "Supplied revocation metadata; no clock freeze or extension"
    record["native_signing_clock_policy"] = "Native signing uses the ambient clock; validation uses the supplied metadata moment"
    evidence_snapshots = []

    def read_evidence(path):
        path = Path(path).resolve()
        data = path.read_bytes()
        row = {"path": str(path), "length": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        record["actual_case_reads"].append(row)
        evidence_snapshots.append(row)
        return data, row

    output_bytes, record["same_native_output"] = read_evidence(args.file)
    root_bytes, record["actual_root"] = read_evidence(args.root)
    root_der = pem.unarmor(root_bytes)[2] if pem.detect(root_bytes) else root_bytes
    root = x509.Certificate.load(root_der)
    assert root.dump() == root_der
    record["loaded_root_der_sha256"] = hashlib.sha256(root_der).hexdigest()
    metadata_bytes, record["revinfo_metadata"] = read_evidence(args.revinfo)
    metadata = json.loads(metadata_bytes)
    assert metadata["architecture"] == args.arch
    moment = datetime.fromisoformat(metadata["moment"])
    assert moment.tzinfo is not None and moment.utcoffset() is not None
    crls = []
    assert metadata["crls"]
    for expected in metadata["crls"]:
        path = Path(expected["path"])
        assert path.is_absolute()
        data, actual = read_evidence(path)
        assert actual["sha256"] == expected["sha256"]
        assert actual["length"] == expected["length"]
        crls.append(crl.CertificateList.load(data))
    settings = dict(moment=moment, crls=crls, time_tolerance=timedelta(seconds=1),
                    revocation_mode="soft-fail", allow_fetching=False)

    def status_record(status):
        return {"intact": status.intact, "valid": status.valid, "trusted": status.trusted,
                "bottom_line": status.bottom_line, "coverage": status.coverage.name,
                "seed_value_ok": status.seed_value_ok, "docmdp_ok": status.docmdp_ok}

    # Validate the exact captured native bytes. The final snapshot below also
    # detects any mutation of the file or evidence during this inspection.
    reader = PdfFileReader(io.BytesIO(output_bytes))
    signatures = reader.embedded_regular_signatures
    assert len(signatures) == 2
    last = signatures[-1]
    record["signature_count"] = len(signatures)
    record["signature_field_names"] = [signature.field_name for signature in signatures]
    record["last_field_name"] = last.field_name
    record["last_signature_field"] = last.field_name
    record["last_signature_pdf_m"] = str(last.sig_object.get("/M", ""))
    positive = validate_pdf_signature(last, signer_validation_context=ValidationContext(trust_roots=[root], **settings))
    record["root_positive"] = status_record(positive)
    assert positive.intact and positive.valid and positive.trusted and positive.bottom_line
    assert positive.coverage.name == "ENTIRE_FILE"
    assert positive.seed_value_ok and positive.docmdp_ok is True
    assert positive.validation_path is not None
    selected_root_der = positive.validation_path[0].dump()
    record["selected_root_der_sha256"] = hashlib.sha256(selected_root_der).hexdigest()
    assert selected_root_der == root_der
    record["selected_root_equals_loaded_root"] = True
    denied = validate_pdf_signature(last, signer_validation_context=ValidationContext(trust_roots=[], **settings))
    record["empty_roots"] = status_record(denied)
    assert not denied.trusted and not denied.bottom_line
    record["same_evidence_full_pdf_status"] = {
        "moment": metadata["moment"], "crls": metadata["crls"], "allow_fetching": False,
        "time_tolerance_seconds": 1, "revocation_mode": "soft-fail",
        "root_positive": record["root_positive"], "empty_roots": record["empty_roots"],
    }
    record.update(record["root_positive"])

    def actual_widgets(field):
        field = field.get_object()
        if field.get("/Subtype") == "/Widget":
            yield field
        else:
            for child in field.get("/Kids", []):
                yield from actual_widgets(child)

    widgets = list(actual_widgets(last.sig_field))
    assert widgets, "Last signed field must have an actual widget"
    record["last_widgets"] = []
    for widget in widgets:
        rect = [float(value) for value in widget["/Rect"]]
        assert len(rect) == 4 and all(math.isfinite(value) for value in rect)
        width, height = rect[2] - rect[0], rect[3] - rect[1]
        assert math.isfinite(width) and math.isfinite(height) and width > 0 and height > 0
        normal = widget["/AP"]["/N"]
        assert normal["/Subtype"] == "/Form"
        content = normal.data
        assert content, "Actual last widget normal appearance must contain decoded content"
        painted = b"BT" in content and (b"Tj" in content or b"TJ" in content)
        assert painted, "Actual last widget normal appearance must paint text"
        record["last_widgets"].append({
            "rect": rect, "width": width, "height": height,
            "normal_appearance": {"length": len(content), "sha256": hashlib.sha256(content).hexdigest(),
                                  "subtype": str(normal["/Subtype"]), "text_paint_operators_present": painted},
        })
    record["raster_rendering_claim"] = False
    for before in evidence_snapshots:
        assert snapshot(before["path"]) == before
    record["same_native_output_verified"] = True
    record["last_signature_verified"] = True


capture = io.StringIO()
failure = None
try:
    with track_reads(), contextlib.redirect_stdout(capture):
        module, conf = load_original()
        if args.mode == "original":
            original(module, conf)
        elif args.mode == "prepare":
            prepare(module, conf)
        elif args.mode == "inspect-negative":
            inspect_negative(module)
        else:
            verify_last()
    record["success"] = True
except Exception as error:
    failure = error
    record["success"] = False
    record["error"] = repr(error)
    record["traceback"] = traceback.format_exc()
finally:
    record["captured_output"] = capture.getvalue()
    print(json.dumps(record))
if failure is not None:
    sys.exit(1)
