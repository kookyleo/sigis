"""Exact pinned decode-limit bodies and same-native-byte structural checks (MIT).

Fresh original fixtures and native input preparation are separate generations.
Neither parsing an unsigned PDF nor checking a stamp establishes signer trust.
"""
import argparse
import ast
import builtins
import hashlib
import importlib.metadata
import importlib.util
import json
import os
import shutil
import sys
import types
from pathlib import Path

assert sys.flags.optimize == 0 and os.environ.get("PYTHONOPTIMIZE") == "0"
import pyhanko
pyhanko.__path__.append("/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli/src/pyhanko")
from click.testing import CliRunner
from pyhanko.cli import cli_root
import pyhanko.cli as cli_module
from pyhanko.pdf_utils.decode_limits import DecodeLimits
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.fields import enumerate_sig_fields
from pyhanko_testing_commons.test_data import samples

SOURCE = Path("/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko-cli/tests")
SOURCE_SHA = "27f7c491504eda299c2f5e52d62849aa3772c07d4cb163d78340f8195a159d1c"
SAMPLES_SHA = "778ad36a025556160b6701ebc416e34d6a70bd0d81c977be600363e68890ff8b"
FLAG = "--no-decode-limits"
SENTINEL = b"decode-limits-simple-output-sentinel"
CASES = {
    "encrypt": ["encrypt", FLAG, "--password", "secret", "input.pdf", "out.pdf"],
    "list": ["sign", "list", FLAG, "input.pdf"],
    "addfields": ["sign", "addfields", FLAG, "--field", "1/0,0,100,100/Sig1", "input.pdf", "out.pdf"],
    "addfields-resave": ["sign", "addfields", FLAG, "--resave", "--field", "1/0,0,100,100/Sig1", "input.pdf", "out.pdf"],
    "text": ["stamp", FLAG, "--style-name", "test", "input.pdf", "out.pdf", "0", "0"],
    "qr": ["stamp", FLAG, "--style-name", "test", "--stamp-url", "https://example.com", "input.pdf", "out.pdf", "0", "0"],
}

def snapshot(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return {"path": str(path), "length": len(data), "sha256": hashlib.sha256(data).hexdigest()}

parser = argparse.ArgumentParser()
parser.add_argument("mode", choices=["prepare", "original", "same-input", "inspect"])
parser.add_argument("case", choices=CASES)
parser.add_argument("--file", type=Path)
args = parser.parse_args()
record = {"mode": args.mode, "case": args.case, "python": sys.executable,
          "optimize": sys.flags.optimize, "cwd": str(Path.cwd()), "calls": [], "reads": []}
record["versions"] = {name: importlib.metadata.version(name) for name in ["pyhanko", "pyhanko-certvalidator"]}
assert record["versions"] == {"pyhanko": "0.38.1", "pyhanko-certvalidator": "0.33.0"}
record["original_source"] = snapshot(SOURCE / "test_cli_decode_limits.py")
record["fixture_source"] = snapshot(samples.__file__)
assert record["original_source"]["sha256"] == SOURCE_SHA
assert record["fixture_source"]["sha256"] == SAMPLES_SHA
record["actual_cli_module"] = snapshot(cli_module.__file__)
record["minimal"] = {"length": len(samples.MINIMAL), "sha256": hashlib.sha256(samples.MINIMAL).hexdigest()}

real_open = builtins.open
seen = set()
def observed_open(file, mode="r", *a, **kw):
    if isinstance(file, (str, os.PathLike)) and "r" in mode:
        p = Path(file).resolve()
        if p.is_file() and p.is_relative_to(Path.cwd()) and str(p) not in seen:
            seen.add(str(p))
            record["reads"].append(snapshot(p))
    return real_open(file, mode, *a, **kw)
builtins.open = observed_open

class TracedRunner(CliRunner):
    def invoke(self, cli, argv=None, *a, **kw):
        before = snapshot("input.pdf") if Path("input.pdf").exists() else None
        result = super().invoke(cli, argv, *a, **kw)
        record["calls"].append({"argv": list(argv), "exit_code": result.exit_code,
                                "output": result.output, "exception": repr(result.exception),
                                "input_before": before,
                                "output_after": snapshot("out.pdf") if Path("out.pdf").exists() else None})
        return result

def load_original():
    name = "_sigis_decode_simple_original"
    package = types.ModuleType(name)
    package.__path__ = [str(SOURCE)]
    sys.modules[name] = package
    spec = importlib.util.spec_from_file_location(name + ".test_cli_decode_limits", SOURCE / "test_cli_decode_limits.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    text = (SOURCE / "test_cli_decode_limits.py").read_text()
    lines = text.splitlines(keepends=True)
    record["bodies"] = []
    for node in ast.parse(text).body:
        if isinstance(node, ast.FunctionDef) and node.name in {"oversized_input", "_check_flag", "test_simple_commands", "test_text_stamp", "test_qr_stamp"}:
            body = "".join(lines[node.lineno - 1:node.end_lineno]).encode()
            record["bodies"].append({"name": node.name, "line": node.lineno, "sha256": hashlib.sha256(body).hexdigest()})
    conftest = sys.modules[name + ".conftest"]
    record["actual_conftest"] = snapshot(conftest.__file__)
    assert record["actual_conftest"]["sha256"] == "6a67cf73ca8f81394e9fd3fa0fec18ad9a0896e70d0f6c90621787062e1612e6"
    return module, conftest

if args.mode == "prepare":
    module, _ = load_original()
    # Exact upstream fixture, including copy_into_new_writer(MINIMAL), all
    # non-stream objects in ObjStm and a 3 MiB zero ByteString (hex serialized).
    module.oversized_input.__wrapped__()
    record["input"] = snapshot("input.pdf")
    if args.case in {"text", "qr"}:
        module._write_config({"stamp-styles": {"test": {"type": args.case}}})
        record["config"] = snapshot("pyhanko.yml")
elif args.mode == "original":
    module, conftest = load_original()
    archive = Path.cwd() / "original-artifacts"
    archive.mkdir()
    fixture = conftest.cli_runner.__wrapped__()
    fixture_runner = next(fixture)
    try:
        runner = TracedRunner()
        module.oversized_input.__wrapped__()
        record["fixture_input"] = snapshot("input.pdf")
        if args.case in {"text", "qr"}:
            getattr(module, "test_" + args.case + "_stamp")(runner, None)
        else:
            module.test_simple_commands(runner, None, CASES[args.case])
        assert len(record["calls"]) == 2
        record["original_body_completed"] = True
        record["original_artifacts"] = []
        for name in ["input.pdf", "out.pdf", "pyhanko.yml"]:
            if Path(name).exists():
                shutil.copy2(name, archive / name)
                record["original_artifacts"].append(snapshot(archive / name))
    finally:
        fixture.close()
elif args.mode == "same-input":
    module, _ = load_original()
    record["same_native_input"] = snapshot("input.pdf")
    module._check_flag(TracedRunner(), CASES[args.case])
    assert len(record["calls"]) == 2
    record["same_input_check_completed"] = True
else:
    assert args.file is not None
    record["same_native_output"] = snapshot(args.file)
    with open(args.file, "rb") as stream:
        reader = PdfFileReader(stream, strict=False, decode_limits=DecodeLimits.for_trusted_input())
        if args.case == "encrypt":
            assert reader.encrypted
            auth = reader.decrypt("secret")
            assert auth.status.name == "OWNER"
        else:
            assert not reader.encrypted
        pages = reader.root["/Pages"]
        assert pages["/Count"] == 1
        record["revisions"] = reader.total_revisions
        record["encrypted"] = reader.encrypted
        record["page_count"] = pages["/Count"]
        fields = list(enumerate_sig_fields(reader))
        record["fields"] = [name for name, _, _ in fields]
        if args.case.startswith("addfields"):
            assert record["fields"] == ["Sig1"]
            assert fields[0][1] is None
            field_ref = fields[0][2]
            field = field_ref.get_object()
            assert tuple(field["/Rect"]) == (0, 0, 100, 100)
            assert field["/Subtype"] == "/Widget"
            page_ref, _ = reader.find_page_for_modification(0)
            assert field.raw_get("/P") == page_ref
            assert field_ref in page_ref.get_object()["/Annots"]
            record["widget_on_first_page"] = True
            assert reader.total_revisions == (1 if args.case.endswith("resave") else 2)
        elif args.case in {"text", "qr"}:
            assert reader.total_revisions == 2
            page_ref, _ = reader.find_page_for_modification(0)
            page = page_ref.get_object()
            forms = list(page["/Resources"]["/XObject"].values())
            assert forms and any(obj.get_object().get("/Subtype") == "/Form" for obj in forms)
            record["form_count"] = len(forms)
        else:
            assert not fields
            assert reader.total_revisions == 1
record["success"] = True
print(json.dumps(record, sort_keys=True))
