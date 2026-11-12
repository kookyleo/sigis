"""Capture exact upstream PDF-MAC PAdES proof and paired rejection inputs.

MIT-derived assertions: pyHanko 0.38.1 tests/test_pdfmac.py, including the
pdf_mac_good decorator. This is Python oracle evidence, not a native Rust
signing or validation acceptance claim. Only the requested output directory
is written. Run directly to generate through unmodified upstream pytest, or
use --replay to validate the committed input bytes offline.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
from datetime import datetime, timezone
import hashlib
from importlib.metadata import version
from io import BytesIO
import json
import logging
import os
from pathlib import Path
import subprocess
import sys

TIME = "2020-11-01T00:00:00Z"
UPSTREAM_ID = "pyhanko/test_pdfmac.py::test_pdf_mac_pades"
_HTTP = []
_LTA = []
_TRACE = []
_OUTCOME = None


def b64(value):
    return base64.b64encode(value).decode("ascii")


def api_status_dict(status):
    if status is None:
        return None
    output = {"type": type(status).__name__}
    for key in ["bottom_line", "valid", "intact", "trusted", "docmdp_ok"]:
        if hasattr(status, key):
            output[key] = getattr(status, key)
    for key in ["coverage", "modification_level", "trust_problem_indic"]:
        value = getattr(status, key, None)
        output[key] = getattr(value, "standard_name", getattr(value, "name", None)) if value is not None else None
    timestamp = getattr(status, "timestamp", None)
    output["timestamp"] = timestamp.isoformat() if timestamp else None
    certificate = getattr(status, "signing_cert", None)
    output["signing_certificate_subject"] = certificate.subject.human_friendly if certificate else None
    path = getattr(status, "validation_path", None)
    output["validation_path"] = [certificate.subject.human_friendly for certificate in path.iter_certs(include_root=True)] if path else None
    return output


def status_dict(result):
    status = result.api_status
    output = dict(api_status_dict(status) or {})
    output.update({
        "ades_subindic": result.ades_subindic.standard_name,
        "ades_status": result.ades_subindic.status.name,
        "failure_msg": getattr(result, "failure_msg", None),
        "best_signature_time": getattr(result, "best_signature_time", None).isoformat()
            if getattr(result, "best_signature_time", None) else None,
        "signature_timestamp": api_status_dict(getattr(status, "timestamp_validity", None)),
        "content_timestamp": api_status_dict(getattr(status, "content_timestamp_validity", None)),
    })
    return output


def install_validation_traces():
    from pyhanko.sign.validation import ades
    for name in ["ades_timestamp_validation", "ades_timestamp_validation_internal",
                 "ades_with_time_validation", "_scoped_ades_with_time_validation"]:
        original = getattr(ades, name)
        if getattr(original, "_pdfmac_trace", False):
            continue
        def wrap(original, name):
            async def traced(*args, **kwargs):
                result = await original(*args, **kwargs)
                _TRACE.append({"function": name, "input_type": type(args[0]).__name__ if args else None,
                               "result": status_dict(result)})
                return result
            traced._pdfmac_trace = True
            return traced
        setattr(ades, name, wrap(original, name))


def pytest_configure(config):
    """Plugin mode records the exact original test without modifying it."""
    assert version("pyhanko") == "0.38.1"
    assert version("pyhanko-certvalidator") == "0.33.0"
    from pyhanko.sign.validation import ades
    from pyhanko_testing_commons.test_utils.live_http import PKIServiceRegistry

    install_validation_traces()
    original_lta = ades.ades_lta_validation

    async def lta(*args, **kwargs):
        result = await original_lta(*args, **kwargs)
        _LTA.append(status_dict(result))
        return result

    ades.ades_lta_validation = lta
    original_dispatch = PKIServiceRegistry._dispatch

    async def dispatch(self, request):
        body = await request.read()
        response = await original_dispatch(self, request)
        _HTTP.append({
            "method": request.method, "path": request.path_qs,
            "time": datetime.now(timezone.utc).isoformat(),
            "status": response.status, "content_type": response.content_type,
            "request_body": b64(body), "response_body": b64(response.body or b""),
        })
        return response

    PKIServiceRegistry._dispatch = dispatch


def pytest_collection_modifyitems(session, config, items):
    output = os.environ.get("HANKO_PDFMAC_OUTPUT")
    if output:
        for item in items:
            if item.name == "test_pdf_mac_pades":
                # The decorator writes only after the body, MAC and ISO checks
                # all pass. Its original fixture and function body are retained.
                item.module.GENERATED_TEST_OUTPUTS = str(Path(output) / "upstream")


def pytest_runtest_logreport(report):
    global _OUTCOME
    if report.when == "call" and report.nodeid.endswith("::test_pdf_mac_pades"):
        _OUTCOME = report.outcome


def pytest_sessionfinish(session, exitstatus):
    output = os.environ.get("HANKO_PDFMAC_OUTPUT")
    if not output:
        return
    root = Path(output)
    root.mkdir(parents=True, exist_ok=True)
    (root / "upstream-evidence.json").write_text(json.dumps({
        "upstream_function": UPSTREAM_ID, "outcome": _OUTCOME,
        "pytest_exitstatus": int(exitstatus), "lta_calls": _LTA, "validation_trace": _TRACE,
        "http": _HTTP,
    }, indent=2, sort_keys=True) + "\n")


def validate_bytes(value, password, root_cert, *, diagnostic_ignore_mac=False, continue_after_failed_mac=False):
    from freezegun import freeze_time
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation.ades import ades_lta_validation
    from pyhanko.sign.validation.policy_decl import PdfSignatureValidationSpec, SignatureValidationSpec
    from pyhanko_certvalidator.context import CertValidationPolicySpec
    from pyhanko_certvalidator.policy_decl import CertRevTrustPolicy, NO_REVOCATION
    from pyhanko_certvalidator.registry import SimpleTrustManager

    with freeze_time(TIME):
        reader = PdfFileReader(BytesIO(value))
        if diagnostic_ignore_mac:
            # Diagnostic only: proves that the unsigned token mutation leaves
            # CMS/LTA cryptography intact. This never models an accepted reader.
            reader._validate_pdf_mac = lambda auth: auth
        auth = reader.decrypt(password)
        result = {
            "sha256": hashlib.sha256(value).hexdigest(),
            "encrypted": reader.encrypted,
            "auth_status": auth.status.name,
            "mac_status": auth.mac_status.name if auth.mac_status else None,
            "mac_failure_reason": auth.mac_failure_reason,
            "password": password,
            "diagnostic_ignore_mac": diagnostic_ignore_mac,
            "continue_after_failed_mac": continue_after_failed_mac,
        }
        if auth.status.name == "FAILED" and not continue_after_failed_mac:
            result["lta_attempted"] = False
            return result
        extensions = sorted({int(ext.get_object()["/ExtensionLevel"])
                             for ext in reader.root["/Extensions"]["/ISO_"]})
        result["iso_extension_levels"] = extensions
        auth_code = reader.trailer_view["/AuthCode"]
        result["mac_location"] = str(auth_code["/MACLocation"])
        result["signatures"] = [{
            "field_name": signature.field_name,
            "type": str(signature.sig_object_type),
            "subfilter": str(signature.sig_object["/SubFilter"]),
            "byte_range": list(signature.byte_range),
            "signed_revision": signature.signed_revision,
        } for signature in reader.embedded_signatures]
        specification = PdfSignatureValidationSpec(SignatureValidationSpec(
            cert_validation_policy=CertValidationPolicySpec(
                trust_manager=SimpleTrustManager.build(trust_roots=[root_cert]),
                revinfo_policy=CertRevTrustPolicy(NO_REVOCATION),
            ),
        ))
        # No test PKI service is started for this independent replay. The
        # validation policy matches the original, including its default handlers;
        # preserve the actual sub-indication rather than assuming full AdES OK.
        trace_start = len(_TRACE)
        validation = asyncio.run(ades_lta_validation(reader.embedded_signatures[0], specification))
        result["validation_trace"] = _TRACE[trace_start:]
        result["lta_attempted"] = True
        result["lta"] = status_dict(validation)
        return result


def mutate_mac(value):
    from asn1crypto import cms
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.general import find_unique_cms_attribute
    from pyhanko.sign.validation.pdf_embedded import extract_contents

    reader = PdfFileReader(BytesIO(value))
    auth = reader.decrypt("secret")
    assert auth.mac_status.name == "SUCCESSFUL"
    auth_code = reader.trailer_view["/AuthCode"]
    location = str(auth_code["/MACLocation"])
    if location == "/Standalone":
        original_contents = auth_code.raw_get("/MAC").original_bytes
        content_info = cms.ContentInfo.load(original_contents)
        token = content_info
        byte_range = list(auth_code["/ByteRange"])
    else:
        assert location == "/AttachedToSig"
        signature_dictionary = auth_code.get_value_as_reference("/SigObjRef").get_object()
        original_contents = extract_contents(signature_dictionary)
        content_info = cms.ContentInfo.load(original_contents)
        signer = content_info["content"]["signer_infos"][0]
        token = find_unique_cms_attribute(signer["unsigned_attrs"], "pdf_mac_data")
        byte_range = list(signature_dictionary["/ByteRange"])
    auth_data = token["content"]
    original_mac = auth_data["mac"].native
    altered_mac = bytes([original_mac[0] ^ 1]) + original_mac[1:]
    auth_data["mac"] = altered_mac
    altered_contents = content_info.dump()
    assert len(altered_contents) <= len(original_contents)
    start, end = byte_range[1], byte_range[2]
    assert value[start:start + 1] == b"<" and value[end - 1:end] == b">"
    slot_length = (end - start - 2) // 2
    assert slot_length == len(original_contents)
    padded = altered_contents + bytes(slot_length - len(altered_contents))
    encoded = padded.hex().upper().encode("ascii")
    mutated = value[:start + 1] + encoded + value[end - 1:]
    assert len(mutated) == len(value)
    assert mutated[:start] == value[:start] and mutated[end:] == value[end:]
    return mutated, {"mutation": "flip first bit of CMS AuthenticatedData.mac", "location": location,
                     "original_mac": b64(original_mac), "altered_mac": b64(altered_mac),
                     "byte_range": byte_range, "contents_start": start, "contents_end": end}


def verify_output(output, *, replay):
    from asn1crypto import pem, x509
    from pyhanko_testing_commons.test_utils.signing_commons import ECC_ROOT_CERT

    install_validation_traces()
    if not replay:
        original = (output / "upstream/good/test_pdf_mac_pades.pdf").read_bytes()
        (output / "exact.pdf").write_bytes(original)
        (output / "root.der").write_bytes(ECC_ROOT_CERT.dump())
        (output / "root.pem").write_bytes(pem.armor("CERTIFICATE", ECC_ROOT_CERT.dump()))
        token_mutation, mutation = mutate_mac(original)
        (output / "mac-token-mutated.pdf").write_bytes(token_mutation)
        header_mutation = original[:10] + bytes([original[10] ^ 1]) + original[11:]
        (output / "document-mutated.pdf").write_bytes(header_mutation)
    else:
        previous = json.loads((output / "manifest.json").read_text())
        mutation = previous["token_mutation"]
        original = (output / "exact.pdf").read_bytes()
        token_mutation = (output / "mac-token-mutated.pdf").read_bytes()
        header_mutation = (output / "document-mutated.pdf").read_bytes()
    root = x509.Certificate.load((output / "root.der").read_bytes())
    cases = {
        "correct_password": validate_bytes(original, "secret", root),
        "wrong_password": validate_bytes(original, "incorrect-password", root),
        "mac_token_mutation": validate_bytes(token_mutation, "secret", root),
        "document_mutation": validate_bytes(header_mutation, "secret", root),
        "token_mutation_cms_control": validate_bytes(token_mutation, "secret", root, diagnostic_ignore_mac=True),
        "post_failed_mac_lta_diagnostic": validate_bytes(token_mutation, "secret", root, continue_after_failed_mac=True),
    }
    good = cases["correct_password"]
    assert good["encrypted"] and good["auth_status"] != "FAILED"
    assert good["mac_status"] == "SUCCESSFUL"
    assert 32004 in good["iso_extension_levels"]
    assert good["lta"]["bottom_line"]
    assert good["lta"]["valid"] and good["lta"]["intact"] and good["lta"]["trusted"]
    assert cases["wrong_password"]["auth_status"] == "FAILED"
    for name in ["mac_token_mutation", "document_mutation"]:
        assert cases[name]["auth_status"] == "FAILED" and cases[name]["mac_status"] == "FAILED"
        assert not cases[name]["lta_attempted"]
    control = cases["token_mutation_cms_control"]
    assert control["lta"]["bottom_line"] and control["lta"]["valid"] and control["lta"]["intact"]
    post_failed = cases["post_failed_mac_lta_diagnostic"]
    assert post_failed["auth_status"] == "FAILED" and post_failed["mac_status"] == "FAILED"
    assert post_failed["lta_attempted"]
    evidence = json.loads((output / "upstream-evidence.json").read_text())
    assert evidence["outcome"] == "passed" and evidence["pytest_exitstatus"] == 0
    assert evidence["lta_calls"][0]["bottom_line"]
    assert good["lta"]["ades_subindic"] == evidence["lta_calls"][0]["ades_subindic"]
    serialized_cases = []
    for identifier, case in cases.items():
        file = ("document-mutated.pdf" if identifier == "document_mutation" else
                "mac-token-mutated.pdf" if identifier in {
                    "mac_token_mutation", "token_mutation_cms_control", "post_failed_mac_lta_diagnostic"
                } else "exact.pdf")
        oracle = {key: value for key, value in case.items()
                  if key not in {"password", "lta"}}
        oracle.update(case.get("lta", {}))
        serialized_cases.append({"id": identifier, "file": file, "password": case["password"], "oracle": oracle})
    manifest = {
        "upstream_function": UPSTREAM_ID, "pyhanko": "0.38.1", "certvalidator": "0.33.0",
        "frozen_time": TIME, "validation_time": TIME, "trust_root": b64(root.dump()), "encryption": "STANDARD", "password": "secret",
        "root_certificate": "root.der", "positive_file": "exact.pdf",
        "token_mutation_file": "mac-token-mutated.pdf", "document_mutation_file": "document-mutated.pdf",
        "original_assertions": ["ades_status.api_status.bottom_line", "decrypt.mac_status == SUCCESSFUL",
                                "32004 in root.Extensions.ISO_.ExtensionLevel"],
        "token_mutation": mutation, "cases": serialized_cases,
        "upstream_evidence": "upstream-evidence.json",
        "native_rust_acceptance": False,
    }
    if replay:
        assert manifest == previous
    else:
        (output / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"upstream_functions": 1, "upstream_parameter_cases": 1,
                      "independent_cases": len(cases), "replay": replay,
                      "correct_password_lta": good["lta"]["ades_subindic"]}))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, default=Path("/tmp/pyhanko-oracle/src/v0.38.1"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--replay", action="store_true")
    parser.add_argument("--reuse-upstream", action="store_true")
    args = parser.parse_args()
    args.output = args.output.resolve()
    for path in [args.source / "internal/common-test-utils/src", args.source / "pkgs/pyhanko/src"]:
        sys.path.insert(0, str(path))
    assert version("pyhanko") == "0.38.1" and version("pyhanko-certvalidator") == "0.33.0"
    args.output.mkdir(parents=True, exist_ok=True)
    if not args.replay and not args.reuse_upstream:
        environment = dict(os.environ, HANKO_PDFMAC_OUTPUT=str(args.output), PYTHONDONTWRITEBYTECODE="1")
        paths = [Path(__file__).resolve().parent, args.source / "pkgs/pyhanko/src",
                 args.source / "internal/common-test-utils/src"]
        environment["PYTHONPATH"] = os.pathsep.join(str(path) for path in paths)
        command = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p", "pdfmac_oracle",
                   "-o", "log_cli=false", "tests/test_pdfmac.py::test_pdf_mac_pades"]
        with (args.output / "upstream-pytest.log").open("w") as stream:
            result = subprocess.run(command, cwd=args.source / "pkgs/pyhanko", env=environment,
                                    stdout=stream, stderr=subprocess.STDOUT, check=False)
        assert result.returncode == 0, (args.output / "upstream-pytest.log").read_text()
    verify_output(args.output, replay=args.replay)


if __name__ == "__main__":
    logging.basicConfig(level=logging.CRITICAL)
    main()
