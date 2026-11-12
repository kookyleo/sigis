"""Fresh, real-PKI evidence-chain controls supplementing the owned LTA tests.

The malformed member changes only its CMS signature inside excluded Contents.
No parser, crypto verifier, policy or clock-flow implementation is patched.
Only HTTP observations are instrumented. No upstream function credit is earned.
"""

import argparse
import asyncio
import base64
from datetime import datetime, timezone
import hashlib
from importlib.metadata import version
from io import BytesIO
import json
import logging
from pathlib import Path
import sys


SOURCE = Path("/tmp/pyhanko-oracle/src")
for path in [SOURCE / "cv-0.33.0/pkgs/pyhanko-certvalidator/src",
             SOURCE / "v0.38.1/internal/common-test-utils/src",
             SOURCE / "v0.38.1/pkgs/pyhanko/src", SOURCE / "v0.38.1/pkgs/pyhanko"]:
    sys.path.insert(0, str(path))

from freezegun import freeze_time
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import PdfTimeStamper
from pyhanko.sign.validation import ades
from pyhanko.sign.validation.policy_decl import (
    LocalKnowledge, PdfSignatureValidationSpec, SignatureValidationSpec,
)
from pyhanko_certvalidator.context import CertValidationPolicySpec
from pyhanko_certvalidator.registry import SimpleTrustManager
from pyhanko_testing_commons.test_utils.live_http import live_pki_services, PKIServiceRegistry
from pyhanko_testing_commons.test_utils.signing_commons import (
    ROOT_CERT, INTERM_CERT, DUMMY_TS, live_testing_vc,
)
from tests.test_ades_validation import (
    _generate_pades_test_doc, _assert_certs_known, DEFAULT_REVINFO_POLICY,
    NoSha512AfterSomeTime,
)


def b64(value):
    return base64.b64encode(value).decode("ascii")


def describe(result):
    api = result.api_status
    return {
        "ades_subindic": result.ades_subindic.name,
        "api_status.intact": api.intact,
        "api_status.valid": api.valid,
        "api_status.trusted": api.trusted,
        "api_status.bottom_line": api.bottom_line,
        "best_signature_time": result.best_signature_time.isoformat(),
    }


async def generate(output):
    assert version("pyhanko") == "0.38.1"
    assert version("pyhanko-certvalidator") == "0.33.0"
    exchanges = []
    original = PKIServiceRegistry._dispatch

    async def dispatch(self, request):
        body = await request.read()
        response = await original(self, request)
        exchanges.append({
            "method": request.method, "path": request.path_qs,
            "status": response.status, "content_type": response.content_type,
            "request_body": b64(body), "response_body": b64(response.body or b""),
        })
        return response

    PKIServiceRegistry._dispatch = dispatch
    document = {"pyhanko": "0.38.1", "certvalidator": "0.33.0", "pki": {
        "testing-ca": {"root": b64(ROOT_CERT.dump()), "interm": b64(INTERM_CERT.dump())},
    }, "tests": {}}
    try:
        with live_pki_services() as services:
            with freeze_time("2020-11-20", real_asyncio=True):
                stream = await _generate_pades_test_doc(services, md_algorithm="sha512")
            with freeze_time("2021-11-20", real_asyncio=True):
                await PdfTimeStamper(DUMMY_TS).async_timestamp_pdf(
                    IncrementalPdfFileWriter(stream), "sha256",
                    validation_context=live_testing_vc(services), in_place=True,
                )
            clean = stream.getvalue()
            original_signatures = PdfFileReader(BytesIO(clean)).embedded_signatures
            assert len(original_signatures) == 3
            latest = original_signatures[-1]
            encoded = latest.signer_info["signature"].native.hex().encode("ascii")
            offset = clean.lower().rfind(encoded)
            assert latest.byte_range[1] < offset < latest.byte_range[2]
            corrupt = bytearray(clean)
            corrupt[offset] = ord("0") if corrupt[offset] != ord("0") else ord("1")
            corrupt = bytes(corrupt)
            assert len(corrupt) == len(clean)
            assert clean[:offset] == corrupt[:offset] and clean[offset + 1:] == corrupt[offset + 1:]
            output.mkdir(parents=True, exist_ok=True)
            for case, data in [("positive", clean), ("corrupt", corrupt)]:
                (output / f"{case}.pdf").write_bytes(data)
                with freeze_time("2024-11-20", real_asyncio=True):
                    spec = SignatureValidationSpec(
                        cert_validation_policy=CertValidationPolicySpec(
                            trust_manager=SimpleTrustManager.build([ROOT_CERT]),
                            algorithm_usage_policy=NoSha512AfterSomeTime(2022),
                            revinfo_policy=DEFAULT_REVINFO_POLICY,
                        ),
                        local_knowledge=LocalKnowledge(
                            known_poes=_assert_certs_known([ROOT_CERT, INTERM_CERT]),
                        ),
                    )
                    reader = PdfFileReader(BytesIO(data))
                    signatures = reader.embedded_signatures
                    # Mutation is cryptographic only: original signature and
                    # older DTS still cover exactly the same bytes as before.
                    assert [s.compute_digest() for s in signatures] == [
                        s.compute_digest() for s in original_signatures
                    ]
                    controls = []
                    for timestamp in signatures[1:]:
                        result = await ades.ades_timestamp_validation(
                            timestamp.signed_data, spec,
                            expected_tst_imprint=timestamp.compute_digest,
                        )
                        controls.append({"subindic": result.ades_subindic.name,
                                         "intact": result.api_status.intact,
                                         "valid": result.api_status.valid,
                                         "trusted": result.api_status.trusted})
                    assert controls[0]["subindic"] == "OK"
                    assert controls[1]["intact"]
                    assert controls[1]["valid"] == (case == "positive")
                    assert controls[1]["subindic"] == (
                        "OK" if case == "positive" else "SIG_CRYPTO_FAILURE"
                    )
                    start = len(exchanges)
                    result = await ades.ades_lta_validation(
                        signatures[0], PdfSignatureValidationSpec(spec),
                    )
                    expected = "OK" if case == "positive" else "NO_POE"
                    assert result.ades_subindic.name == expected
                    assert result.api_status.intact and result.api_status.valid
                    assert result.api_status.trusted == (case == "positive")
                    assert result.best_signature_time == datetime(2020, 11, 20, tzinfo=timezone.utc)
                    document["tests"][f"tests/poe_chain.py::{case}"] = {
                        "outcome": "passed", "controls": controls,
                        "sha256": hashlib.sha256(data).hexdigest(),
                        "calls": [{"function": "ades_lta_validation",
                                   "time": datetime.now(timezone.utc).isoformat(),
                                   "input": {"kind": "pdf_signature", "pdf": b64(data),
                                             "field_name": signatures[0].field_name},
                                   "http": exchanges[start:], "result": describe(result)}],
                    }
    finally:
        PKIServiceRegistry._dispatch = original
    (output / "oracle.json").write_text(json.dumps(document, indent=2) + "\n")
    print(json.dumps({"cases": 2, "lta_calls": 2, "timestamp_control_calls": 4,
                      "total_http": len(exchanges), "new_upstream_credit": 0}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    logging.basicConfig(level=logging.CRITICAL)
    asyncio.run(generate(parser.parse_args().output))
