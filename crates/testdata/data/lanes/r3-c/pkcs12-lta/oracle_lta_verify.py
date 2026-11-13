"""Fresh current-clock full-LTA check of an actual native CLI PDF.

This helper never signs, invokes a CLI, substitutes a clock or installs replay
fetchers. The exact upstream unit post-check is api_status.bottom_line under
REQUIRE_REVINFO. Additional integrity/trust/no-root/digest controls are separate.
"""

import argparse
import asyncio
import hashlib
import importlib.metadata
import json
import sys
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path

import aiohttp
import pyhanko.sign.validation.ades as ades
import pyhanko.sign.validation.generic_cms as generic_cms
import pyhanko_certvalidator
from asn1crypto import pem, x509
from pyhanko.pdf_utils.decode_limits import DecodeLimits
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import DocumentSecurityStore
from pyhanko.sign.validation.policy_decl import (
    PdfSignatureValidationSpec, RevocationInfoGatheringSpec,
    SignatureValidationSpec,
)
from pyhanko_certvalidator.context import CertValidationPolicySpec
from pyhanko_certvalidator.fetchers.aiohttp_fetchers import AIOHttpFetcherBackend
from pyhanko_certvalidator.policy_decl import REQUIRE_REVINFO, CertRevTrustPolicy
from pyhanko_certvalidator.registry import SimpleTrustManager


def file_record(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return {"path": str(path), "length": len(data),
            "sha256": hashlib.sha256(data).hexdigest()}


def read_root(path):
    data = Path(path).read_bytes()
    if pem.detect(data):
        data = pem.unarmor(data)[2]
    return x509.Certificate.load(data, strict=True)


async def validate(data, roots, session, strict):
    reader = PdfFileReader(
        BytesIO(data), strict=strict,
        decode_limits=DecodeLimits.for_trusted_input(),
    )
    assert reader.embedded_regular_signatures, "An actual regular signature is required"
    assert reader.embedded_timestamp_signatures, "PAdES-LTA must contain a document timestamp"
    signature = reader.embedded_regular_signatures[-1]
    spec = PdfSignatureValidationSpec(SignatureValidationSpec(
        cert_validation_policy=CertValidationPolicySpec(
            trust_manager=SimpleTrustManager.build(trust_roots=roots),
            revinfo_policy=CertRevTrustPolicy(REQUIRE_REVINFO),
        ),
        revinfo_gathering_policy=RevocationInfoGatheringSpec(
            fetcher_backend=AIOHttpFetcherBackend(session, per_request_timeout=5),
        ),
    ))
    result = await ades.ades_lta_validation(signature, spec)
    status = result.api_status
    dss = DocumentSecurityStore.read_dss(reader)
    record = {
        "api_status_present": status is not None,
        "intact": status is not None and status.intact,
        "valid": status is not None and status.valid,
        "trusted": status is not None and status.trusted,
        "bottom_line": status is not None and status.bottom_line,
        "modification_level": (None if status is None
                               or status.modification_level is None
                               else status.modification_level.name),
        "ades_subindic": result.ades_subindic.standard_name,
        "failure_msg": result.failure_msg,
        "field_name": signature.field_name,
        "regular_signatures": len(reader.embedded_regular_signatures),
        "document_timestamps": len(reader.embedded_timestamp_signatures),
        "dss_crls": len(dss.crls), "dss_ocsps": len(dss.ocsps),
    }
    return record, signature


async def verify(args):
    data = Path(args.output).read_bytes()
    root = read_root(args.root)
    # Explicitly parse the source input as well, with the same requested syntax
    # policy, rather than silently relaxing the output parser on any exception.
    PdfFileReader(
        BytesIO(Path(args.input).read_bytes()), strict=not args.allow_hybrid,
        decode_limits=DecodeLimits.for_trusted_input(),
    )
    async with aiohttp.ClientSession() as session:
        positive, signature = await validate(data, [root], session, not args.allow_hybrid)
        assert positive["bottom_line"], positive
        assert positive["intact"] and positive["valid"] and positive["trusted"], positive
        if args.require_lta_updates:
            assert positive["modification_level"] == "LTA_UPDATES", positive
        digest = signature.compute_digest()
        original = generic_cms.validate_sig_integrity(
            signature.signer_info, signature.signer_cert, "data", digest
        )
        changed = bytes([digest[0] ^ 1]) + digest[1:]
        wrong_digest = generic_cms.validate_sig_integrity(
            signature.signer_info, signature.signer_cert, "data", changed
        )
        assert original == (True, True), original
        assert wrong_digest == (False, True), wrong_digest
        try:
            empty, _ = await validate(data, [], session, not args.allow_hybrid)
        except Exception as error:
            empty = {"trusted": False, "bottom_line": False,
                     "error_class": type(error).__name__, "error": str(error)}
        assert not empty["trusted"] and not empty["bottom_line"], empty
    return {"positive": positive, "empty_roots": empty,
            "original_integrity": original, "wrong_digest_integrity": wrong_digest}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--root", required=True)
    parser.add_argument("--allow-hybrid", action="store_true")
    parser.add_argument("--require-lta-updates", action="store_true")
    parser.add_argument("--record")
    args = parser.parse_args()
    assert importlib.metadata.version("pyhanko") == "0.38.1"
    assert importlib.metadata.version("pyhanko-certvalidator") == "0.33.0"
    record = {
        "kind": "fresh pinned full-LTA validation of actual native CLI output",
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "clock": "current UTC; no override", "argv": sys.argv[1:],
        "cwd": str(Path.cwd()), "sys_executable": sys.executable, "python": file_record(sys.executable),
        "driver": file_record(__file__),
        "ades_module": file_record(ades.__file__),
        "cms_module": file_record(generic_cms.__file__),
        "validator_module": file_record(pyhanko_certvalidator.__file__),
        "pyhanko": importlib.metadata.version("pyhanko"),
        "certvalidator": importlib.metadata.version("pyhanko-certvalidator"),
        "new_unique_credit": 0,
    }
    try:
        record["opened_before_parse"] = {
            "input": file_record(args.input), "output": file_record(args.output),
            "root": file_record(args.root),
        }
        record["result"] = asyncio.run(verify(args))
        for name, path in [("input", args.input), ("output", args.output), ("root", args.root)]:
            assert file_record(path) == record["opened_before_parse"][name]
        record["success"] = True
    except Exception as error:
        record.update(success=False, error_class=type(error).__name__, error=str(error))
    record["finished_utc"] = datetime.now(timezone.utc).isoformat()
    if args.record:
        Path(args.record).write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(record))
    return 0 if record["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
