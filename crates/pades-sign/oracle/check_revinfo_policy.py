"""Validate actual native-collected evidence under the caller's exact policy.

Usage: python -I check_revinfo_policy.py MANIFEST.json
Relative certificate/PDF paths are resolved against the manifest directory.
No network fetchers, HTTP services or upstream-function credit are involved.
"""

import asyncio
from collections import Counter
from datetime import datetime
import hashlib
import importlib.metadata
from io import BytesIO
import json
from pathlib import Path
import sys

from asn1crypto import ocsp
from freezegun import freeze_time
from pyhanko.keys import load_cert_from_pemder
from pyhanko.pdf_utils import generic
from pyhanko.pdf_utils.decode_limits import DecodePurpose
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import async_validate_pdf_signature
from pyhanko.sign.validation.dss import DocumentSecurityStore
from pyhanko_certvalidator import CertificateValidator, ValidationContext
from pyhanko_certvalidator.errors import PathBuildingError, ValidationError
from pyhanko_certvalidator.policy_decl import (
    CertRevTrustPolicy,
    RevocationCheckingPolicy,
    RevocationCheckingRule,
)

PYHANKO_VERSION = importlib.metadata.version("pyhanko")
VALIDATOR_VERSION = importlib.metadata.version("pyhanko-certvalidator")
assert PYHANKO_VERSION == "0.38.1"
assert VALIDATOR_VERSION == "0.33.0"


def path_from_manifest(directory, value):
    path = Path(value)
    return path if path.is_absolute() else directory / path


def evidence_arrays(case, key):
    arrays = case[key]
    assert isinstance(arrays, list), (case["name"], key)
    for array in arrays:
        assert isinstance(array, list), (case["name"], key)
        assert all(type(value) is int and 0 <= value <= 255 for value in array)
    return [bytes(array) for array in arrays]


def policy_for(case):
    return CertRevTrustPolicy(
        RevocationCheckingPolicy(
            ee_certificate_rule=RevocationCheckingRule(case["ee_rule"]),
            intermediate_ca_cert_rule=RevocationCheckingRule(case["ca_rule"]),
        )
    )


def expected_dss_certificates(leaf, intermediate, root, responses):
    certificates = {cert.dump() for cert in [leaf, intermediate, root]}
    for data in responses:
        response = ocsp.OCSPResponse.load(data, strict=True)
        response_bytes = response["response_bytes"]
        if response_bytes.native is not None and response_bytes["response_type"].native == "basic_ocsp_response":
            basic = response_bytes["response"].parsed
            certificates.update(cert.dump() for cert in basic["certs"])
    return certificates


def dss_streams(dictionary, name, purpose):
    references = dictionary.get(name)
    if references is None:
        return []
    references = references.get_object()
    assert isinstance(references, generic.ArrayObject), name
    result = []
    for reference in references:
        stream = reference.get_object()
        assert isinstance(stream, generic.StreamObject), name
        result.append(stream.read_data(purpose))
    return result


async def check_pdf(path, leaf, intermediate, root, moment, policy, ocsps, crls):
    data = path.read_bytes()
    with BytesIO(data) as source:
        reader = PdfFileReader(source)
        dictionary = reader.root["/DSS"]
        actual = {
            "certs": dss_streams(dictionary, "/Certs", DecodePurpose.CERTIFICATE),
            "ocsps": dss_streams(dictionary, "/OCSPs", DecodePurpose.OCSP_RESPONSE),
            "crls": dss_streams(dictionary, "/CRLs", DecodePurpose.CRL),
        }
        # P deduplicates collected blobs and embeds path/OCSP responder certs.
        expected = {
            "certs": expected_dss_certificates(leaf, intermediate, root, ocsps),
            "ocsps": set(ocsps),
            "crls": set(crls),
        }
        for kind in actual:
            assert Counter(actual[kind]) == Counter(expected[kind]), (
                str(path), kind, len(actual[kind]), len(expected[kind])
            )
        dss = DocumentSecurityStore.read_dss(reader)
        for kind in actual:
            assert len(getattr(dss, kind)) == len(actual[kind]), kind
        signatures = list(reader.embedded_signatures)
        assert len(signatures) == 1
        signature = signatures[0]
        assert signature.signer_cert.dump() == leaf.dump()
        verdicts = {}
        for name, roots, trusted in [
            ("trusted", [root], True),
            ("empty_root", [], False),
        ]:
            context = dss.as_validation_context(dict(
                trust_roots=roots,
                allow_fetching=False,
                moment=moment,
                revinfo_policy=policy,
            ))
            status = await async_validate_pdf_signature(
                signature, signer_validation_context=context
            )
            assert status.intact and status.valid, (name, status.summary())
            assert status.coverage.name == "ENTIRE_FILE", status.coverage
            assert status.trusted == trusted, (name, status.summary())
            assert status.bottom_line == trusted, (name, status.summary())
            verdicts[name] = status.trusted
        return {
            "path": str(path.resolve()),
            "sha256": hashlib.sha256(data).hexdigest(),
            "trusted": verdicts["trusted"],
            "empty_root_trusted": verdicts["empty_root"],
            "intact": True,
            "valid": True,
            "coverage": "ENTIRE_FILE",
            **{kind: len(values) for kind, values in actual.items()},
        }


async def execute(manifest, directory):
    leaf = load_cert_from_pemder(str(path_from_manifest(directory, manifest["leaf_path"])))
    intermediate = load_cert_from_pemder(str(path_from_manifest(directory, manifest["intermediate_path"])))
    root = load_cert_from_pemder(str(path_from_manifest(directory, manifest["root_path"])))
    certificates = {}
    for label, cert, path_key in [
        ("leaf", leaf, "leaf_path"),
        ("intermediate", intermediate, "intermediate_path"),
        ("root", root, "root_path"),
    ]:
        native = manifest["native_certificates"][label]
        assert isinstance(native, list)
        assert all(type(value) is int and 0 <= value <= 255 for value in native)
        assert cert.dump() == bytes(native), (label, "Opened certificate differs from native DER")
        certificates[label] = {
            "path": str(path_from_manifest(directory, manifest[path_key]).resolve()),
            "sha256": hashlib.sha256(cert.dump()).hexdigest(),
        }
    moment = datetime.fromisoformat(manifest["time"].replace("Z", "+00:00"))
    assert moment.utcoffset() is not None
    cases = manifest["cases"]
    assert isinstance(cases, list) and cases
    assert len({case["name"] for case in cases}) == len(cases)
    results = []
    for case in cases:
        assert type(case["expected_valid"]) is bool
        policy = policy_for(case)
        ocsps = evidence_arrays(case, "ocsps")
        crls = evidence_arrays(case, "crls")
        # Explicit empty lists are intentional: absence of evidence is a
        # validation case, not an invalid None/mandatory-policy configuration.
        context = ValidationContext(
            trust_roots=[root],
            other_certs=[intermediate],
            allow_fetching=False,
            moment=moment,
            revinfo_policy=policy,
            ocsps=ocsps,
            crls=crls,
        )
        error_name = None
        message = None
        try:
            await CertificateValidator(
                leaf, validation_context=context
            ).async_validate_usage(set())
        except (ValidationError, PathBuildingError) as error:
            valid = False
            error_name = type(error).__name__
            message = str(error)
            assert message, error_name
        else:
            valid = True
        assert valid == case["expected_valid"], (
            case["name"], valid, error_name, message
        )
        result = {
            "name": case["name"], "valid": valid,
            "error": error_name, "message": message,
        }
        if "pdf_path" in case:
            assert valid, "PDF comparisons require an accepted evidence case"
            result["pdf"] = await check_pdf(
                path_from_manifest(directory, case["pdf_path"]),
                leaf, intermediate, root, moment, policy, ocsps, crls,
            )
        results.append(result)
    return {
        "cases": results,
        "pyhanko": PYHANKO_VERSION,
        "pyhanko_certvalidator": VALIDATOR_VERSION,
        "certificates": certificates,
    }


def main():
    if len(sys.argv) != 2:
        raise ValueError("Usage: check_revinfo_policy.py MANIFEST.json")
    manifest_path = Path(sys.argv[1]).resolve()
    manifest = json.loads(manifest_path.read_text())
    with freeze_time(manifest["time"]):
        result = asyncio.run(execute(manifest, manifest_path.parent))
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
