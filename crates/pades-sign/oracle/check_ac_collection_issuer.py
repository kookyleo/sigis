"""Compare actual AC issuer metadata and signatures with pinned public APIs.

Usage: python -I check_ac_collection_issuer.py MANIFEST.json
This does not perform whole-AC trust, HTTP, revocation or LTA validation.
"""

import hashlib
import importlib.metadata
import json
from pathlib import Path
import sys

from asn1crypto import cms, x509
from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pyhanko_certvalidator.util import extract_ac_issuer_dir_name

PYHANKO_VERSION = importlib.metadata.version("pyhanko")
VALIDATOR_VERSION = importlib.metadata.version("pyhanko-certvalidator")
assert PYHANKO_VERSION == "0.38.1"
assert VALIDATOR_VERSION == "0.33.0"

EXPECTED = {
    "v1_name": True,
    "v2_name": True,
    "v2_name_and_base": True,
    "base_only": False,
    "dns_only": False,
}


def der_bytes(values):
    assert isinstance(values, list)
    assert all(type(value) is int and 0 <= value <= 255 for value in values)
    return bytes(values)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def main():
    if len(sys.argv) != 2:
        raise ValueError("Usage: check_ac_collection_issuer.py MANIFEST.json")
    manifest = json.loads(Path(sys.argv[1]).read_text())
    aa_der = der_bytes(manifest["aa_der"])
    aa = x509.Certificate.load(aa_der, strict=True)
    aa_key = crypto_x509.load_der_x509_certificate(aa_der).public_key()
    assert isinstance(aa_key, rsa.RSAPublicKey)
    cases = manifest["cases"]
    assert isinstance(cases, list) and len(cases) == len(EXPECTED)
    assert {case["form"] for case in cases} == set(EXPECTED)
    results = []
    for case in cases:
        form = case["form"]
        assert type(case["accepted"]) is bool
        assert case["accepted"] == EXPECTED[form]
        data = der_bytes(case["ac_der"])
        ac = cms.AttributeCertificateV2.load(data, strict=True)
        info = ac["ac_info"]
        inner = info["signature"]
        envelope = ac["signature_algorithm"]
        assert inner.dump() == envelope.dump(), form
        assert envelope["algorithm"].dotted == "1.2.840.113549.1.1.11", form
        # dump() preserves the unmodified actual signed ACInfo DER. Verify every
        # supplied case before asking whether its issuer metadata is supported.
        aa_key.verify(
            ac["signature"].native,
            info.dump(),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        error_name = None
        message = None
        issuer_hash = None
        try:
            issuer = extract_ac_issuer_dir_name(ac)
        except NotImplementedError as error:
            assert form in {"base_only", "dns_only"}, (form, str(error))
            message = str(error)
            assert message == (
                "Could not extract AC issuer name; only distinguished names "
                "are supported, and none were found."
            ), message
            accepted = False
            error_name = type(error).__name__
        else:
            assert form in {"v1_name", "v2_name", "v2_name_and_base"}, form
            # In particular, never substitute aa.issuer for a missing AC name.
            assert issuer.dump() == aa.subject.dump(), form
            issuer_hash = sha256(issuer.dump())
            accepted = True
        assert accepted == case["accepted"], form
        results.append({
            "form": form,
            "accepted": accepted,
            "valid_signature": True,
            "ac_sha256": sha256(data),
            "issuer_name_sha256": issuer_hash,
            "error": error_name,
            "message": message,
        })
    print(json.dumps({
        "cases": results,
        "aa_sha256": sha256(aa_der),
        "aa_subject_sha256": sha256(aa.subject.dump()),
        "pyhanko": PYHANKO_VERSION,
        "pyhanko_certvalidator": VALIDATOR_VERSION,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
