"""Compare actual native NoRevAvail controls using pinned public AC validation.

Usage: python -I check_ac_no_rev_avail.py MANIFEST.json
The strict Python rule isolates missing-evidence equivalence, not full parity
with Rust's CrlOrOcspRequired policy. No network, PDF or LTA proof is claimed.
"""

import asyncio
import hashlib
import importlib.metadata
import json
from pathlib import Path
import sys
from datetime import datetime

from asn1crypto import cms, core, x509
from cryptography import x509 as crypto_x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pyhanko_certvalidator import ValidationContext, validate
from pyhanko_certvalidator.errors import PathBuildingError, ValidationError
from pyhanko_certvalidator.policy_decl import (
    CertRevTrustPolicy,
    RevocationCheckingPolicy,
    RevocationCheckingRule,
)

VERSIONS = {
    "pyhanko": importlib.metadata.version("pyhanko"),
    "pyhanko_certvalidator": importlib.metadata.version("pyhanko-certvalidator"),
}
assert VERSIONS == {"pyhanko": "0.38.1", "pyhanko_certvalidator": "0.33.0"}
NO_REV_AVAIL = "2.5.29.56"
REVOCATION_LOCATIONS = {"1.3.6.1.5.5.7.1.1", "2.5.29.31", "2.5.29.46"}
EXPECTED = {
    (case, mode): case == "genuine"
    for mode in ("require", "soft-fail")
    for case in ("genuine", "bad-signature", "wrong-holder", "untrusted-aa")
}
EXPECTED[("ordinary-missing-evidence", "require")] = False


def der_bytes(value):
    assert isinstance(value, list)
    assert all(type(byte) is int and 0 <= byte <= 255 for byte in value)
    return bytes(value)


def sha256(value):
    return hashlib.sha256(value).hexdigest()


def signature_valid(ac, key):
    info = ac["ac_info"]
    algorithm = ac["signature_algorithm"]
    assert info["signature"].dump() == algorithm.dump()
    assert algorithm["algorithm"].dotted == "1.2.840.113549.1.1.11"
    try:
        key.verify(
            ac["signature"].native,
            info.dump(),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except InvalidSignature:
        return False
    return True


def assert_no_rev_avail(ac):
    extensions = list(ac["ac_info"]["extensions"])
    assert not any(ext["extn_id"].dotted in REVOCATION_LOCATIONS for ext in extensions)
    matches = [ext for ext in extensions if ext["extn_id"].dotted == NO_REV_AVAIL]
    assert len(matches) == 1
    extension = matches[0]
    assert extension["critical"].native is False
    raw_value = extension["extn_value"].contents
    assert raw_value == b"\x05\x00"
    assert core.Null.load(raw_value, strict=True).native is None


def policy_for(mode):
    # Native "require" uses CrlOrOcspRequired. Both Python rules deliberately
    # demand OCSP for this no-evidence comparison, since the pinned AC process
    # state can classify the AC at a CA index. This is not general policy parity.
    rule = (
        RevocationCheckingRule.OCSP_REQUIRED
        if mode == "require"
        else RevocationCheckingRule.CHECK_IF_DECLARED_SOFT
    )
    return CertRevTrustPolicy(RevocationCheckingPolicy(rule, rule))


async def compare(manifest, aa, key, moment):
    rows = manifest["cases"]
    assert isinstance(rows, list) and len(rows) == 9
    identifiers = [(row["case"], row["mode"]) for row in rows]
    assert len(set(identifiers)) == 9 and set(identifiers) == set(EXPECTED)
    by_id = dict(zip(identifiers, rows))
    genuine_der = der_bytes(by_id[("genuine", "require")]["ac"])
    genuine = cms.AttributeCertificateV2.load(genuine_der, strict=True)
    correct_holder = der_bytes(by_id[("genuine", "require")]["holder"])
    ordinary = cms.AttributeCertificateV2.load(
        der_bytes(by_id[("ordinary-missing-evidence", "require")]["ac"]), strict=True
    )
    assert signature_valid(genuine, key)
    assert_no_rev_avail(genuine)
    ordinary_extensions = list(ordinary["ac_info"]["extensions"])
    assert all(ext["extn_id"].dotted != NO_REV_AVAIL for ext in ordinary_extensions)
    assert any(ext["extn_id"].dotted in REVOCATION_LOCATIONS for ext in ordinary_extensions)
    # Compare supplied ordinary and re-signed ACs without rebuilding either one.
    for field in genuine["ac_info"]:
        if field != "extensions":
            assert genuine["ac_info"][field].dump() == ordinary["ac_info"][field].dump()
    assert [ext.dump() for ext in ordinary_extensions
            if ext["extn_id"].dotted not in REVOCATION_LOCATIONS] == [
                ext.dump() for ext in genuine["ac_info"]["extensions"]
                if ext["extn_id"].dotted != NO_REV_AVAIL
            ]
    results = []
    for row in rows:
        name, mode = row["case"], row["mode"]
        assert type(row["accepted"]) is bool and row["accepted"] == EXPECTED[(name, mode)]
        assert type(row["trusted"]) is bool and row["trusted"] == (name != "untrusted-aa")
        ac_der, holder_der = der_bytes(row["ac"]), der_bytes(row["holder"])
        ac = cms.AttributeCertificateV2.load(ac_der, strict=True)
        holder = x509.Certificate.load(holder_der, strict=True)
        valid_signature = signature_valid(ac, key)
        assert valid_signature == (name != "bad-signature"), (name, mode)
        if name != "ordinary-missing-evidence":
            assert_no_rev_avail(ac)
            if name == "bad-signature":
                assert ac["ac_info"].dump() == genuine["ac_info"].dump()
                assert ac["signature_algorithm"].dump() == genuine["signature_algorithm"].dump()
                signature, original = ac["signature"].native, genuine["signature"].native
                assert len(signature) == len(original)
                assert sum((left ^ right).bit_count() for left, right in zip(signature, original)) == 1
            else:
                assert ac_der == genuine_der
        assert (holder_der != correct_holder) == (name == "wrong-holder")
        context = ValidationContext(
            trust_roots=[aa] if row["trusted"] else [],
            other_certs=[aa],
            moment=moment,
            allow_fetching=False,
            ocsps=[], crls=[],
            revinfo_policy=policy_for(mode),
        )
        errorclass = error_message = None
        try:
            result = await validate.async_validate_ac(ac, context, holder_cert=holder)
        except (PathBuildingError, ValidationError) as error:
            accepted = False
            errorclass, error_message = type(error).__name__, str(error)
        else:
            accepted = True
            assert result.attr_cert.dump() == ac_der
            assert result.aa_cert.dump() == aa.dump()
            assert len(result.aa_path) == 1
            assert list(result.approved_attributes) == ["role"]
            role, = result.approved_attributes["role"]["values"]
            assert role["role_name"].native == "bigboss@example.com"
        finally:
            await context.aclose()
        assert accepted == row["accepted"], (name, mode, accepted, errorclass, error_message)
        if not accepted:
            expected_error = {
                "bad-signature": "InvalidAttrCertificateError",
                "wrong-holder": "InvalidAttrCertificateError",
                "untrusted-aa": "PathBuildingError",
                "ordinary-missing-evidence": "InsufficientRevinfoError",
            }[name]
            assert errorclass == expected_error, (name, mode, errorclass, error_message)
        results.append({
            "case": name, "mode": mode, "accepted": accepted,
            "errorclass": errorclass, "error": error_message,
            "valid_signature": valid_signature,
            "ac_length": len(ac_der), "ac_sha256": sha256(ac_der),
            "holder_length": len(holder_der), "holder_sha256": sha256(holder_der),
        })
    return results


def main():
    if len(sys.argv) != 2:
        raise ValueError("Usage: check_ac_no_rev_avail.py MANIFEST.json")
    path = Path(sys.argv[1]).resolve()
    manifest_bytes = path.read_bytes()
    manifest = json.loads(manifest_bytes)
    aa_der = der_bytes(manifest["aa"])
    aa = x509.Certificate.load(aa_der, strict=True)
    key = crypto_x509.load_der_x509_certificate(aa_der).public_key()
    assert isinstance(key, rsa.RSAPublicKey)
    moment = datetime.fromisoformat(manifest["time"])
    assert moment.tzinfo is not None and moment.utcoffset() is not None
    cases = asyncio.run(compare(manifest, aa, key, moment))
    print(json.dumps({
        "agreements": len(cases), "cases": cases, "versions": VERSIONS,
        "manifest_path": str(path), "manifest_length": len(manifest_bytes),
        "manifest_sha256": sha256(manifest_bytes),
        "aa_length": len(aa_der), "aa_sha256": sha256(aa_der),
    }, sort_keys=True))


if __name__ == "__main__":
    main()
