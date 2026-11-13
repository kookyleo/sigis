# Derived from pyHanko 0.38.1 tests/test_cms.py (MIT).
"""Fresh exact Adobe AC LTA assertion tail over actual native-produced bytes.

This does not sign or replay a verdict. The backend case is original fixture
provenance: the original validation_spec itself leaves backend selection at its
public default, which this helper preserves rather than silently overriding it.
"""

import asyncio
from hashlib import sha256
from importlib.metadata import version
from io import BytesIO
import json
from pathlib import Path
import sys

from asn1crypto import cms, x509
from certomancer.registry import ArchLabel
from freezegun import freeze_time
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.general import find_unique_cms_attribute
from pyhanko.sign.validation.ades import ades_lta_validation
from pyhanko.sign.validation.policy_decl import (
    PdfSignatureValidationSpec,
    SignatureValidationSpec,
)
from pyhanko_certvalidator.context import CertValidationPolicySpec
from pyhanko_certvalidator.policy_decl import REQUIRE_REVINFO, CertRevTrustPolicy
from pyhanko_certvalidator.registry import SimpleTrustManager
from pyhanko_testing_commons.test_data.samples import CERTOMANCER
from pyhanko_testing_commons.test_utils.live_http import live_pki_services


def specification(root, aa_root):
    # Exact original policy: separate main/AA trust, both REQUIRE_REVINFO.
    # Default NO_HISTORICAL_FETCH still allows current-time online gathering;
    # no explicit backend/local-knowledge/POE override is introduced here.
    return PdfSignatureValidationSpec(
        SignatureValidationSpec(
            cert_validation_policy=CertValidationPolicySpec(
                trust_manager=SimpleTrustManager.build(trust_roots=[root]),
                revinfo_policy=CertRevTrustPolicy(REQUIRE_REVINFO),
            ),
            ac_validation_policy=CertValidationPolicySpec(
                SimpleTrustManager.build(trust_roots=[aa_root]),
                revinfo_policy=CertRevTrustPolicy(REQUIRE_REVINFO),
            ),
        )
    )


def summarize(result):
    status = result.api_status
    if status is None:
        return {
            "bottom_line": False,
            "authenticated_role": False,
            "ades_subindic": result.ades_subindic.standard_name,
        }
    attrs = status.ac_attrs
    roles = [] if attrs is None or "role" not in attrs else list(attrs["role"].attr_values)
    return {
        "bottom_line": status.bottom_line,
        "intact": status.intact,
        "valid": status.valid,
        "trusted": status.trusted,
        "authenticated_role": bool(roles),
        "role_type": None if not roles else type(roles[0]).__name__,
        "role_name": None if not roles else roles[0]["role_name"].native,
        "ades_subindic": result.ades_subindic.standard_name,
        "ac_validation_errors": [str(error) for error in (status.ac_validation_errs or [])],
    }


async def main():
    assert version("pyhanko") == "0.38.1"
    assert version("pyhanko-certvalidator") == "0.33.0"
    pdf_path, root_path, aa_path, ac_path, ac_ocsp_path, backend, at = sys.argv[1:]
    assert backend in ("requests", "aiohttp")
    data = Path(pdf_path).read_bytes()
    root_bytes = Path(root_path).read_bytes()
    aa_bytes = Path(aa_path).read_bytes()
    ac_bytes = Path(ac_path).read_bytes()
    ac_ocsp_bytes = Path(ac_ocsp_path).read_bytes()
    root = x509.Certificate.load(root_bytes, strict=True)
    aa_root = x509.Certificate.load(aa_bytes, strict=True)
    reader = PdfFileReader(BytesIO(data))
    signature = reader.embedded_signatures[0]
    assert signature.field_name == "Sig1"
    assert signature.sig_object["/SubFilter"] == "/adbe.pkcs7.detached"
    # Exact original certificate assertions, plus explicit material identity.
    assert len(signature.other_embedded_certs) == 5
    assert len(signature.embedded_attr_certs) == 1
    assert len(signature.signed_data["certificates"]) == 7
    assert signature.embedded_attr_certs[0].dump() == ac_bytes
    ria = find_unique_cms_attribute(
        signature.signer_info["signed_attrs"], "adobe_revocation_info_archival"
    )
    assert list(ria["crl"])
    assert ac_ocsp_bytes in [response.dump() for response in ria["ocsp"]]
    assert "/DSS" not in reader.root
    result = await ades_lta_validation(signature, specification(root, aa_root))
    status = result.api_status
    # Preserve all original tail assertions, including actual ASN.1 class.
    assert status.bottom_line
    roles = list(status.ac_attrs["role"].attr_values)
    role = roles[0]
    assert isinstance(role, cms.RoleSyntax)
    assert role["role_name"].native == "bigboss@example.com"
    correct = summarize(result)
    # Supplemental no-AA-trust control. A valid main signature cannot grant an
    # authenticated role from an AC with an independently untrusted authority.
    try:
        wrong = await ades_lta_validation(signature, specification(root, root))
        wrong = summarize(wrong)
    except Exception as error:
        wrong = {
            "authenticated_role": False,
            "error_class": type(error).__name__,
            "error": str(error),
        }
    assert wrong["authenticated_role"] is False
    return {
        "kind": "fresh pinned public ades_lta_validation of same native Adobe AC PDF",
        "pyhanko": version("pyhanko"),
        "certvalidator": version("pyhanko-certvalidator"),
        "backend_case": backend,
        "validation_backend": "original public default; no explicit backend override",
        "validation_time": at,
        "pdf_sha256": sha256(data).hexdigest(),
        "root_sha256": sha256(root_bytes).hexdigest(),
        "aa_root_sha256": sha256(aa_bytes).hexdigest(),
        "ac_sha256": sha256(ac_bytes).hexdigest(),
        "adobe_revinfo_sha256": sha256(ria.dump()).hexdigest(),
        "other_certificates": len(signature.other_embedded_certs),
        "attribute_certificates": len(signature.embedded_attr_certs),
        "total_certificates": len(signature.signed_data["certificates"]),
        "correct": correct,
        "wrong_ac_root": wrong,
    }


if __name__ == "__main__":
    with freeze_time(sys.argv[-1], real_asyncio=True), live_pki_services() as services:
        services.register(CERTOMANCER.get_pki_arch(ArchLabel("testing-ca-with-aa")))
        print(json.dumps(asyncio.run(main())))
