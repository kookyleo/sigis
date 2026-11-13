"""Validate actual native-collected DSS material with pinned certvalidator."""

import asyncio
import hashlib
import importlib.metadata
import json
import sys
from datetime import datetime
from collections import Counter
from io import BytesIO

from asn1crypto import cms, x509
from pyhanko.pdf_utils.decode_limits import DecodePurpose
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import DocumentSecurityStore
from pyhanko_certvalidator import validate
from pyhanko_certvalidator.errors import PathBuildingError, PathValidationError

assert importlib.metadata.version("pyhanko") == "0.38.1"
assert importlib.metadata.version("pyhanko-certvalidator") == "0.33.0"
payload = json.load(sys.stdin)
data, ac_der = bytes(payload["pdf"]), bytes(payload["ac"])
assert hashlib.sha256(data).hexdigest() == payload["pdf_sha256"]
assert hashlib.sha256(ac_der).hexdigest() == payload["ac_sha256"]
dss = DocumentSecurityStore.read_dss(PdfFileReader(BytesIO(data)))
assert len(dss.certs) == 3 and len(dss.ocsps) == 1 and len(dss.crls) == 2
for field, refs, purpose in (
    ("certs", dss.certs.values(), DecodePurpose.CERTIFICATE),
    ("ocsps", dss.ocsps, DecodePurpose.OCSP_RESPONSE),
    ("crls", dss.crls, DecodePurpose.CRL),
):
    actual = [ref.get_object().read_data(purpose) for ref in refs]
    assert Counter(actual) == Counter(bytes(v) for v in payload[field]), field


async def check(roots):
    context = dss.as_validation_context({
        "trust_roots": roots,
        "moment": datetime.fromisoformat("2020-11-01T00:00:00+00:00"),
        "allow_fetching": False, "revocation_mode": "require",
    })
    return await validate.async_validate_ac(
        cms.AttributeCertificateV2.load(ac_der, strict=True), context,
        holder_cert=x509.Certificate.load(bytes(payload["holder"]), strict=True),
    )


result = asyncio.run(check([x509.Certificate.load(bytes(payload["root"]), strict=True)]))
assert len(result.aa_path) == 3
assert result.aa_cert.dump() in [bytes(v) for v in payload["certs"]]
assert list(result.approved_attributes) == ["role"]
role, = result.approved_attributes["role"]["values"]
assert role["role_name"].native == "bigboss@example.com"
try:
    asyncio.run(check([]))
except (PathBuildingError, PathValidationError):
    pass
else:
    raise AssertionError("Empty AA roots must not approve the AC")
print(json.dumps({
    "approved": True, "empty_roots_approved": False,
    "role": role["role_name"].native, "pdf_sha256": payload["pdf_sha256"],
    "ac_sha256": payload["ac_sha256"],
    "crl_sha256": [hashlib.sha256(bytes(v)).hexdigest() for v in payload["crls"]],
    "ocsp_sha256": [hashlib.sha256(bytes(v)).hexdigest() for v in payload["ocsps"]],
}))
