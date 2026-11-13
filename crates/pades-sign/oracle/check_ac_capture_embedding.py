"""Fresh same-output AC embedding and online public-validation controls.

Frozen raw HTTP bodies prove producer collection; public validation remains
online as in the original Adobe case. No raw AC evidence is preloaded here.
"""

import asyncio
import hashlib
import importlib.metadata
import json
import sys
from io import BytesIO
from pathlib import Path

from asn1crypto import cms, pdf, x509
from certomancer.registry import ArchLabel
from freezegun import freeze_time
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import async_validate_pdf_signature
from pyhanko_certvalidator import ValidationContext
from pyhanko_testing_commons.test_data.samples import CERTOMANCER
from pyhanko_testing_commons.test_utils.live_http import live_pki_services

assert importlib.metadata.version("pyhanko") == "0.38.1"
assert importlib.metadata.version("pyhanko-certvalidator") == "0.33.0"


async def run(directory):
    opened = directory / "output.pdf"
    raw = opened.read_bytes()
    record = json.loads((directory / "receipt.json").read_bytes())
    assert hashlib.sha256(raw).hexdigest() == record["pdf_sha256"]
    assert len(raw) == record["pdf_length"]
    expected = bytes(record["ac_ocsp"])
    received = [row for row in record["http"]
                if row["path"] == "/testing-ca-with-aa/ocsp/leaf-aa" and row["status"] == 200]
    assert len(received) == 1 and bytes(received[0]["response_der"]) == expected
    for row in record["http"]:
        for field in ("request", "response"):
            assert hashlib.sha256(bytes(row[field + "_der"])).hexdigest() == row[field + "_sha256"]
    reader = PdfFileReader(BytesIO(raw))
    signature = reader.embedded_signatures[0]
    assert len(signature.other_embedded_certs) == 5
    assert [ac.dump() for ac in signature.embedded_attr_certs] == [bytes(record["ac"])]
    if record["kind"] == "adobe":
        assert signature.sig_object["/SubFilter"] == "/adbe.pkcs7.detached"
        assert "/DSS" not in reader.root
        attrs = signature.signer_info["signed_attrs"]
        ria = [attr for attr in attrs if attr["type"].dotted == "1.2.840.113583.1.1.8"]
        assert len(ria) == 1
        archival = pdf.RevocationInfoArchival.load(ria[0]["values"][0].dump())
        material = [item.dump() for item in archival["ocsp"]]
    else:
        assert signature.sig_object["/SubFilter"] == "/ETSI.CAdES.detached"
        material = [item.get_object().data for item in reader.root["/DSS"]["/OCSPs"]]
    assert expected in material, "actual HTTP AC OCSP must be embedded"

    root = x509.Certificate.load(bytes(record["root"]))
    aa_root = x509.Certificate.load(bytes(record["aa_root"]))
    results = []
    for trusted in (True, False):
        # Real configured online capability, never manual RIA/DSS injection.
        main = ValidationContext(trust_roots=[root], allow_fetching=True, revocation_mode="require")
        aa = ValidationContext(trust_roots=[aa_root] if trusted else [],
                               allow_fetching=True, revocation_mode="require")
        assert not list(main.ocsps) and not list(aa.ocsps)
        status = await async_validate_pdf_signature(signature, signer_validation_context=main,
                                                    ac_validation_context=aa)
        assert status.intact and status.valid and status.trusted
        if trusted:
            assert status.bottom_line and len(status.ac_attrs) == 1
            roles = list(status.ac_attrs["role"].attr_values)
            assert len(roles) == 1 and isinstance(roles[0], cms.RoleSyntax)
            assert roles[0]["role_name"].native == "bigboss@example.com"
        else:
            assert not status.ac_attrs
            assert len(status.ac_validation_errs) == 1
        results.append({"trusted_aa_root": trusted, "authenticated_role": bool(status.ac_attrs)})
    return {"kind": record["kind"], "opened_path": str(opened.resolve()),
            "pdf_sha256": hashlib.sha256(raw).hexdigest(),
            "actual_ac_ocsp_sha256": hashlib.sha256(expected).hexdigest(),
            "root_sha256": hashlib.sha256(root.dump()).hexdigest(),
            "aa_root_sha256": hashlib.sha256(aa_root.dump()).hexdigest(), "public_validation": results}


with freeze_time("2020-11-01"), live_pki_services() as services:
    architecture = CERTOMANCER.get_pki_arch(ArchLabel("testing-ca-with-aa"))
    services.register(architecture)
    print(json.dumps(asyncio.run(run(Path(sys.argv[1]))), sort_keys=True))
