"""Fresh public AC validation of the exact native HTTP response bodies."""

import asyncio
import hashlib
import importlib.metadata
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import requests_mock
from asn1crypto import cms, crl, ocsp, x509
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.fetchers.requests_fetchers import RequestsFetcherBackend
from pyhanko_certvalidator.validate import async_validate_ac


async def main():
    assert importlib.metadata.version("pyhanko") == "0.38.1"
    assert importlib.metadata.version("pyhanko-certvalidator") == "0.33.0"
    path = Path(sys.argv[1])
    raw = path.read_bytes()
    record = json.loads(raw)
    ac = cms.AttributeCertificateV2.load(bytes(record["ac"]))
    holder = x509.Certificate.load(bytes(record["holder"]))
    root = x509.Certificate.load(bytes(record["root"]))
    responses = record["http"]
    assert any(row["path"] == "/testing-ca-with-aa/ocsp/leaf-aa" for row in responses)
    for row in responses:
        assert hashlib.sha256(bytes(row["response_der"])).hexdigest() == row["response_sha256"]
        assert hashlib.sha256(bytes(row["request_der"])).hexdigest() == row["request_sha256"]

    def reply(request, context):
        candidates = [row for row in responses if row["method"] == request.method
                      and row["path"] == urlsplit(request.url).path]
        if request.method == "POST":
            query = ocsp.OCSPRequest.load(request.body)
            cert_id = query["tbs_request"]["request_list"][0]["req_cert"].dump()
            candidates = [row for row in candidates if bytes(row["cert_id_der"]) == cert_id]
        assert candidates, f"oracle requested evidence outside the native receipt: {request.url}"
        selected = candidates[0]
        assert all((row["status"], row["response_der"]) ==
                   (selected["status"], selected["response_der"]) for row in candidates)
        context.status_code = selected["status"]
        context.headers["Content-Type"] = ("application/ocsp-response" if request.method == "POST"
                                            else "application/pkix-crl")
        return bytes(selected["response_der"])

    backend = RequestsFetcherBackend()
    try:
        with requests_mock.Mocker() as mock:
            mock.register_uri(requests_mock.ANY, requests_mock.ANY, content=reply)
            ctx = ValidationContext(
                trust_roots=[root],
                other_certs=[x509.Certificate.load(bytes(cert)) for cert in record["authorities"]],
                moment=datetime(2020, 11, 1, tzinfo=timezone.utc),
                allow_fetching=True, revocation_mode="require", fetchers=backend.get_fetchers(),
            )
            try:
                result = await async_validate_ac(ac, ctx, holder_cert=holder)
            except Exception as error:
                verdict = {"accepted": False, "class": type(error).__name__, "message": str(error)}
            else:
                attrs = result.approved_attributes
                roles = attrs["role"]["values"]
                assert len(roles) == 1
                assert roles[0]["role_name"].native == "bigboss@example.com"
                verdict = {"accepted": True, "role": roles[0]["role_name"].native}
        assert verdict["accepted"] == record["native_accepted"], verdict
        if record["case"] == "forged_crl":
            assert "CRL signature could not be verified" in verdict["message"], verdict
        verdict.update(case=record["case"], opened_path=str(path.resolve()),
                       input_sha256=hashlib.sha256(raw).hexdigest(), length=len(raw))
        print(json.dumps(verdict, sort_keys=True))
    finally:
        await backend.close()


asyncio.run(main())
