"""Fresh pinned AC revocation-fetch comparisons; no upstream function credit."""

import asyncio
import hashlib
import importlib.metadata
import json
import sys
from datetime import datetime
from pathlib import Path

from asn1crypto import cms, crl, ocsp, x509
from certomancer.registry import ArchLabel
from freezegun import freeze_time
from pyhanko_certvalidator import ValidationContext, validate
from pyhanko_certvalidator.errors import (
    CRLFetchError,
    InsufficientRevinfoError,
    OCSPFetchError,
)
from pyhanko_certvalidator.fetchers.api import CRLFetcher, Fetchers, OCSPFetcher
from pyhanko_certvalidator.fetchers.requests_fetchers import RequestsFetcherBackend
from pyhanko_testing_commons.test_data.samples import CERTOMANCER
from pyhanko_testing_commons.test_utils.live_http import live_pki_services

assert importlib.metadata.version("pyhanko") == "0.38.1"
assert importlib.metadata.version("pyhanko-certvalidator") == "0.33.0"

DATA = Path(sys.argv[1])
PKI = DATA / "lanes/d/pki/testing-ca-with-aa"
REVINFO = DATA / "lanes/d/revinfo/testing-ca-with-aa/2020-11-01"
MANIFEST = json.loads((PKI / "manifest.json").read_text())
AC_DER = (DATA / "lanes/r3-p/ac/alice-role-with-rev.der").read_bytes()
GOOD_OCSP = (DATA / "lanes/r3-p/ac/ocsp-alice-role-with-rev.der").read_bytes()
WRONG_OCSP = (REVINFO / "ocsp-signer1.der").read_bytes()
FALLBACK_CRL = (REVINFO / "crl-leaf-aa.der").read_bytes()
AC = cms.AttributeCertificateV2.load(AC_DER)
MODE = sys.argv[2] if len(sys.argv) > 2 else "require"
assert MODE in {"require", "soft-fail", "none"}, MODE
CASE_EXPECTATIONS = {
    "good_ocsp": True,
    "malformed_ocsp": False,
    "wrong_target_ocsp": False,
    "transport_crl_fallback": True,
    "missing_all": False,
    "tampered_ocsp": False,
    "mixed_crl_batch": True,
    "bad_signature_crl": False,
}
if MODE in {"soft-fail", "none"}:
    # Pinned soft-fail tolerates the CRL transport failures after unusable
    # OCSP, and tolerates the OCSP transport failure with an invalid CRL.
    # Keep these verdict differences explicit; they are not require-mode
    # rejection assertions and do not authenticate those unusable responses.
    CASE_EXPECTATIONS = {case: True for case in CASE_EXPECTATIONS}


def certificate(label):
    return x509.Certificate.load((PKI / MANIFEST["certs"][label]["file"]).read_bytes())


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def tampered_ocsp():
    response = ocsp.OCSPResponse.load(GOOD_OCSP, strict=True)
    original = response["response_bytes"]["response"].parsed
    changed = original.copy()
    signature = bytearray(original["signature"].native)
    signature[0] ^= 1
    changed["signature"] = bytes(signature)
    response["response_bytes"]["response"] = changed
    payload = response.dump()
    decoded = ocsp.OCSPResponse.load(payload, strict=True)["response_bytes"]["response"].parsed
    assert decoded["signature"].native == bytes(signature)
    assert decoded["signature"].native != original["signature"].native
    for field in ["tbs_response_data", "signature_algorithm", "certs"]:
        assert decoded[field].dump() == original[field].dump(), field
    return payload


def tampered_crl():
    original = crl.CertificateList.load(FALLBACK_CRL, strict=True)
    changed = original.copy()
    signature = bytearray(original["signature"].native)
    signature[0] ^= 1
    changed["signature"] = bytes(signature)
    decoded = crl.CertificateList.load(changed.dump(), strict=True)
    assert decoded["signature"].native == bytes(signature)
    assert decoded["signature"].native != original["signature"].native
    for field in ["tbs_cert_list", "signature_algorithm"]:
        assert decoded[field].dump() == original[field].dump(), field
    return decoded


def check_ac_request(cert):
    assert isinstance(cert, cms.AttributeCertificateV2), type(cert)
    assert cert.dump() == AC_DER, "Fetcher must receive the actual AC, not its holder PKC"
    # CRLFetcher.fetch has no authority parameter; verify the issuer encoded in
    # the actual AC as well as its complete DER. OCSP also checks the authority.
    issuer = cert["ac_info"]["issuer"].chosen["issuer_name"]
    names = [name.chosen for name in issuer if name.name == "directory_name"]
    assert len(names) == 1
    assert names[0].untag().dump() == certificate("leaf-aa").subject.dump()


class AcOCSPFetcher(OCSPFetcher):
    def __init__(self, delegate, case):
        self.delegate = delegate
        self.case = case
        self.calls = []
        self.pkc_calls = []
        self.cached = []
        self.outcome = None

    async def fetch(self, cert, authority):
        if isinstance(cert, x509.Certificate):
            self.pkc_calls.append(cert.dump())
            return await self.delegate.fetch(cert, authority)
        check_ac_request(cert)
        issuer = authority.certificate
        assert issuer.dump() == certificate("leaf-aa").dump()
        assert authority.name.dump() == issuer.subject.dump()
        assert authority.public_key.dump() == issuer.public_key.dump()
        self.calls.append((cert.dump(), issuer.dump()))
        if self.case in {
            "transport_crl_fallback", "missing_all", "mixed_crl_batch", "bad_signature_crl"
        }:
            self.outcome = "transport_error"
            raise OCSPFetchError("Test AC OCSP transport unavailable")
        payload = {
            "good_ocsp": GOOD_OCSP,
            "malformed_ocsp": b"bad",
            "wrong_target_ocsp": WRONG_OCSP,
            "tampered_ocsp": tampered_ocsp(),
        }[self.case]
        try:
            response = ocsp.OCSPResponse.load(payload, strict=True)
            # ASN.1 parsing is lazy; force decoding before returning the object.
            response.native
        except ValueError as error:
            # RequestsOCSPFetcher likewise converts malformed response bytes
            # into OCSPFetchError; do not return bytes through an ASN.1 API.
            self.outcome = "malformed_response"
            raise OCSPFetchError("Test AC OCSP response is malformed") from error
        self.outcome = {
            "wrong_target_ocsp": "wrong_target_response",
            "tampered_ocsp": "tampered_signature_response",
        }.get(self.case, "good_response")
        self.cached.append(response)
        return response

    def fetched_responses(self):
        return [*self.delegate.fetched_responses(), *self.cached]

    def fetched_responses_for_cert(self, cert):
        if isinstance(cert, x509.Certificate):
            return self.delegate.fetched_responses_for_cert(cert)
        check_ac_request(cert)
        return list(self.cached)


class AcCRLFetcher(CRLFetcher):
    def __init__(self, delegate, case):
        self.delegate = delegate
        self.case = case
        self.calls = []
        self.pkc_calls = []
        self.cached = None

    async def fetch(self, cert, *, use_deltas=None):
        if isinstance(cert, x509.Certificate):
            self.pkc_calls.append(cert.dump())
            return await self.delegate.fetch(cert, use_deltas=use_deltas)
        check_ac_request(cert)
        self.calls.append(cert.dump())
        if self.case not in {"transport_crl_fallback", "mixed_crl_batch", "bad_signature_crl"}:
            raise CRLFetchError("Test AC CRL transport unavailable")
        value = crl.CertificateList.load(FALLBACK_CRL, strict=True)
        assert value.issuer.dump() == certificate("leaf-aa").subject.dump()
        self.cached = [value]
        if self.case == "mixed_crl_batch":
            self.cached.append(crl.CertificateList.load((REVINFO / "crl-root.der").read_bytes(), strict=True))
        elif self.case == "bad_signature_crl":
            self.cached = [tampered_crl()]
        return list(self.cached)

    def fetched_crls(self):
        return [*self.delegate.fetched_crls(), *(self.cached or [])]

    def fetched_crls_for_cert(self, cert):
        if isinstance(cert, x509.Certificate):
            return self.delegate.fetched_crls_for_cert(cert)
        check_ac_request(cert)
        if self.cached is None:
            raise KeyError(cert.dump())
        return list(self.cached)


async def execute():
    results = {}
    for case, expected in CASE_EXPECTATIONS.items():
        backend = RequestsFetcherBackend()
        http = backend.get_fetchers()
        ocsp_fetcher = AcOCSPFetcher(http.ocsp_fetcher, case)
        crl_fetcher = AcCRLFetcher(http.crl_fetcher, case)
        try:
            context = ValidationContext(
                trust_roots=[certificate("root-aa")],
                other_certs=[certificate("interm-aa"), certificate("leaf-aa")],
                moment=datetime.fromisoformat("2020-11-01T00:00:00+00:00"),
                revocation_mode=MODE,
                allow_fetching=True,
                fetchers=Fetchers(ocsp_fetcher, crl_fetcher, http.cert_fetcher),
            )
            # No AC revocation evidence is preloaded in this context.
            assert not context.ocsps and not context.crls
            try:
                result = await validate.async_validate_ac(
                    AC, context, holder_cert=certificate("signer1")
                )
            except InsufficientRevinfoError as error:
                assert not expected, f"{case}: {error}"
                message = str(error)
                if case == "tampered_ocsp":
                    assert "Unable to verify OCSP response signature" in message, message
                    assert "Test AC CRL transport unavailable" in message, message
                elif case == "bad_signature_crl":
                    assert "CRL signature could not be verified" in message, message
                else:
                    # Pinned upstream describes this appended AC as intermediate
                    # certificate 4, and loses fetch-failure details here.
                    assert message.strip() == (
                        "The path could not be validated because no revocation "
                        "information could be found for intermediate certificate 4"
                    ), (case, message)
                decision = {
                    "accepted": False,
                    "error": type(error).__name__,
                    "message": message,
                }
            else:
                assert expected, f"Unexpected acceptance: {case}"
                assert len(result.aa_path) == 3
                assert result.aa_cert.dump() == certificate("leaf-aa").dump()
                assert len(result.approved_attributes) == 1
                roles = result.approved_attributes["role"]["values"]
                assert len(roles) == 1 and isinstance(roles[0], cms.RoleSyntax)
                assert roles[0]["role_name"].native == "bigboss@example.com"
                decision = {"accepted": True, "error": None, "message": None}
            if MODE == "none":
                assert not ocsp_fetcher.calls and not crl_fetcher.calls
                assert not ocsp_fetcher.pkc_calls and not crl_fetcher.pkc_calls
            else:
                assert len(ocsp_fetcher.calls) == 1, (case, ocsp_fetcher.calls)
                assert len(crl_fetcher.calls) == (0 if case == "good_ocsp" else 1)
                assert crl_fetcher.pkc_calls, "AA PKC revocation must use delegated HTTP fetching"
            decision.update(
                revocation_mode=MODE,
                ac_ocsp_calls=len(ocsp_fetcher.calls),
                ac_crl_calls=len(crl_fetcher.calls),
                ac_sha256=sha256(AC_DER),
                ocsp_issuer_sha256=[sha256(issuer) for _, issuer in ocsp_fetcher.calls],
                pkc_ocsp_calls=len(ocsp_fetcher.pkc_calls),
                pkc_crl_calls=len(crl_fetcher.pkc_calls),
                ac_ocsp_outcome=ocsp_fetcher.outcome,
            )
            results[case] = decision
        finally:
            await backend.close()
    return results


with freeze_time("2020-11-01"), live_pki_services() as services:
    arch = CERTOMANCER.get_pki_arch(ArchLabel("testing-ca-with-aa"))
    for label in ["root-aa", "interm-aa", "leaf-aa", "signer1"]:
        assert arch.get_cert(label).dump() == certificate(label).dump()
    services.register(arch)
    print(json.dumps(asyncio.run(execute()), sort_keys=True))
