"""Fresh native-fixture AC issuer-fetch comparisons; no upstream credit."""

import asyncio
import importlib.metadata
import json
import sys
from datetime import datetime
from pathlib import Path

from asn1crypto import cms, x509
from certomancer.registry import ArchLabel
from freezegun import freeze_time
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import async_validate_pdf_signature
from pyhanko.sign.validation.dss import DocumentSecurityStore
from pyhanko_certvalidator import ValidationContext, validate
from pyhanko_certvalidator.errors import CertificateFetchError
from pyhanko_certvalidator.fetchers.api import CertificateFetcher, Fetchers
from pyhanko_certvalidator.fetchers.requests_fetchers import RequestsFetcherBackend
from pyhanko_certvalidator.policy_decl import (
    AlgorithmUsageConstraint,
    AlgorithmUsagePolicy,
)
from pyhanko_testing_commons.test_data.samples import CERTOMANCER
from pyhanko_testing_commons.test_utils.live_http import live_pki_services

assert importlib.metadata.version("pyhanko") == "0.38.1"
assert importlib.metadata.version("pyhanko-certvalidator") == "0.33.0"

DATA = Path(sys.argv[1])
PKI = DATA / "lanes/d/pki/testing-ca-with-aa"
MANIFEST = json.loads((PKI / "manifest.json").read_text())
DENIAL = "Fetched issuer certificate is forbidden by caller policy"


def certificate(label):
    return x509.Certificate.load((PKI / MANIFEST["certs"][label]["file"]).read_bytes())


class FixedIssuers(CertificateFetcher):
    def __init__(self, candidates, once):
        self.candidates = candidates
        self.once = once
        self.calls = []

    async def fetch_cert_issuers(self, cert):
        self.calls.append(cert.dump())
        if self.once and len(self.calls) > 1:
            raise CertificateFetchError("Test certificate-fetch allowance exhausted")
        for candidate in self.candidates:
            yield candidate

    async def fetch_crl_issuers(self, certificate_list):
        raise AssertionError("The test CRLs have known issuers")
        yield

    def fetched_certs(self):
        return self.candidates if self.calls else []


class DenyFetchedIssuerSignature(AlgorithmUsagePolicy):
    def digest_algorithm_allowed(self, algo, moment):
        return AlgorithmUsageConstraint(allowed=True)

    def signature_algorithm_allowed(self, algo, moment, public_key):
        denied = public_key is not None and public_key.dump() == certificate("root-aa").public_key.dump()
        return AlgorithmUsageConstraint(allowed=not denied, failure_reason=DENIAL if denied else None)


async def execute():
    ac = cms.AttributeCertificateV2.load(
        (DATA / "lanes/r3-p/ac/alice-role-with-rev.der").read_bytes()
    )
    results = {}
    for case in ["allowed", "policy", "holder", "untrusted"]:
        candidates = [certificate("interm-aa")]
        if case == "untrusted":
            candidates.append(certificate("root-aa"))
        issuer_fetcher = FixedIssuers(candidates, once=case != "untrusted")
        backend = RequestsFetcherBackend()
        http = backend.get_fetchers()
        try:
            context = ValidationContext(
                trust_roots=[certificate("root" if case == "untrusted" else "root-aa")],
                other_certs=[certificate("leaf-aa")],
                moment=datetime.fromisoformat("2020-11-01T00:00:00+00:00"),
                revocation_mode="require",
                ocsps=[(DATA / "lanes/r3-p/ac/ocsp-alice-role-with-rev.der").read_bytes()],
                allow_fetching=True,
                fetchers=Fetchers(http.ocsp_fetcher, http.crl_fetcher, issuer_fetcher),
                **({"algorithm_usage_policy": DenyFetchedIssuerSignature()} if case == "policy" else {}),
            )
            try:
                result = await validate.async_validate_ac(
                    ac, context,
                    holder_cert=certificate("signer2" if case == "holder" else "signer1"),
                )
            except Exception as error:
                assert case != "allowed", repr(error)
                if case == "policy":
                    assert DENIAL in str(error), repr(error)
                elif case == "holder":
                    assert "holder" in str(error).lower(), repr(error)
                else:
                    assert "path" in type(error).__name__.lower(), repr(error)
                results[case] = {"accepted": False, "error": type(error).__name__}
            else:
                assert case == "allowed", f"Unexpected accepted AC case: {case}"
                assert "role" in result.approved_attributes
                assert len(result.aa_path) == 3
                assert issuer_fetcher.calls == [certificate("leaf-aa").dump()]
                results[case] = {"accepted": True, "issuer_calls": len(issuer_fetcher.calls)}
        finally:
            await backend.close()
    return results


async def validate_output(path):
    results = {}
    with Path(path).open("rb") as source:
        reader = PdfFileReader(source)
        dss = DocumentSecurityStore.read_dss(reader)
        assert len(dss.certs) == 7
        assert len(dss.ocsps) == 2
        assert len(dss.crls) == 3
        kwargs = dict(
            allow_fetching=False,
            moment=datetime.fromisoformat("2020-11-01T00:00:00+00:00"),
            revocation_mode="require",
        )
        for case, roots in [("pdf_trusted", [certificate("root-aa")]), ("pdf_no_aa_root", [])]:
            # Basic PDF validation does not import DSS certificates by itself.
            # Import only the actual output's evidence as untrusted candidates.
            main = dss.as_validation_context(dict(trust_roots=[certificate("root")], **kwargs))
            aa = dss.as_validation_context(dict(trust_roots=roots, **kwargs))
            status = await async_validate_pdf_signature(
                reader.embedded_signatures[0],
                signer_validation_context=main,
                ac_validation_context=aa,
            )
            assert status.intact and status.valid and status.trusted
            assert status.coverage.name == "ENTIRE_FILE"
            attrs = status.cades_signer_attrs
            assert attrs is not None
            assert not attrs.claimed_attrs
            assert not attrs.unknown_attrs_present
            expected = case == "pdf_trusted"
            assert attrs.valid == expected
            if expected:
                assert status.bottom_line
                assert "CERTIFIED_SIGNER_ATTRS_INVALID" not in status.summary()
                assert len(status.ac_attrs) == 1
                roles = list(status.ac_attrs["role"].attr_values)
                assert len(roles) == 1 and isinstance(roles[0], cms.RoleSyntax)
                assert roles[0]["role_name"].native == "bigboss@example.com"
                assert len(attrs.certified_attrs) == 1
            else:
                assert "CERTIFIED_SIGNER_ATTRS_INVALID" in status.summary()
                assert not status.ac_attrs
                assert len(status.ac_validation_errs) == 1
            results[case] = {"certified_attributes_valid": attrs.valid}
    return results


with freeze_time("2020-11-01"), live_pki_services() as services:
    arch = CERTOMANCER.get_pki_arch(ArchLabel("testing-ca-with-aa"))
    assert arch.get_cert("root-aa").dump() == certificate("root-aa").dump()
    assert arch.get_cert("interm-aa").dump() == certificate("interm-aa").dump()
    services.register(arch)
    result = validate_output(sys.argv[2]) if len(sys.argv) == 3 else execute()
    print(json.dumps(asyncio.run(result), sort_keys=True))
