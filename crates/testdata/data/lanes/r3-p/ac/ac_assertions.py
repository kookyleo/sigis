# SPDX-License-Identifier: MIT
# Derived from pyHanko 0.38.1, copyright (c) 2020-2026 Matthias Valvekens.
# See LICENSE-pyHanko and ac-assertions-source.json in this directory.
"""Exact post-signing assertion tails for freshly generated Rust AC PDFs.

No upstream source checkout is needed when this fixture executes.
"""

import asyncio
import importlib.metadata
import json
import sys
from io import BytesIO
from pathlib import Path

from asn1crypto import cms
from certomancer.registry import ArchLabel, CertLabel
from freezegun import freeze_time
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import async_validate_pdf_signature
from pyhanko.sign.validation.ades import ades_lta_validation
from pyhanko.sign.validation.policy_decl import (
    PdfSignatureValidationSpec,
    SignatureValidationSpec,
)
from pyhanko_certvalidator import ValidationContext
from pyhanko_certvalidator.context import CertValidationPolicySpec
from pyhanko_certvalidator.policy_decl import REQUIRE_REVINFO, CertRevTrustPolicy
from pyhanko_certvalidator.registry import SimpleTrustManager
from pyhanko_testing_commons.test_data.samples import CERTOMANCER
from pyhanko_testing_commons.test_utils.live_http import live_pki_services

assert importlib.metadata.version("pyhanko") == "0.38.1"
assert importlib.metadata.version("pyhanko-certvalidator") == "0.33.0"

def live_ac_vcs(pki_services, with_authorities=False):
    pki_arch = CERTOMANCER.get_pki_arch(ArchLabel('testing-ca-with-aa'))
    if with_authorities:
        other_certs = [
            pki_arch.get_cert('interm'),
            pki_arch.get_cert('interm-aa'),
            pki_arch.get_cert('leaf-aa'),
        ]
    else:
        other_certs = []
    main_vc = ValidationContext(
        trust_roots=[pki_arch.get_cert(CertLabel('root'))],
        allow_fetching=True,
        other_certs=other_certs,
    )
    ac_vc = ValidationContext(
        trust_roots=[pki_arch.get_cert(CertLabel('root-aa'))],
        allow_fetching=True,
        other_certs=other_certs,
    )
    pki_services.register(pki_arch)
    return main_vc, ac_vc


async def test_pades_live_ac_presign_validation():
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    # 4 CA certs, 1 AA certs, 1 AC, 1 signer cert, 1 TSA cert,
    # 1 OCSP responder cert -> 9 certs total
    # 7 (4 CA + 1 AA + 1 AC + 1 signer) are in the CMS payload
    assert len(s.other_embedded_certs) == 5
    assert len(s.embedded_attr_certs) == 1
    dss = r.root['/DSS']
    assert len(dss['/Certs']) == 8  # no ACs here, but OCSP and TSA are present
    assert len(dss['/OCSPs']) == 2  # signer + AC (leaf-aa has OCSP)
    assert len(dss['/CRLs']) == 3  # root, interm-aa, root-aa

    trust_manager = SimpleTrustManager.build(
        trust_roots=[pki_arch.get_cert('root')],
    )
    ac_trust_manager = SimpleTrustManager.build(
        trust_roots=[pki_arch.get_cert('root-aa')],
    )
    validation_spec = PdfSignatureValidationSpec(
        SignatureValidationSpec(
            cert_validation_policy=CertValidationPolicySpec(
                trust_manager=trust_manager,
                revinfo_policy=CertRevTrustPolicy(REQUIRE_REVINFO),
            ),
            ac_validation_policy=CertValidationPolicySpec(
                ac_trust_manager,
                revinfo_policy=CertRevTrustPolicy(REQUIRE_REVINFO),
            ),
        )
    )
    ades_status = await ades_lta_validation(s, validation_spec)
    status = ades_status.api_status
    assert status.bottom_line
    roles = list(status.ac_attrs['role'].attr_values)
    role = roles[0]
    assert isinstance(role, cms.RoleSyntax)
    assert len(status.ac_attrs) == 1
    assert role['role_name'].native == 'bigboss@example.com'


async def test_pades_lta_live_ac_presign_validation():
    with freeze_time('2028-02-01'):
        r = PdfFileReader(out)
        s = r.embedded_signatures[0]
        trust_manager = SimpleTrustManager.build(
            trust_roots=[pki_arch.get_cert('root')],
        )
        ac_trust_manager = SimpleTrustManager.build(
            trust_roots=[pki_arch.get_cert('root-aa')],
        )
        validation_spec = PdfSignatureValidationSpec(
            SignatureValidationSpec(
                cert_validation_policy=CertValidationPolicySpec(
                    trust_manager=trust_manager,
                    revinfo_policy=CertRevTrustPolicy(REQUIRE_REVINFO),
                ),
                ac_validation_policy=CertValidationPolicySpec(
                    ac_trust_manager,
                    revinfo_policy=CertRevTrustPolicy(REQUIRE_REVINFO),
                ),
            )
        )
        ades_status = await ades_lta_validation(s, validation_spec)
        status = ades_status.api_status
        assert status.bottom_line
        roles = list(status.ac_attrs['role'].attr_values)
        role = roles[0]
        assert isinstance(role, cms.RoleSyntax)
        assert len(status.ac_attrs) == 1
        assert role['role_name'].native == 'bigboss@example.com'


async def test_cades_signer_attrs_autofill_dss():
    r = PdfFileReader(out)
    # 4 CA certs, 1 AA certs, 1 signer cert, 1 OCSP responder cert -> 7 certs
    dss = r.root['/DSS']
    assert len(dss['/Certs']) == 7


async def test_cades_signer_attrs_validate_acs():
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert len(s.embedded_attr_certs) == 0  # nothing here
    main_vc, ac_vc = live_ac_vcs(pki_services)
    status = await async_validate_pdf_signature(
        s, signer_validation_context=main_vc, ac_validation_context=ac_vc
    )
    assert status.bottom_line
    # this one was only 'claimed'
    assert 'group' not in status.ac_attrs
    roles = list(status.ac_attrs['role'].attr_values)
    role = roles[0]
    assert isinstance(role, cms.RoleSyntax)
    assert role['role_name'].native == 'bigboss@example.com'

    # also perform checks for the CAdES signer attrs info
    cades_signer_attrs = status.cades_signer_attrs
    assert cades_signer_attrs is not None
    assert len(cades_signer_attrs.claimed_attrs) == 1
    assert len(cades_signer_attrs.certified_attrs) == 1

    # claimed attrs
    assert 'role' not in cades_signer_attrs.claimed_attrs
    (all_values,) = iter(cades_signer_attrs.claimed_attrs)
    assert all_values == cades_signer_attrs.claimed_attrs['group']
    (groups_ietf_attr,) = iter(all_values.attr_values)
    assert isinstance(groups_ietf_attr, cms.IetfAttrSyntax)
    groups = groups_ietf_attr['values']
    assert set(groups.native) == {'Executives', 'Employees'}

    # certified attrs
    assert 'group' not in cades_signer_attrs.certified_attrs
    roles = list(cades_signer_attrs.certified_attrs['role'].attr_values)
    role = roles[0]
    assert isinstance(role, cms.RoleSyntax)
    assert role['role_name'].native == 'bigboss@example.com'


async def test_cades_signer_attrs_validate_acs_no_claimed():
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert len(s.embedded_attr_certs) == 0  # nothing here
    main_vc, ac_vc = live_ac_vcs(pki_services)
    status = await async_validate_pdf_signature(
        s, signer_validation_context=main_vc, ac_validation_context=ac_vc
    )
    assert status.bottom_line
    assert 'CERTIFIED_SIGNER_ATTRS_INVALID' not in status.summary()
    # this one was only 'claimed'
    roles = list(status.ac_attrs['role'].attr_values)
    role = roles[0]
    assert isinstance(role, cms.RoleSyntax)
    assert role['role_name'].native == 'bigboss@example.com'

    # also perform checks for the CAdES signer attrs info
    cades_signer_attrs = status.cades_signer_attrs
    assert cades_signer_attrs is not None
    assert not cades_signer_attrs.claimed_attrs
    assert len(cades_signer_attrs.certified_attrs) == 1

    roles = list(cades_signer_attrs.certified_attrs['role'].attr_values)
    role = roles[0]
    assert isinstance(role, cms.RoleSyntax)
    assert role['role_name'].native == 'bigboss@example.com'
    assert not cades_signer_attrs.unknown_attrs_present


async def test_cades_signer_attrs_validate_acs_wrong_vc():
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert len(s.embedded_attr_certs) == 0  # nothing here
    main_vc, ac_vc = live_ac_vcs(pki_services)

    # validate with the wrong AC VC
    status = await async_validate_pdf_signature(
        s, signer_validation_context=main_vc, ac_validation_context=main_vc
    )

    assert not status.cades_signer_attrs.valid
    assert 'CERTIFIED_SIGNER_ATTRS_INVALID' in status.summary()

    assert len(status.ac_attrs) == 0

    # also perform checks for the CAdES signer attrs info
    cades_signer_attrs = status.cades_signer_attrs
    assert cades_signer_attrs is not None
    assert len(cades_signer_attrs.claimed_attrs) == 1
    assert len(cades_signer_attrs.certified_attrs) == 0
    assert len(status.ac_validation_errs) == 1
    assert len(cades_signer_attrs.ac_validation_errs) == 1
    assert not cades_signer_attrs.unknown_attrs_present


async def test_cades_signer_attrs_validate_acs_missing_vc():
    r = PdfFileReader(out)
    s = r.embedded_signatures[0]
    assert len(s.embedded_attr_certs) == 0  # nothing here
    main_vc, _ = live_ac_vcs(pki_services)

    # validate with the wrong AC VC
    status = await async_validate_pdf_signature(
        s,
        signer_validation_context=main_vc,
    )

    # this should _not_ fail validation, since we've indicated that we don't
    # care about ACs
    assert status.bottom_line
    assert 'CERTIFIED_SIGNER_ATTRS_INVALID' not in status.summary()
    assert status.ac_attrs is None

    cades_signer_attrs = status.cades_signer_attrs
    assert cades_signer_attrs is not None
    assert len(cades_signer_attrs.claimed_attrs) == 1
    assert cades_signer_attrs.certified_attrs is None
    assert status.ac_validation_errs is None
    assert cades_signer_attrs.ac_validation_errs is None


ASSERTION_COUNTS = {'test_pades_live_ac_presign_validation': 9, 'test_pades_lta_live_ac_presign_validation': 4, 'test_cades_signer_attrs_autofill_dss': 1, 'test_cades_signer_attrs_validate_acs': 15, 'test_cades_signer_attrs_validate_acs_no_claimed': 11, 'test_cades_signer_attrs_validate_acs_wrong_vc': 10, 'test_cades_signer_attrs_validate_acs_missing_vc': 9}

def main():
    if sys.argv[1:] == ["--list"]:
        print(json.dumps(ASSERTION_COUNTS, sort_keys=True))
        return
    name, output, backend = sys.argv[1:]
    if name not in ASSERTION_COUNTS or backend not in {"requests", "aiohttp"}:
        raise ValueError("Unknown exact AC case or fetcher backend")
    with freeze_time("2020-11-01"), live_pki_services() as services:
        arch = CERTOMANCER.get_pki_arch(ArchLabel("testing-ca-with-aa"))
        services.register(arch)
        globals().update(
            pki_arch=arch,
            pki_services=services,
            out=BytesIO(Path(output).read_bytes()),
        )
        if backend == "aiohttp":
            from pyhanko_certvalidator.fetchers.aiohttp_fetchers import AIOHttpFetcherBackend
            fetcher_backend = AIOHttpFetcherBackend()
        else:
            from pyhanko_certvalidator.fetchers.requests_fetchers import RequestsFetcherBackend
            fetcher_backend = RequestsFetcherBackend()
        async def execute():
            try:
                globals()["fetchers"] = fetcher_backend.get_fetchers()
                await globals()[name]()
            finally:
                await fetcher_backend.close()
        asyncio.run(execute())
    print("PASS exact upstream assertions", name, backend)


if __name__ == "__main__":
    main()
