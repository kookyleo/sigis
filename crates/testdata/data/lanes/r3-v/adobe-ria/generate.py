"""Fixed-time, genuinely signed Adobe RIA PDF inputs with no DSS.

Run using the pinned pyHanko0.38.1 venv. This is a V consumer fixture;
it does not establish correctness of the native P signing implementation.
"""
import asyncio
import hashlib
import json
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path

from asn1crypto import cms, crl, pdf as asn1_pdf
from certomancer.registry import ArchLabel
from freezegun import freeze_time
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import signers, timestamps
from pyhanko.sign.general import simple_cms_attribute
from pyhanko.sign.validation import DocumentSecurityStore
from pyhanko.sign.validation.ades import ades_lta_validation
from pyhanko.sign.validation.errors import NoDSSFoundError
from pyhanko.sign.validation.policy_decl import (
    PdfSignatureValidationSpec, SignatureValidationSpec,
    RevocationInfoGatheringSpec, RevinfoOnlineFetchingRule,
)
from pyhanko_certvalidator.context import CertValidationPolicySpec
from pyhanko_certvalidator.policy_decl import REQUIRE_REVINFO, CertRevTrustPolicy
from pyhanko_certvalidator.registry import SimpleCertificateStore, SimpleTrustManager
from pyhanko_certvalidator.ltv.types import ValidationTimingInfo
from pyhanko_testing_commons.test_data.samples import CERTOMANCER, MINIMAL

OUT = Path(__file__).resolve().parent
CASES = OUT / 'cases'
CASES.mkdir(exist_ok=True)
AT = datetime(2020, 11, 1, tzinfo=UTC)
PKI = CERTOMANCER.get_pki_arch(ArchLabel('testing-ca-with-aa'))
LABELS = ['root', 'interm', 'root-aa', 'interm-aa', 'leaf-aa']
CRLS = [PKI.service_registry.get_crl(info.label, at_time=AT)
        for info in PKI.service_registry.list_crl_repos()]


def tlv(tag, content):
    size = len(content)
    count = (size.bit_length() + 7) // 8
    length = bytes([size]) if size < 128 else bytes([128 + count]) + size.to_bytes(count, 'big')
    return bytes([tag]) + length + content


class FixtureSigner(signers.SimpleSigner):
    def __init__(self, case):
        super().__init__(
            signing_cert=PKI.get_cert('signer1'),
            signing_key=PKI.key_set.get_private_key('signer1'),
            cert_registry=SimpleCertificateStore.from_certs([PKI.get_cert(x) for x in LABELS]),
            attribute_certs=[PKI.get_attr_cert('alice-role-with-rev')],
        )
        self.case = case

    async def signed_attrs(self, *args, **kwargs):
        attrs = await super().signed_attrs(*args, **kwargs)
        if self.case in ['missing', 'unsigned-only']:
            return attrs
        values = list(CRLS)
        if self.case == 'forged-crl':
            values = []
            for item in CRLS:
                changed = bytearray(item.dump())
                changed[-1] ^= 1
                values.append(crl.CertificateList.load(bytes(changed)))
        ria = (asn1_pdf.RevocationInfoArchival.load(b'\x30\x00') if self.case == 'empty'
               else asn1_pdf.RevocationInfoArchival({'crl': values}))
        attr = simple_cms_attribute('adobe_revocation_info_archival', ria)
        if self.case == 'malformed':
            # An INTEGER is not RevocationInfoArchival. Keep the original raw
            # malformed value while genuinely signing the surrounding SET.
            oid = attr['type'].dump()
            attr = cms.CMSAttribute.load(tlv(0x30, oid + tlv(0x31, b'\x02\x01\x01')))
        attrs.append(attr)
        if self.case == 'duplicate':
            attrs.append(attr)
        return attrs

    async def unsigned_attrs(self, *args, **kwargs):
        attrs = await super().unsigned_attrs(*args, **kwargs)
        if self.case == 'unsigned-only':
            attrs = attrs or cms.CMSAttributes()
            attrs.append(simple_cms_attribute(
                'adobe_revocation_info_archival',
                asn1_pdf.RevocationInfoArchival({'crl': list(CRLS)})))
        return attrs


def spec():
    policy = lambda name: CertValidationPolicySpec(
        trust_manager=SimpleTrustManager.build(trust_roots=[PKI.get_cert(name)]),
        revinfo_policy=CertRevTrustPolicy(REQUIRE_REVINFO),
    )
    return PdfSignatureValidationSpec(SignatureValidationSpec(
        cert_validation_policy=policy('root'),
        ac_validation_policy=policy('root-aa'),
        revinfo_gathering_policy=RevocationInfoGatheringSpec(RevinfoOnlineFetchingRule.LOCAL_ONLY),
    ))


async def inspect(case, raw):
    reader = PdfFileReader(BytesIO(raw))
    embedded = reader.embedded_signatures[0]
    try:
        DocumentSecurityStore.read_dss(reader)
        raise AssertionError('Fixture unexpectedly has DSS')
    except NoDSSFoundError:
        pass
    info = {'case': case, 'pdf': f'cases/{case}.pdf', 'sha256': hashlib.sha256(raw).hexdigest(), 'length': len(raw),
            'other_embedded_certs': len(embedded.other_embedded_certs),
            'embedded_attr_certs': len(embedded.embedded_attr_certs), 'dss': False}
    try:
        result = await ades_lta_validation(
            embedded, spec(), timing_info=ValidationTimingInfo(AT, AT, True))
        status = result.api_status
        roles = list(status.ac_attrs['role'].attr_values) if status and status.ac_attrs and 'role' in status.ac_attrs else []
        info.update(subindication=result.ades_subindic.name, bottom_line=status.bottom_line,
                    intact=status.intact, valid=status.valid, trusted=status.trusted,
                    role_names=[x['role_name'].native for x in roles],
                    roles_are_role_syntax=all(isinstance(x, cms.RoleSyntax) for x in roles),
                    best_signature_time=str(result.best_signature_time),
                    failure_msg=result.failure_msg,
                    ac_errors=[str(x) for x in (status.ac_validation_errs or [])])
    except Exception as e:
        info.update(error_type=type(e).__name__, error=str(e))
    return info


async def main():
    cases = {}
    timestamper = timestamps.DummyTimeStamper(
        tsa_cert=PKI.get_cert('tsa'), tsa_key=PKI.key_set.get_private_key('tsa'),
        certs_to_embed=SimpleCertificateStore.from_certs([PKI.get_cert('root')]),
    )
    for case in ['good', 'missing', 'malformed', 'forged-crl', 'empty', 'duplicate', 'unsigned-only']:
        writer = IncrementalPdfFileWriter(BytesIO(MINIMAL))
        output = await signers.async_sign_pdf(
            writer, signers.PdfSignatureMetadata(field_name='Sig1'),
            signer=FixtureSigner(case), timestamper=timestamper,
        )
        raw = output.getvalue()
        (CASES / f'{case}.pdf').write_bytes(raw)
        cases[case] = await inspect(case, raw)
    good = (CASES / 'good.pdf').read_bytes()
    reader = PdfFileReader(BytesIO(good))
    embedded = reader.embedded_signatures[0]
    signature = embedded.signer_info['signature'].native
    changed_signature = bytes([signature[0] ^ 1]) + signature[1:]
    source = signature.hex().upper().encode()
    target = changed_signature.hex().upper().encode()
    assert good.count(source) == 1
    raw = good.replace(source, target)
    (CASES / 'bad-signature.pdf').write_bytes(raw)
    cases['bad-signature'] = await inspect('bad-signature', raw)
    raw = bytearray(good)
    needle = b'%PDF-'
    assert raw.startswith(needle)
    raw[7] = ord('5') if raw[7] != ord('5') else ord('6')
    raw = bytes(raw)
    (CASES / 'tampered-content.pdf').write_bytes(raw)
    cases['tampered-content'] = await inspect('tampered-content', raw)
    ria = next(a['values'][0] for a in embedded.signer_info['signed_attrs']
               if a['type'].native == 'adobe_revocation_info_archival')
    (OUT / 'good-ria.der').write_bytes(ria.dump())
    (OUT / 'good.cms.der').write_bytes(cms.ContentInfo.load(bytes(embedded.pkcs7_content)).dump())
    byte_range = list(embedded.sig_object['/ByteRange'])
    (OUT / 'good-content.bin').write_bytes(b''.join(
        good[int(byte_range[i]):int(byte_range[i]) + int(byte_range[i + 1])]
        for i in range(0, len(byte_range), 2)))
    for label in ['root', 'interm', 'root-aa', 'interm-aa', 'leaf-aa', 'signer1', 'tsa']:
        (OUT / f'{label}.der').write_bytes(PKI.get_cert(label).dump())
    for index, item in enumerate(CRLS):
        (OUT / f'crl-{index}.der').write_bytes(item.dump())
    manifest = {'reference': 'pyHanko0.38.1/certvalidator0.33.0', 'at': AT.isoformat(),
                'revocation_policy': 'REQUIRE_REVINFO', 'online_fetching': False,
                'generator_scope': 'Python consumer fixtures, not native P signing acceptance',
                'determinism': 'Fixed time; fresh timestamp serial/nonce and PDF IDs are frozen after generation',
                'crls': [f'crl-{i}.der' for i in range(len(CRLS))], 'ocsps': [],
                'signed_ria': 'good-ria.der',
                'original_function': 'pyhanko/test_cms.py::test_embed_ac_revinfo_adobe_style',
                'original_fetcher_parameters': ['aiohttp', 'requests'],
                'new_upstream_credit': 0, 'cases': cases,
                'files': {str(p.relative_to(OUT)): {'sha256': hashlib.sha256(p.read_bytes()).hexdigest(),
                                   'length': p.stat().st_size}
                          for p in sorted(OUT.rglob('*')) if p.is_file() and p.suffix in ('.pdf', '.der', '.bin')}}
    (OUT / 'oracle.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    with freeze_time(AT):
        asyncio.run(main())
