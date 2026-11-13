"""Additional Adobe RIA OCSP and enclosing DocTS inputs; original snapshot untouched."""
import asyncio
import dataclasses
import hashlib
import json
import sys

sys.dont_write_bytecode = True
from datetime import timedelta
from io import BytesIO
from pathlib import Path

from asn1crypto import cms, ocsp, pdf as asn1_pdf
from freezegun import freeze_time
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import signers, timestamps
from pyhanko.sign.general import simple_cms_attribute
from pyhanko.sign.validation import DocumentSecurityStore
from pyhanko.sign.validation.ades import (
    ades_lta_validation,
    _adobe_revinfo_archival_to_local_knowledge,
    _build_prima_facie_poe_index_from_pdf_timestamps,
    _validate_prima_facie_poe,
)
from pyhanko.sign.validation.errors import NoDSSFoundError
from pyhanko_certvalidator.authority import AuthorityWithCert
from pyhanko_certvalidator.fetchers.common_utils import format_ocsp_request
from pyhanko_certvalidator.ltv.types import ValidationTimingInfo
from pyhanko_certvalidator.registry import SimpleCertificateStore
import generate as base

OUT = base.OUT / 'additional'
OUT.mkdir(exist_ok=True)
LATER = base.AT + timedelta(days=1)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read_dss(reader):
    try:
        DocumentSecurityStore.read_dss(reader)
        return True
    except NoDSSFoundError:
        return False


def timestamp_backend():
    return timestamps.DummyTimeStamper(
        tsa_cert=base.PKI.get_cert('tsa'), tsa_key=base.PKI.key_set.get_private_key('tsa'),
        certs_to_embed=SimpleCertificateStore.from_certs([base.PKI.get_cert('root')]),
    )


class OcspFixtureSigner(base.FixtureSigner):
    def __init__(self, response):
        super().__init__('missing')
        self.response = response

    async def signed_attrs(self, *args, **kwargs):
        attrs = await super().signed_attrs(*args, **kwargs)
        # The final leaf-AA CRL is the only AC-target CRL and is excluded:
        # an invalid AC OCSP cannot fall back to genuine AC CRL evidence.
        ria = asn1_pdf.RevocationInfoArchival({'crl': list(base.CRLS[:-1]),
                                             'ocsp': [self.response]})
        attrs.append(simple_cms_attribute('adobe_revocation_info_archival', ria))
        return attrs


async def inspect(name, raw, at):
    reader = PdfFileReader(BytesIO(raw))
    main = reader.embedded_regular_signatures[0]
    dts = reader.embedded_timestamp_signatures
    result = await ades_lta_validation(main, base.spec(),
        timing_info=ValidationTimingInfo(at, at, True))
    status = result.api_status
    roles = list(status.ac_attrs['role'].attr_values) if status and status.ac_attrs and 'role' in status.ac_attrs else []
    info = {'pdf': f'additional/{name}.pdf', 'sha256': sha(raw), 'length': len(raw),
            'validation_time': at.isoformat(), 'dss': read_dss(reader),
            'subindication': result.ades_subindic.name,
            'bottom_line': status.bottom_line, 'intact': status.intact,
            'valid': status.valid, 'trusted': status.trusted,
            'role_names': [x['role_name'].native for x in roles],
            'roles_are_role_syntax': all(isinstance(x, cms.RoleSyntax) for x in roles),
            'best_signature_time': str(result.best_signature_time),
            'failure_msg': result.failure_msg,
            'ac_errors': [str(x) for x in (status.ac_validation_errs or [])],
            'document_timestamp_count': len(dts)}
    # Actual pinned ER validation, not publishing an unvalidated prima-facie
    # timestamp. Do not query manager[crl], which invents a current-time entry.
    candidates = _build_prima_facie_poe_index_from_pdf_timestamps(reader, include_content_ts=True, diff_policy=None)
    signature_spec = base.spec().signature_validation_spec
    ria = _adobe_revinfo_archival_to_local_knowledge(main)
    signature_spec = dataclasses.replace(signature_spec, local_knowledge=ria)
    try:
        proofs = await _validate_prima_facie_poe(candidates, signature_spec,
            cur_timing_info=ValidationTimingInfo(at, at, True))
        actual = {x.digest: x for x in proofs}
        info['authenticated_ria_crl_poes'] = [
            {'sha256': sha(item.dump()), 'time': actual[hashlib.sha256(item.dump()).digest()].poe_time.isoformat(),
             'type': actual[hashlib.sha256(item.dump()).digest()].poe_type.name}
            for item in base.CRLS if hashlib.sha256(item.dump()).digest() in actual]
        info['poe_validation_error'] = None
    except Exception as error:
        info['authenticated_ria_crl_poes'] = []
        info['poe_validation_error'] = {'type': type(error).__name__, 'message': str(error)}
    return info


async def main():
    original_files = {str(x.relative_to(base.OUT)): sha(x.read_bytes())
        for x in base.OUT.rglob('*') if x.is_file()
        and 'additional' not in x.relative_to(base.OUT).parts
        and '__pycache__' not in x.relative_to(base.OUT).parts
        and x.name not in ['generate_additional.py', 'additional-oracle.json']}
    original_good = (base.OUT / 'cases/good.pdf').read_bytes()
    request = format_ocsp_request(base.PKI.get_attr_cert('alice-role-with-rev'),
        AuthorityWithCert(base.PKI.get_cert('leaf-aa')), certid_hash_algo='sha256', request_nonces=False)
    response = base.PKI.service_registry.summon_responder('leaf-aa', at_time=base.AT).build_ocsp_response(request)
    (OUT / 'ac-good.ocsp.der').write_bytes(response.dump())
    (OUT / 'ac-request.der').write_bytes(request.dump())
    broken = response.copy()
    basic = broken['response_bytes']['response'].parsed
    signature = basic['signature'].native
    basic['signature'] = bytes([signature[0] ^ 1]) + signature[1:]
    broken['response_bytes']['response'] = basic
    (OUT / 'ac-forged.ocsp.der').write_bytes(broken.dump())
    cases = {}
    with freeze_time(base.AT):
        for name, item in [('ocsp-good', response), ('ocsp-forged', broken)]:
            output = await signers.async_sign_pdf(
                IncrementalPdfFileWriter(BytesIO(base.MINIMAL)),
                signers.PdfSignatureMetadata(field_name='Sig1'),
                signer=OcspFixtureSigner(item), timestamper=timestamp_backend())
            raw = output.getvalue()
            (OUT / f'{name}.pdf').write_bytes(raw)
            cases[name] = await inspect(name, raw, base.AT)
    with freeze_time(LATER):
        output = await signers.PdfTimeStamper(timestamp_backend(), field_name='DocTS').async_timestamp_pdf(
            IncrementalPdfFileWriter(BytesIO(original_good)), 'sha256', validation_context=None)
        raw = output.getvalue()
        assert raw.startswith(original_good)
        (OUT / 'enclosing-good.pdf').write_bytes(raw)
        cases['enclosing-good'] = await inspect('enclosing-good', raw, LATER)
        reader = PdfFileReader(BytesIO(raw))
        dts = reader.embedded_timestamp_signatures[0]
        signature = dts.signer_info['signature'].native
        original = signature.hex().upper().encode()
        modified = (bytes([signature[0] ^ 1]) + signature[1:]).hex().upper().encode()
        assert raw.count(original) == 1
        bad = raw.replace(original, modified)
        assert bad.startswith(original_good)
        (OUT / 'enclosing-bad.pdf').write_bytes(bad)
        cases['enclosing-bad'] = await inspect('enclosing-bad', bad, LATER)
        cases['original-no-doc-ts'] = await inspect('original-no-doc-ts', original_good, LATER)
        cases['original-no-doc-ts']['pdf'] = 'cases/good.pdf'
    for name, digest in original_files.items():
        assert sha((base.OUT / name).read_bytes()) == digest, name
    manifest = {'reference': 'pyHanko0.38.1/certvalidator0.33.0',
        'original_frozen_inputs_unchanged': original_files,
        'scope': 'Additional V consumer proof, not native P signing or new upstream credit',
        'fresh_public_lta_calls': len(cases), 'fresh_internal_authenticated_poe_calls': len(cases),
        'no_network': True, 'no_injected_poes': True, 'cases': cases,
        'files': {str(x.relative_to(base.OUT)): {'sha256': sha(x.read_bytes()), 'length': x.stat().st_size}
                  for x in sorted(OUT.iterdir()) if x.is_file()}}
    (base.OUT / 'additional-oracle.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    asyncio.run(main())
