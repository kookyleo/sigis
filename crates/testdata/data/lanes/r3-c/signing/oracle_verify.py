"""Fresh, strict trust verification matching upstream CLI post_validate."""
import argparse
import hashlib
import importlib.metadata
import json
import sys
from pathlib import Path
from datetime import datetime, timezone
from io import BytesIO
from asn1crypto import cms, pem, x509
from freezegun import freeze_time
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.pdf_utils.misc import PdfStrictReadError
from pyhanko.pdf_utils.decode_limits import DecodeLimits
from pyhanko.sign.validation import validate_pdf_signature, validate_pdf_timestamp, async_validate_detached_cms
from pyhanko.sign.validation.status import TimestampSignatureStatus,DocumentTimestampStatus
from pyhanko_certvalidator import ValidationContext
import pyhanko_certvalidator
import pyhanko.sign.validation.generic_cms as generic_cms
from pyhanko_testing_commons.test_utils.live_http import live_pki_services
from pyhanko_testing_commons.test_data.samples import TESTING_CA, TESTING_CA_ECDSA, TESTING_CA_ED25519, TESTING_CA_ED448
import asyncio
p=argparse.ArgumentParser(); p.add_argument('output');p.add_argument('input');p.add_argument('root');p.add_argument('architecture');p.add_argument('--cms',action='store_true');p.add_argument('--timestamp',action='store_true');p.add_argument('--allow-hybrid-xrefs',action='store_true');p.add_argument('--trust-controls',action='store_true');a=p.parse_args()
assert importlib.metadata.version('pyhanko') == '0.38.1'
assert importlib.metadata.version('pyhanko-certvalidator') == '0.33.0'
def file_record(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return {'path': str(path), 'length': len(data), 'sha256': hashlib.sha256(data).hexdigest()}
architectures={'rsa':TESTING_CA,'ecdsa':TESTING_CA_ECDSA,'ed25519':TESTING_CA_ED25519,'ed448':TESTING_CA_ED448}
root=x509.Certificate.load(pem.unarmor(open(a.root,'rb').read())[2])
with freeze_time(datetime(2020,8,1,tzinfo=timezone.utc)):
    with live_pki_services() as services:
        services.register(architectures[a.architecture])
        vc=ValidationContext(trust_roots=[root],allow_fetching=True)
        if a.cms:
            data=open(a.output,'rb').read()
            if pem.detect(data):data=pem.unarmor(data)[2]
            status=asyncio.run(async_validate_detached_cms(open(a.input,'rb'),cms.ContentInfo.load(data)['content'],signer_validation_context=vc))
            assert (status.timestamp_validity is not None)==a.timestamp
        else:
            strict=not a.allow_hybrid_xrefs
            try:PdfFileReader(BytesIO(open(a.input,'rb').read()),decode_limits=DecodeLimits.for_trusted_input())
            except PdfStrictReadError:strict=False
            reader=PdfFileReader(open(a.output,'rb'),strict=strict)
            if reader.encrypted:reader.decrypt('ownersecret')
            if reader.embedded_timestamp_signatures and reader.embedded_regular_signatures:
                from pyhanko.sign.validation.ades import ades_lta_validation
                from pyhanko.sign.validation.policy_decl import PdfSignatureValidationSpec,SignatureValidationSpec
                from pyhanko_certvalidator.context import CertValidationPolicySpec
                from pyhanko_certvalidator.policy_decl import REQUIRE_REVINFO,CertRevTrustPolicy
                from pyhanko_certvalidator.registry import SimpleTrustManager
                spec=PdfSignatureValidationSpec(SignatureValidationSpec(cert_validation_policy=CertValidationPolicySpec(trust_manager=SimpleTrustManager.build(trust_roots=[root]),revinfo_policy=CertRevTrustPolicy(REQUIRE_REVINFO))))
                status=asyncio.run(ades_lta_validation(reader.embedded_regular_signatures[-1],spec)).api_status
            elif reader.embedded_timestamp_signatures:
                status=validate_pdf_timestamp(reader.embedded_timestamp_signatures[-1],vc)
            else:
                status=validate_pdf_signature(reader.embedded_regular_signatures[-1],signer_validation_context=vc)
        if isinstance(status,TimestampSignatureStatus):
            assert status.intact and status.valid and status.trusted,repr(status)
            if isinstance(status,DocumentTimestampStatus):assert status.docmdp_ok is not False,repr(status)
        else:
            assert status.bottom_line and status.intact and status.valid,status.pretty_print_details()
        if a.timestamp:
            timestamp=status.timestamp_validity
            assert timestamp.intact and timestamp.valid and timestamp.trusted,repr(timestamp)
        controls = None
        if a.trust_controls:
            assert not a.cms and not reader.encrypted
            embedded = reader.embedded_regular_signatures[-1]
            digest = embedded.compute_digest()
            original = generic_cms.validate_sig_integrity(embedded.signer_info, embedded.signer_cert, 'data', digest)
            changed = bytes([digest[0] ^ 1]) + digest[1:]
            wrong_digest = generic_cms.validate_sig_integrity(embedded.signer_info, embedded.signer_cert, 'data', changed)
            assert original == (True, True), original
            assert wrong_digest == (False, True), wrong_digest
            no_roots = validate_pdf_signature(embedded, signer_validation_context=ValidationContext(trust_roots=[], allow_fetching=False))
            assert no_roots.intact and no_roots.valid and not no_roots.trusted and not no_roots.bottom_line, no_roots.pretty_print_details()
            controls = {'original_integrity': original, 'wrong_digest_integrity': wrong_digest,
                        'no_roots': {'intact': no_roots.intact, 'valid': no_roots.valid,
                                     'trusted': no_roots.trusted, 'bottom_line': no_roots.bottom_line}}
        print('SIGNING_ORACLE_VERIFY ' + json.dumps({
            'python': file_record(sys.executable), 'driver': file_record(__file__),
            'cms_module': file_record(generic_cms.__file__),
            'validator_module': file_record(pyhanko_certvalidator.__file__),
            'pyhanko_version': importlib.metadata.version('pyhanko'),
            'certvalidator_version': importlib.metadata.version('pyhanko-certvalidator'),
            'input': file_record(a.input), 'output': file_record(a.output),
            'root': file_record(a.root), 'architecture': a.architecture,
            'moment': datetime.now(timezone.utc).isoformat(),
            'intact': status.intact, 'valid': status.valid, 'trusted': status.trusted,
            'bottom_line': getattr(status, 'bottom_line', None), 'controls': controls,
        }), file=sys.stderr)
        print('VALID')
