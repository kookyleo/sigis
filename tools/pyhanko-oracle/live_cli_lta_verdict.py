# Derived from pyHanko 0.38.1 integration-tests/test_live_certomancer.py (MIT).
"""Fresh exact live CLI output validation tail; does not sign or invoke a CLI.

The actual output PDF/root and native-check reference moment are required.
The original full-LTA valid/trusted/LTA_UPDATES and DSS1/1 assertions are kept.
The empty-root check is a separate supplemental trust control.
"""
import asyncio
from hashlib import sha256
from importlib.metadata import version
from io import BytesIO
import json
from pathlib import Path
import sys

import aiohttp
from asn1crypto import x509
from freezegun import freeze_time
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.diff_analysis import ModificationLevel
from pyhanko.sign.validation import DocumentSecurityStore
from pyhanko.sign.validation.ades import ades_lta_validation
from pyhanko.sign.validation.policy_decl import (
    PdfSignatureValidationSpec, RevocationInfoGatheringSpec, SignatureValidationSpec,
)
from pyhanko_certvalidator.context import CertValidationPolicySpec
from pyhanko_certvalidator.fetchers.aiohttp_fetchers import AIOHttpFetcherBackend
from pyhanko_certvalidator.policy_decl import REQUIRE_REVINFO, CertRevTrustPolicy
from pyhanko_certvalidator.registry import SimpleTrustManager


async def validate(data, roots, session):
    reader = PdfFileReader(BytesIO(data))
    signature = reader.embedded_signatures[0]
    assert signature.field_name == 'Sig1'
    spec = PdfSignatureValidationSpec(SignatureValidationSpec(
        cert_validation_policy=CertValidationPolicySpec(
            trust_manager=SimpleTrustManager.build(trust_roots=roots),
            revinfo_policy=CertRevTrustPolicy(REQUIRE_REVINFO),
        ),
        revinfo_gathering_policy=RevocationInfoGatheringSpec(
            fetcher_backend=AIOHttpFetcherBackend(session, per_request_timeout=5),
        ),
    ))
    result = await ades_lta_validation(signature, spec)
    status = result.api_status
    dss = DocumentSecurityStore.read_dss(reader)
    return {
        'valid': False if status is None else status.valid,
        'intact': False if status is None else status.intact,
        'trusted': False if status is None else status.trusted,
        'modification_level': None if status is None or status.modification_level is None
                              else status.modification_level.name,
        'ades_subindic': result.ades_subindic.standard_name,
        'failure_msg': result.failure_msg,
        'field_name': signature.field_name,
        'dss_crls': len(dss.crls), 'dss_ocsps': len(dss.ocsps),
    }


async def main():
    assert version('pyhanko') == '0.38.1'
    assert version('pyhanko-certvalidator') == '0.33.0'
    data = Path(sys.argv[1]).read_bytes()
    root_data = Path(sys.argv[2]).read_bytes()
    opened = {'pdf': {'path': str(Path(sys.argv[1]).resolve()), 'length': len(data),
                      'sha256': sha256(data).hexdigest()},
              'root': {'path': str(Path(sys.argv[2]).resolve()), 'length': len(root_data),
                       'sha256': sha256(root_data).hexdigest()}}
    print('LIVE_CLI_PY_INPUT ' + json.dumps(opened), file=sys.stderr, flush=True)
    root = x509.Certificate.load(root_data, strict=True)
    async with aiohttp.ClientSession() as session:
        correct = await validate(data, [root], session)
        # Exact original _check_pades_result plus the CLI-specific _check DSS.
        assert correct['valid'] and correct['trusted']
        assert correct['modification_level'] == ModificationLevel.LTA_UPDATES.name
        assert correct['dss_crls'] == 1 and correct['dss_ocsps'] == 1
        try:
            empty = await validate(data, [], session)
        except Exception as error:
            empty = {'valid': False, 'trusted': False,
                     'error_class': type(error).__name__, 'error': str(error)}
        assert not empty['trusted']
    return {'kind': 'fresh pinned public full-LTA check of actual native CLI output',
            'pyhanko': version('pyhanko'), 'certvalidator': version('pyhanko-certvalidator'),
            'opened_before_parse': opened, 'pdf_sha256': sha256(data).hexdigest(),
            'root_sha256': sha256(root_data).hexdigest(), 'validation_time': sys.argv[3],
            'correct': correct, 'empty_roots': empty,
            'signing_or_original_CLI_execution_performed_by_helper': False}


if __name__ == '__main__':
    with freeze_time(sys.argv[3], real_asyncio=True):
        print(json.dumps(asyncio.run(main())))
