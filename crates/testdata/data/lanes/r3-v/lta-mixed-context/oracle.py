"""Pinned public full-LTA profiles of retained29b; no expected verdict is forced."""
import argparse
import asyncio
import dataclasses
from datetime import datetime, timedelta, timezone
from enum import Enum
from hashlib import sha256
from importlib.metadata import version
from io import BytesIO
import json
from pathlib import Path
import sys

PINS = {
    'pdf': '29b0a8a97e32bb220c96ac34d9906bcadf2d38dc7a13eb77336b63eaa6cdc4b2',
    'ecc': 'ccc409838b97b5c04b18f889fa39b9b123868ff685751f58956206fb86d5ba90',
    'rsa': '2b6dea78737d478eaf911cddc71d58b0c557eceb1623e6475dfa5770d3ff26fa',
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--pdf', required=True)
    ap.add_argument('--ecc-root', required=True)
    ap.add_argument('--rsa-root', required=True)
    ap.add_argument('--native-source-head', required=True)
    ap.add_argument('--output', required=True)
    args = ap.parse_args()
    paths = {'pdf': Path(args.pdf), 'ecc': Path(args.ecc_root), 'rsa': Path(args.rsa_root)}
    raw = {k: p.read_bytes() for k, p in paths.items()}
    opened = {k: {'path': str(paths[k].resolve()), 'length': len(b), 'sha256': sha256(b).hexdigest()}
              for k, b in raw.items()}
    receipt = {'opened_before_parse': opened, 'native_source_head': args.native_source_head,
               'helper_sha256': sha256(Path(__file__).read_bytes()).hexdigest(),
               'pyhanko': version('pyhanko'), 'certvalidator': version('pyhanko-certvalidator')}
    print('LTA_MIXED_INPUT ' + json.dumps(receipt), file=sys.stderr, flush=True)
    assert {k: v['sha256'] for k, v in opened.items()} == PINS
    assert receipt['pyhanko'] == '0.38.1' and receipt['certvalidator'] == '0.33.0'

    from asn1crypto import core, x509
    from freezegun import freeze_time
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.pdf_utils.crypt.api import PdfMacStatus
    from pyhanko.sign.validation.ades import ades_lta_validation
    from pyhanko.sign.validation.policy_decl import (
        CertificateFetchingRule, PdfSignatureValidationSpec, RevinfoOnlineFetchingRule,
        RevocationInfoGatheringSpec, SignatureValidationSpec,
    )
    from pyhanko_certvalidator.context import CertValidationPolicySpec
    from pyhanko_certvalidator.ltv.types import ValidationTimingInfo
    from pyhanko_certvalidator.path import ValidationPath
    from pyhanko_certvalidator.policy_decl import (
        CertRevTrustPolicy, DisallowWeakAlgorithmsPolicy, NO_REVOCATION,
    )
    from pyhanko_certvalidator.registry import SimpleTrustManager

    moment = datetime(2020, 11, 1, tzinfo=timezone.utc)
    roots = [x509.Certificate.load(raw[k], strict=True) for k in ['ecc', 'rsa']]
    import inspect
    sources = [inspect.getsourcefile(ades_lta_validation), inspect.getsourcefile(CertValidationPolicySpec),
               inspect.getsourcefile(ValidationTimingInfo), inspect.getsourcefile(SignatureValidationSpec),
               inspect.getsourcefile(SimpleTrustManager)]
    receipt['primary_source_before'] = {p: sha256(Path(p).read_bytes()).hexdigest() for p in sources}

    def cert_info(cert):
        return {'sha256': cert.sha256.hex(), 'subject': cert.subject.human_friendly,
                'issuer': cert.issuer.human_friendly, 'serial': str(cert.serial_number)}

    def encode(obj, depth=0):
        if depth > 12:
            return {'class': type(obj).__name__, 'repr': repr(obj)}
        if isinstance(obj, x509.Certificate):
            return cert_info(obj)
        if isinstance(obj, ValidationPath):
            return [cert_info(c) for c in obj]
        if isinstance(obj, Enum):
            return {'enum': type(obj).__name__, 'name': obj.name, 'value': str(obj.value)}
        if isinstance(obj, datetime):
            return obj.isoformat().replace('+00:00', 'Z')
        if isinstance(obj, timedelta):
            return {'seconds': obj.total_seconds()}
        if isinstance(obj, bytes):
            return {'length': len(obj), 'sha256': sha256(obj).hexdigest()}
        if obj is None or isinstance(obj, (bool, str, int, float)):
            return obj
        if isinstance(obj, core.Asn1Value):
            b = obj.dump()
            return {'asn1': type(obj).__name__, 'length': len(b), 'sha256': sha256(b).hexdigest()}
        if dataclasses.is_dataclass(obj):
            return {f.name: encode(getattr(obj, f.name), depth + 1) for f in dataclasses.fields(obj)}
        if isinstance(obj, dict):
            return {str(k): encode(v, depth + 1) for k, v in obj.items()}
        if isinstance(obj, (list, tuple, set, frozenset)):
            return [encode(v, depth + 1) for v in obj]
        return {'class': type(obj).__name__, 'repr': repr(obj)}

    def status_info(status):
        if status is None:
            return None
        ts = getattr(status, 'timestamp_validity', None)
        path = status.validation_path
        return {'intact': status.intact, 'valid': status.valid, 'trusted': status.trusted,
                'bottom_line': getattr(status, 'bottom_line', None), 'summary': status.summary(),
                'signer_sha256': status.signing_cert.sha256.hex(),
                'path_sha256': [] if path is None else [c.sha256.hex() for c in path],
                'timestamp': None if ts is None else {
                    'intact': ts.intact, 'valid': ts.valid, 'trusted': ts.trusted,
                    'timestamp': encode(ts.timestamp), 'summary': ts.summary(),
                    'signer_sha256': ts.signing_cert.sha256.hex(),
                    'path_sha256': [] if ts.validation_path is None else
                                   [c.sha256.hex() for c in ts.validation_path]},
                'all_dataclass_fields': encode(status)}

    async def run(historical):
        policy = CertValidationPolicySpec(
            trust_manager=SimpleTrustManager.build(trust_roots=roots),
            revinfo_policy=CertRevTrustPolicy(NO_REVOCATION),
            time_tolerance=timedelta(seconds=1),
            algorithm_usage_policy=DisallowWeakAlgorithmsPolicy(),
        )
        # No explicit timestamp policy: use the public API's inherited policy.
        spec = PdfSignatureValidationSpec(SignatureValidationSpec(
            cert_validation_policy=policy,
            revinfo_gathering_policy=RevocationInfoGatheringSpec(
                online_fetching_rule=RevinfoOnlineFetchingRule.LOCAL_ONLY,
                certificate_fetching_rule=CertificateFetchingRule.NEVER_FETCH,
            ),
        ))
        timing = ValidationTimingInfo(moment, moment, historical)
        row = {'id': 'public-full-lta-implicit-shared-' + str(historical).lower(),
               'role_profile': 'implicit shared policy; no explicit TS override',
               'point_in_time_validation_argument': historical,
               'timing_argument': encode(timing), 'trust_roots_in_input_order': [c.sha256.hex() for c in roots],
               'revocation': 'NO_REVOCATION (nocheck/nocheck)',
               'gathering': 'LOCAL_ONLY; NEVER_FETCH certificates',
               'time_tolerance_seconds': 1, 'preloaded_local_knowledge': False,
               'algorithm_policy': repr(policy.algorithm_usage_policy)}
        try:
            reader = PdfFileReader(BytesIO(raw['pdf']))
            auth = reader.decrypt('secret')
            row['mac_status'] = auth.mac_status.name
            assert auth.mac_status == PdfMacStatus.SUCCESSFUL
            signatures = reader.embedded_regular_signatures
            assert len(signatures) == 1 and signatures[0].field_name == 'Sig'
            result = await ades_lta_validation(signatures[0], spec, timing_info=timing)
            row['exception'] = None
            row['ades_subindication'] = result.ades_subindic.name
            row['failure_msg'] = result.failure_msg
            row['best_signature_time'] = encode(result.best_signature_time)
            row['signature_not_before_time'] = encode(result.signature_not_before_time)
            row['oldest_evidence_record_timestamp'] = encode(result.oldest_evidence_record_timestamp)
            row['api_status'] = status_info(result.api_status)
            row['signature_timestamp_status'] = None if result.signature_timestamp_status is None else {
                'ades_subindication': result.signature_timestamp_status.ades_subindic.name,
                'failure_msg': result.signature_timestamp_status.failure_msg,
                'api_status': status_info(result.signature_timestamp_status.api_status)}
            row['validation_objects'] = [encode(o) for o in result.validation_objects]
            row['full_result_repr'] = repr(result)
        except Exception as error:
            import traceback
            row['exception'] = {'class': type(error).__name__, 'message': str(error),
                                'traceback': traceback.format_exc()}
        print('LTA_MIXED_PROFILE ' + json.dumps(row), file=sys.stderr, flush=True)
        return row

    with freeze_time('2020-11-01T00:00:00Z'):
        rows = asyncio.run(asyncio.gather(*[]) if False else run_all(run))
    receipt['primary_source_after'] = {p: sha256(Path(p).read_bytes()).hexdigest() for p in sources}
    assert receipt['primary_source_before'] == receipt['primary_source_after']
    result = {'receipt': receipt, 'profiles': rows, 'fresh_public_calls': 2,
              'new_native_execution': False, 'new_unique_credit': 0,
              'expected_verdict_forced': False, 'frozen_input_not_new_signature_generation': True,
              'context_semantics_note': 'Public policy build_validation_context_kwargs supplies moment for both flags. The input timing flag is retained; no internal context identity hook or TS-role override is injected.'}
    Path(args.output).write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result), flush=True)


async def run_all(run):
    return [await run(False), await run(True)]


if __name__ == '__main__':
    main()
