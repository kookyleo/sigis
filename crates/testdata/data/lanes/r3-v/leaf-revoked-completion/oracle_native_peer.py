"""Fresh pinned AdES peer for actual supplied native CMS bytes.

Uses the unchanged original DEFAULT_SIG_VALIDATION_SPEC (REQUIRE_REVINFO,
MAX_DIFF_REVOCATION_VALIDATION), genuine live local services and Dec25 clock.
No signing, replacement CMS, ordinary-facade fallback or injected Good status.
"""

import argparse
import base64
import datetime
import hashlib
import importlib.metadata
import inspect
import json
import os
from pathlib import Path
import sys
import time

PINNED = Path('/tmp/pyhanko-oracle/src/v0.38.1')
TEST_ROOT = PINNED / 'pkgs/pyhanko'
sys.path[:0] = [str(TEST_ROOT), str(PINNED / 'pkgs/pyhanko/src'),
                str(PINNED / 'internal/common-test-utils/src')]
import pytest


def sha(data):
    return hashlib.sha256(data).hexdigest()


def identity(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return {'path': str(path), 'length': len(data), 'sha256': sha(data)}


def save_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True, default=str) + '\n')


class PeerCapture:
    def __init__(self, out, fixture_dir):
        self.out = out
        self.fixture_dir = fixture_dir
        self.http = []
        self.reports = []
        self.original_dispatch = None

    def pytest_configure(self, config):
        from pyhanko_testing_commons.test_utils import live_http
        self.original_dispatch = live_http.PKIServiceRegistry._dispatch
        original = self.original_dispatch
        fixture_hashes = {}
        for path in self.fixture_dir.glob('20*/*.der'):
            fixture_hashes.setdefault(sha(path.read_bytes()), []).append(str(path.resolve()))

        async def dispatch(registry, request):
            body = await request.read()
            response = await original(registry, request)
            data = response.body or b''
            row = {'method': request.method, 'path': request.path_qs,
                   'request_length': len(body), 'request_sha256': sha(body),
                   'request_b64': base64.b64encode(body).decode(),
                   'status': response.status, 'response_length': len(data),
                   'response_sha256': sha(data),
                   'matching_native_fixture_files': fixture_hashes.get(sha(data), [])}
            target = self.out / 'http' / f'{sha(data)}.der'
            target.parent.mkdir(exist_ok=True)
            target.write_bytes(data)
            row['response_file'] = str(target)
            self.http.append(row)
            return response

        live_http.PKIServiceRegistry._dispatch = dispatch

    def pytest_unconfigure(self, config):
        if self.original_dispatch is not None:
            from pyhanko_testing_commons.test_utils import live_http
            live_http.PKIServiceRegistry._dispatch = self.original_dispatch

    def pytest_runtest_logreport(self, report):
        self.reports.append({'nodeid': report.nodeid, 'when': report.when,
                             'outcome': report.outcome, 'duration': report.duration})


@pytest.mark.asyncio
async def test_same_native_bytes(pki_services):
    from asn1crypto import cms
    from freezegun import freeze_time
    from tests import test_ades_validation as original
    from pyhanko.sign.validation import ades
    from pyhanko.sign.ades.report import AdESPassed
    source = Path(os.environ['HANKO_LEAF_PEER_INPUT'])
    out = Path(os.environ['HANKO_LEAF_PEER_OUTPUT'])
    raw = source.read_bytes()
    kind = os.environ['HANKO_LEAF_PEER_KIND']
    if kind == 'cms-content-info':
        content_info = cms.ContentInfo.load(raw, strict=True)
        assert content_info['content_type'].native == 'signed_data'
        signed_data = content_info['content']
    else:
        signed_data = cms.SignedData.load(raw, strict=True)
    row = {'input': identity(source), 'input_kind': kind,
           'signed_data_length': len(signed_data.dump()),
           'signed_data_sha256': sha(signed_data.dump()),
           'content_sha256': sha(signed_data['encap_content_info']['content'].native),
           'reference': 'Actual pinned AdES WithTime, unchanged original DEFAULT_SIG_VALIDATION_SPEC',
           'spec': repr(original.DEFAULT_SIG_VALIDATION_SPEC),
           'source_original': identity(inspect.getfile(original)),
           'source_ades': identity(inspect.getfile(ades)),
           'reference_clock': '2020-12-25T00:00:00+00:00',
           'new_signature_generated': False}
    try:
        with freeze_time('2020-12-25'):
            # This registers genuine testing-ca services only. Its returned
            # context is NOT substituted for the original AdES policy spec.
            original.live_testing_vc(pki_services)
            row['observed_time'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
            result = await ades.ades_with_time_validation(
                signed_data, validation_spec=original.DEFAULT_SIG_VALIDATION_SPEC)
            status = result.api_status
            row['result'] = {
                'subindication': result.ades_subindic.name,
                'best_signature_time': result.best_signature_time,
                'not_before_time': getattr(result, 'signature_not_before_time', None),
                'intact': status.intact, 'valid': status.valid,
                'trusted': status.trusted, 'revoked': status.revoked,
                'bottom_line': status.bottom_line,
                'failure_msg': result.failure_msg,
                'qualification_result': repr(status.qualification_result),
                'signer_reported_dt': getattr(status, 'signer_reported_dt', None),
                'timestamp_validity': repr(status.timestamp_validity),
                'validation_path': repr(status.validation_path),
                'full_result': repr(result),
            }
            assert result.ades_subindic == AdESPassed.OK
            assert result.best_signature_time == datetime.datetime(2020, 11, 1, tzinfo=datetime.UTC)
            assert status.intact and status.valid and status.trusted and status.bottom_line
    except Exception as exc:
        row['exception'] = {'type': type(exc).__name__, 'message': str(exc)}
        raise
    finally:
        save_json(out / 'same-native-peer.json', row)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cms', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--input-kind', choices=('cms-content-info', 'signed-data'), required=True)
    args = parser.parse_args()
    assert __debug__, 'Assertions must remain enabled'
    args.cms = args.cms.resolve(strict=True)
    args.out = args.out.resolve()
    args.out.mkdir(parents=True, exist_ok=True)
    os.environ['HANKO_LEAF_PEER_INPUT'] = str(args.cms)
    os.environ['HANKO_LEAF_PEER_OUTPUT'] = str(args.out)
    os.environ['HANKO_LEAF_PEER_KIND'] = args.input_kind
    before = identity(args.cms)
    import pyhanko.sign.validation.ades as ades
    import pyhanko_certvalidator.validate as validate
    capture = PeerCapture(args.out, Path(__file__).resolve().parent)
    save_json(args.out / 'runtime-profile.json', {
        'assertions_enabled': __debug__, 'python': sys.version,
        'interpreter': identity(sys.executable), 'runner': identity(__file__),
        'versions': {key: importlib.metadata.version(key) for key in
                     ('pyHanko', 'pyhanko-certvalidator', 'cryptography', 'pytest')},
        'modules': [identity(inspect.getfile(module)) for module in (ades, validate)],
    })
    argv = ['-q', '-s', '-p', 'no:cacheprovider',
            '-p', 'pyhanko_testing_commons.test_utils.live_http_fixtures',
            '-o', 'log_cli=false', f'{Path(__file__).resolve()}::test_same_native_bytes']
    start = time.monotonic()
    code = pytest.main(argv, plugins=[capture])
    after = identity(args.cms)
    assert before == after
    save_json(args.out / 'execution-receipt.json', {
        'pytest_args': argv, 'exit_code': int(code), 'elapsed_seconds': time.monotonic() - start,
        'input_before': before, 'input_after': after,
        'reports': capture.reports, 'http': capture.http,
        'native_execution': False, 'new_signing': False, 'provider_exclusions': [],
        'network': 'Genuine local pinned original pki_services only',
        'nonce_note': 'Fresh service replies may carry request nonces unlike exported nonce-free native evidence; compare raw hashes explicitly',
    })
    return int(code)


if __name__ == '__main__':
    raise SystemExit(main())
