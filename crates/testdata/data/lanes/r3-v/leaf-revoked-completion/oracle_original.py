"""Run the unchanged pinned original and export its real fixture closure.

Invoke with /tmp/pyhanko-oracle/venv/bin/python oracle_original.py --out DIR
--fixture-dir DIR. This invokes pytest's real local PKI-service fixture. It
never replaces the original body or validation implementation. Observational
wrappers record the Nov 1 path precondition separately from Dec 25 WithTime.
Exported DER is signed by the actual immutable Certomancer fixture keys.
"""

import argparse
import ast
import datetime
import functools
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
TEST_FILE = TEST_ROOT / 'tests/test_ades_validation.py'
NAME = 'test_embedded_cades_pre_revoke_with_poe'
NODE = f'tests/test_ades_validation.py::{NAME}'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def identity(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return {'path': str(path), 'length': len(data), 'sha256': sha(data)}


def emit_json(path, data):
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + '\n')


class Capture:
    def __init__(self, out, fixture_dir):
        self.out = out
        self.fixture_dir = fixture_dir
        self.calls = []
        self.http = []
        self.stage = None
        self.files = []
        self.reports = []
        self.restores = []

    def write(self, relative, data):
        path = self.fixture_dir / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and path.read_bytes() != data:
            raise RuntimeError(f'Refusing to overwrite different fixture: {path}')
        path.write_bytes(data)
        row = identity(path)
        row['relative_path'] = relative
        self.files.append(row)
        return row

    def patch(self, obj, name, replacement):
        original = getattr(obj, name)
        self.restores.append((obj, name, original))
        setattr(obj, name, replacement)

    def pytest_collection_modifyitems(self, items):
        assert len(items) == 1 and items[0].nodeid == NODE
        module = items[0].module
        from pyhanko_testing_commons.test_utils import live_http
        original_dispatch = live_http.PKIServiceRegistry._dispatch

        async def dispatch(registry, request):
            body = await request.read()
            response = await original_dispatch(registry, request)
            import base64
            self.http.append({
                'stage': self.stage,
                'method': request.method, 'path': request.path_qs,
                'request_b64': base64.b64encode(body).decode(),
                'response_b64': base64.b64encode(response.body or b'').decode(),
                'status': response.status,
            })
            return response

        self.patch(live_http.PKIServiceRegistry, '_dispatch', dispatch)
        original_path = module.async_validate_path

        @functools.wraps(original_path)
        async def path_call(ctx, path, *args, **kwargs):
            self.stage = 'original-Nov1-path-precondition'
            row = {'stage': self.stage,
                   'observed_time': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                   'leaf_sha256': sha(path.leaf.dump()),
                   'path_type': type(path).__name__}
            try:
                result = await original_path(ctx, path, *args, **kwargs)
                row['completed'] = True
                return result
            except Exception as exc:
                row['exception'] = {'type': type(exc).__name__, 'message': str(exc)}
                raise
            finally:
                self.calls.append(row)
                self.stage = None

        self.patch(module, 'async_validate_path', path_call)
        original_time = module.ades.ades_with_time_validation

        @functools.wraps(original_time)
        async def with_time_call(signed_data, *args, **kwargs):
            self.stage = 'original-Dec25-WithTime'
            row = {'stage': self.stage,
                   'observed_time': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                   'signed_data': self.write('fresh-original-signed-data.der', signed_data.dump())}
            self.write('fresh-original-content.bin', signed_data['encap_content_info']['content'].native)
            try:
                result = await original_time(signed_data, *args, **kwargs)
                status = result.api_status
                row['result'] = {
                    'subindication': result.ades_subindic.name,
                    'best_signature_time': result.best_signature_time.isoformat() if result.best_signature_time else None,
                    'intact': status.intact, 'valid': status.valid,
                    'trusted': status.trusted, 'revoked': status.revoked,
                    'bottom_line': status.bottom_line,
                    'failure': result.failure_msg,
                    'qualification_result': repr(status.qualification_result),
                }
                return result
            except Exception as exc:
                row['exception'] = {'type': type(exc).__name__, 'message': str(exc)}
                raise
            finally:
                self.calls.append(row)
                self.stage = None

        self.patch(module.ades, 'ades_with_time_validation', with_time_call)

    def pytest_runtest_logreport(self, report):
        self.reports.append({'nodeid': report.nodeid, 'when': report.when,
                             'outcome': report.outcome, 'duration': report.duration})

    def restore(self):
        for obj, name, value in reversed(self.restores):
            setattr(obj, name, value)

    def export_closure(self):
        from asn1crypto import ocsp
        from certomancer.registry import ArchLabel
        from pyhanko_testing_commons.test_data.samples import CERTOMANCER
        arch = CERTOMANCER.get_pki_arch(ArchLabel('testing-ca'))
        services = arch.service_registry
        for label in ('root', 'interm', 'signer2', 'tsa'):
            self.write(f'cert-{label}.der', arch.get_cert(label).dump())
        for day in ('2020-11-01', '2020-12-25'):
            at = datetime.datetime.fromisoformat(day).replace(tzinfo=datetime.timezone.utc)
            for info in services.list_ocsp_responders():
                issuer = arch.get_cert(info.resolve_issuer_cert(arch))
                responder = services.summon_responder(info.label, at_time=at)
                for issuer_label, specs in arch.enumerate_certs_by_issuer():
                    if str(issuer_label) != str(info.for_issuer):
                        continue
                    for spec in specs:
                        cert = arch.get_cert(spec.label)
                        cert_id = ocsp.CertId({
                            'hash_algorithm': {'algorithm': 'sha1'},
                            'issuer_name_hash': issuer.subject.sha1,
                            'issuer_key_hash': issuer.public_key.sha1,
                            'serial_number': cert.serial_number,
                        })
                        single = responder.format_single_ocsp_response(cert_id, issuer)
                        response = responder.assemble_simple_ocsp_responses([single])
                        self.write(f'{day}/ocsp-{spec.label}.der', response.dump())
            for info in services.list_crl_repos():
                if str(info.label) in ('root', 'interm'):
                    self.write(f'{day}/crl-{info.label}.der', services.get_crl(info.label, at_time=at).dump())
        emit_json(self.fixture_dir / 'manifest.json', {
            'scope': 'Actual pinned original fixture closure; no native execution or same-native-byte claim',
            'architecture': 'testing-ca', 'dates': ['2020-11-01', '2020-12-25'],
            'generation': 'Actual Certomancer signed evidence, no injected Good status',
            'files': self.files,
        })


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--fixture-dir', type=Path, required=True)
    args = parser.parse_args()
    args.out = args.out.resolve()
    args.fixture_dir = args.fixture_dir.resolve()
    assert __debug__, 'Assertions must remain enabled'
    args.out.mkdir(parents=True, exist_ok=True)
    args.fixture_dir.mkdir(parents=True, exist_ok=True)
    before = [identity(TEST_FILE), identity(TEST_ROOT / 'tests/conftest.py')]
    tree = ast.parse(TEST_FILE.read_text())
    function = next(node for node in tree.body if isinstance(node, ast.AsyncFunctionDef) and node.name == NAME)
    lines = TEST_FILE.read_bytes().splitlines(keepends=True)
    body = b''.join(lines[function.lineno - 1:function.end_lineno])
    (args.out / 'unchanged-original-body.py.txt').write_bytes(body)
    sys.path[:0] = [str(TEST_ROOT), str(PINNED / 'pkgs/pyhanko/src'),
                    str(PINNED / 'internal/common-test-utils/src')]
    import pytest
    import pyhanko.sign.validation.ades as ades
    import pyhanko_certvalidator.validate as validate
    import pyhanko_certvalidator.context as context
    import certomancer
    runtime = {'assertions_enabled': __debug__, 'python': sys.version,
               'interpreter': identity(sys.executable),
               'versions': {key: importlib.metadata.version(key) for key in
                            ('pyHanko', 'pyhanko-certvalidator', 'certomancer', 'cryptography', 'pytest')},
               'modules': [identity(inspect.getfile(module)) for module in (ades, validate, context, certomancer)],
               'runner': identity(__file__), 'original_body': {'length': len(body), 'sha256': sha(body)}}
    emit_json(args.out / 'runtime-profile.json', runtime)
    capture = Capture(args.out, args.fixture_dir)
    previous = Path.cwd()
    os.chdir(TEST_ROOT)
    started = time.monotonic()
    argv = ['-q', '-s', '-p', 'no:cacheprovider', '-o', 'log_cli=false', NODE]
    try:
        result = pytest.main(argv, plugins=[capture])
    finally:
        capture.restore()
        os.chdir(previous)
    capture.export_closure()
    after = [identity(TEST_FILE), identity(TEST_ROOT / 'tests/conftest.py')]
    assert before == after
    emit_json(args.out / 'execution-receipt.json', {
        'pytest_args': argv, 'cwd': str(TEST_ROOT), 'exit_code': int(result),
        'elapsed_seconds': time.monotonic() - started,
        'calls': capture.calls, 'http': capture.http, 'reports': capture.reports,
        'source_before': before, 'source_after': after,
        'scope': 'Fresh unchanged Python original and actual signed fixture export; zero Cargo/native runs',
        'provider_exclusions': [], 'network': 'Exact original local pki_services fixture only',
    })
    return int(result)


if __name__ == '__main__':
    raise SystemExit(main())
