#!/usr/bin/env python3
"""Fresh pinned validation of actual native-exported default-context CMS bytes.

HTTP transport/selection ownership is native evidence. This offline oracle
compares actual available candidate bytes, roots, clock and predicate separately
using exact low-level MAIN and ordinary normalizing facade surfaces. It does not
regenerate signatures, replace missing evidence or claim universal parity.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
from datetime import datetime, timedelta
import hashlib
import importlib
import importlib.metadata
import inspect
import json
from pathlib import Path
import sys
import traceback

PY = Path('/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko/src')
CV = Path('/tmp/pyhanko-oracle/src/cv-0.33.0/pkgs/pyhanko-certvalidator/src')
FIELDS = {'key_usage', 'key_usage_forbidden', 'extd_key_usage',
          'explicit_extd_key_usage_required', 'match_all_key_usages'}
sha = lambda data: hashlib.sha256(data).hexdigest()


def file_record(path: Path) -> dict:
    data = path.read_bytes()
    return {'path': str(path), 'resolved_path': str(path.resolve()),
            'length': len(data), 'sha256': sha(data)}


def decode(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


def dt(text: str) -> datetime:
    result = datetime.fromisoformat(text.replace('Z', '+00:00'))
    assert result.utcoffset() is not None
    return result


def predicate(value):
    if value is None:
        return None
    assert set(value) == FIELDS, value
    result = dict(value)
    for key in ('key_usage', 'key_usage_forbidden', 'extd_key_usage'):
        if result[key] is not None:
            assert isinstance(result[key], list)
            result[key] = set(result[key])
    for key in ('explicit_extd_key_usage_required', 'match_all_key_usages'):
        assert type(result[key]) is bool
    return KeyUsageConstraints(**result)


def module_record(name, root):
    module = importlib.import_module(name)
    actual = Path(inspect.getfile(module))
    package = name.split('.')[0]
    relative = Path(*name.split('.')[1:])
    pinned = root / package / relative.with_suffix('.py')
    if actual.name == '__init__.py':
        pinned = root / package / relative / '__init__.py'
    assert actual.read_bytes() == pinned.read_bytes(), (actual, pinned)
    return {'module': name, 'actual': file_record(actual),
            'pinned': file_record(pinned), 'byte_equal': True}


def native_signature(row):
    value = row['native']
    return value.get('signature', value)


def status(value):
    return {'intact': value.intact, 'valid': value.valid,
            'trusted': value.trusted,
            'bottom_line': getattr(value, 'bottom_line', value.trusted),
            'subindication': None if value.trust_problem_indic is None
                else value.trust_problem_indic.standard_name,
            'signer_sha256': None if value.signing_cert is None
                else sha(value.signing_cert.dump())}


async def capture(coroutine):
    try:
        return {'status': await coroutine(), 'exception': None}
    except Exception as exc:
        return {'status': None, 'exception': {
            'class': type(exc).__name__, 'module': type(exc).__module__,
            'message': str(exc), 'traceback': traceback.format_exc()}}


def material(row, key):
    value = row.get(key)
    assert value is not None, ('required exact material array absent', key)
    return [decode(item) for item in value]


async def validate(row):
    data = decode(row['cms_b64'])
    content = decode(row['content_b64'])
    assert row.get('cms_sha256', sha(data)) == sha(data)
    assert row.get('content_sha256', sha(content)) == sha(content)
    roots = material(row, 'roots_b64')
    other = material(row, 'other_certs_b64')
    crls = material(row, 'crls_b64')
    ocsps = material(row, 'ocsps_b64')
    requested = predicate(row.get('predicate'))
    # Native None has ordinary non-repudiation defaults. Record both the exact
    # native-effective MAIN peer and separately the ordinary normalizing facade.
    exact = requested if requested is not None else SignatureStatus.default_usage_constraints(None)
    now = dt(row['time'])
    point = row.get('point_in_time_validation', False)
    assert type(point) is bool
    rule_pair = row['revocation_policy']
    assert set(rule_pair) == {'ee', 'ca'}
    policy = CertRevTrustPolicy(RevocationCheckingPolicy(
        RevocationCheckingRule(rule_pair['ee']), RevocationCheckingRule(rule_pair['ca'])))
    profile = row.get('oracle_profile', 'ordinary_serialized_context')
    report = {
        'label': row.get('label'), 'native': row['native'],
        'native_source': row['_source'], 'context': {
            'roots_sha256': [sha(item) for item in roots],
            'other_certs_sha256': [sha(item) for item in other],
            'crls_sha256': [sha(item) for item in crls],
            'ocsps_sha256': [sha(item) for item in ocsps],
            'time': row['time'], 'point_in_time_validation': point,
            'revocation_policy': rule_pair, 'time_tolerance_seconds': row.get('time_tolerance_seconds', 1),
            'best_signature_time': row.get('best_signature_time', row['time'])},
        'cms_sha256': sha(data), 'content_sha256': sha(content),
        'predicate': row.get('predicate'), 'references': {},
        'actual_context_build_attempts': 0, 'actual_validation_api_calls': 0, 'new_original_credit': 0,
        'selection_limit': 'Offline candidate-material comparison; not fresh Python HTTP/default-pool proof. Malformed exact supplied bytes remain constructor exceptions rather than being filtered.',
    }
    if profile != 'ordinary_serialized_context':
        report.update(excluded=True, reason='Unserialized custom caller policy retained as native-only evidence; no default substitution.', oracle_profile=profile)
        return report

    def build_context():
        report['actual_context_build_attempts'] += 1
        ctx = ValidationContext(
            trust_roots=[x509.Certificate.load(item) for item in roots],
            other_certs=[x509.Certificate.load(item) for item in other],
            crls=crls, ocsps=ocsps, allow_fetching=False,
            moment=now if point else None,
            best_signature_time=dt(row.get('best_signature_time', row['time'])),
            time_tolerance=timedelta(seconds=row.get('time_tolerance_seconds', 1)),
            revinfo_policy=policy,
        )
        assert ctx.moment == now and ctx.timing_params.point_in_time_validation == point
        return ctx

    async def surface(name):
        phase = 'context_construction'
        try:
            ctx = build_context()
            phase = 'cms_parse'
            sd = cms.ContentInfo.load(data, strict=True)['content']
            si = generic_cms.extract_signer_info(sd)
            digest = hashlib.new(si['digest_algorithm']['algorithm'].native, content).digest()
            phase = 'validation_api'
            report['actual_validation_api_calls'] += 1
            if name == 'exact_lowlevel_main':
                kw = await generic_cms.cms_basic_validation(
                    sd, raw_digest=digest, validation_context=ctx,
                    key_usage_settings=exact)
                answer = status(SignatureStatus(**kw))
            else:
                result = await generic_cms.async_validate_detached_cms(
                    content, sd, signer_validation_context=ctx,
                    key_usage_settings=requested)
                answer = status(result)
            return {'status': answer, 'exception': None, 'terminal_phase': phase}
        except Exception as exc:
            return {'status': None, 'terminal_phase': phase, 'exception': {
                'phase': phase, 'class': type(exc).__name__,
                'module': type(exc).__module__, 'message': str(exc),
                'traceback': traceback.format_exc()}}

    with freeze_time(now, real_asyncio=True):
        report['references']['exact_lowlevel_main'] = await surface('exact_lowlevel_main')
        report['references']['ordinary_normalizing_cms'] = await surface('ordinary_normalizing_cms')
    native = native_signature(row)
    for name, reference in report['references'].items():
        py = reference['status']
        reference['main_flags_equal'] = None if py is None else all(native[key] == py[key] for key in ('intact', 'valid', 'trusted'))
        reference['verdict_agreement'] = None if py is None else bool(native['trusted']) == bool(py['trusted'])
        reference['exception_is_refusal_not_flags_parity'] = py is None
        reference['reference_disposition'] = ('exception_refusal' if py is None else 'trusted' if py['trusted'] else 'untrusted')
        reference['native_was_trusted'] = native.get('trusted')
        reference['more_trusting_than_reference'] = bool(native.get('trusted')) and (py is None or not py['trusted'])
    report['excluded'] = False
    report['surface_limit'] = 'Exact Core/MAIN predicate and ordinary public normalization are separate. Forbidden-only stricter native behavior is not erased. No timestamp final-result or full-AdES claim.'
    return report


async def main(args):
    assert not args.output.exists(), 'Preserve prior comparison attempts'
    assert __debug__ and sys.flags.optimize == 0
    assert Path(sys.prefix).resolve() == Path('/tmp/pyhanko-oracle/venv')
    versions = {name: importlib.metadata.version(name) for name in ('pyhanko', 'pyhanko-certvalidator', 'asn1crypto', 'cryptography', 'freezegun')}
    assert versions['pyhanko'] == '0.38.1' and versions['pyhanko-certvalidator'] == '0.33.0'
    modules = [module_record(name, PY) for name in ('pyhanko.sign.validation.generic_cms', 'pyhanko.sign.validation.settings', 'pyhanko.sign.validation.status')]
    modules += [module_record(name, CV) for name in ('pyhanko_certvalidator.context', 'pyhanko_certvalidator.policy_decl')]
    receipts = {}
    executables = []
    http_exchanges = []
    for log in args.native_log:
        for line in log.read_text().splitlines():
            if 'CONTEXT_DEFAULT_NATIVE_CASE ' in line:
                receipt = json.loads(line.split('CONTEXT_DEFAULT_NATIVE_CASE ', 1)[1])
                receipts.setdefault(receipt['sha256'], []).append(receipt | {'log': str(log)})
            if 'CONTEXT_DEFAULT_EXECUTABLE ' in line:
                executables.append(json.loads(line.split('CONTEXT_DEFAULT_EXECUTABLE ', 1)[1]))
            if 'CONTEXT_DEFAULT_HTTP_EXCHANGE ' in line:
                exchange = json.loads(line.split('CONTEXT_DEFAULT_HTTP_EXCHANGE ', 1)[1])
                for key in ('request', 'response'):
                    binary = decode(exchange[key + '_b64'])
                    assert len(binary) == exchange[key + '_length'] and sha(binary) == exchange[key + '_sha256']
                body = decode(exchange['response_b64']).split(b'\r\n\r\n', 1)[1]
                assert len(body) == exchange['body_length'] and sha(body) == exchange['body_sha256']
                http_exchanges.append(exchange)

    assert receipts and executables, 'No actual native output/ELF receipts'
    assert all(row == executables[0] for row in executables)
    native_receipt = json.loads(args.native_receipt.read_text())
    assert native_receipt['source_head'] == args.native_source
    assert native_receipt['returncode'] == 0
    frozen = [row for row in native_receipt['frozen_test_executables'] if row['sha256'] == executables[0]['sha256']]
    assert len(frozen) == 1
    frozen = frozen[0]
    assert frozen['length'] == executables[0]['length']
    import gzip
    archive = Path(frozen['snapshot'])
    assert sha(archive.read_bytes()) == frozen['lossless_gzip_archive_sha256']
    measured = hashlib.sha256(); total = 0
    with gzip.open(archive, 'rb') as file:
        for chunk in iter(lambda:file.read(1024 * 1024), b''):
            measured.update(chunk); total += len(chunk)
    assert measured.hexdigest() == executables[0]['sha256'] and total == executables[0]['length']
    rows = []
    for path in sorted(args.cases.glob('*.json')):
        raw = path.read_bytes(); h = sha(raw)
        assert h in receipts and all(item['length'] == len(raw) for item in receipts[h]), (path, 'not native-receipted')
        row = json.loads(raw)
        row['_source'] = file_record(path) | {'native_receipts': receipts[h]}
        rows.append(row)
    assert rows and set(receipts) == {row['_source']['sha256'] for row in rows}, 'native log/file set mismatch'
    network = []

    def deny_network(event, values):
        if event in {'socket.connect', 'socket.getaddrinfo', 'socket.sendto', 'socket.gethostbyname'}:
            network.append({'event': event, 'arguments': repr(values)})
            raise RuntimeError('Network forbidden in local-only same-byte comparison')

    sys.addaudithook(deny_network)
    results = []
    for row in rows:
        answer = await validate(row); results.append(answer)
        print('CONTEXT_DEFAULT_ORACLE_CASE ' + json.dumps(answer), flush=True)
    summary = {'actual_native_case_files': len(rows), 'actual_context_build_attempts': sum(row['actual_context_build_attempts'] for row in results), 'actual_validation_api_calls': sum(row['actual_validation_api_calls'] for row in results),
               'excluded_cases': [row['label'] for row in results if row['excluded']],
               'exceptions': [{'label': row['label'], 'surface': name, 'exception': result['exception']} for row in results for name, result in row['references'].items() if result['exception'] is not None],
               'main_flag_differences': [{'label': row['label'], 'surface': name} for row in results for name, result in row['references'].items() if result.get('main_flags_equal') is False],
               'more_trusting_native_results': [{'label':row['label'],'surface':name} for row in results for name,result in row['references'].items() if result.get('more_trusting_than_reference')],
               'flags_comparable_calls': sum(result['status'] is not None for row in results for result in row['references'].values()),
               'exception_phase_refusals': [{'label':row['label'],'surface':name,'phase':result['terminal_phase'],'class':result['exception']['class']} for row in results for name,result in row['references'].items() if result['exception'] is not None],
               'network_attempts': network, 'new_original_credit': 0}
    result = {'runner': file_record(Path(__file__)), 'interpreter': file_record(Path(sys.executable)), 'sys_prefix': sys.prefix,
              'assertions_enabled': __debug__, 'python': sys.version, 'versions': versions, 'modules': modules,
              'argv': sys.argv, 'native_executed_source': args.native_source, 'native_receipt': file_record(args.native_receipt),
              'native_ELF':executables[0], 'lossless_ELF_archive':file_record(archive), 'archive_decompressed_matches_runtime_ELF':True,
              'actual_HTTP_exchanges_verified': len(http_exchanges), 'native_logs': [file_record(log) for log in args.native_log],
              'actual_export_selection':'all native-receipted case files; no exclusions or material filtering', 'summary': summary, 'cases': results}
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print('CONTEXT_DEFAULT_ORACLE_SUMMARY ' + json.dumps(summary), flush=True)
    assert not network


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cases', type=Path, required=True)
    parser.add_argument('--native-log', type=Path, nargs='+', required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--native-source', required=True)
    parser.add_argument('--native-receipt', type=Path, required=True)
    args = parser.parse_args()
    # Imported modules are byte-checked against these pinned source trees.
    from asn1crypto import cms, x509
    from freezegun import freeze_time
    from pyhanko.sign.validation import generic_cms
    from pyhanko.sign.validation.settings import KeyUsageConstraints
    from pyhanko.sign.validation.status import SignatureStatus
    from pyhanko_certvalidator.context import ValidationContext
    from pyhanko_certvalidator.policy_decl import CertRevTrustPolicy, RevocationCheckingPolicy, RevocationCheckingRule
    asyncio.run(main(args))
