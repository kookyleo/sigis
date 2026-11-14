#!/usr/bin/env python3
"""Fresh unchanged pinned lifecycle originals and separate identity/error probes.

Only the exact three named upstream functions are executed by pytest. Separate
probes inspect their real empty C/R fixture and production context/kwargs path.
The supplied RecordingBackend counts explicit close; it does not close its
real delegate transport. No native HTTP/trust or general source graph parity
follows from these network-free observations.
"""
from __future__ import annotations

import argparse
import ast
import asyncio
import contextlib
import hashlib
import importlib.metadata
import importlib.util
import inspect
import io
import json
from pathlib import Path
import sys
import traceback
from unittest.mock import patch

import pytest
import pyhanko_certvalidator
import pyhanko.version
from pyhanko_certvalidator import context
from pyhanko_certvalidator.fetchers.aiohttp_fetchers import AIOHttpFetcherBackend
from pyhanko_certvalidator.fetchers.aiohttp_fetchers.util import LazySession
from pyhanko_certvalidator.registry import CertificateRegistry
from pyhanko_certvalidator.revinfo.manager import RevinfoManager

NAMES = (
    'test_policy_without_handlers_hands_over_nothing',
    'test_no_backend_when_fetchers_are_unreachable',
    'test_unreachable_fetchers_still_adopt_an_owned_backend',
)
DEFAULT_SOURCE = Path('/tmp/pyhanko-oracle/src/cv-0.33.0/pkgs/'
                      'pyhanko-certvalidator/tests/test_fetcher_lifecycle.py')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_record(path):
    path = Path(path)
    data = path.resolve().read_bytes()
    return {'path': str(path), 'resolved_path': str(path.resolve()),
            'length': len(data), 'sha256': sha(data)}


def node_record(source, name):
    node = next(item for item in ast.parse(source).body
                if isinstance(item, (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
                and item.name == name)
    lines = source.splitlines(keepends=True)
    body = ''.join(lines[node.lineno - 1:node.end_lineno])
    first = min([node.lineno] + [item.lineno for item in getattr(node, 'decorator_list', [])])
    decorated = ''.join(lines[first - 1:node.end_lineno])
    return {'name': name, 'line': node.lineno, 'end_line': node.end_lineno,
            'body': body, 'body_sha256': sha(body.encode()),
            'decorated_body': decorated, 'decorated_body_sha256': sha(decorated.encode()),
            'decorators': [ast.get_source_segment(source, item)
                           for item in getattr(node, 'decorator_list', [])],
            'assertions': [ast.get_source_segment(source, item) for item in ast.walk(node)
                           if isinstance(item, ast.Assert)]}


async def separate_probes(module):
    observations = []
    for ownership in ('none', 'borrowed', 'adopted'):
        manager, registry = module._handlers_only()
        backend = module.RecordingBackend()
        factories = []
        defaults = []
        assert registry.fetcher is None
        assert manager._fetchers is None
        assert not manager.fetching_allowed
        assert manager.certificate_registry is registry
        assert registry.certs == {}
        assert manager.crls == [] and manager.ocsps == []
        assert backend.closed == 0

        def forbidden_factory():
            factories.append('called')
            raise AssertionError('Internal issued fetchers must be unreachable for the actual empty C/R fixture')

        def forbidden_default():
            defaults.append('called')
            raise AssertionError('No default backend may be constructed for supplied C/R')

        kwargs = dict(trust_roots=[], allow_fetching=True,
                      revinfo_manager=manager, certificate_registry=registry)
        if ownership == 'borrowed':
            kwargs['fetcher_backend'] = backend
        elif ownership == 'adopted':
            kwargs['fetcher_backend'] = module.OwnedFetcherBackend(backend)
        with patch.object(context, '_default_fetcher_backend', forbidden_default), \
             patch.object(backend, 'get_fetchers', forbidden_factory):
            vc = context.ValidationContext(**kwargs)
            assert vc.certificate_registry is registry
            assert vc.path_builder.registry is registry
            assert vc.revinfo_manager is manager
            assert manager.certificate_registry is registry
            assert manager._fetchers is None and registry.fetcher is None
            assert vc._owned_fetcher_backend is (backend if ownership == 'adopted' else None)
            await vc.aclose()
            first = backend.closed
            assert first == (1 if ownership == 'adopted' else 0)
            await vc.aclose()
            second = backend.closed
            assert second == (2 if ownership == 'adopted' else 0)
            # The old caller alias remains independently usable. This is an
            # explicit additional call, not context Drop or transport cleanup.
            await backend.close()
            third = backend.closed
            assert third == second + 1
            assert not factories and not defaults
        observations.append({'selection': ownership, 'backend_factory_calls': len(factories),
                             'default_factory_calls': len(defaults), 'allow_fetching': True,
                             'actual_empty_fixture': True, 'registry_fetcher_is_None': True,
                             'revinfo_fetchers_are_None': True, 'R_C_alias_identity': True,
                             'context_C_R_path_builder_identity': True,
                             'owned_backend_exact_identity': ownership == 'adopted',
                             'initial_close_count': 0, 'after_context_close': first,
                             'after_repeat_context_close': second,
                             'after_explicit_old_backend_alias_close': third,
                             'backend_id': id(backend), 'registry_id': id(registry),
                             'manager_id': id(manager), 'R_internal_P_id': id(manager.poe_manager)})

    policy = module.CertValidationPolicySpec(
        trust_manager=module.SimpleTrustManager.build(trust_roots=[]),
        revinfo_policy=module.CertRevTrustPolicy(module.RevocationCheckingPolicy.from_legacy('soft-fail')),
    )
    timing = module.ValidationTimingInfo.now()
    defaults = []

    def forbidden_policy_default():
        defaults.append('called')
        raise AssertionError('Absent handlers must not provision a default backend')

    with patch.object(context, '_default_fetcher_backend', forbidden_policy_default):
        kwargs = policy.build_validation_context_kwargs(timing_info=timing, handlers=None)
        assert 'fetcher_backend' not in kwargs
        assert kwargs['allow_fetching'] is False
        manager = kwargs['revinfo_manager']
        registry = kwargs['certificate_registry']
        assert manager.certificate_registry is registry
        assert manager.poe_manager is kwargs['poe_manager']
        assert manager._fetchers is None and registry.fetcher is None
        for key, expected in [('trust_manager', policy.trust_manager),
                              ('revinfo_policy', policy.revinfo_policy),
                              ('algorithm_usage_policy', policy.algorithm_usage_policy),
                              ('signature_validator', policy.signature_validator),
                              ('moment', timing.validation_time),
                              ('best_signature_time', timing.best_signature_time),
                              ('time_tolerance', policy.time_tolerance),
                              ('acceptable_ac_targets', policy.acceptable_ac_targets)]:
            assert kwargs[key] is expected
        vc = context.ValidationContext(trust_roots=[], **kwargs)
        assert vc._owned_fetcher_backend is None
        assert vc.certificate_registry is registry and vc.revinfo_manager is manager
        await vc.aclose()
        await vc.aclose()
        assert not defaults
    absent = {'backend_key_absent': True, 'default_factory_calls': len(defaults),
              'ordinary_constructor_owned_backend': None, 'allow_fetching': False,
              'new_real_empty_C_R_P_created': True, 'full_forwarded_fields_preserved': True,
              'no_claim_that_native_None_clears_explicit_builder_selections': True}

    class MarkerError(RuntimeError):
        pass

    marker = MarkerError('Unreachable adopted owner close error identity')

    class FailingBackend(module.RecordingBackend):
        def get_fetchers(self):
            raise AssertionError('No factory call is reachable')

        async def close(self):
            self.closed += 1
            raise marker

    failing = FailingBackend()
    manager, registry = module._handlers_only()
    failed_ctx = context.ValidationContext(
        trust_roots=[], allow_fetching=True, revinfo_manager=manager,
        certificate_registry=registry,
        fetcher_backend=module.OwnedFetcherBackend(failing))
    errors = []
    for close in (failed_ctx.aclose, failed_ctx.aclose, failing.close):
        try:
            await close()
        except MarkerError as exc:
            assert exc is marker
            errors.append({'class': type(exc).__name__, 'message': str(exc),
                           'same_exception_identity': True, 'closed': failing.closed})
        else:
            raise AssertionError('Explicit close error must propagate')
    assert failed_ctx._owned_fetcher_backend is failing and failing.closed == 3
    return {'kind': 'Separate supplemental probes; zero additional original executions',
            'actual_empty_fixture_reachability': observations,
            'policy_None_producer': absent, 'typed_close_errors': errors,
            'caller_backend_alias_survives': True, 'implicit_Drop_close_claimed': False,
            'RecordingBackend_actual_HTTP_pool_close_claimed': False,
            'broader_external_nonempty_custom_C_R_graph_parity_claimed': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, default=DEFAULT_SOURCE)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    assert __debug__ and sys.flags.optimize == 0
    assert Path(sys.prefix).resolve() == Path('/tmp/pyhanko-oracle/venv')
    assert not args.output.exists(), 'Preserve prior oracle outputs'
    versions = {name: importlib.metadata.version(name)
                for name in ('pyHanko', 'pyhanko-certvalidator')}
    assert versions == {'pyHanko': '0.38.1', 'pyhanko-certvalidator': '0.33.0'}
    source_bytes = args.source.read_bytes()
    source = source_bytes.decode()
    originals = [node_record(source, name) for name in NAMES]
    helpers = [node_record(source, name) for name in ('RecordingBackend', '_handlers_only')]
    network_events = []
    framework_binds = []

    def deny_network(event, values):
        if event == 'socket.bind':
            framework_binds.append({'event': event, 'arguments': repr(values),
                                    'stack': traceback.format_stack()})
            raise AssertionError('No socket listener belongs to these originals')
        if event in {'socket.connect', 'socket.sendto', 'socket.getaddrinfo', 'socket.gethostbyname'}:
            network_events.append({'event': event, 'arguments': repr(values)})
            raise AssertionError('Network is forbidden for these lifecycle originals/probes')

    sys.addaudithook(deny_network)

    class Reports:
        def __init__(self):
            self.rows = []

        def pytest_runtest_logreport(self, report):
            self.rows.append({'nodeid': report.nodeid, 'when': report.when,
                              'outcome': report.outcome,
                              'longrepr': str(report.longrepr) if report.failed else None})

    reports = Reports()
    output = io.StringIO()
    pytest_args = ['-q', '--strict-markers', '-p', 'no:requests_mock']
    pytest_args += [str(args.source) + '::' + name for name in NAMES]
    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
        exit_code = int(pytest.main(pytest_args, plugins=[reports]))
    spec = importlib.util.spec_from_file_location('remaining_fetch_lifecycle_probe_source', args.source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # Preserve the unchanged-original stage even if a separate probe fails.
    args.output.parent.mkdir(parents=True, exist_ok=True)
    stage = args.output.with_name(args.output.stem + '-original-stage.json')
    assert not stage.exists()
    stage.write_text(json.dumps({'runner': file_record(__file__), 'pytest_exit': exit_code,
                                'pytest_reports': reports.rows, 'pytest_output': output.getvalue(),
                                'originals': originals, 'fixture_closure': helpers}, indent=2) + '\n')
    probe = asyncio.run(separate_probes(module))
    package_root = args.source.parent.parent / 'src' / 'pyhanko_certvalidator'
    modules = []
    for value, relative in [(pyhanko_certvalidator, '__init__.py'),
                            (context, 'context.py'),
                            (RevinfoManager, 'revinfo/manager.py'),
                            (CertificateRegistry, 'registry.py'),
                            (AIOHttpFetcherBackend, 'fetchers/aiohttp_fetchers/__init__.py'),
                            (LazySession, 'fetchers/aiohttp_fetchers/util.py')]:
        actual = Path(inspect.getsourcefile(value))
        pinned = package_root / relative
        assert actual.read_bytes() == pinned.read_bytes()
        modules.append({'actual': file_record(actual), 'pinned': file_record(pinned), 'byte_equal': True})
    pyhanko_version_source = Path(inspect.getsourcefile(pyhanko.version))
    pinned_pyhanko_version = Path('/tmp/pyhanko-oracle/src/v0.38.1/pkgs/pyhanko/src/pyhanko/version/__init__.py')
    assert pyhanko.version.__version__ == '0.38.1'
    version_record = {'actual': file_record(pyhanko_version_source),
                      'pinned': file_record(pinned_pyhanko_version),
                      'byte_equal': pyhanko_version_source.read_bytes() == pinned_pyhanko_version.read_bytes(),
                      'actual_version': pyhanko.version.__version__,
                      'disposition': 'Installed release-generated version differs from source placeholder 0.0.0.dev1; validation implementation sources above remain byte-equal.'}
    result = {'schema': 1, 'kind': 'Fresh unchanged original3 and separate identity/count/error probes',
              'runner': file_record(__file__), 'interpreter': file_record(sys.executable),
              'python': sys.version, 'sys_prefix': sys.prefix, 'assertions_enabled': __debug__,
              'versions': versions, 'package': file_record(pyhanko_certvalidator.__file__),
              'original_test_module': file_record(args.source), 'originals': originals,
              'fixture_closure': helpers, 'imported_sources_match_pinned': modules,
              'release_generated_pyHanko_version_module': version_record,
              'pytest_arguments': pytest_args, 'pytest_exit': exit_code,
              'pytest_reports': reports.rows, 'pytest_output': output.getvalue(),
              'actual_unchanged_original_executions': len(NAMES), 'original_parameter_counts': [1, 1, 1],
              'supplemental_probes': probe, 'network_request_attempts': network_events,
              'denied_framework_bind_probes': framework_binds,
              'provider_exclusions': [], 'original_parameter_exclusions': [],
              'unused_plugin_disabled': 'requests_mock: unused import performs an IPv6 bind probe',
              'new_accepted_upstream_credit': 0,
              'scope': 'Only exact empty supplied-C/R fixture. Native explicit-none component adaptation is a separate Lead decision, not general manager/source graph equivalence or a Python API change.'}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'output': str(args.output), 'pytest_exit': exit_code,
                      'original_executions': len(NAMES), 'probe': probe,
                      'network_attempts': len(network_events),
                      'denied_framework_binds': len(framework_binds)}, indent=2))
    assert source_bytes == args.source.read_bytes()
    calls = [row for row in reports.rows if row['when'] == 'call']
    assert exit_code == 0 and len(calls) == 3 and all(row['outcome'] == 'passed' for row in calls)
    assert not network_events
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
