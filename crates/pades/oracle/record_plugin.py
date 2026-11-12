"""pytest plugin: record pyHanko AdES validation runs as fixtures.

Run pyHanko's own test modules (tag v0.38.1) with this plugin loaded to
record, for every call of a public ``pyhanko.sign.validation.ades``
function:

* the validated object (CMS SignedData, or the whole PDF plus the field
  name of the embedded signature),
* the (frozen) wall-clock time of the call,
* every HTTP exchange with the Certomancer PKI services during the call,
* pyHanko's verdict (AdES indication, sub-indication and a few flags).

The Rust tests port the validation specs by hand and replay the recorded
inputs, HTTP exchanges and verdicts.

Usage: see ``run_oracle.sh`` next to this file. The output path is taken
from the ``HANKO_RECORD_OUT`` environment variable.
"""

import base64
import functools
import json
import os
from datetime import datetime, timezone

import pytest

_RECORDS = {}
_CURRENT = {'nodeid': None, 'http': None}


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode('ascii')


def _describe_input(obj):
    from asn1crypto import cms

    if isinstance(obj, cms.SignedData):
        return {'kind': 'cms_signed_data', 'der': _b64(obj.dump())}
    # EmbeddedPdfSignature
    reader = getattr(obj, 'reader', None)
    if reader is not None:
        stream = reader.stream
        pos = stream.tell()
        stream.seek(0)
        data = stream.read()
        stream.seek(pos)
        return {
            'kind': 'pdf_signature',
            'pdf': _b64(data),
            'field_name': obj.field_name,
            'sig_object_type': str(obj.sig_object_type),
        }
    return {'kind': type(obj).__name__}


def _enum_name(v):
    if v is None:
        return None
    return getattr(v, 'name', str(v))


def _describe_result(res):
    out = {
        'type': type(res).__name__,
        'ades_subindic': _enum_name(getattr(res, 'ades_subindic', None)),
    }
    sub = getattr(res, 'ades_subindic', None)
    if sub is not None:
        out['ades_status'] = _enum_name(sub.status)
        out['ades_subindic_class'] = type(sub).__name__
    status = getattr(res, 'api_status', None)
    if status is not None:
        for attr in ('intact', 'valid', 'trusted', 'revoked', 'bottom_line', 'coverage', 'docmdp_ok'):
            try:
                val = getattr(status, attr)
            except Exception:  # noqa: BLE001
                continue
            out[f'api_status.{attr}'] = val if isinstance(val, (bool, type(None))) else _enum_name(val)
        qr = getattr(status, 'qualification_result', None)
        if qr is not None:
            out['qualified'] = qr.status.qualified
            out['qc_type'] = _enum_name(qr.status.qc_type)
            out['qc_key_security'] = _enum_name(qr.status.qc_key_security)
    for attr in ('best_signature_time', 'signature_poe_time'):
        val = getattr(res, attr, None)
        if isinstance(val, datetime):
            out[attr] = val.astimezone(timezone.utc).isoformat()
    failure_msg = getattr(res, 'failure_msg', None)
    if failure_msg is not None:
        out['failure_msg'] = str(failure_msg)
    return out


def _wrap(module, name):
    orig = getattr(module, name)

    @functools.wraps(orig)
    async def wrapper(*args, **kwargs):
        http = []
        prev = _CURRENT['http']
        _CURRENT['http'] = http
        call = {
            'function': name,
            'time': datetime.now(timezone.utc).isoformat(),
            'input': _describe_input(args[0]) if args else None,
        }
        if 'raw_digest' in kwargs and kwargs['raw_digest'] is not None:
            call['raw_digest'] = _b64(kwargs['raw_digest'])
        try:
            res = await orig(*args, **kwargs)
        except Exception as e:  # noqa: BLE001
            call['exception'] = {'type': type(e).__name__, 'message': str(e)}
            raise
        finally:
            _CURRENT['http'] = prev
            call['http'] = http
            _RECORDS.setdefault(_CURRENT['nodeid'], []).append(call)
        call['result'] = _describe_result(res)
        return res

    setattr(module, name, wrapper)


def _patch_dispatch():
    from pyhanko_testing_commons.test_utils import live_http

    registry_cls = live_http.PKIServiceRegistry
    orig = registry_cls._dispatch

    async def dispatch(self, request):
        body = await request.read()
        resp = await orig(self, request)
        http = _CURRENT['http']
        if http is not None:
            http.append(
                {
                    'method': request.method,
                    'path': request.path_qs,
                    'request_body': _b64(body),
                    'status': resp.status,
                    'content_type': resp.content_type,
                    'response_body': _b64(resp.body or b''),
                }
            )
        return resp

    registry_cls._dispatch = dispatch



def _patch_requests_dispatch():
    """Capture the requests backend in addition to aiohttp service dispatch."""
    import requests
    from urllib.parse import urlsplit

    original = requests.Session.request

    def request(self, *args, **kwargs):
        response = original(self, *args, **kwargs)
        request = response.request
        http = _CURRENT['http']
        if http is not None:
            url = urlsplit(request.url)
            body = request.body or b''
            if isinstance(body, str):
                body = body.encode('utf-8')
            http.append({
                'method': request.method,
                'path': url.path + ('?' + url.query if url.query else ''),
                'request_body': _b64(body),
                'status': response.status_code,
                'content_type': response.headers.get('Content-Type', ''),
                'response_body': _b64(response.content),
            })
        return response

    requests.Session.request = request


_GENERATED_TLS = []
PKI_ARCHS = [
    'testing-ca',
    'testing-ca-ecdsa',
    'testing-ca-qualified',
    'unrelated-tsa',
    'testing-ca-with-aa',
]


def _patch_tl_generation():
    from pyhanko_testing_commons.test_data import certomancer_trust_lists as ctl

    orig = ctl.certomancer_pki_as_trusted_list

    def wrapped(pki_arch, tlso_entity):
        xml = orig(pki_arch, tlso_entity)
        _GENERATED_TLS.append(
            {
                'nodeid': _CURRENT['nodeid'],
                'arch': str(pki_arch.arch_label),
                'tlso_entity': str(tlso_entity),
                'xml': xml,
            }
        )
        return xml

    ctl.certomancer_pki_as_trusted_list = wrapped


def _export_pki():
    from certomancer.registry import ArchLabel
    from pyhanko_testing_commons.test_data.samples import CERTOMANCER

    out = {}
    for arch in PKI_ARCHS:
        pki = CERTOMANCER.get_pki_arch(ArchLabel(arch))
        certs = {}
        for _iss, specs in pki.enumerate_certs_by_issuer():
            for spec in specs:
                certs[str(spec.label)] = _b64(pki.get_cert(spec.label).dump())
        out[arch] = certs
    return out


def pytest_configure(config):
    from pyhanko.sign.validation import ades

    _patch_tl_generation()

    for name in (
        'ades_basic_validation',
        'ades_with_time_validation',
        'ades_lta_validation',
        'ades_timestamp_validation',
        'simulate_future_ades_lta_validation',
    ):
        _wrap(ades, name)
    _patch_dispatch()
    _patch_requests_dispatch()


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item):
    _CURRENT['nodeid'] = item.nodeid
    yield
    _CURRENT['nodeid'] = None


def pytest_runtest_logreport(report):
    if report.when == 'call':
        _RECORDS.setdefault(report.nodeid, [])
        _OUTCOMES[report.nodeid] = report.outcome


_OUTCOMES = {}


def pytest_sessionfinish(session):
    out = os.environ.get('HANKO_RECORD_OUT')
    if not out:
        return
    doc = {
        'pyhanko': '0.38.1',
        'pki': _export_pki(),
        'generated_tls': _GENERATED_TLS,
        'tests': {
            nodeid: {'outcome': _OUTCOMES.get(nodeid), 'calls': calls}
            for nodeid, calls in sorted(_RECORDS.items())
            if nodeid
        },
    }
    with open(out, 'w', encoding='utf-8') as f:
        json.dump(doc, f, indent=1, sort_keys=True)
