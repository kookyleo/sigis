"""pytest plugin: record pyHanko's validation calls as JSON fixtures.

Runs the upstream pyHanko 0.38.1 tests unchanged and wraps the CMS-level
validation entry points. Every call is recorded with its inputs (the CMS
bytes, digests, certificates and the validation context's settings) and its
outcome (the status fields, or the exception class, message and AdES
sub-indication). The Rust tests replay these calls against hanko-cms.

Usage: see harvest.sh next to this file. Output: $HARVEST_OUT (JSON).
"""

import asyncio
import base64
import functools
import hashlib
import json
import os
from datetime import datetime, timezone

import pytest

RECORDS = []
CERTS = {}
CURRENT = {'test': None, 'index': 0}
DEPTH = {'n': 0}


def b64(data):
    return base64.b64encode(bytes(data)).decode('ascii')


def cert_ref(cert):
    der = cert.dump()
    key = hashlib.sha256(der).hexdigest()[:16]
    CERTS[key] = b64(der)
    return key


def dt(value):
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc).isoformat()


def describe_policy(policy):
    if policy is None:
        return None
    inner = getattr(policy, '_policy', None) or getattr(policy, 'policy', None)
    out = {'class': type(policy).__name__}
    if inner is not None:
        out['inner'] = describe_policy(inner)
    for attr in (
        'weak_hash_algos',
        'weak_signature_algos',
        'rsa_key_size_threshold',
        'dsa_key_size_threshold',
    ):
        if hasattr(policy, attr):
            v = getattr(policy, attr)
            out[attr] = sorted(v) if isinstance(v, (set, frozenset)) else v
    return out


def describe_vc(vc):
    if vc is None:
        return None
    tm = vc.path_builder.trust_manager
    roots = [cert_ref(c) for c in tm.iter_certs()] if hasattr(tm, 'iter_certs') else None
    others = [cert_ref(c) for c in vc.certificate_registry]
    rp = vc.revinfo_policy
    return {
        'trust_roots': roots,
        'trust_manager': type(tm).__name__,
        'other_certs': others,
        'moment': dt(vc.moment),
        'best_signature_time': dt(vc.best_signature_time),
        'time_tolerance': vc.time_tolerance.total_seconds(),
        'fetching_allowed': vc.fetching_allowed,
        'crls': [b64(c.dump()) for c in vc.crls],
        'ocsps': [b64(o.dump()) for o in vc.ocsps],
        'revinfo_policy': {
            'ee': rp.revocation_checking_policy.ee_certificate_rule.value,
            'intermediate': rp.revocation_checking_policy.intermediate_ca_cert_rule.value,
            'retroactive_revinfo': rp.retroactive_revinfo,
        },
        'algorithm_policy': describe_policy(vc.algorithm_policy),
    }


def describe_signature_status(st):
    if st is None:
        return None
    out = {
        'class': type(st).__name__,
        'intact': st.intact,
        'valid': st.valid,
        'trusted': st.trusted,
        'revoked': st.revoked,
        'trust_problem_indic': (
            None if st.trust_problem_indic is None else st.trust_problem_indic.name
        ),
        'md_algorithm': st.md_algorithm,
        'pkcs7_signature_mechanism': st.pkcs7_signature_mechanism,
        'signing_cert': cert_ref(st.signing_cert) if st.signing_cert is not None else None,
        'validation_path_len': (
            None if st.validation_path is None else len(st.validation_path)
        ),
        'error_time_horizon': dt(getattr(st, 'error_time_horizon', None)),
    }
    rd = getattr(st, 'revocation_details', None)
    if rd is not None:
        out['revocation_details'] = {
            'ca_revoked': rd.ca_revoked,
            'revocation_date': dt(rd.revocation_date),
            'revocation_reason': rd.revocation_reason.native,
        }
    if hasattr(st, 'timestamp') and not hasattr(st, 'timestamp_validity'):
        out['timestamp'] = dt(st.timestamp)
    for attr in ('timestamp_validity', 'content_timestamp_validity'):
        if hasattr(st, attr):
            out[attr] = describe_signature_status(getattr(st, attr))
    if hasattr(st, 'signer_reported_dt'):
        out['signer_reported_dt'] = dt(st.signer_reported_dt)
    if hasattr(st, 'bottom_line'):
        out['bottom_line'] = st.bottom_line
    try:
        out['summary'] = st.summary()
    except Exception:  # noqa: BLE001
        pass
    for attr in ('ac_attrs',):
        v = getattr(st, attr, None)
        if v is not None:
            out[attr] = sorted(a.attr_type.native for a in v)
    errs = getattr(st, 'ac_validation_errs', None)
    if errs is not None:
        out['ac_validation_errs'] = [type(e).__name__ for e in errs]
    csa = getattr(st, 'cades_signer_attrs', None)
    if csa is not None:
        out['cades_signer_attrs'] = {
            'claimed_attrs': sorted(a.attr_type.native for a in csa.claimed_attrs),
            'certified_attrs': (
                None
                if csa.certified_attrs is None
                else sorted(a.attr_type.native for a in csa.certified_attrs)
            ),
            'valid': csa.valid,
            'unknown_attrs_present': csa.unknown_attrs_present,
        }
    return out


def describe_exception(e):
    sub = getattr(e, 'ades_subindication', None)
    return {
        'error': type(e).__name__,
        'mro': [c.__name__ for c in type(e).__mro__],
        'message': str(e),
        'ades_subindication': None if sub is None else sub.name,
    }


def record(fn_name, inputs, outcome):
    RECORDS.append(
        {
            'test': CURRENT['test'],
            'index': CURRENT['index'],
            'fn': fn_name,
            'inputs': inputs,
            'outcome': outcome,
        }
    )
    CURRENT['index'] += 1


def sd_bytes(signed_data):
    from asn1crypto import cms

    return b64(cms.ContentInfo({'content_type': 'signed_data', 'content': signed_data}).dump())


def input_data_desc(input_data):
    from asn1crypto import cms

    if isinstance(input_data, bytes):
        return {'bytes': b64(input_data)}
    if isinstance(input_data, (cms.ContentInfo, cms.EncapsulatedContentInfo)):
        return {'bytes': b64(bytes(input_data['content']))}
    pos = input_data.tell()
    data = input_data.read()
    input_data.seek(pos)
    return {'bytes': b64(data)}


def wrap_async(fn_name, original, describe_inputs):
    @functools.wraps(original)
    async def wrapper(*args, **kwargs):
        if DEPTH['n'] > 0:
            return await original(*args, **kwargs)
        DEPTH['n'] += 1
        try:
            inputs = describe_inputs(*args, **kwargs)
            try:
                result = await original(*args, **kwargs)
            except Exception as e:
                record(fn_name, inputs, describe_exception(e))
                raise
            record(fn_name, inputs, {'status': describe_signature_status(result)})
            return result
        finally:
            DEPTH['n'] -= 1

    return wrapper


def wrap_sync(fn_name, original, describe_inputs, describe_result):
    @functools.wraps(original)
    def wrapper(*args, **kwargs):
        if DEPTH['n'] > 0:
            return original(*args, **kwargs)
        DEPTH['n'] += 1
        try:
            inputs = describe_inputs(*args, **kwargs)
            try:
                result = original(*args, **kwargs)
            except Exception as e:
                record(fn_name, inputs, describe_exception(e))
                raise
            record(fn_name, inputs, describe_result(result))
            return result
        finally:
            DEPTH['n'] -= 1

    return wrapper


def bind(original, args, kwargs):
    import inspect

    sig = inspect.signature(original)
    ba = sig.bind(*args, **kwargs)
    ba.apply_defaults()
    return ba.arguments


def install():
    from pyhanko.sign import validation as v
    from pyhanko.sign.validation import generic_cms, pdf_embedded

    orig_cms = generic_cms.async_validate_cms_signature

    def cms_inputs(*args, **kwargs):
        a = bind(orig_cms, args, kwargs)
        return {
            'signed_data': sd_bytes(a['signed_data']),
            'status_cls': a['status_cls'].__name__,
            'raw_digest': None if a['raw_digest'] is None else a['raw_digest'].hex(),
            'vc': describe_vc(a['validation_context']),
            'key_usage_settings': repr(a['key_usage_settings']),
            'algorithm_policy': describe_policy(a['algorithm_policy']),
        }

    orig_detached = generic_cms.async_validate_detached_cms

    def detached_inputs(*args, **kwargs):
        a = bind(orig_detached, args, kwargs)
        return {
            'input_data': input_data_desc(a['input_data']),
            'signed_data': sd_bytes(a['signed_data']),
            'vc': describe_vc(a['signer_validation_context']),
            'ts_vc': describe_vc(a['ts_validation_context']),
            'ac_vc': describe_vc(a['ac_validation_context']),
            'key_usage_settings': repr(a['key_usage_settings']),
            'algorithm_policy': describe_policy(a['algorithm_policy']),
        }

    orig_integrity = generic_cms.validate_sig_integrity

    def integrity_inputs(*args, **kwargs):
        from asn1crypto import cms

        a = bind(orig_integrity, args, kwargs)
        return {
            'signer_info': b64(cms.SignerInfo.load(a['signer_info'].dump()).dump()),
            'cert': cert_ref(a['cert']),
            'expected_content_type': a['expected_content_type'],
            'actual_digest': a['actual_digest'].hex(),
        }

    def integrity_result(result):
        intact, valid = result
        return {'intact': intact, 'valid': valid}

    orig_pdf = pdf_embedded.async_validate_pdf_signature

    def pdf_inputs(*args, **kwargs):
        a = bind(orig_pdf, args, kwargs)
        emb = a['embedded_sig']
        return {
            'signed_data': sd_bytes(emb.signed_data),
            'md_algorithm': emb.md_algorithm,
            'document_digest': emb.compute_digest().hex(),
            'vc': describe_vc(a['signer_validation_context']),
            'ts_vc': describe_vc(a['ts_validation_context']),
            'ac_vc': describe_vc(a['ac_validation_context']),
            'key_usage_settings': repr(a['key_usage_settings']),
            'algorithm_policy': describe_policy(a['algorithm_policy']),
            'skip_diff': a['skip_diff'],
        }

    orig_extract = generic_cms.extract_certs_for_validation

    def extract_inputs(*args, **kwargs):
        a = bind(orig_extract, args, kwargs)
        return {'signed_data': sd_bytes(a['signed_data'])}

    def extract_result(result):
        return {
            'signer_cert': cert_ref(result.signer_cert),
            'other_certs': len(result.other_certs),
            'attribute_certs': len(result.attribute_certs),
        }

    orig_signer_info = pdf_embedded.extract_signer_info

    def signer_info_inputs(*args, **kwargs):
        a = bind(orig_signer_info, args, kwargs)
        return {'signed_data': sd_bytes(a['signed_data'])}

    w_extract = wrap_sync(
        'extract_certs_for_validation', orig_extract, extract_inputs, extract_result
    )
    w_signer_info = wrap_sync(
        'extract_signer_info',
        orig_signer_info,
        signer_info_inputs,
        lambda result: {'ok': True},
    )
    generic_cms.extract_certs_for_validation = w_extract
    pdf_embedded.extract_signer_info = w_signer_info

    w_cms = wrap_async('async_validate_cms_signature', orig_cms, cms_inputs)
    w_detached = wrap_async('async_validate_detached_cms', orig_detached, detached_inputs)
    w_integrity = wrap_sync(
        'validate_sig_integrity', orig_integrity, integrity_inputs, integrity_result
    )
    w_pdf = wrap_async('async_validate_pdf_signature', orig_pdf, pdf_inputs)

    for mod in (generic_cms, v):
        mod.async_validate_cms_signature = w_cms
        mod.async_validate_detached_cms = w_detached
        mod.validate_sig_integrity = w_integrity
    for mod in (pdf_embedded, v):
        mod.async_validate_pdf_signature = w_pdf


def pytest_configure(config):
    install()


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item):
    CURRENT['test'] = item.nodeid.split('::', 1)[-1]
    CURRENT['index'] = 0
    yield


def pytest_sessionfinish(session, exitstatus):
    out = os.environ.get('HARVEST_OUT')
    if not out:
        return
    with open(out, 'w') as f:
        json.dump({'calls': RECORDS, 'certs': CERTS}, f, indent=1, sort_keys=True)
        f.write('\n')
