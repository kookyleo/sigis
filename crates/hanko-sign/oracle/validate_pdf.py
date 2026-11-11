"""pyHanko verdicts on every signature of a PDF produced by hanko-sign.

Usage: python validate_pdf.py --pdf FILE [--trust CERT ...] [--other CERT ...]
           [--time ISO8601] [--extd] [--no-trust]
           [--password PWD]

Runs pyHanko's ``validate_pdf_signature`` (or ``validate_pdf_timestamp`` for
document timestamps) on each
embedded signature, with the clock frozen at --time and fetching disabled.
--extd runs the difference analysis (pyHanko's ``skip_diff=False``).
Prints a JSON list with one object per signature.
"""

import argparse
import asyncio
import json
from datetime import datetime

from freezegun import freeze_time
from pyhanko.keys import load_cert_from_pemder
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import (
    async_validate_pdf_signature,
    async_validate_pdf_timestamp,
)
from pyhanko_certvalidator import ValidationContext


def enum_name(v):
    return None if v is None else getattr(v, 'name', str(v))


def status_json(st):
    out = {}
    for f in ('intact', 'valid', 'trusted', 'docmdp_ok', 'bottom_line',
              'md_algorithm', 'pkcs7_signature_mechanism', 'seed_value_ok'):
        if hasattr(st, f):
            v = getattr(st, f)
            out[f] = v if isinstance(v, (bool, str, type(None))) else str(v)
    for f in ('coverage', 'modification_level', 'validation_path'):
        pass
    if hasattr(st, 'coverage'):
        out['coverage'] = enum_name(st.coverage)
    if hasattr(st, 'modification_level'):
        out['modification_level'] = enum_name(st.modification_level)
    if hasattr(st, 'summary'):
        try:
            out['summary'] = st.summary()
        except Exception as e:  # noqa
            out['summary_error'] = str(e)
    ts = getattr(st, 'timestamp', None)
    if ts is not None:
        out['timestamp'] = ts.isoformat()
    for f in ('timestamp_validity', 'content_timestamp_validity'):
        sub = getattr(st, f, None)
        if sub is not None:
            out[f] = status_json(sub)
    if getattr(st, 'signer_reported_dt', None) is not None:
        out['signer_reported_dt'] = st.signer_reported_dt.isoformat()
    if getattr(st, 'signing_cert', None) is not None:
        out['signing_cert_sha256'] = st.signing_cert.sha256.hex()
    if hasattr(st, 'ac_attrs'):
        out['ac_attrs_is_none'] = st.ac_attrs is None
        out['ac_attrs_len'] = len(st.ac_attrs) if st.ac_attrs else 0
    csa = getattr(st, 'cades_signer_attrs', None)
    if csa is not None:
        claimed = csa.claimed_attrs
        out['cades_signer_attrs'] = {
            'unknown_attrs_present': csa.unknown_attrs_present,
            'claimed_count': len(claimed) if claimed is not None else None,
            'certified_is_none': csa.certified_attrs is None,
            'certified_count': len(csa.certified_attrs) if csa.certified_attrs else 0,
            'groups': sorted(
                v for a in claimed['group'].attr_values for v in a['values'].native
            ) if claimed is not None and 'group' in claimed else None,
        }
    if getattr(st, 'diff_result', None) is not None:
        out['diff_result'] = str(st.diff_result)
    return out


async def run(a):
    with open(a.pdf, 'rb') as f:
        r = PdfFileReader(f, strict=not a.lenient)
        if a.password is not None:
            r.decrypt(a.password.encode())
        out = []
        try:
            if a.from_fields:
                from pyhanko.sign import fields as _fields
                from pyhanko.sign.validation import EmbeddedPdfSignature

                sigs = [
                    EmbeddedPdfSignature(r, sig_field, fq_name)
                    for fq_name, _v, sig_field in _fields.enumerate_sig_fields(
                        r, filled_status=True
                    )
                ]
            else:
                sigs = list(r.embedded_signatures)
        except Exception as e:
            return [{'reader_error': f'{e.__class__.__name__}: {e}'}]
        if a.count_only:
            return [{'count': len(sigs)}]
        for sig in sigs:
            roots = [] if a.no_trust else [load_cert_from_pemder(p) for p in a.trust]
            if a.ts_anchor:
                from pyhanko_certvalidator.authority import (
                    CertTrustAnchor,
                    TrustedServiceType,
                    TrustQualifiers,
                )
                from pyhanko_certvalidator.registry import SimpleTrustManager

                anchors = list(roots)
                for spec in a.ts_anchor:
                    path, _, kind = spec.partition(':')
                    cert = load_cert_from_pemder(path)
                    if kind:
                        anchors.append(CertTrustAnchor(
                            cert,
                            TrustQualifiers(trusted_service_type=TrustedServiceType[kind]),
                        ))
                    else:
                        anchors.append(cert)
                vc = ValidationContext(
                    trust_manager=SimpleTrustManager.build(anchors),
                    allow_fetching=bool(a.live),
                    revocation_mode=a.revocation_mode,
                )
            else:
                vc = ValidationContext(
                    trust_roots=roots,
                    other_certs=[load_cert_from_pemder(p) for p in a.other],
                    allow_fetching=bool(a.live),
                    revocation_mode=a.revocation_mode,
                )
            entry = {
                'field': sig.field_name,
                'type': sig.sig_object_type,
                'subfilter': str(sig.sig_object.get('/SubFilter')),
            }
            try:
                if a.ades_lta and sig.sig_object_type == '/Sig':
                    from pyhanko.sign.validation.ades import ades_lta_validation
                    from pyhanko.sign.validation.policy_decl import (
                        PdfSignatureValidationSpec,
                        SignatureValidationSpec,
                    )
                    from pyhanko_certvalidator.context import (
                        CertValidationPolicySpec,
                    )
                    from pyhanko_certvalidator.policy_decl import (
                        NO_REVOCATION,
                        REQUIRE_REVINFO,
                        CertRevTrustPolicy,
                    )
                    from pyhanko_certvalidator.registry import SimpleTrustManager

                    spec = PdfSignatureValidationSpec(
                        SignatureValidationSpec(
                            cert_validation_policy=CertValidationPolicySpec(
                                trust_manager=SimpleTrustManager.build(
                                    trust_roots=[load_cert_from_pemder(p) for p in a.trust]
                                ),
                                revinfo_policy=CertRevTrustPolicy(
                                    NO_REVOCATION if a.norev else REQUIRE_REVINFO
                                ),
                            )
                        )
                    )
                    ades = await ades_lta_validation(sig, spec)
                    entry['ades_indication'] = enum_name(ades.ades_subindic) if ades.ades_subindic else None
                    entry['ades_subindic'] = enum_name(ades.ades_subindic)
                    if ades.api_status is not None:
                        entry.update(status_json(ades.api_status))
                    out.append(entry)
                    continue
                if a.as_timestamp or sig.sig_object_type == '/DocTimeStamp':
                    st = await async_validate_pdf_timestamp(sig, validation_context=vc)
                else:
                    kwargs = {}
                    if a.diff_policy == 'no-changes':
                        from pyhanko.sign.diff_analysis import NO_CHANGES_DIFF_POLICY

                        kwargs['diff_policy'] = NO_CHANGES_DIFF_POLICY
                    st = await async_validate_pdf_signature(
                        sig, vc, skip_diff=not a.extd,
                        ac_validation_context=vc if a.ac_vc else None,
                        **kwargs,
                    )
                    entry['revoked'] = getattr(st, 'revoked', None)
                    entry['diff_result_is_none'] = sig.diff_result is None
                entry.update(status_json(st))
            except Exception as e:  # report pyHanko's rejection class
                entry['error'] = f'{e.__class__.__name__}: {e}'
            out.append(entry)
    return out


def run_with_services(a):
    if not a.live:
        return asyncio.run(run(a))
    # Certomancer's live services, as pyHanko's `pki_services` fixture
    # provides them (answers at the frozen time).
    from certomancer.registry import ArchLabel
    from pyhanko_testing_commons.test_data.samples import CERTOMANCER
    from pyhanko_testing_commons.test_utils.live_http import live_pki_services

    with live_pki_services() as reg:
        for arch in a.live:
            reg.register(CERTOMANCER.get_pki_arch(ArchLabel(arch)))
        return asyncio.run(run(a))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--pdf', required=True)
    ap.add_argument('--trust', action='append', default=[])
    ap.add_argument('--other', action='append', default=[])
    ap.add_argument('--time')
    ap.add_argument('--extd', action='store_true')
    ap.add_argument('--no-trust', action='store_true')
    ap.add_argument('--password')
    ap.add_argument('--ades-lta', action='store_true')
    ap.add_argument('--norev', action='store_true')
    ap.add_argument('--ac-vc', action='store_true')
    ap.add_argument('--as-timestamp', action='store_true')
    ap.add_argument('--from-fields', action='store_true')
    ap.add_argument('--count-only', action='store_true')
    ap.add_argument('--diff-policy')
    ap.add_argument('--ts-anchor', action='append', default=[])
    ap.add_argument('--live', action='append', default=[])
    ap.add_argument('--lenient', action='store_true')
    ap.add_argument('--revocation-mode', default='soft-fail')
    a = ap.parse_args()
    if a.time:
        with freeze_time(datetime.fromisoformat(a.time)):
            out = run_with_services(a)
    else:
        out = run_with_services(a)
    print(json.dumps(out))


main()
