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
    if getattr(st, 'diff_result', None) is not None:
        out['diff_result'] = str(st.diff_result)
    return out


async def run(a):
    with open(a.pdf, 'rb') as f:
        r = PdfFileReader(f, strict=not a.lenient)
        if a.password is not None:
            r.decrypt(a.password.encode())
        out = []
        for sig in r.embedded_signatures:
            vc = ValidationContext(
                trust_roots=[] if a.no_trust else [load_cert_from_pemder(p) for p in a.trust],
                other_certs=[load_cert_from_pemder(p) for p in a.other],
                allow_fetching=False,
                revocation_mode=a.revocation_mode,
            )
            entry = {
                'field': sig.field_name,
                'type': sig.sig_object_type,
                'subfilter': str(sig.sig_object.get('/SubFilter')),
            }
            try:
                if sig.sig_object_type == '/DocTimeStamp':
                    st = await async_validate_pdf_timestamp(sig, validation_context=vc)
                else:
                    st = await async_validate_pdf_signature(
                        sig, vc, skip_diff=not a.extd
                    )
                entry.update(status_json(st))
            except Exception as e:  # report pyHanko's rejection class
                entry['error'] = f'{e.__class__.__name__}: {e}'
            out.append(entry)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--pdf', required=True)
    ap.add_argument('--trust', action='append', default=[])
    ap.add_argument('--other', action='append', default=[])
    ap.add_argument('--time')
    ap.add_argument('--extd', action='store_true')
    ap.add_argument('--no-trust', action='store_true')
    ap.add_argument('--password')
    ap.add_argument('--lenient', action='store_true')
    ap.add_argument('--revocation-mode', default='soft-fail')
    a = ap.parse_args()
    if a.time:
        with freeze_time(datetime.fromisoformat(a.time)):
            out = asyncio.run(run(a))
    else:
        out = asyncio.run(run(a))
    print(json.dumps(out))


main()
