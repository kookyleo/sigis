"""pyHanko verdict on a CMS signature produced by hanko-sign.

Usage: python validate_cms.py --cms FILE [--data FILE] [--trust CERT ...]
                              [--time ISO8601] [--tst-imprint HEX]

With --tst-imprint the CMS object is validated as an RFC 3161 timestamp
token whose message imprint must equal the given digest. Otherwise it is
validated as a (detached or enveloping) CMS signature over --data.
The validation time is pinned with --time; fetching is disabled.
Prints a JSON object with pyHanko's status fields, or {"error": ...}.
"""

import argparse
import asyncio
import json
from datetime import datetime

from asn1crypto import cms
from pyhanko.keys import load_cert_from_pemder
from pyhanko.sign.validation import generic_cms
from pyhanko_certvalidator import ValidationContext


def status_json(st):
    out = {
        'intact': st.intact,
        'valid': st.valid,
        'trusted': st.trusted,
        'md_algorithm': st.md_algorithm,
        'pkcs7_signature_mechanism': st.pkcs7_signature_mechanism,
        'signing_cert_sha256': st.signing_cert.sha256.hex(),
    }
    for name in ('bottom_line',):
        if hasattr(st, name):
            out[name] = getattr(st, name)
    ts = getattr(st, 'timestamp', None)
    if ts is not None:
        out['timestamp'] = ts.isoformat()
    for name in ('timestamp_validity', 'content_timestamp_validity'):
        sub = getattr(st, name, None)
        if sub is not None:
            out[name] = status_json(sub)
    if getattr(st, 'signer_reported_dt', None) is not None:
        out['signer_reported_dt'] = st.signer_reported_dt.isoformat()
    return out


async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--cms', required=True)
    ap.add_argument('--data')
    ap.add_argument('--trust', action='append', default=[])
    ap.add_argument('--other', action='append', default=[])
    ap.add_argument('--time')
    ap.add_argument('--tst-imprint')
    a = ap.parse_args()
    with open(a.cms, 'rb') as f:
        ci = cms.ContentInfo.load(f.read())
    moment = datetime.fromisoformat(a.time) if a.time else None
    vc = ValidationContext(
        trust_roots=[load_cert_from_pemder(p) for p in a.trust],
        other_certs=[load_cert_from_pemder(p) for p in a.other],
        allow_fetching=False,
        moment=moment,
        revocation_mode='soft-fail',
    )
    sd = ci['content']
    try:
        if a.tst_imprint is not None:
            st = await generic_cms.validate_tst_signed_data(
                sd, vc, lambda _md: bytes.fromhex(a.tst_imprint)
            )
            from pyhanko.sign.validation.status import TimestampSignatureStatus

            out = status_json(TimestampSignatureStatus(**st))
        else:
            data = None
            if a.data:
                with open(a.data, 'rb') as f:
                    data = f.read()
            if data is None:
                st = await generic_cms.async_validate_cms_signature(
                    sd, validation_context=vc
                )
            else:
                st = await generic_cms.async_validate_detached_cms(
                    data, sd, signer_validation_context=vc
                )
            out = status_json(st)
    except Exception as e:  # report pyHanko's rejection class
        out = {'error': f'{e.__class__.__name__}: {e}'}
    print(json.dumps(out))


asyncio.run(main())
