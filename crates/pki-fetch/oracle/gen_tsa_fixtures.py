"""Generate the RFC 3161 fixtures of lane A (hanko-fetch tests).

Run with the pyHanko 0.38.1 oracle interpreter, which has
pyhanko_testing_commons (the upstream test helpers) installed:

    $HANKO_ORACLE crates/pki-fetch/oracle/gen_tsa_fixtures.py OUT_DIR

Writes, with time frozen at 2020-11-01T00:00:00Z:

- error-{1,2,3}.der: the TimeStampResp values of test_handle_error_response;
- granted-fixed-nonce.der: pyHanko's DUMMY_TS response to a request over
  SHA-256("Hello world!") with nonce 0x0102030405060708;
- root.der: the testing CA root certificate.
"""

import hashlib
import os
import sys

from asn1crypto import algos, cms, tsp
from freezegun import freeze_time

out = sys.argv[1]
os.makedirs(out, exist_ok=True)


def write(name, data):
    with open(os.path.join(out, name), 'wb') as f:
        f.write(data)


with freeze_time('2020-11-01'):
    from pyhanko_testing_commons.test_utils.signing_commons import (
        DUMMY_TS,
        ROOT_CERT,
    )

    def bogus_token():
        return cms.ContentInfo({'content_type': 'data'})

    write(
        'error-1.der',
        tsp.TimeStampResp(
            {
                'status': {
                    'status': 'waiting',
                    'status_string': ['clock is down'],
                    'fail_info': tsp.PKIFailureInfo({'time_not_available'}),
                },
                'time_stamp_token': bogus_token(),
            }
        ).dump(),
    )
    write(
        'error-2.der',
        tsp.TimeStampResp(
            {
                'status': {
                    'status': 'waiting',
                    'status_string': ['clock is down'],
                },
                'time_stamp_token': bogus_token(),
            }
        ).dump(),
    )
    write(
        'error-3.der',
        tsp.TimeStampResp(
            {
                'status': {
                    'status': 'waiting',
                    'fail_info': tsp.PKIFailureInfo({'time_not_available'}),
                },
                'time_stamp_token': bogus_token(),
            }
        ).dump(),
    )
    digest = hashlib.sha256(b'Hello world!').digest()
    req = tsp.TimeStampReq(
        {
            'version': 1,
            'message_imprint': tsp.MessageImprint(
                {
                    'hash_algorithm': algos.DigestAlgorithm({'algorithm': 'sha256'}),
                    'hashed_message': digest,
                }
            ),
            'nonce': cms.Integer(0x0102030405060708),
            'cert_req': True,
        }
    )
    write('granted-fixed-nonce.der', DUMMY_TS.request_tsa_response(req).dump())
    write('root.der', ROOT_CERT.dump())
