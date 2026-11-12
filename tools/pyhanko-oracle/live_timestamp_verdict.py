"""Verify Rust-fetched tokens with the pinned Python oracle, without fetching."""

import asyncio
import json
import sys
from pathlib import Path

from asn1crypto import cms
from freezegun import freeze_time
from pyhanko.sign.validation.generic_cms import validate_tst_signed_data
from pyhanko_certvalidator import ValidationContext


async def verdict(token, imprint):
    status = await validate_tst_signed_data(
        cms.ContentInfo.load(token)['content'],
        ValidationContext(trust_roots=[], allow_fetching=False),
        expected_tst_imprint=lambda _: imprint,
    )
    problem = status.get('trust_problem_indic')
    return {
        'valid': status['valid'], 'intact': status['intact'],
        'trust_problem_indic': None if problem is None else problem.name,
    }


async def run():
    token = Path(sys.argv[1]).read_bytes()
    imprint = bytes.fromhex(sys.argv[2])
    wrong = bytes([imprint[0] ^ 1]) + imprint[1:]
    return {'correct': await verdict(token, imprint), 'wrong': await verdict(token, wrong)}


with freeze_time(sys.argv[3]):
    print(json.dumps(asyncio.run(run())))
