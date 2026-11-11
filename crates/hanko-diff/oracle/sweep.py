"""
Differential sweep: run pyHanko's DEFAULT_DIFF_POLICY on every recorded
input file (``crates/hanko-testdata/data/lanes/c/pdf/``) for every base
revision, in strict and non-strict reading mode, and print the verdicts as
JSON (``sweep.json``).

Usage: python sweep.py LANE_C_DIR [SHA ...]
"""

import json
import os
import sys
from io import BytesIO

from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.diff_analysis import DEFAULT_DIFF_POLICY, SuspiciousModification


def verdict(data: bytes, encrypted: bool, strict: bool, base: int):
    try:
        reader = PdfFileReader(BytesIO(data), strict=strict)
        if encrypted:
            reader.decrypt('secret')
        result = DEFAULT_DIFF_POLICY.review_file(reader, base)
    except Exception as e:  # noqa: BLE001
        return {'error': type(e).__name__, 'message': str(e)[:500]}
    if isinstance(result, SuspiciousModification):
        return {'suspicious': str(result)[:500]}
    return {
        'level': result.modification_level.value,
        'changed_form_fields': sorted(result.changed_form_fields),
    }


def main():
    lane = sys.argv[1]
    shas = sys.argv[2:] or sorted(
        f[:-4] for f in os.listdir(os.path.join(lane, 'pdf')) if f.endswith('.pdf')
    )
    out = {}
    for sha in shas:
        with open(os.path.join(lane, 'pdf', sha + '.pdf'), 'rb') as f:
            data = f.read()
        with open(os.path.join(lane, 'model', sha + '.json')) as f:
            model = json.load(f)
        n = len(model['revisions'])
        entry = {}
        for strict in (True, False):
            entry['strict' if strict else 'lenient'] = [
                verdict(data, model['encrypted'], strict, base)
                for base in range(n - 1)
            ]
        out[sha] = entry
    json.dump(out, sys.stdout, indent=1, sort_keys=True)


if __name__ == '__main__':
    main()
