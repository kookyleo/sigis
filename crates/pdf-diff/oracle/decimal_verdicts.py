"""Review raw PDF decimal changes with the pinned pyHanko oracle."""

import json
import sys

from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.diff_analysis import DEFAULT_DIFF_POLICY, SuspiciousModification

out = []
for path in sys.argv[1:]:
    try:
        with open(path, "rb") as stream:
            result = DEFAULT_DIFF_POLICY.review_file(PdfFileReader(stream), 0)
        out.append({"accepted": not isinstance(result, SuspiciousModification)})
    except Exception as exc:
        out.append({"accepted": False, "error": type(exc).__name__})
print(json.dumps(out))
