"""Write pyhanko_testing_commons' ``minimal_with_oversized_objstm()`` to a
file (test input for ``test_stamp_file_decode_limits``).

Usage: python -I oversized_objstm.py OUT.pdf
Prints a JSON object with the output size.
"""

import json
import sys

from pyhanko_testing_commons.test_data.samples import (
    minimal_with_oversized_objstm,
)


def main():
    out = sys.argv[1]
    w = minimal_with_oversized_objstm()
    with open(out, 'wb') as f:
        w.write(f)
    with open(out, 'rb') as f:
        size = len(f.read())
    json.dump({'size': size}, sys.stdout)


if __name__ == '__main__':
    main()
