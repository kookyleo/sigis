"""Encrypted inputs for the ported test_sign_encrypted.py tests.

Usage: python gen_encrypted.py <pdf-data-dir> <out-dir>

Reproduces the documents those tests build with pyHanko's writer:
- minimal-with-field-owner-only.pdf: MINIMAL_ONE_FIELD copied into a new
  writer, encrypted with owner password 'ownersecret' and an empty user
  password (test_sign_crypt_empty_user_pass);
- minimal-with-field-secret.pdf: the same, with 'secret' as both passwords
  (test_sign_encrypted_with_extensions).
The file IDs and encryption salts are random, so outputs differ per run.
"""

import os
import sys
from io import BytesIO

from pyhanko.pdf_utils import writer
from pyhanko.pdf_utils.reader import PdfFileReader


def make(src, owner, user, dest):
    with open(src, 'rb') as f:
        w = writer.copy_into_new_writer(PdfFileReader(BytesIO(f.read())))
    if user is None:
        w.encrypt(owner)
    else:
        w.encrypt(owner, user)
    out = BytesIO()
    w.write(out)
    with open(dest, 'wb') as f:
        f.write(out.getvalue())


def main():
    pdf_dir, out_dir = sys.argv[1], sys.argv[2]
    os.makedirs(out_dir, exist_ok=True)
    src = os.path.join(pdf_dir, 'minimal-with-field.pdf')
    make(src, 'ownersecret', '', os.path.join(out_dir, 'minimal-with-field-owner-only.pdf'))
    make(src, 'secret', None, os.path.join(out_dir, 'minimal-with-field-secret.pdf'))
    print('ok')


main()
