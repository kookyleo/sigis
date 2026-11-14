"""Validate one actual native PDF using the pinned original fixture profile.

Usage: pinned-python validate_output.py ACTUAL_PDF ACTUAL_ROOT_DER
The 2020 original profile is explicit; this does not claim current-time trust.
"""
from __future__ import annotations

from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
import sys


def main():
    if len(sys.argv) != 3:
        raise SystemExit("Usage: validate_output.py ACTUAL_PDF ACTUAL_ROOT_DER")
    from asn1crypto import x509
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.sign.validation import validate_pdf_signature
    from pyhanko_certvalidator import ValidationContext

    raw = Path(sys.argv[1]).read_bytes()
    root = x509.Certificate.load(Path(sys.argv[2]).read_bytes(), strict=True)
    reader = PdfFileReader(BytesIO(raw))
    assert len(reader.embedded_signatures) == 1
    signature = reader.embedded_signatures[0]
    assert signature.field_name == "Sig1"
    moment = datetime(2020, 11, 1, tzinfo=timezone.utc)

    def context(roots):
        return ValidationContext(trust_roots=roots, moment=moment, allow_fetching=False)

    status = validate_pdf_signature(signature, context([root]))
    assert status.intact and status.valid and status.trusted and status.bottom_line, status.summary()
    assert status.coverage.name == "ENTIRE_FILE"
    assert len(status.validation_path) == 3
    denied = validate_pdf_signature(signature, context([]))
    assert not denied.trusted and not denied.bottom_line
    mutated = bytearray(raw)
    assert mutated.startswith(b"%PDF-") and len(mutated) > 12
    mutated[12] ^= 1
    changed = PdfFileReader(BytesIO(mutated)).embedded_signatures[0]
    changed_status = validate_pdf_signature(changed, context([root]))
    assert not changed_status.intact and not changed_status.bottom_line
    print("Actual native PDF: Sig1 intact valid trusted EntireFile path3; empty-root and modified-byte controls deny (2020-11-01 profile)")


if __name__ == "__main__":
    main()
