"""Structural facts about a PDF, as pyHanko's reader sees them.

Usage: python inspect_pdf.py FILE [--lenient] [--password PWD]

Prints JSON: total revisions, input version, embedded signatures (field,
type, signed revision), DSS cardinalities and the revision in which the
DSS was last changed.
"""

import json
import sys

from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation.dss import DocumentSecurityStore


def main():
    path = sys.argv[1]
    lenient = '--lenient' in sys.argv
    with open(path, 'rb') as f:
        r = PdfFileReader(f, strict=not lenient)
        if '--password' in sys.argv:
            r.decrypt(sys.argv[sys.argv.index('--password') + 1].encode())
        out = {
            'total_revisions': r.xrefs.total_revisions,
            'input_version': list(r.input_version),
            'signatures': [],
        }
        for s in r.embedded_signatures:
            out['signatures'].append({
                'field': s.field_name,
                'type': s.sig_object_type,
                'signed_revision': s.signed_revision,
                'cert_count': len(s.signed_data['certificates']),
            })
        try:
            dss = DocumentSecurityStore.read_dss(r)
            out['dss'] = {
                'certs': len(dss.certs),
                'ocsps': len(dss.ocsps),
                'crls': len(dss.crls),
                'vri': len(dss.vri_entries),
            }
            ref = r.root.get_value_as_reference('/DSS')
            out['dss_last_change'] = r.xrefs.get_last_change(ref)
        except Exception as e:  # no DSS or direct DSS
            out['dss_error'] = f'{e.__class__.__name__}: {e}'
        print(json.dumps(out))


main()
