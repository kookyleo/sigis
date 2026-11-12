"""pyHanko's verdicts on trusted lists, for the differential test.

Usage: tl_verdicts.py <cases.json>

``cases.json`` is a list of objects ``{"xml": path, "certs": [pem paths],
"time": ISO 8601 or null}``. For each case the script prints, as JSON:

* ``signature``: ``"valid"`` / ``"invalid"`` (validation with the given
  certificates at the given time; ``null`` if no certificates were given),
* ``cas``, ``qtsts``: numbers of CA and QTST service definitions read from
  the (signed, if validated) list, ``errors``: number of parsing errors,
* ``known_cas``, ``known_tsas``: distinct authorities in the registry.

If pyHanko cannot be imported, prints ``{"skip": reason}``.
"""

import json
import sys
from datetime import datetime


def main():
    try:
        from lxml.etree import DocumentInvalid
        from pyhanko.keys import load_certs_from_pemder
        from pyhanko.sign.validation.errors import SignatureValidationError
        from pyhanko.sign.validation.qualified import eutl_parse
        from pyhanko.sign.validation.qualified.tsp import CAServiceInformation
    except ImportError as e:
        print(json.dumps({'skip': f'pyHanko not importable: {e}'}))
        return
    with open(sys.argv[1], 'r', encoding='utf-8') as f:
        cases = json.load(f)
    out = []
    for case in cases:
        with open(case['xml'], 'r', encoding='utf-8') as f:
            xml = f.read()
        certs = []
        for p in case.get('certs') or []:
            certs.extend(load_certs_from_pemder([p]))
        verdict = {'signature': None}
        if certs:
            t = case.get('time')
            when = datetime.fromisoformat(t.replace('Z', '+00:00')) if t else None
            try:
                xml = eutl_parse._validate_and_extract_tl_data_multiple_certs(xml, certs, when)
                verdict['signature'] = 'valid'
            except (SignatureValidationError, DocumentInvalid):
                verdict['signature'] = 'invalid'
                out.append(verdict)
                continue
        try:
            g = eutl_parse.read_qualified_service_definitions(xml)
            cas = qtsts = 0
            while True:
                try:
                    sd = next(g)
                except StopIteration as stop:
                    errors = stop.value
                    break
                if isinstance(sd, CAServiceInformation):
                    cas += 1
                else:
                    qtsts += 1
            registry, _ = eutl_parse.trust_list_to_registry_unsafe(xml)
            verdict.update(
                cas=cas,
                qtsts=qtsts,
                errors=len(errors),
                known_cas=len(set(registry.known_certificate_authorities)),
                known_tsas=len(set(registry.known_timestamp_authorities)),
            )
        except Exception as e:  # noqa: BLE001
            verdict['parse_error'] = f'{type(e).__name__}: {e}'
        out.append(verdict)
    print(json.dumps(out))


if __name__ == '__main__':
    main()
