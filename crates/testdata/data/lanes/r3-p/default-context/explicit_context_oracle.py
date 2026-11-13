"""Fresh same-native-output checks with explicit roots in every call."""
import hashlib
import importlib.metadata
import inspect
import json
from datetime import datetime
from io import BytesIO
from pathlib import Path
import sys
import platform
import warnings

from asn1crypto import x509
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext

OPENED = []


def read(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    OPENED.append(dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest()))
    return data


assert __debug__ and not sys.flags.optimize
assert importlib.metadata.version("pyHanko") == "0.38.1"
assert importlib.metadata.version("pyhanko-certvalidator") == "0.33.0"
import importlib
for module_name, expected_sha256 in [('pyhanko.sign.validation', '4a89ea2185b990ba735755c7911a50f2dc4647905e97b2d9751814ecb1a8fe0d'), ('pyhanko.sign.validation.pdf_embedded', '3455928ac7588ca1b5c836b58b0c7c678ff982c484bd5a1602bdbe62e24bdd8a'), ('pyhanko_certvalidator.registry', 'f17a075c516fafeb0b1355b183a9a86e2357f7d0a6462b298dc88a81ee964361'), ('pyhanko_certvalidator.context', '3d66e60ebd6dbaf932f76c4c0cc6c4dcb4e1f312876d0e74836a4796ebc15a3d')]:
    module = importlib.import_module(module_name)
    assert hashlib.sha256(read(inspect.getfile(module))).hexdigest() == expected_sha256
request = json.loads(read(sys.argv[1]))
assert request["time"] == "2020-11-01T00:00:00Z"
raw = read(request["pdf"])
root = x509.Certificate.load(read(request["root"]))
intermediate = x509.Certificate.load(read(request["intermediate"]))
leaf = x509.Certificate.load(read(request["leaf"]))
signatures = PdfFileReader(BytesIO(raw)).embedded_signatures
assert len(signatures) == 1 and signatures[0].field_name == "Sig1"
assert signatures[0].signer_cert.dump() == leaf.dump()
statuses = []
for has_root in [True, False]:
    with warnings.catch_warnings(record=True) as observed:
        warnings.simplefilter("always")
        context = ValidationContext(trust_roots=[root] if has_root else [],
            other_certs=[intermediate, root], moment=datetime.fromisoformat(request["time"]),
            allow_fetching=False, revocation_mode="soft-fail")
        status = validate_pdf_signature(signatures[0], context)
    assert not any(issubclass(w.category, DeprecationWarning) and "operating system's trust" in str(w.message) for w in observed)
    assert status.intact and status.valid
    assert status.trusted == has_root and status.bottom_line == has_root
    assert status.md_algorithm == "sha256"
    assert status.signing_cert.dump() == leaf.dump()
    assert status.coverage.name == "ENTIRE_FILE" and status.modification_level.name == "NONE"
    if has_root:
        path = [cert.dump() for cert in status.validation_path]
        assert path == [root.dump(), intermediate.dump(), leaf.dump()]
    else:
        assert status.trust_problem_indic.name == "NO_CERTIFICATE_CHAIN_FOUND"
    statuses.append(dict(explicit_root=has_root, intact=status.intact, valid=status.valid,
        trusted=status.trusted, bottom_line=status.bottom_line,
        coverage=status.coverage.name, modification_level=status.modification_level.name,
        trust_indication=None if status.trust_problem_indic is None else status.trust_problem_indic.name,
        path_sha256=None if status.validation_path is None else [hashlib.sha256(cert.dump()).hexdigest() for cert in status.validation_path]))
print(json.dumps(dict(versions={"pyhanko":importlib.metadata.version("pyHanko"),"certvalidator":importlib.metadata.version("pyhanko-certvalidator")},
    runtime=dict(executable=sys.executable, version=sys.version, host=platform.node(),
        debug=__debug__, optimize=sys.flags.optimize, isolated=sys.flags.isolated),
    pdf_sha256=hashlib.sha256(raw).hexdigest(), signer_sha256=hashlib.sha256(leaf.dump()).hexdigest(),
    statuses=statuses, opened_inputs=OPENED), sort_keys=True))
