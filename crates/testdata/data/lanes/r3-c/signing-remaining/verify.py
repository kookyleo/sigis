"""Fresh pinned validation of the actual native bytes, without evidence reports."""
import sys
from datetime import datetime, timezone
assert __debug__ and sys.flags.optimize == 0
from asn1crypto import pem, x509
from freezegun import freeze_time
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext
from pyhanko_testing_commons.test_data.samples import TESTING_CA, TESTING_CA_ECDSA, TESTING_CA_ED25519, TESTING_CA_ED448
from pyhanko_testing_commons.test_utils.live_http import live_pki_services
path, root_path, arch, strict = sys.argv[1:]
architecture={"rsa":TESTING_CA,"ecdsa":TESTING_CA_ECDSA,"ed25519":TESTING_CA_ED25519,"ed448":TESTING_CA_ED448}[arch]
root=x509.Certificate.load(pem.unarmor(open(root_path,"rb").read())[2])
before=open(path,"rb").read()
with freeze_time(datetime(2020,7,31,16,tzinfo=timezone.utc)),live_pki_services() as services:
    services.register(architecture)
    with open(path,"rb") as stream:
        reader=PdfFileReader(stream,strict=strict=="true")
        signature=reader.embedded_regular_signatures[-1]
        status=validate_pdf_signature(signature,signer_validation_context=ValidationContext(trust_roots=[root],allow_fetching=True))
        assert status.bottom_line,status.pretty_print_details()
        denied=validate_pdf_signature(signature,signer_validation_context=ValidationContext(trust_roots=[],allow_fetching=True))
        assert not denied.bottom_line
assert open(path,"rb").read()==before
print("VALID; empty roots refused")
